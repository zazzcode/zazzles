# Architecture phase 2 — Pipeline and concurrent language runners

**Branch / assigned sibling worktree:** `arch-pipeline-runners` (owner-created, 2026-11-18)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 2. Objective: performance and maintainability
**Depends on:** satisfied — phase 1 complete; [PR #24](https://github.com/zazzcode/zazzles/pull/24) merged into `stage` at `6bf2ca14a63869cb0957eec7f830ba0544b819a7`
**Delivery topology:** existing owner-created branch/worktree from the phase 1 merge; one separate draft PR into `stage`
**Coordination:** Lead Agent. A Contributor Agent may do the mechanical caller migration (§9 step 5) after the seam compiles
**Run log:** `.zazz/ephemeral/architecture-phase-2-pipeline-runners-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Today a full scan walks the target up to three times, opens all three grammars, and runs JS/TS,
Python, and PHP one after another inside `parse.AnalyzeWithOptions`. This phase changes that:

- **One walk.** The new `internal/pipeline` package walks the target once.
- **Empty languages are skipped.** A language with no files opens no grammar.
- **Concurrent runners.** The language runners run concurrently.
- **Single merge point.** A single `parse.Assemble` merges results in the existing fixed order and
  finalizes them.

`internal/parse` becomes a producer: it exposes per-language runners and `Assemble`. It no longer
owns repository orchestration. That gives phase 3 an acyclic place to plug in `internal/langphp`.
Output bytes do not change.

## 2. Required reading

- Plan [what already exists](architecture-update-plan.md#what-already-exists) and the merge-order rule
  in [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).
- Code: `internal/parse/analysis.go` (`AnalyzeWithOptions`: the deferred `RecordCheckMatches`/`Attach`,
  the `.py`/`.php` entry branches, the JS body, and the Python/PHP merge block that runs only when
  `entry == ""`); `python_modules.go` and `php_modules.go` (`newPythonSet`/`newPHPSet` each call
  `walk.Walk`); `python_browser.go` (Python builds its own JS parser set); `cmd/scan/analysis.go`.
- [Testing: concurrency](../standards/testing.md#6-concurrency), [code structure](../standards/code-structure.md#1-package-layout)
  ("Import cycles are a design error").
- [Architecture §2 pipeline](../architecture/README.md#2-pipeline), [§11](../architecture/README.md#11-implemented-package-boundaries).

## 3. Invariants

- `TestArchitectureBaseline` is unchanged, byte for byte. There are no listed deltas.
- Merge order is JS/TS, then Python, then PHP, as today. That includes today's conditions: Python
  and PHP `Limitations`/`AnalysisGuidelines` are appended only when that language produced entries,
  and Python/PHP merge only when `entry == ""`.
- If several runners fail, the returned error is that of the earliest runner in the fixed order,
  regardless of completion order.
- `--entry` behavior is unchanged: a `.py` entry runs only Python, a `.php` entry runs only PHP, and
  a JS/TS entry runs only JS/TS.
- Runners share no mutable package-level state. Each owns its parsers and module sets.
- `parse.Routes` (route-inventory mode) and the `cmd/scan` manifest mode keep their own walks. They are separate commands.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/pipeline/pipeline.go`, `pipeline_test.go` | new | `Analyze`, `AnalyzeWithChecks`, `AnalyzeWithOptions`, `Options{DiscoverRoutes bool; Workers int}`; one walk, runner selection, concurrency, `parse.Assemble`, check/pack attachment |
| `internal/parse/analysis.go` | modified | Split into `Inventory`, `RunJavaScript`, `Assemble`; remove the exported `Analyze*` functions |
| `internal/parse/python_modules.go`, `php_modules.go` | modified | `RunPython(inv, …)` and `RunPHP(inv, …)` take the shared inventory; no walk |
| `internal/parse/analyze_test.go` | new (test-only) | `Analyze`/`AnalyzeWithChecks` helpers for internal tests: runners in sequence, then `Assemble` |
| All files calling `parse.Analyze`, `parse.AnalyzeWithChecks`, `parse.AnalyzeWithOptions`, or `parse.Options` outside `internal/parse` (37 files at the plan baseline; list them in the run log) | modified | Import `internal/pipeline` instead |
| `cmd/scan/architecture_baseline_test.go` | modified | Call `pipeline.AnalyzeWithOptions` |
| `.zazz/architecture/README.md` §2 and §11, orientation code-structure row | modified | `pipeline` responsibility; `parse` as producer |
| `.zazz/evaluation/architecture-baseline.md` | modified | After measurements and walk count |

Out of scope:

- moving any language into its own package (phase 3);
- judge concurrency (phase 4);
- new CLI flags (`Workers` is internal, default 0 = one worker per selected runner);
- route-inventory mode.

Review shape: one PR. The caller migration is a separate commit so reviewers can skip it.

## 5. Decisions

- **D-1 Orchestration lives in a new `internal/pipeline`, and `parse` exposes runners.** Phase 3's
  `langphp` must import `parse` core helpers. If `parse` kept orchestration, it would have to import
  `langphp`, which is a cycle. Rejected alternatives:
  - `init()` self-registration hides the dependency, which the code-structure standard forbids.
  - Extracting a shared core out of `parse` first means moving deeply entangled flow types. That
    is much larger and has no consumer yet.
- **D-2 The fixed merge lives in `parse.Assemble`, called by both `pipeline` and the parse test
  helper.** One copy of the merge-and-finalize logic, so the test helper cannot drift from
  production. `Assemble` takes nil for a language that did not run.
- **D-3 One `walk.Walk` result, `parse.Inventory{Root string; Files []walk.File}`, is passed to
  every runner.** It is computed once. Runners filter by `lang.Language`.
- **D-4 Empty-language skip keeps the JS base report.** The JS runner always builds the base report
  with today's fixed `Limitations`. With no JS/TS files it skips `newParsers` and module work only.
  A Python or PHP runner with no files is not run, and `Assemble` treats it as nil. Phase 0 shows
  that is byte-identical to merging today's empty report. If it is not, halt.
- **D-5 Concurrency uses standard-library goroutines with a `sync.WaitGroup` and per-runner result
  slots.** There is no worker-pool library. `Workers: 1` runs the runners one after another in the
  fixed order. The equivalence test uses it, and it is the debugging fallback.
- **D-6 Tests inside `parse` keep calling an unqualified `Analyze`.** A same-package `_test.go`
  helper keeps hundreds of call sites unchanged and makes no production alias. No obsolete Go
  aliases remain in production code.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Any phase 0 golden byte changes.
- `go test -race` reports a race between runners. Fix it by moving the state into the runner. Do
  not add locks around shared parse tables without asking.
- An external caller depends on a behavior of the old `parse.AnalyzeWithOptions` that `pipeline`
  cannot reproduce without a public signature change.

## 7. Acceptance criteria

1. **AC1 One walk.** A `pipeline` test with a counting `walk` hook, or a stubbed inventory provider,
   shows exactly one walk for a full scan of `mixed/three-language`. `grep -n "walk.Walk" internal/parse`
   lists only `parse.go` (route inventory).
2. **AC2 Skip.** For `python/routes` (no JS/TS or PHP files), the JS module set and PHP parser are never
   created, and Python is the only runner that runs. A test hook records which runners ran. The
   report matches the golden.
3. **AC3 Equivalence.** For every phase 0 fixture, `pipeline.AnalyzeWithOptions` with `Workers: 1`
   and with the default produce identical JSON. The test runs both 5 times under `-race`.
4. **AC4 Error order.** With stub runners where Python and PHP both fail and PHP finishes first, the
   returned error is Python's. This uses a test-only runner injection seam inside `pipeline`.
5. **AC5 Entry modes.** The existing `--entry` CLI tests in `cmd/scan` (`python_test.go`,
   `php_test.go`, `analysis_test.go`) pass unchanged.
6. **AC6 Golden.** `TestArchitectureBaseline` passes against the phase 1 golden with no update.
7. **AC7 Measurement.** The evaluation record compares this phase with phase 0 on juice-shop,
   vulnpy, and DVWA: median of 3 offline wall-clock runs, peak RSS, and walk count. It also has a
   `BenchmarkPipelineMixed` result for `Workers: 1` versus the default. A single-language sample
   that shows no parallel gain is stated as such.
8. **AC8 Gate and docs.** The architecture §2 and §11 and orientation updates are made, and the
   contributor gate passes.

## 8. Test strategy

`pipeline_test.go` covers AC1–AC4 with real fixtures plus one injected-runner case for error order.
AC5 and AC6 reuse existing tests and the phase 0 golden. No per-runner unit tests are added: the
runner bodies move unchanged and the golden covers them.

## 9. TDD entry point and execution sequence

1. **Red:** write `pipeline_test.go` AC3 against a `pipeline` package that only declares the API.
2. Split `parse`:

```go
// internal/parse
type Inventory struct{ Root string; Files []walk.File }
type Options struct{ DiscoverRoutes bool } // unchanged meaning
func RunJavaScript(inv Inventory, entry string, checks []analysis.Check, opts Options) (*analysis.AnalysisReport, error)
func RunPython(inv Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error) // nil, nil when no files
func RunPHP(inv Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)    // nil, nil when no files
// Assemble merges in fixed order and finalizes (finalizeEntries, blockUnlinkedStoredOrigins,
// linkNavigationClaims). Single-language entry modes pass only that language's report.
func Assemble(entry string, js, py, php *analysis.AnalysisReport) (*analysis.AnalysisReport, error)
```

3. Add `internal/pipeline`:

```go
package pipeline
type Options struct{ DiscoverRoutes bool; Workers int }
func Analyze(root, entry string) (*analysis.AnalysisReport, error)
func AnalyzeWithChecks(root, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)
func AnalyzeWithOptions(root, entry string, checks []analysis.Check, opts Options) (*analysis.AnalysisReport, error)
// validate packs; walk once; select runners by entry extension and inventory languages;
// run (Workers); parse.Assemble; RecordCheckMatches; analysispacks.Attach each use
```

4. Add the parse test helper (`analyze_test.go`). Get the `parse` tests green.
5. Migrate the external callers in their own commit, then run AC5 and AC6.
6. AC1, AC2, and AC4 tests; `-race`; measurements for AC7; docs; gate; commit and push.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC8 verified, with evidence in the run log.
- [ ] `git diff <phase start HEAD> --stat` matches §4. The caller migration commit is mechanical, with an import and call rename only.
- [ ] The run log's PR summary states that there are no output changes and gives the before/after timing table.

## 11. Open questions

None.

## 12. Run log protocol

Use the plan's common rules. Record the migrated caller list, race-test output, and timing tables.

## 13. Agent implementation prompt

> Implement phase 2 in the existing owner-created arch-pipeline-runners sibling worktree and
> branch. PR #24 is merged at 6bf2ca14a63869cb0957eec7f830ba0544b819a7. Do not create a worktree
> or branch. Read AGENTS.md, then the orientation contents and only relevant sections, the plan's
> shared/common/session-start rules, this spec in full (including every §14 entry), and the phase 2
> run log if it exists. Load the required repository skills and matched standards.
>
> Verify pwd, branch, git status --short --branch, git worktree list and the predecessor merge.
> Stop if in a .claude/worktrees checkout or claude/* branch. Preserve existing changes; record
> the starting HEAD and migrated caller inventory. Run TestArchitectureBaseline before code changes.
> Reconcile §4 and §9 with the merged phase 1 code before implementing. The golden has no planned
> delta; do not refresh it to accept a refactor difference.
>
> Execute §9 in small verified slices. Keep the mechanical caller migration in its own commit.
> After the seam compiles, one Contributor Agent may migrate callers in disjoint files in this same
> checkout; no agent-created worktrees. Stop on §6 or common-rule halts. Preserve fixed merge/error
> order, entry behavior, native evidence and exact output/request bytes.
>
> Offline only: no paid/live model calls or provider credentials. Samples are read-only; verify pins
> and clean status before/after. Write outputs under the container's _test-findings/<app>/run-arch-2/.
> Record three-run wall-clock medians, peak RSS and walk counts for all three samples, plus the mixed
> sequential/default benchmark. Compare with phase 0 and final phase 1 (9.21/3.42/0.60 seconds).
>
> Run the full contributor gate (gofmt on changed Go files only, go vet ./..., go build ./...,
> go test -race ./... -count=1, and TestArchitectureBaseline). A fresh-context verifier subagent runs
> go test -race ./internal/pipeline ./cmd/scan -count=3, checks walk ownership and removal of exported
> production parse.Analyze* functions, and confirms the golden is unchanged from starting HEAD.
> Update the evaluation, architecture/orientation, spec §14 and append-only run log with AC1–AC8
> evidence. Verify Git user.name and gh profile are zazzcode; commit with [AREA] prefixes, push
> origin arch-pipeline-runners and open a separate draft PR into stage using pr-builder and the
> PR standard. Never mark ready or merge. Report commits, AC evidence, deltas, timings, PR and limits.

## 14. Implementation and review change log

### 2026-11-17 — Owner topology decision

Source: owner, in the planning session. Runs in the `arch-review-clean-up` worktree as one fresh
session, after the previous phase's commits, with no new worktree. Changed: header, §10 scope diff
base, §13 prompt. Verification impact: the scope diff is taken from this phase's recorded starting
HEAD, not `origin/stage`. The PR is the shared milestone draft PR into `stage`.

### 2026-11-18 — Separate phase 2 after owner merge

Owner steering: review and merge the current spec's PR, then start a new branch for phase 2.
Updated header and implementation prompt to require merged phase 1 and the arch-pipeline-runners branch.
This changes delivery metadata only; phase 2 is not started by the phase 1 agent.

### 2026-11-18 — Correct branch spelling and assign existing checkout

Owner confirms PR #24 is merged and has created the local arch-pipeline-runners branch/worktree.
Corrected the earlier branch typo throughout the architecture handoff references. Verified merge
6bf2ca14a63869cb0957eec7f830ba0544b819a7 and the clean assigned sibling checkout. Updated the header
and §13 startup prompt to reuse that checkout, preserve the golden, and carry offline verification,
measurement and draft-PR requirements into the next session. This update changes documentation only;
phase 2 implementation has not started.
