# Architecture phase 3A — PHP language package and behavior-named files

**Branch / assigned sibling worktree:** `arch-multi-lang-packaging` (owner-assigned, 2026-11-18)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 3A. Objective: maintainability
**Depends on:** satisfied — phase 2 merged into `stage` via [PR #25](https://github.com/zazzcode/zazzles/pull/25) at `52cdc36`
**Delivery topology:** first of two deliverables on this branch. Phase 3B,
[JS/TS and Python packages](architecture-phase-3-js-ts-python-package.md), follows on the same branch.
Both ship in one milestone draft PR into `stage`
**Coordination:** Lead Agent alone. The moves are tightly coupled
**Run log:** `.zazz/ephemeral/architecture-phase-3-php-package-run-log.md`
**Drafted:** 2026-11-17. **Reconciled** against merged phase 2 code: 2026-11-18 (§14)
**Status:** implemented on `arch-multi-lang-packaging` (from `f4ebb6d`); in the milestone draft PR, which phase 3B extends

## 1. Capability

Move the PHP adapter into `internal/langphp`:

- the `internal/parse/php_*.go` sources;
- their tests;
- `internal/parse/testdata/php/`.

Phase 2 left PHP behind `parse.RunPHP(inv, entry, checks)` in `php_modules.go`, called by
`internal/pipeline`. This phase replaces it with `langphp.Run(inv parse.Inventory, entry string,
checks []analysis.Check)`. Route-inventory mode (`parse.Routes`) also opens the PHP set, so route
orchestration moves to `pipeline.Routes`, and `langphp.Routes(inv)` supplies the PHP part.

The helpers PHP needs from `internal/parse` become a small, documented, exported **language core
API**. That API is the first written extension point for a language adapter. Phase 3B extends it
for Python and JS/TS. Symfony (phase 6) and Drupal (phase 9) build on it.

In the same phase, the eleven delivery-named `p1_`–`p4_` files are renamed for the behavior they
implement. Output bytes do not change.

## 2. Required reading

- Plan [what already exists](architecture-update-plan.md#what-already-exists) and [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).
- [Phase 2 spec](architecture-phase-2-pipeline-runners.md) §5 and its §14 reconciliation and post-review
  entries (`Inventory`, `NormalizeEntry`, `Inventory.Runners`, `Assemble`, the parse test helper).
- [Phase 3B spec](architecture-phase-3-js-ts-python-package.md) §1 and §5, so the core API names chosen
  here extend cleanly.
- [Code structure](../../standards/code-structure.md#1-package-layout), [file size thresholds](../../standards/code-structure.md#2-file-size-thresholds).
- [PHP support contract](php-support.md) §4 and §5 (what the adapter owns), [PHP results](../../evaluation/php-support-results.md).
- [Architecture: shared, language and framework layers](../../architecture/README.md#shared-language-and-framework-layers), [§11](../../architecture/README.md#11-implemented-package-boundaries).
- [Orientation: code structure](../../docs/zazzles-agent-orientation.md#code-structure).
- Code: `internal/parse/php_modules.go` (`RunPHP`, `openPHPSet`), `parse.go` (`Routes`),
  `closed_summary.go`, `analyze_test.go`, `internal/pipeline/pipeline.go`, `cmd/scan/main.go`.

## 3. Invariants

- `TestArchitectureBaseline` passes with no update except fixture keys: keys under
  `internal/parse/testdata/php/` move to `internal/langphp/testdata/`. Digests must not change,
  except PHP `report_sha256` values, which embed the fixture root path (§14, 2026-11-18 owner decision).
- Route-inventory output (`--routes` and its JSON) is unchanged for every fixture.
- `langphp` imports `internal/parse` (core API), `internal/analysis`, `internal/lang`, and Tree-sitter.
  It does not import `internal/pipeline` or any other language package. `internal/parse` never imports
  `langphp`. `internal/pipeline` imports both.
- The core API exports functions and small value types only. PHP must not reach into JS flow
  internals (`flow`, `value`, `moduleSet`, `sourceModule`).
- PHP fixtures keep their repository-relative contents. Evidence paths in goldens are relative to
  the fixture root, so they are unchanged.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/langphp/*.go` (from `internal/parse/php_*.go`, package renamed, `php` prefix dropped where it now stutters) | moved | PHP adapter; `Run` and `Routes` replace `RunPHP`, `openPHPSet` and `phpRoutes` as entry points |
| `internal/langphp/*_test.go` (from the six `php_*_test.go` files and `php_test.go`), `internal/langphp/testdata/` (from `internal/parse/testdata/php/`) | moved | PHP tests and fixtures |
| `internal/langphp/analyze_test.go` | new (test-only) | Same-package helper: `parse.RunJavaScript` for the base report, `langphp.Run`, then `parse.Assemble` |
| `internal/parse/core_api.go` (name adaptive) | new | Exported wrappers or renamed functions forming the language core API, with doc comments |
| `internal/parse/closed_summary.go` | modified | `closedCallable` becomes the exported shared lattice; `inertPHP` moves to `langphp` |
| `internal/parse/python_templates.go` and one neutral file (for `appendUniqueString`) | modified | Rehome the one neutral helper PHP takes from a Python-named file (§5 D-3) |
| `internal/parse/analysis.go` | modified | `Inventory.hasLanguage` exported or replaced (§9 step 1). `Assemble` keeps its PHP slot |
| `internal/parse/parse.go` | modified | `Routes` moves out of `parse`; the JS/TS and Python route parts become parse-level functions that `pipeline.Routes` calls |
| `internal/pipeline/pipeline.go`, `internal/pipeline/routes.go` (new), `pipeline_test.go` | modified / new | Call `langphp.Run`; own route-inventory orchestration and its sort |
| `cmd/scan/main.go` | modified | Call `pipeline.Routes` |
| `internal/parse/p1_*.go` … `p4_*.go` | renamed | See D-4 |
| `internal/parse/analyze_test.go` | modified | Drop the PHP runner from the test helper |
| Mixed-language tests in `internal/parse` that need PHP output (at least `analyze_test.go` and `python_index_parity_test.go` cases on `mixed/three-language`; exact list from §9 step 1) | moved | To `internal/pipeline`, which can import every runner |
| `cmd/scan/testdata/architecture-baseline.json` | modified | PHP fixture keys only |
| `.zazz/architecture/README.md` §3 and §11, `.zazz/architecture/repository-graph.md` (acquisition adapters), orientation code-structure and testdata rows, `docs/contributing.md` repository layout | modified | New package, core API, `pipeline.Routes` |
| `.zazz/standards/pr-process.md` scope-label table | modified | `PARSE` also covers `internal/lang*` language packages |
| `.zazz/specifications/scan/php-support.md` §4 | modified | Paths now under `internal/langphp`, with a change-log entry |

Out of scope: moving Python or JS/TS (phase 3B); behavior changes; new PHP families; Symfony.
Review shape: four commits in the shared milestone PR — helper rehoming, the PHP move with
`pipeline.Routes`, the `p*` renames, then docs.

## 5. Decisions

- **D-1 Move PHP first.** PHP is the newest and least coupled adapter. At `52cdc36` it uses 20
  non-field `parse` identifiers defined outside `php_*.go`, plus fields of `Inventory` and
  `closedCallable` (measured with a type-checked cross-reference; see §14). Python builds a JS
  `moduleSet` for templates and browser code (`python_browser.go`), so it moves in phase 3B after
  the core API exists.
- **D-2 The core API is exported from `parse`; no new core package.** A separate core package would
  have to move JS-entangled types. Exporting about 20 functions is reviewable and reversible. Phase
  3B keeps the name `parse` for the core (its D-4).
- **D-3 Rehome neutral helpers before exporting them.** A helper used by PHP and defined in a
  `python_*.go` file is language-neutral. At `52cdc36` that is only `appendUniqueString`. It moves
  to a neutral file in `parse` first, as a pure move, so the export does not look Python-owned.
  Conversely, `inertPHP` in `closed_summary.go` is PHP-owned and moves with PHP.
- **D-4 Rename `p*` files by behavior.** The names below are adaptive; keep them close in meaning.

| Current | New |
|---|---|
| `p1_catchall_join.go` | `next_catchall_join.go` |
| `p1_const_origin.go` | `const_origin_fold.go` |
| `p1_nonenforcing.go` | `outbound_nonenforcing_checks.go` |
| `p1_zod_fields.go` | `zod_field_reads.go` |
| `p2_fixed_origin.go` | `redirect_fixed_origin.go` |
| `p2_redirect_predicates.go` | `redirect_normalization.go` |
| `p3_keyed_store.go` | `keyed_store_lookup.go` |
| `p3_loop_control.go` | `control_context_loops.go` |
| `p3_python_decode.go` | `python_decode.go` |
| `p4_sql_literal_escape.go` | `prisma_sql_literal_escape.go` |
| `p4_stored_code.go` | `code_stored_links.go` |

- **D-5 Use `git mv` for moves.** That preserves history. Each moved file keeps its content apart
  from package, import, and identifier qualification changes.
- **D-6 Route-inventory orchestration moves to `pipeline`.** `parse.Routes` opens the PHP set, so
  keeping it in `parse` would need `parse` → `langphp`, a cycle. `pipeline` already owns repository
  orchestration. Rejected: passing a PHP route callback into `parse.Routes`, which hides the dependency.
  `Routes` keeps its own walk (phase 2 invariant); only its home changes.
- **D-7 Mixed-language tests live in `internal/pipeline`.** A test in package `parse` cannot import
  `langphp`, because `langphp` imports `parse`. Tests that need several runners move to `pipeline`.
  Single-language PHP tests use a `langphp` test helper that runs the JS base report, PHP and
  `Assemble`, matching production assembly.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- The exported core API would exceed 30 identifiers, or PHP would need a JS flow type. Stop with
  the compile-error list and a proposal.
- Any golden digest changes, or route-inventory output changes.
- A moved file needs a logic edit beyond qualification to compile.

## 7. Acceptance criteria

1. **AC1** `internal/parse` contains no `php_*.go` and no PHP testdata. `go list -deps ./internal/parse`
   does not include `langphp`. `grep -rn "openPHPSet\|phpRoutes\|RunPHP" internal/parse` is empty.
2. **AC2** `langphp.Run` and `langphp.Routes` are called only by `internal/pipeline` (and `langphp`'s
   own tests). A full scan of `mixed/three-language` matches the golden.
3. **AC3** `internal/parse/core_api.go` documents each exported identifier as part of the language
   core API, with a one-line contract. The run log lists the count, which must be 30 or fewer.
4. **AC4** No file matches `internal/parse/p[0-9]_*.go`, and `git log --follow` works for each renamed file.
5. **AC5** `TestArchitectureBaseline` passes. The golden diff is PHP key renames plus PHP
   `report_sha256` values that change only through the embedded root path (proved by re-hashing with
   the old root); request, signature and SARIF digests, IDs and counts are unchanged.
6. **AC6** `go test ./internal/langphp ./internal/pipeline -count=1` and `cmd/scan` `TestPHPCLI` and the
   route-inventory tests pass. The contributor gate passes.
7. **AC7** The docs in §4 name `internal/langphp`, `pipeline.Routes`, and the core API. Orientation no
   longer lists `internal/parse/testdata/php/`.

## 8. Test strategy

There are no new behavior tests. Moved tests, the phase 0 golden, the route-inventory tests, and the
CLI tests are the signal. A new test would only restate the move. The `langphp` test helper and the
mixed-language tests moved to `pipeline` are relocations, not new coverage.

## 9. TDD entry point and execution sequence

1. **Measure.** Create `internal/langphp`, `git mv` the PHP files, change the package, and build.
   Record the undefined-identifier list in the run log; it should match the 20 identifiers in §14.
   Revert the scratch build if needed, then classify each item as JS-internal (halt), neutral helper
   (rehome), PHP-owned (move with PHP), or core helper (export). Also list the `parse` tests that
   fail once the helper drops PHP; they move to `pipeline` (D-7).
2. **Commit 1: rehome** `appendUniqueString` within `parse` and split `inertPHP` out of
   `closed_summary.go` into a PHP file. Pure moves; the golden passes.
3. **Commit 2: core API, PHP move and `pipeline.Routes`.** Export the API, finish the move, wire
   `pipeline`, move `Routes`, and move the mixed-language tests. The shape is:

```go
// internal/parse/core_api.go — language core API for adapters outside parse.
func (inv Inventory) HasLanguage(languages ...lang.Language) bool
func SnapshotID(kind string, source analysis.Evidence, owner, key string) string
func Span(file string, n *sitter.Node) analysis.Span
func OpenParser(language unsafe.Pointer) (*sitter.Parser, error)
func ModelSource(src []byte, start, end uint, comments []SourceComment) string
func RegisterInvocation(out *analysis.AnalysisReport, entry analysis.EntryPoint, handler *analysis.Evidence, mechanism string, inputs []analysis.InputBinding, gaps []analysis.Gap) analysis.InvocationContext
func FinalizeEntries(out *analysis.AnalysisReport) error
func AssembleXSSClaims(out *analysis.AnalysisReport)
type ClosedCallable struct{ Params []string; Callees []analysis.Span; /* … */ }
// … remaining items from step 1; each with a one-line contract comment
```

```go
// internal/langphp
func Run(inv parse.Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)
func Routes(inv parse.Inventory) ([]analysis.Route, []analysis.Gap, error)

// internal/pipeline
func Routes(root string) (*analysis.RouteInventory, error)
```

4. **Commit 3:** the D-4 renames.
5. **Commit 4:** docs. Then the gate. The owner then opened the milestone draft PR early (§14); phase 3B continues on this branch.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC7 verified, with evidence in the run log.
- [ ] `git diff <phase start HEAD> --stat` matches §4. Moves show as renames.
- [ ] The run log records the core API list and count for phase 3B to extend.

## 11. Open questions

None.

## 12. Run log protocol

Use the plan's common rules. Record the step 1 identifier classification and the list of moved
mixed-language tests.

## 13. Agent implementation prompt

> Work in the assigned `arch-multi-lang-packaging` sibling worktree. Verify `pwd`, branch, clean
> status and `git worktree list`; confirm `origin/stage` contains the phase 2 merge (`52cdc36`) and
> record the starting HEAD. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md),
> this spec and the [phase 3B spec](architecture-phase-3-js-ts-python-package.md) §1 and §5.
> Run `TestArchitectureBaseline` before any change. Execute §9 in order as four commits. Do not
> delegate; the moves interlock. Stop on any §6 halt, especially the API-size halt. Do not push;
> phase 3B continues on this branch and opens the milestone draft PR. Verifier: a fresh-context
> subagent runs `go list -deps` on `parse`, `langphp`, and `pipeline` to confirm the import direction.
> It confirms every moved file is a rename with only qualification edits (`git diff -M --stat` and a
> spot diff of three files), runs `TestArchitectureBaseline` and the route-inventory tests, and
> reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-17 — Owner topology decision

Source: owner, in the planning session. Runs in the `arch-review-clean-up` worktree as one fresh
session, after the previous phase's commits, with no new worktree. Changed: header, §10 scope diff
base, §13 prompt. Verification impact: the scope diff is taken from this phase's recorded starting
HEAD, not `origin/stage`. The PR is the shared milestone draft PR into `stage`.

### 2026-11-18 — Reconcile with merged phase 2 and assign worktree

Source: owner, assigning the `arch-multi-lang-packaging` worktree for this spec and the new phase 3B
spec; reconciliation by the Lead Agent per [session start](architecture-update-plan.md#session-start-for-every-phase)
step 4. No implementation has started. Changed:

- Header: phase 2 is merged (PR #25, `52cdc36`); the branch is `arch-multi-lang-packaging`; the phase
  is now 3A, and 3B follows on the same branch in one milestone draft PR.
- §1, §4, §9: phase 2 put `RunPHP` in `php_modules.go`, not `analysis.go`, and kept PHP route
  inventory in `parse.Routes` (`openPHPSet`, `phpRoutes`). `Routes` therefore moves to `pipeline`
  (new D-6), and `langphp` exposes `Run` and `Routes`.
- §4, D-3: a type-checked cross-reference at `52cdc36` found that PHP takes only `appendUniqueString`
  from a Python-named file. The earlier `attachChecks`, `linkStorage` and `storageWrite` examples no
  longer apply. `closed_summary.go` holds the shared `closedCallable` lattice and a PHP-owned `inertPHP`.
- D-1: the measured candidate set is 20 identifiers — `Inventory`, `Inventory.hasLanguage`,
  `checkContextMatches`, `closedCallable` and its `closed`/`finish`/`read`/`reject` methods,
  `inertPHP`, `finalizeEntries`, `registerInvocation`, `snapshotID`, `modelSource`, `sourceComment`,
  `sourceComments`, `openParser`, `spanOf`, `renderMarkup`, `assembleXSSClaims`, `htmlOutputContext`
  and `appendUniqueString` — plus `Inventory` and `closedCallable` fields. Test files were not counted;
  §9 step 1 still measures.
- New D-7 and §4 rows: tests in `parse` that run PHP through the shared helper move to `pipeline`,
  and `langphp` gets its own helper.
- §4: `PARSE` scope label extended to `internal/lang*` packages.
- §9 step 5, §10, §13: no push at the end of 3A; phase 3B opens the shared draft PR.

Verification impact: AC1, AC2, AC6 and AC7 gain the route-inventory checks. The 30-identifier halt
is unchanged.

### 2026-11-18 — Implementation, golden root-path delta (owner decision)

Source: Lead Agent implementing §9 from starting HEAD `f4ebb6d`; owner decision in session.
Changed:

- **§6 halt fired and was resolved by the owner.** Moving the PHP fixtures changes `report_sha256`
  for all ten PHP fixtures, because the normalized report embeds `root`, the fixture path. Re-hashing
  each new report with the root replaced by the old path reproduces every old hash. No request,
  signature or SARIF digest, ID or count changed, and no JS/TS, Python or mixed fixture changed. The
  owner accepted the root-only delta; §3 and AC5 now say so.
- **Core API (AC3): 20 identifiers.** `Inventory`, `Inventory.HasLanguage`, `ClosedCallable` with
  `Closed`/`Reject`/`Read`/`Finish` and exported fields `Params`, `Callees`, `Reasons` (`Reasons` only
  for the PHP halves of the closed-summary tests), and wrappers `SourceComment`, `SnapshotID`, `Span`,
  `OpenParser`, `SourceComments`, `ModelSource`, `RegisterInvocation`, `FinalizeEntries`,
  `AssembleXSSClaims`, `HTMLOutputContext`, `RenderMarkup`, `CheckContextMatches`,
  `AppendUniqueString`. Runner entry points `JavaScriptRoutes` and `PythonRoutes` (called by
  `pipeline.Routes`) sit beside phase 2's `RunJavaScript`/`RunPython` and are not counted.
- **D-3 neutral file:** `internal/parse/string_sets.go`.
- **D-7 test moves:** `TestPHPRoutes`, `TestPHPMixedRepository`, `dvwa_test.go` and
  `summary_witness_integration_test.go` move to `internal/pipeline`. The shared closed-summary tests
  split by language under the same names. The PHP call-resolution measurement becomes
  `langphp.TestPHPCallResolutionMeasure` (output `ZAZZLES_MEASURE_PHP_OUT`). `parse` keeps a
  test-only `Routes` mirror for its JS/TS and Python route tests. The architecture-baseline and
  pipeline fixture lists read PHP fixtures from `internal/langphp/testdata`.
- `langphp` also imports `internal/guidelines`, as `php_modules.go` did before the move.

Verification impact: route-inventory JSON is byte-identical for all 41 fixtures between the
pre-move and post-move binaries. The full gate is green. Evidence is in the run log.

### 2026-11-18 — Milestone draft PR opened at the end of 3A (owner decision)

Source: owner, after 3A verification. The branch is pushed and the shared milestone draft PR into
`stage` is opened now to log the 3A implementation and its passing gate. Phase 3B pushes further
commits to that PR. Changed: status, §9 step 5. Verification impact: none.
