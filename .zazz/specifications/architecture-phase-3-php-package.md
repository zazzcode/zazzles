# Architecture phase 3 — PHP language package and behavior-named files

**Worktree / branch:** `arch-review-clean-up` (owner decision 2026-11-17; phases 0–3 share it)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 3. Objective: maintainability
**Depends on:** phase 2 committed on `arch-review-clean-up` with green gates
**Delivery topology:** one deliverable; its commits join the phases 0–3 milestone draft PR into `stage`
**Coordination:** Lead Agent alone. The moves are tightly coupled
**Run log:** `.zazz/ephemeral/architecture-phase-3-php-package-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Move the PHP adapter into `internal/langphp`:

- the `internal/parse/php_*.go` sources;
- their tests;
- `internal/parse/testdata/php/`.

The new package exposes `langphp.Run(inv, entry, checks)` for `internal/pipeline`. The helpers it
needs from `internal/parse` become a small, documented, exported **language core API**. That API is
the first written extension point for a language adapter, and Symfony (phase 6) and Drupal (phase 9)
build on it. In the same phase, the eleven delivery-named `p1_`–`p4_` files are renamed for the
behavior they implement. Output bytes do not change.

## 2. Required reading

- Plan [what already exists](architecture-update-plan.md#what-already-exists), [phase 2 spec](architecture-phase-2-pipeline-runners.md) §5.
- [Code structure](../standards/code-structure.md#1-package-layout), [file size thresholds](../standards/code-structure.md#2-file-size-thresholds).
- [PHP support contract](php-support.md) §4 and §5 (what the adapter owns), [PHP results](../evaluation/php-support-results.md).
- [Architecture: shared, language and framework layers](../architecture/README.md#shared-language-and-framework-layers), [§11](../architecture/README.md#11-implemented-package-boundaries).
- [Orientation: code structure](../docs/zazzles-agent-orientation.md#code-structure).

## 3. Invariants

- `TestArchitectureBaseline` passes with no update. The only change is that fixture keys under
  `internal/parse/testdata/php/` move to `internal/langphp/testdata/` paths. Digests must not change.
- `langphp` imports `internal/parse` (core API), `internal/analysis`, `internal/lang`, and Tree-sitter.
  `internal/parse` never imports `langphp`. `internal/pipeline` imports both.
- The core API exports functions and small value types only. PHP must not reach into JS flow
  internals (`flow`, `value`, `moduleSet`, `sourceModule`).
- PHP fixtures keep their repository-relative contents. Evidence paths in goldens are relative to
  the fixture root, so they are unchanged.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/langphp/*.go` (from `internal/parse/php_*.go`, package renamed, `php` prefix dropped where it now stutters) | moved | PHP adapter |
| `internal/langphp/*_test.go` (from `php_test.go`, `php_flow_test.go`), `internal/langphp/testdata/` (from `internal/parse/testdata/php/`) | moved | PHP tests and fixtures |
| `internal/parse/core_api.go` (name adaptive) | new | Exported wrappers or renamed functions forming the language core API, with doc comments |
| `internal/parse/*.go` holding language-neutral helpers currently in `python_*` files (`attachChecks`, `linkStorage`, `storageWrite`, and similar; see §9 step 1) | modified or moved within `parse` | Rehome neutral helpers out of Python-named files before exporting |
| `internal/parse/analysis.go` | modified | Remove `RunPHP`. `Assemble` keeps its PHP slot |
| `internal/pipeline/pipeline.go` | modified | Call `langphp.Run` |
| `internal/parse/p1_*.go` … `p4_*.go` | renamed | See D-4 |
| `internal/parse/analyze_test.go` | modified | Drop the PHP runner from the test helper |
| `cmd/scan/testdata/architecture-baseline.json` | modified | PHP fixture keys only |
| `.zazz/architecture/README.md` §3 and §11, `.zazz/architecture/repository-graph.md` (acquisition adapters), orientation code-structure and testdata rows, `docs/contributing.md` repository layout | modified | New package and core API |
| `.zazz/specifications/php-support.md` §4 | modified | Paths now under `internal/langphp`, with a change-log entry |

Out of scope: moving Python or JS/TS; behavior changes; new PHP families; Symfony. Review shape:
one PR in four commits — helper rehoming, the PHP move, the `p*` renames, then docs.

## 5. Decisions

- **D-1 Move PHP first.** PHP is the newest and least coupled adapter: about 15 real helper
  dependencies at the plan baseline. Python reuses the JS module set for templates and browser
  code (`python_browser.go`), so Python waits for a JS API (plan "Explicitly later").
- **D-2 The core API is exported from `parse`; no new core package.** A separate core package would
  have to move JS-entangled types. Exporting about 15 functions is reviewable and reversible.
- **D-3 Rehome neutral helpers before exporting them.** A helper used by PHP and defined in a
  `python_*.go` file is language-neutral. It moves to a neutral file in `parse` first, as a pure
  move, so the export does not look Python-owned.
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

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- The exported core API would exceed 30 identifiers, or PHP would need a JS flow type. Stop with
  the compile-error list and a proposal.
- Any golden digest changes.
- A moved file needs a logic edit beyond qualification to compile.

## 7. Acceptance criteria

1. **AC1** `internal/parse` contains no `php_*.go` and no PHP testdata. `go list -deps ./internal/parse`
   does not include `langphp`.
2. **AC2** `langphp.Run` is called only by `internal/pipeline`. A full scan of `mixed/three-language`
   matches the golden.
3. **AC3** `internal/parse/core_api.go` documents each exported identifier as part of the language
   core API, with a one-line contract. The run log lists the count, which must be 30 or fewer.
4. **AC4** No file matches `internal/parse/p[0-9]_*.go`, and `git log --follow` works for each renamed file.
5. **AC5** `TestArchitectureBaseline` passes. The golden diff is PHP key renames only, and digests are unchanged.
6. **AC6** `go test ./internal/langphp -count=1` and `cmd/scan` `TestPHPCLI` pass. The contributor gate passes.
7. **AC7** The docs in §4 name `internal/langphp` and the core API. Orientation no longer lists
   `internal/parse/testdata/php/`.

## 8. Test strategy

There are no new tests. Moved tests, the phase 0 golden, and the CLI tests are the signal. A new
test would only restate the move.

## 9. TDD entry point and execution sequence

1. **Measure.** Create `internal/langphp`, `git mv` the PHP files, change the package, and build.
   Record the undefined-identifier list in the run log. That list is the API candidate set. Revert
   the scratch build if needed, then classify each item as JS-internal (halt), neutral helper
   (rehome), or core helper (export).
2. **Commit 1: rehome neutral helpers** within `parse`. Pure moves; the golden passes.
3. **Commit 2: core API and PHP move.** Export the API, finish the move, and wire `pipeline`. The
   shape is:

```go
// internal/parse/core_api.go — language core API for adapters outside parse.
func SnapshotID(kind string, source analysis.Evidence, owner, key string) string
func Span(file string, n *sitter.Node) analysis.Span
func ModelSource(src []byte, start, end uint, comments []SourceComment) string
func RegisterInvocation(out *analysis.AnalysisReport, entry analysis.EntryPoint, handler *analysis.Evidence, mechanism string, inputs []analysis.InputBinding, gaps []analysis.Gap) analysis.InvocationContext
func AssembleXSSClaims(out *analysis.AnalysisReport)
// … remaining items from step 1; each with a one-line contract comment
```

```go
// internal/langphp
func Run(inv parse.Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)
```

4. **Commit 3:** the D-4 renames.
5. **Commit 4:** docs. Then the gate, push, and the milestone draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC7 verified, with evidence in the run log.
- [ ] `git diff <phase start HEAD> --stat` matches §4. Moves show as renames.
- [ ] The PR lists the core API and states that there are no output changes.

## 11. Open questions

None.

## 12. Run log protocol

Use the plan's common rules. Record the step 1 identifier classification.

## 13. Agent implementation prompt

> Work in the `arch-review-clean-up` worktree (`<DEV_ROOT>/zazzcode/zazzles/arch-review-clean-up`).
> Confirm the phase 2 commits are on the branch and its run log shows green gates; record the starting HEAD. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md), and this spec.
> Follow the plan's session start and common rules. Execute §9 in order as four commits. Do not
> delegate; the moves interlock. Stop on any §6 halt, especially the API-size halt. Finish by pushing and
> opening the milestone draft PR into `stage` (plan plus phases 0–3). Its body lists each phase's AC
> evidence from the four run logs, per the PR process standard. Verifier: a fresh-context subagent runs
> `go list -deps` on `parse`, `langphp`, and `pipeline` to confirm the import direction. It confirms
> every moved file is a rename with only qualification edits (`git diff -M --stat` and a spot diff
> of three files), runs `TestArchitectureBaseline`, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-17 — Owner topology decision

Source: owner, in the planning session. Runs in the `arch-review-clean-up` worktree as one fresh
session, after the previous phase's commits, with no new worktree. Changed: header, §10 scope diff
base, §13 prompt. Verification impact: the scope diff is taken from this phase's recorded starting
HEAD, not `origin/stage`. The PR is the shared milestone draft PR into `stage`.
