# Architecture phase 3B — JavaScript/TypeScript and Python language packages

**Branch / assigned sibling worktree:** `arch-multi-lang-packaging` (owner-assigned, 2026-11-18)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 3B. Objective: maintainability
**Depends on:** [phase 3A](architecture-phase-3-php-package.md) committed on this branch with green gates
**Delivery topology:** second of two deliverables on this branch; one milestone draft PR into `stage`,
already open as [PR #26](https://github.com/zazzcode/zazzles/pull/26). 3B pushes to it and updates its body
carries 3A and 3B
**Coordination:** Lead Agent. Moves interlock, so do not delegate them. A Contributor Agent may update
external test fixture paths (§9 step 4 and 5) after a stage compiles
**Run log:** `.zazz/ephemeral/architecture-phase-3-js-ts-python-package-run-log.md`
**Drafted:** 2026-11-18
**Status:** implemented on `arch-multi-lang-packaging` (from `8bc0b9a`); in the milestone draft PR #26 with phase 3A

## 1. Capability

After phase 3A, `internal/parse` still holds three things: the JS/TS adapter, the Python adapter,
and the language core API. This phase separates them, so each language has its own package and
`parse` holds only the core:

```text
internal/parse     language core: Inventory, entry selection, Assemble, entry finalization,
                   shared claim, completeness and guard engines, spans, model source, text sources
internal/langjs    JS/TS adapter: Node, Express, Next.js, browser frameworks, GraphQL, gRPC
internal/langpy    Python adapter
internal/langphp   PHP adapter (phase 3A)
internal/pipeline  orchestration: one walk, runners, Assemble, route inventory
```

Two stages, in order:

1. **Python → `internal/langpy`.** Python's coupling to JS becomes one named bridge.
2. **JS/TS → `internal/langjs`.** Everything left in `parse` that is not core moves.

Fixtures move with their language. Output bytes do not change.

## 2. Required reading

- [Phase 3A spec](architecture-phase-3-php-package.md) §5 and its run log (core API list and count,
  moved mixed-language tests, `pipeline.Routes`).
- Plan [what already exists](architecture-update-plan.md#what-already-exists) and [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).
- [Phase 2 spec](architecture-phase-2-pipeline-runners.md) §5 D-4 (the JS runner builds the base report) and D-6 (the parse test helper).
- [Code structure](../standards/code-structure.md#1-package-layout), [file size thresholds](../standards/code-structure.md#2-file-size-thresholds).
- [Python support contract](python-support.md) (what the Python adapter owns).
- [Architecture: shared, language and framework layers](../architecture/README.md#shared-language-and-framework-layers), [§11](../architecture/README.md#11-implemented-package-boundaries).
- Code: `python_browser.go`, `python_modules.go`, `call_effects.go`, `guard_lang.go`, `guard_climb.go`,
  `closed_summary.go`, `python_binding_index.go`, `binding_index.go`, `xss_templates.go` (`readText`,
  `textSources`), `analysis.go`, `cmd/scan/discovery.go` (`parse.NewDiscoveryVerifier`).

## 3. Invariants

- `TestArchitectureBaseline` passes. The only golden change is fixture keys moving to the new
  `testdata/` paths. Digests must not change, except `report_sha256` of moved fixtures, which embeds
  the fixture root path. That delta is allowed only with the 3A proof: re-hashing each new report with
  the old root path reproduces the old hash (§14, carry-over C-1).
- Route-inventory output is unchanged for every fixture.
- Import direction: `parse` imports no `lang*` package. `langjs` imports `parse`. `langpy` imports
  `parse` and, for the browser bridge only, `langjs`. `langphp` imports only `parse`. No language
  package imports `pipeline`. `go list -deps` proves it.
- Core contains only code that at least two language packages, `Assemble`, or `pipeline` use. Code
  used by one language moves with that language, even if its signature is language-neutral.
- Core files reference no JS flow type (`flow`, `value`, `moduleSet`, `sourceModule`) and no
  Python or PHP flow type.
- Fixtures keep their contents. Evidence paths are relative to the fixture root, so they are unchanged.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/parse` files mixing neutral and language-owned code: at least `call_effects.go`, `guard_lang.go`, `closed_summary.go`, `command_claims.go`, `command_guards.go`, `path_claims.go`, `path_guard_classify.go`, `entry_context.go`, `xss_templates.go`, `outbound_ssrf.go`, `log_classes.go`, `check_context.go`, `code_redirect.go`, `python_binding_index.go` (exact list from §9 step 1) | modified | Stage 1 rehoming: split neutral helpers into core files and language-owned code into language files |
| `internal/parse/text_sources.go` (name adaptive) | new | Template text reader that Python now gets from a `moduleSet` (`s.text.readText`) |
| `internal/parse/inline_scripts.go`, then `internal/langjs/inline_scripts.go` | new, then moved | Browser bridge that replaces Python's own `moduleSet` construction in `python_browser.go` |
| `internal/langpy/*.go` (from `internal/parse/python_*.go` and `python_decode.go`, `python_` prefix dropped) | moved | Python adapter: `Run` and `Routes` replace `RunPython`, `openPythonSet` and `routeEntries` |
| `internal/langpy/*_test.go`, `internal/langpy/testdata/` (from `internal/parse/testdata/python/`) | moved | Python tests and fixtures |
| `internal/langjs/*.go` (every remaining non-core `internal/parse/*.go`) | moved | JS/TS adapter: `Run` and `Routes` replace `RunJavaScript` and the JS part of route inventory |
| `internal/langjs/*_test.go`, `internal/langjs/testdata/{javascript,typescript,express-login,string-flow}/` | moved | JS/TS tests and fixtures |
| `internal/pipeline/testdata/mixed/` (from `internal/parse/testdata/mixed/`) and mixed-language tests | moved | Multi-runner fixture and tests (phase 3A D-7) |
| `internal/{langjs,langpy,langphp}/analyze_test.go` | new or modified (test-only) | Same-package helpers that run their own runner, the JS base report and `parse.Assemble` |
| `internal/parse/core_api.go`, `internal/parse/analyze_test.go` | modified | Core API grows by stage; the parse helper keeps only core tests |
| `internal/pipeline/pipeline.go`, `routes.go`, tests | modified | Call `langjs.Run`, `langpy.Run`, `langjs.Routes`, `langpy.Routes` |
| `cmd/scan/discovery.go` | modified | `NewDiscoveryVerifier` from its new owner (§9 step 1 decides) |
| Tests outside `parse` naming `internal/parse/testdata/...` (at least `cmd/scan`, `internal/judge`, `internal/report`, `internal/analysispacks`) | modified | Fixture paths only |
| `cmd/scan/testdata/architecture-baseline.json` | modified | Fixture keys only |
| `.zazz/architecture/README.md` §3 and §11, `repository-graph.md` (acquisition adapters), orientation code-structure and testdata rows, `docs/contributing.md` repository layout, `.zazz/standards/code-structure.md` §1 (`parse` ownership bullet), `.zazz/specifications/python-support.md` paths | modified | New packages and core |

Out of scope: behavior changes; renaming `parse`; splitting `langjs` into framework packages
(`langjs/next` and similar); new language features; judge or report changes. Review shape: five
commits in the shared milestone PR — rehoming, the Python bridge, the Python move, the JS/TS move,
then docs. Reviewers read the moves with `git diff -M`.

## 5. Decisions

- **D-1 One spec for JS/TS and Python.** The coupling runs one way, Python → JS, and both
  separations need the same rehoming step. A type-checked cross-reference at `52cdc36` found that
  Python uses about 65 non-field `parse` identifiers defined outside Python files. They fall in two
  groups:
  - **JS module set** (`moduleSet`, `sourceModule`, `importBinding`, `newParsers`, `moduleSet.browser`,
    `moduleSet.readText`, and their fields). Python uses it in `python_browser.go` for inline scripts
    and as a template text reader in three files.
  - **Neutral helpers in JS-named files** (command, path and SSRF completeness; guard climbing; path
    guard classification; HTTP entry and input records). Their signatures use only `analysis` and
    Tree-sitter types.

  The reverse direction also exists. `call_effects.go`, `guard_lang.go` and `closed_summary.go` hold
  Python-owned code, and `binding_index.go` and `modules.go` use `bindingIndex`, which is defined in
  `python_binding_index.go`. Separate specs would each redo this classification.
- **D-2 Python first, then JS/TS.** Moving Python first shrinks its JS coupling to one named bridge,
  and the JS/TS move then becomes "everything not core". Moving JS/TS first would make `langpy`
  import `langjs` for about 65 helpers that are really core. Stage 2 is separable: if a stage 2
  halt fires, the PR ships with stage 1 and stage 2 returns to the owner.
- **D-3 The Python → JS coupling becomes two explicit seams, not exported JS internals.**
  - Template reading becomes a core `TextSources` type. It is file reading with an allow list and
    snapshot evidence, which is language-neutral.
  - Inline-script analysis becomes one bridge function that takes text sources and literal globals
    and appends to the report. It lives in `parse` during stage 1, because JS is still there, and
    moves to `langjs` in stage 2.

  Rejected: exporting `moduleSet` and `sourceModule`. That leaks the JS flow model into Python and
  breaks the phase 3A invariant that adapters do not reach into JS flow internals.
- **D-4 Keep the package name `parse` for the core.** Renaming it (for example to `langcore`) would
  touch every importer with no behavior change. Rejected for this phase; a later rename-only spec may
  revisit it. The package doc comment states that `parse` is the language core.
- **D-5 Ownership rule for the split.** A helper used by one language moves with it. A helper used
  by two or more languages, `Assemble` or `pipeline` stays in core and is exported. A file that mixes
  both is split by pure moves before export. This keeps core small and makes each move reviewable.
- **D-6 The JS base report stays in `langjs.Run`.** Phase 2 D-4 has the JS runner build the base
  report, and `Assemble` requires it for a full scan. Language test helpers for Python and PHP
  therefore call `langjs.Run`, and test packages may import `langjs`. Moving the base report into
  core would change `Assemble`'s contract and is not needed for the package split.
- **D-7 Drop redundant prefixes on move.** `python_flow.go` becomes `langpy/flow.go`. JS/TS file
  names keep their framework prefixes (`next_`, `node_`, `xss_`), which still carry meaning inside
  `langjs`. A rename that would collide stops for a name choice in the run log.
- **D-8 Use `git mv`** as in phase 3A D-5. Apart from the stage 1 bridge commit, moved files change
  only package, import and qualification.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- The core API would exceed 90 exported identifiers after either stage, or a core function would
  need a JS, Python or PHP flow type. Stop with the list and a proposal.
- The bridge (§9 step 3) cannot reproduce today's inline-script or template evidence without
  changing a golden byte.
- Any golden digest change other than the root-path-only `report_sha256` delta proved per C-1, or any
  route-inventory change.
- A moved file needs a logic edit beyond qualification, outside the stage 1 bridge commit.
- An import cycle appears that the D-5 ownership rule does not resolve.

## 7. Acceptance criteria

1. **AC1 Python separated.** `internal/parse` has no `python_*.go` and no Python testdata.
   `grep -rn "pythonFlow\|pythonSet\|pythonValue" internal/parse` is empty.
2. **AC2 JS/TS separated.** `internal/parse` contains no file that references `moduleSet`,
   `sourceModule`, `flow` or `value`, and no JS/TS testdata. `parse.RunJavaScript` no longer exists.
3. **AC3 Import direction.** `go list -deps` shows the §3 direction for `parse`, `langjs`, `langpy`,
   `langphp` and `pipeline`. `langpy` uses `langjs` only for the bridge (`grep -n "langjs\." internal/langpy`
   lists only bridge calls).
4. **AC4 Core API.** `core_api.go` documents each exported identifier with a one-line contract.
   The run log records the count after each stage; each is 90 or fewer.
5. **AC5 Golden.** `TestArchitectureBaseline` passes after each stage. The golden diff is fixture-key
   renames plus moved-fixture `report_sha256` values proved root-path-only (C-1); request, signature
   and SARIF digests, IDs and counts unchanged.
6. **AC6 Tests.** `go test ./internal/langjs ./internal/langpy ./internal/langphp ./internal/parse ./internal/pipeline -count=1`,
   `cmd/scan` CLI and route-inventory tests, and the contributor gate (including `-race`) pass.
7. **AC7 Renames.** `git diff -M --stat <3B start HEAD>` shows the moved files as renames, and a spot diff
   of five moved files shows only qualification edits.
8. **AC8 Docs.** The docs in §4 describe `parse` as the language core and name the three language
   packages. Orientation lists no `internal/parse/testdata/` language fixtures.

## 8. Test strategy

There are no new behavior tests. The phase 0 golden, the moved tests, the route-inventory tests and
the CLI tests are the signal. The bridge commit (§9 step 3) is the only logic change. It is covered
by the existing Python browser-template and template fixtures in the golden, which must stay
byte-identical.

## 9. TDD entry point and execution sequence

1. **Measure.** Record the starting HEAD and the phase 3A core API list. Do a scratch `git mv` of
   the Python files into `internal/langpy` and build. Record every undefined identifier, and classify
   each by the D-5 rule: core (export), Python-owned in a neutral file (move with Python), neutral in
   a JS file (rehome to core), or JS module set (bridge). Repeat for JS/TS against the post-stage-1
   tree when stage 2 starts. Revert scratch builds. Decide the owner of `NewDiscoveryVerifier`.
2. **Commit 1: rehome.** Pure moves inside `parse` per step 1, including `bindingIndex` out of
   `python_binding_index.go` and the `*pythonFlow` methods out of `call_effects.go` and `guard_lang.go`.
   The golden passes.
3. **Commit 2: Python bridge.** Add `TextSources` and the inline-script bridge in `parse`. Switch
   `python_browser.go`, `python_templates.go`, `python_html_responses.go` and `python_validation.go`
   to them. The golden passes byte for byte.
4. **Commit 3: Python move.** `git mv` to `internal/langpy`, export the core API additions, wire
   `pipeline` (`langpy.Run`, `langpy.Routes`), move the fixtures and update external fixture paths.
   The golden passes with key renames only. **Stage 1 gate:** run the full contributor gate; record AC1, AC3–AC5.
5. **Commit 4: JS/TS move.** `git mv` every non-core file to `internal/langjs`, move the bridge, wire
   `pipeline` (`langjs.Run`, `langjs.Routes`), move JS/TS and mixed fixtures, and update tests. The shape is:

```go
// internal/langjs
func Run(inv parse.Inventory, entry string, checks []analysis.Check, opts parse.Options) (*analysis.AnalysisReport, error)
func Routes(inv parse.Inventory) ([]analysis.Route, []analysis.Gap, error)
func AnalyzeInlineScripts(texts *parse.TextSources, globals map[string]analysis.Evidence, out *analysis.AnalysisReport) error // name adaptive

// internal/langpy
func Run(inv parse.Inventory, entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)
func Routes(inv parse.Inventory) ([]analysis.Route, []analysis.Gap, error)
```

6. **Commit 5: docs.** Then the gate, push to the open milestone PR (#26), and update its body with the
   3B section and evidence. Do not open another PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC8 verified, with evidence in the run log.
- [ ] `git diff <3B start HEAD> --stat` matches §4. Moves show as renames.
- [ ] The milestone PR body lists the core API, both phases' AC evidence, and states that there are
      no output changes.

## 11. Open questions

None. The owner decides at the stage 1 gate only if a stage 2 halt fires (D-2).

## 12. Run log protocol

Use the plan's common rules. Record the step 1 classifications for both stages, the core API count
after each stage, and every collision rename (D-7).

## 13. Agent implementation prompt

> Work in the assigned `arch-multi-lang-packaging` sibling worktree. Verify `pwd`, branch, clean status
> and `git worktree list`. Confirm the phase 3A commits are on the branch and its run log records green
> gates; record the starting HEAD. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md),
> the [phase 3A spec](architecture-phase-3-php-package.md) and this spec. Run `TestArchitectureBaseline`
> before any change. Read the §14 "Carry-over from phase 3A" entry first. Execute §9 in order as five
> commits (plus the C-2 consolidation commit). Do not delegate the moves; a Contributor
> Agent may update external fixture paths after a stage compiles. Stop on any §6 halt. If a stage 2
> halt fires, keep stage 1, record the halt, and ask the owner. Finish by pushing to the open
> milestone draft [PR #26](https://github.com/zazzcode/zazzles/pull/26) and updating its body with the
> 3B section, per the PR process standard. Do not open a new PR.
> Verifier: a fresh-context subagent runs `go list -deps` on every package in §3, confirms the moves
> are renames with only qualification edits outside commit 2, runs `TestArchitectureBaseline` and the
> route-inventory tests, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-18 — Drafted

Source: owner, asking for the JS/TS and Python separation in the `arch-multi-lang-packaging` worktree
alongside the PHP spec. Measurements: a type-checked cross-reference of non-test `internal/parse`
files at `52cdc36` (D-1), plus a scan that found 138 of the 148 non-Python, non-PHP files reference
JS flow types. The scan supports D-5: core is the handful of neutral files plus rehomed helpers, and
everything else is the JS/TS adapter.

### 2026-11-18 — Carry-over from phase 3A (work items for the 3B session)

Source: phase 3A implementation (`f4ebb6d`..`2673b46`, run log
`.zazz/ephemeral/architecture-phase-3-php-package-run-log.md`) and owner decisions in that session.
Changed: header, §3, §6, AC5, §9 step 6, §13. Work items:

- **C-1 Golden root-path delta.** The normalized report embeds `root`, so moving a fixture changes
  its `report_sha256` while request, signature and SARIF digests stay equal. In 3A the owner accepted
  this for the ten PHP fixtures after a proof. For every JS/TS, Python and mixed fixture moved here:
  regenerate with `-update-architecture-baseline` and prove each changed `report_sha256` reproduces the
  old value when the new root string is replaced by the old path (3A used a temporary, uncommitted
  `cmd/scan` test). Any other digest, ID or count change is still a halt. Record the proof in the run log.
- **C-2 Replace the 3A wrappers with renames (no transitional cruft).** 3A exported most of the core
  API as one-line wrappers in `core_api.go` (`Span` → `spanOf`, `SnapshotID` → `snapshotID`, and so on)
  to keep its diff small. Once JS/TS and Python leave `parse`, rename the real functions to the
  exported names, delete the wrappers, and keep `core_api.go` as the documented index of the API
  (contract comments stay). Do this in its own late commit so the moves stay reviewable. The 3A list
  of 20 identifiers is the baseline count for AC4. `ClosedCallable.Reasons` is exported only for tests.
- **C-3 One route sort.** `internal/parse/analyze_test.go` keeps a test-only `Routes` mirror (JS/TS
  plus Python, same sort as `pipeline.Routes`). When the route tests move to `langjs`/`langpy`, or to
  `pipeline` if they need several languages, delete the mirror so the comparator exists only in
  `pipeline.Routes`. `parse.JavaScriptRoutes` and `parse.PythonRoutes` become `langjs.Routes` and
  `langpy.Routes`.
- **C-4 Fixture lists and cross-package paths.** These must point at the new testdata trees:
  - `cmd/scan/architecture_baseline_test.go` `architectureFixtures` and the `fixtures` list in
    `internal/pipeline/pipeline_test.go`.
  - `cmd/scan` tests that hard-code `../../internal/parse/testdata/...`.
  - `internal/langphp/analyze_test.go` `TestRunnersWithoutSourcesOpenNoGrammar`, which reads
    `../parse/testdata/python/routes`.

  Decide where `mixed/`, `express-login` and `string-flow` live, and record it.
- **C-5 Test helpers per D-6.** `langphp`'s test helper calls `parse.RunJavaScript` for the JS base
  report. It must call `langjs.Run` after stage 2. `langpy` needs the same helper shape (JS base,
  Python, `parse.Assemble`).
- **C-6 Tests that mix languages.** 3A's test-relocation pattern applies:
  - Tests that need several runners' output go to `internal/pipeline`.
  - Table tests that loop over languages split by language under the same test names (precedent:
    `closed_summary_test.go` in `parse` and `langphp`).
  - Remaining Python/JS cases in `internal/parse` to check: `closed_summary_test.go` (Python half),
    `call_resolution_measure_test.go` (JS+Python classifier; 3A split PHP into
    `langphp.TestPHPCallResolutionMeasure` with `ZAZZLES_MEASURE_PHP_OUT`), `analyze_test.go`
    runner tests, and `python_index_parity_test.go` (reads `mixed/three-language`).
- **C-7 Route-inventory proof.** Build `cmd/scan` before and after each stage (check out the earlier
  commit in place, then return to the branch; no extra worktree). Compare `--routes --json .` byte for
  byte in every fixture directory. 3A compared 41 fixtures with no differences.
- **C-8 Tooling notes.** No `gopls` is installed. 3A used scratch go/types tools (a cross-reference
  and a type-checked renamer) kept in the session scratchpad. macOS `sed` has no `\b`; use `perl -pi`
  for word-boundary qualification. External test packages (`package parse_test`) can call
  same-directory `_test.go` helpers; account for them when moving files.
- **C-9 Docs already updated in 3A.** Extend, do not rewrite: architecture §3 and §11 (core API
  paragraph, `langphp` row, `pipeline.Routes`), the repository-graph acquisition paragraph, the
  orientation and contributing layout rows, and the `PARSE` label (already covers `internal/lang*`).

### 2026-11-18 — Implemented

Source: implementation session (run log `.zazz/ephemeral/architecture-phase-3-js-ts-python-package-run-log.md`).
Commits: rehome `ad9080f`, Python bridge `e70577e`, Python move `25b5b30`, JS/TS move `a9df4b1`, C-2
renames `9bfc2d1`, docs (this commit). Outcomes and deviations:

- **Core API:** 72 identifiers after stage 1, 77 after stage 2 (3A rule: types, functions, methods,
  vars, consts; struct fields and the pipeline-facing `Assemble`, `NormalizeEntry`, `Options`,
  `Languages`, `Runners` not counted). `core_api.go` is the index; a check confirms it lists exactly the
  82 exported identifiers. No core declaration references a JS, Python or PHP flow type.
- **Bridge shape:** `parse.TextSources` (`NewTextSources`, `Root`, `Read`, `ReadBounded`, `Add`, `Get`,
  `Files`) replaces the moduleSet text map for both adapters; the inline-script bridge is
  `langjs.AnalyzeInlineScripts(texts, []langjs.InlineScript{File, Masked, Globals}, out)`. Python keeps its
  own masking. Golden untouched by the bridge; offline reports byte-identical on the four Python samples.
- **D-1 correction:** the `bindingIndex` used by `binding_index.go`/`modules.go` is JS's own type; nothing
  had to leave `python_binding_index.go`.
- **Stage 2 rehoming** was done inside the JS/TS move commit (pure moves to `inventory.go`,
  `assemble.go`, `syntax.go`; package doc to `core_api.go`), keeping the five-commit shape.
- **D-7 name choice:** `parse.go` became `langjs/routes.go`. No other renames; no collisions.
- **C-3/C-6 test placement:** route goldens that pin sorted bytes (`TestPythonRouteGolden`,
  `TestExpressLoginGolden`) and the cross-language sample matrices (`TestCommandSourceCases`,
  `TestPathSourceCases`) live in `internal/pipeline`; adapter route tests use their own unsorted
  `Routes`. Mixed tests split by language under the same names. Core tests stay in `parse`. The
  test-name sets before and after each stage match except relabelled `TestWorkersEquivalence` subtests.
- **C-4:** `mixed/` → `internal/pipeline/testdata/mixed/`; `express-login/`, `string-flow/` →
  `internal/langjs/testdata/`. Test-only `fixtureRoot` helpers (`testdata_paths_test.go`) in `cmd/scan`,
  `judge`, `report` and `analysispacks` map tree-qualified fixture names; this is outside the §4 table.
- **C-1** also covered report hashes embedded in `internal/judge` tests (13 values): each reproduces with
  the old root mapped back, and the want values were updated.
- **Docs beyond §4:** fixture paths in `.zazz/standards/testing.md` and file paths in
  `docs/analysis/nextjs.md` and `xss.md`. Other architecture notes that cite individual source files by
  their old `internal/parse/` path are left for a follow-up.
