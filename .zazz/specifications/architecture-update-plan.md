# Architecture update plan

**Status:** Phases 0 and 1 are merged via [PR #24](https://github.com/zazzcode/zazzles/pull/24)
(`6bf2ca1`) and phase 2 via [PR #25](https://github.com/zazzcode/zazzles/pull/25) (`52cdc36`).
Phases 3A and 3B are implemented on `arch-multi-lang-packaging` in the milestone draft PR.
This document alone authorizes no implementation or paid calls. A phase starts on owner assignment.
**Baseline reviewed:** `stage` at `3890c1cbb6ff8bebbd707052edaed3bf03bc0ae8` (plan revised on
`arch-review-clean-up`, 2026-11-17).
**Languages in scope:** JavaScript/TypeScript, Python, and PHP. Go as a target language is out of this plan.
**Durable design:** [package boundaries](../architecture/README.md#11-implemented-package-boundaries),
[language and framework layers](../architecture/README.md#shared-language-and-framework-layers),
[repository graph](../architecture/repository-graph.md),
[request size and evidence relevance](../architecture/request-size-and-evidence-relevance.md).
The owner's container-root dynamic-route graph note is the design reference: one typed in-memory
graph, no graph database, reports stay projections, judgments stay off the graph.

## Objective and order

The deliverables first improve the foundation (**accuracy, performance, maintainability**) and
then add features on top of it. Phases 0–5 are foundation work. Phases 6–9 are features. A
feature phase does not start until the foundation phases it depends on have merged.

| Objective | What moves it | What does not |
|---|---|---|
| **Accuracy** | A closed, source-backed gap that turns a recorded miss into a candidate; registration facts that stay visible instead of silently dropped | A package move; a new analyzer per framework; asking the model to invent missing edges |
| **Performance** | One directory walk; skipping languages with no files; concurrent language runners; concurrent judge requests under the RPM/TPM caps | Evidence slicing. Request sizes were measured and S1 slicing was deferred ([ledger](../architecture/request-size-and-evidence-relevance.md#evidence-ledger)) |
| **Maintainability** | A byte-level compatibility baseline every refactor runs; one per-file syntax and binding index; an explicit orchestration seam; PHP in its own package; files named for behavior | A fourth copy of `flow.go`; a graph or IR package with no consumer |

## What already exists

The plan builds on these. Phase specs cite them instead of reinventing them.

| Existing piece | Where | What it already answers |
|---|---|---|
| Shared entry records | `internal/analysis/entries.go` (`EntryCatalog`: entries, registrations, dispatch bindings, callables, invocation contexts) | The record kinds a registration graph needs. Unresolved dispatch is a `DispatchBinding` with gaps and no fabricated `CallableID` |
| Persistent identity | `analysis.SnapshotRecordID` in `entry_ids.go` | Versioned, namespaced, content-addressed string IDs. They are snapshot-local, not edit-stable |
| Finalization | `parse.finalizeEntries` in `entry_context.go` | Callable dedup, use binding, invocation rekeying, canonical ID order (`EntryCatalog.Canonical`), and reference validation, all in one place after the language merge |
| Registration mechanism | `DispatchBinding.Mechanism` | `direct_registration`, `decorator_registration`, `table_expansion`, `factory_expansion`, `filesystem_route`, `server_file_mapping`, and others. This is the input to the static/dynamic origin |
| Bounded dynamic HTTP (D5) | [D5 results](../evaluation/common-entry-dispatch-results.md#d5--bounded-dynamic-http-registration-2026-11-04) | Express literal tables and `for…of` loops, direct local literal-argument factories, Flask/FastAPI factories, registry selection, captured callbacks, and SQLite cursor provenance |
| Language merge | `parse.AnalyzeWithOptions` in `analysis.go` | JS/TS, then Python, then PHP, appended in that fixed order, and only when `--entry` is empty. Python and PHP each walk the tree again |
| Judge scheduling | `internal/judge/schedule.go`, `transport.go`, `limits.go` | One sequential loop in priority order. Equivalent signatures reuse only completed answers. `limiter.series` also serializes HTTP when limits are on |
| Report-hash baseline precedent | `internal/parse/python_input_baseline_test.go`, `internal/judge/python_input_compat_test.go` | Whole-report hash and offline request comparison patterns that phase 0 generalizes |

Facts that change the phase design:

- Python's browser/template analysis builds a JS `moduleSet` (`python_browser.go`). Python cannot
  leave `internal/parse` without a JS API, so the Python package move is deferred.
- `registerInvocation` labels `.php` callables `"language": "javascript"`. Phase 1 fixes it as a
  listed report delta.
- Equivalent-signature reuse waits for a completed answer, and the request limit counts only
  calls that reach HTTP. Parallel dispatch has to keep both behaviors (phase 4).
- An import cycle (`parse` → `langphp` → `parse`) is a design error under
  [code structure](../standards/code-structure.md#1-package-layout). Orchestration therefore moves
  to its own package before any language package exists.

## Capability matrix

"Supported" means a passing fixture or recorded result exists today. Each phase claims only its
own row. A row with no new candidates is a representation or speed change. It must not change recall.

| Capability | Fixture or sample | Supported today | Remaining gap | Owning phase | Expected change |
|---|---|---|---|---|---|
| Byte-level refactor guard | All `internal/parse/testdata/*` repositories plus a new mixed fixture | Python-only report hashes; Python request compatibility | JS/TS and PHP request digests; mixed-language order | 0 | None. New golden only |
| Registration origin, path shape, and resolution | `javascript/dynamic-dispatch`, `typescript/dynamic-dispatch`, `python/dynamic-vulnpy`, `php/routes` | Mechanism and dispatch resolution, implicit | Explicit, separate classification on registrations | 1 | Additive `classification` on JSON and SARIF registrations. No new candidates. Request bytes unchanged |
| Indexed registration lookups | Same | Linear scans over catalog slices | One immutable index used by canonical order, selection, and references | 1 | None |
| PHP callable language | `php/*` | Mislabeled `javascript` | Correct `php` | 1 | Report delta on PHP fixtures only |
| One walk and empty-language skip | Mixed fixture; pinned samples | Up to three walks per full scan | One walk; skipped grammars | 2 | None. Measured wall clock |
| Concurrent language runners | Mixed fixture | Sequential | Concurrent with fixed merge order | 2 | None |
| PHP as its own package | `php/*` fixtures | Done in 3A: `internal/langphp` on a 20-identifier `parse` core API | None | 3A | None (PHP report hashes change only through the embedded fixture root path) |
| JS/TS and Python as their own packages | All JS/TS and Python fixtures | Done in 3B: `internal/langjs`, `internal/langpy`; `parse` is the core (77-identifier API) | None | 3B | None (report hashes of moved fixtures change only through the embedded fixture root path) |
| Concurrent judge requests | Stub transport | Sequential | Capped in-flight requests | 4 | None to request bytes. Faster wall clock under caps |
| Jinja `Environment`/`get_template`/`render` | VulnPy `VP-XSS-JINJA` | Yes: xss-hardening `jinjaFileTemplate`; [final evaluation](../evaluation/xss-hardening/final-evaluation.json) passes | None (the VulnPy guide checkbox is stale) | 5 corrects the guide | None |
| Recall misses on pinned samples | Python `cases.json` via `docs/samples/evaluate-python.py`; JS/TS and PHP detection guides | Not measured as one list | Measured inventory by cause; closure of the top-ranked miss | 5 | New candidate for the selected miss only, with paired fixtures |
| Symfony routes, inputs, Doctrine, Twig | New fixtures | None (front controller only) | All | 6 | New entries and candidates |
| npm corpus and direct-model baseline | Proposal corpus | None | Pins, answer keys, baseline | 7 | None to the scanner |
| npm library exports | Corpus pins | None | Export entries, caller-argument inputs, conditional results | 8 | New entries and candidates in library mode only |
| Drupal routes, Form API, database API, render arrays | New fixtures | None | All | 9 | New entries and candidates |

## Phase sequence

One spec per phase, one session per spec, run in series. Each worktree is a direct sibling of
`.bare/`, with the branch named for the directory, cut from current `origin/stage` after the
previous phase has merged. Each phase ends in a draft PR into `stage`. Do not stack branches.

| Phase | Objective | Spec | Worktree | Depends on (merged) |
|---|---|---|---|---|
| 0 | Maintainability (refactor guard) | [Compatibility baseline](architecture-phase-0-compatibility-baseline.md) | `arch-compat-baseline` | This plan |
| 1 | Speed, accuracy | [Source index and callable summaries](architecture-phase-1-source-index.md) (replaces the registration graph) | `arch-review-clean-up` | 0 |
| 2 | Performance, maintainability | [Pipeline and concurrent runners](architecture-phase-2-pipeline-runners.md) | `arch-pipeline-runners` | 1 |
| 3A | Maintainability | [PHP language package](architecture-phase-3-php-package.md) | `arch-multi-lang-packaging` | 2 |
| 3B | Maintainability | [JS/TS and Python language packages](architecture-phase-3-js-ts-python-package.md) | `arch-multi-lang-packaging` | 3A (same branch) |
| 4 | Performance | [Parallel judge](architecture-phase-4-parallel-judge.md) | `parallel-judge` | 0 |
| 5 | Accuracy | [Measured recall gaps](architecture-phase-5-accuracy-gaps.md) | `recall-gap-inventory` | 1 |
| 6 | Feature | [Symfony](architecture-phase-6-symfony.md) | `php-symfony` | 3 |
| 7 | Feature (evaluation) | [npm corpus and baseline](architecture-phase-7-npm-corpus.md) | `npm-library-rce-mvp` | Plan only. Paid steps need an owner cap |
| 8 | Feature | [npm library mode](architecture-phase-8-npm-library-mode.md) | `npm-library-mode` | 2, 7 |
| 9 | Feature | [Drupal](architecture-phase-9-drupal.md) | `php-drupal` | 6 |

**Owner decision, 2026-11-18: phases 0 and 1 finish in the assigned arch-review-clean-up
worktree and PR #24.** The owner has merged that PR. Phase 2 uses the new
arch-pipeline-runners branch from merged stage, with its own draft PR.
PR #24 is now merged at `6bf2ca1`; the owner has created the `arch-pipeline-runners` sibling
worktree and branch. Phase 2 MUST reuse that checkout and MUST NOT create another worktree.
Do not append phase 2 implementation to PR #24.

**Owner decision, 2026-11-18: phases 3A and 3B share the `arch-multi-lang-packaging` worktree.**
Phase 2 merged via PR #25 (`52cdc36`). 3A (PHP) runs first, then 3B (JS/TS and Python), as
commits on one branch with one milestone draft PR into `stage`. The owner opened that draft PR at
the end of 3A to log progress; 3B pushes to the same PR.

This supersedes the 2026-11-17 plan to ship phases 0–3 together on one branch. No phase 2
implementation is authorized by this delivery-topology update.

The table order is the default. Phases 4 and 5 depend only on phase 0 or 1, so the owner may run
them earlier without changing their specs. They are kept after phase 3 so the core refactors land
in consecutive sessions.

The container-root follow-on accuracy handoff (`follow-on-accuracy-improvements-handoff.md`,
outside the repository) is a separate accuracy deliverable with its own contract. When it runs between foundation
phases, the next phase rebaselines (see [session start](#session-start-for-every-phase)).

## Shared rules for every phase

- **Byte compatibility.** Candidate IDs, normalized report JSON, SARIF, and exact-request bytes
  match the phase 0 golden unless the spec lists an expected delta. An unlisted golden change is a
  halt, not an `-update`. Changed evidence gets new judgments. It does not inherit old answers.
- **Merge order.** Language results are concatenated in the fixed order JS/TS, Python, PHP, then
  finalized once. Runner completion order never affects IDs, JSON order, or request bytes. There is
  no new global sort; `finalizeEntries` keeps the canonical record order.
- **No new machinery without a consumer.** No graph database, no third-party graph library, no
  general heap engine, and no replacement of JSON, HTML, or SARIF.
- **Protection stays per value, use, and path.** The graph has no "safe" bit, and model answers
  never become edges.
- **Recall.** A missed edge is an accuracy bug. A smaller report caused by a dropped edge is not a speed win.
- **No duplicated analyzers.** Framework adapters reuse a language's flow, inputs, and sinks.
- **Mode isolation.** Library mode and new framework resolvers leave application-scan output for
  existing fixtures unchanged. The phase 0 golden proves this.

## Common agent implementation rules

Every phase spec's §6 points here and adds only its own halt conditions.

- **Authority.** [AGENTS.md](../../AGENTS.md#authorization-and-delivery) authorization and
  [worktree location](../../AGENTS.md#worktree-location). Verify `pwd`, branch, `git status --short --branch`,
  and `git worktree list` before editing. Use no `.claude/worktrees/` checkouts.
- **Discipline.** [Execution discipline](../docs/agent-execution-discipline.md) and the `spec-driven`
  skill. A fresh [standards index](../standards/index.yaml) lookup is recorded in the run log.
- **Run log.** `.zazz/ephemeral/<spec-file-stem>-run-log.md`, append-only: standards check, OQ
  answers, phase completions with SHAs, deviations, and evidence locations.
- **Commits.** One coherent green commit per execution step is allowed. Use `[AREA]` prefixes as
  in `git log`. Push only at spec completion or for an explicit backup. Draft PR into `stage` per
  [PR process](../standards/pr-process.md). Never merge.
- **Verification.** Scoped tests while working, then the [contributor gate](../../docs/contributing.md#verification):
  `gofmt -l cmd internal` (changed files only), `go vet ./...`, `go build ./...`,
  `go test -race ./... -count=1`, plus `go test ./cmd/scan -run TestArchitectureBaseline -count=1`.
- **Scope check.** `git diff origin/stage --stat` matches the spec's §4 file table.
- **Samples.** Samples are read-only. Verify the pinned HEAD and clean `git status --porcelain --ignored`
  before and after. Write output to the container's `_test-findings/<app>/run-<id>/`.
- **Paid calls.** None unless the owner states provider, model, and a numeric cap in the session.
  No fallback. The judge retries only HTTP 429, 502, 503 and 504 (up to 3 times) and a dropped
  connection (once); no other status, timeout or error is retried.
- **Subagents.** Allowed for disjoint files in the same checkout, never with worktree isolation.
  The lead reviews their diffs and runs the gates.
- **Common halts.** An unresolved OQ; the same test failing 3 iterations in a row; a file outside
  §4; an unlisted baseline delta; a needed change to a public flag or report field not in the spec;
  a missing predecessor merge.

### Session start for every phase

1. Read AGENTS.md, the orientation contents, this plan, and the phase spec.
2. Confirm that every "Depends on" phase is merged into `origin/stage` (`git log origin/stage --oneline`).
   Cut the worktree from that SHA and record it. For phases 0–1 in `arch-review-clean-up`, confirm
   instead that the previous phase's commits are on the branch and that its run log records green
   gates. Record the starting HEAD.
3. Run `go test ./cmd/scan -run TestArchitectureBaseline -count=1` on the fresh cut. If it fails
   because another deliverable merged, regenerate the golden in a separate first commit,
   `[TEST] Rebaseline architecture golden on <sha>`, and record the reason. Do this before any change.
4. Reconcile the spec's §4 file table and skeleton names against the merged code. Update the spec in
   place and add a §14 change-log entry when a predecessor phase chose different names.

## Phase summaries

**0 — Compatibility baseline.** One golden test pins, per fixture: candidate IDs, request digests
from offline `Preview`, equivalence signatures, report JSON and SARIF hashes, and record counts.
It covers JS/TS, Python, PHP, and a new three-language fixture. It also records offline wall clock
and peak RSS on pinned samples as the "before" numbers.

**1 — Source index and callable summaries.** This replaces the registration graph, which improved neither
speed nor findings. Profiles show 59% of juice-shop CPU in whole-module syntax re-walks
(`bindingReassigned`), and most recall loss is at calls the per-language inline helper expansion
cannot follow (depth 3, budget 24). The phase builds, per file, a flat syntax index and a binding
index (steps 1A–1B, speed, byte-identical), and measures call resolution (1C). It then builds a
production call index with receiver typing and a closed effect table (1D), and per-callable
parameter summaries applied at call sites (1E for JS/TS, 1F for Python and PHP). Both 1D and the
summaries change output only through listed recall deltas. Library mode builds on 1E, and Symfony
and Drupal on 1F.

**2 — Pipeline and concurrent runners.** A new `internal/pipeline` owns one walk, empty-language
skip, concurrent JS/TS, Python, and PHP runners, the fixed-order merge, and finalization.
`internal/parse` exposes runners and stays a producer. Callers move from `parse.Analyze` to `pipeline.Analyze`.

**3A — PHP language package.** PHP sources, tests, and fixtures move to `internal/langphp`. It
imports an explicit, small `parse` core API. Phase-named `p1_`–`p4_` files are renamed by behavior.

**3B — JS/TS and Python language packages.** Python moves to `internal/langpy`, with its JS
coupling reduced to a template text reader in core and one inline-script bridge. JS/TS then moves to
`internal/langjs`, and `internal/parse` keeps only the language core.

**4 — Parallel judge.** A deterministic plan pass groups equivalent signatures and assigns request
slots. Then a capped worker pool sends leaders, with `--judge-concurrency` defaulting to 4. Order,
replay bytes, limit accounting, and halting are preserved. Setting it to 1 reproduces today's behavior.

**5 — Measured recall gaps.** Fresh offline scans of every pinned sample that has an answer key
produce one recall-miss inventory, with each miss classified by cause (registration, call binding,
value transfer, sink model, or framework adapter). The phase then closes the top-ranked miss with
paired fixtures. Judgment-level accuracy stays with the follow-on accuracy handoff.

**6 — Symfony.** A registration resolver in `langphp` covers attribute, annotation, and YAML routes,
`Request` inputs, Doctrine DBAL and ORM query construction, `Response` output, and a lexical Twig
output scan. Unresolved routes stay visible.

**7 — npm corpus and baseline.** This is the proposal's phase 0: pins, answer keys, and the capped
direct-model baseline. There are no engine changes.

**8 — npm library mode.** Adds the `--library` mode. `package.json` exports become `library_export`
entries, parameters become caller-argument inputs, and results are conditional weaknesses. The
existing command and code analyzers run unchanged. Application scans are unchanged.

**9 — Drupal.** A second `langphp` resolver reuses the Symfony config-to-callable helper.
`*.routing.yml`, Drupal PHP extensions, Form API values, database API placeholders, and render-array
output are covered.

## Explicitly later

Each needs its own proposal or contract.

- NestJS. Container-root plans name it, and it is a future registration producer on the JS/TS layer.
- npm proposal phases 2–3 (compile-to-JS, deserialization, dynamic-load sinks, and the prototype
  pollution pack), the parameter-trust judge question, the feasibility consumer, and proposal 4 chains.
- Value edges (`CALLS`, `ARG_TO_PARAM`, `RETURN_TO_CALL`, `TRANSFERS_TO`) stored in the graph. They
  are added only when an inventoried gap contract needs a cross-record relation.
- Evidence slicing, owned by the request-size design and its ledger.
- `--only-family` skipping parse work. Stored-code linking depends on stored-XSS linking, so a
  family cut can drop evidence. Revisit only with a measurement spec.
- Go as a scanned language, a graph database, or a third-party graph library.

## Docs each phase updates

Each spec lists its exact sections. Phases 1–3 update the [architecture](../architecture/README.md) package
map and §4. Phase 1 also updates the [repository graph](../architecture/repository-graph.md), so
implemented and proposed records stay distinct. Phases 3A and 3B update the orientation code-structure and
testdata rows. Feature phases update the detection guide, the capability checklist, and the
language-adapter section. User docs change only when a flag or supported framework changes
(phases 4, 6, 8, and 9).

## Change log

- 2026-11-17 — Initial plan (`2107c8c`).
- 2026-11-17 — Revised before any phase started.
  - Foundation now comes before features.
  - Added the capability matrix and the "what already exists" inventory.
  - Added phase 0, the compatibility baseline.
  - Split the old phase 2 into the pipeline (2) and PHP package (3) phases, because Python's JS
    coupling and the import cycle rule it out as one step.
  - Replaced old phase 7 with a measured recall inventory plus one closure, now phase 5. D5
    already delivered the factory, dispatch, and callback rows, and xss-hardening delivered the
    Jinja binding the old phase assumed was open.
  - Split the npm work into corpus (7) and library mode (8).
  - Merge order is now the fixed language concatenation instead of a new sort.
  - Resolved the Twig contradiction with a lexical output scan.
  - Removed evidence slicing as a speed lever.
  - Wrote one spec per phase.
- 2026-11-17 — Owner decision: phases 0–3 run serially in `arch-review-clean-up`, one session per
  phase, with one milestone draft PR. See [phase sequence](#phase-sequence).
- 2026-11-17 — Owner decision: phase 1 is now the [source index and callable summaries](architecture-phase-1-source-index.md)
  spec. The registration graph is superseded and was never committed. Later specs that cite its
  D-5/D-7 tables are repointed to that spec's L3 resolution kinds and L5 model tables when each starts.

- 2026-11-18 — Owner plans to review and merge the phases 0/1 PR, then start phase 2 on
  a new arch-pipeline-runners branch. Updated phase sequence and startup exception; no phase 2
  implementation or worktree creation occurs during phase 1.

### 2026-11-18 — Correct phase 2 branch spelling after phase 1 merge

Owner confirms PR #24 is merged and the new local branch/worktree is arch-pipeline-runners.
Corrected phase 2 branch references and refreshed its implementation prompt to reuse the existing
checkout. Phase 2 implementation remains for the new agent session; no code changes in this update.

### 2026-11-18 — Split phase 3 into 3A and 3B in one worktree

Owner assigned the `arch-multi-lang-packaging` worktree for the PHP spec and asked for a JS/TS and
Python separation spec in the same worktree. Phase 3 becomes 3A (PHP, reconciled against merged
phase 2 names) and 3B ([JS/TS and Python](architecture-phase-3-js-ts-python-package.md)). Updated
the phase table, capability matrix, phase summaries and docs line, and removed the "Explicitly later"
bullet that deferred the Python move. No implementation in this update.

### 2026-11-18 — Phase 3A implemented; milestone draft PR opened early

Owner decision: open the shared `arch-multi-lang-packaging` draft PR at the end of phase 3A to
record what is implemented and the passing gate. Phase 3B adds commits to the same PR instead of
opening it. Status line and the 3A capability row updated.

### 2026-11-18 — Phase 3B implemented in the milestone draft PR

JS/TS and Python moved to `internal/langjs` and `internal/langpy`; `parse` is the language core with a
77-identifier API indexed in `core_api.go` (the 3A wrappers became renames, C-2). Status line and the
3B capability row updated. Same root-path-only golden delta as 3A, proved per fixture.
