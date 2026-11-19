# Architecture compatibility baseline: before measurements

[Contract](../specifications/architecture-phase-0-compatibility-baseline.md) ·
[Plan](../specifications/architecture-update-plan.md)

This record holds the offline "before" cost of a full scan on three pinned samples. Architecture
phases 1–3 rerun the same command and report their change against these numbers. The byte-level
refactor guard is `TestArchitectureBaseline` in `cmd/scan`. It has its own golden and update flag.

## Guard test

```bash
go test ./cmd/scan -run TestArchitectureBaseline -count=1
```

For every fixture repository under `internal/parse/testdata/{javascript,typescript,python,php,mixed}/*`,
plus `express-login` and `string-flow`, the golden `cmd/scan/testdata/architecture-baseline.json`
pins:

- candidate IDs in report order, each with its kind;
- the SHA-256 of the offline `openai` request built by `judge.Client.Preview`, or the Preview error;
- the SHA-256 of the equivalence signature, or its error;
- the SHA-256 of the normalized report JSON and of its SARIF, both taken after `report.Enrich`;
- counts of entries, registrations, dispatch bindings, callables, invocation contexts, uses and gaps.

The test analyzes each fixture twice and fails if the two runs differ. A mismatch with the golden
names the fixture and the first differing use ID. `mixed/three-language` pins the JS/TS → Python →
PHP merge order with one SQL candidate per language. Rewrite the golden only for a change the
running phase spec lists as an expected delta:

```bash
go test ./cmd/scan -run TestArchitectureBaseline -count=1 -update-architecture-baseline
```

## Before measurements (2026-11-17)

Scanner built from `arch-review-clean-up` at `bdb3ee3`, which has the same production code as
`stage` `3890c1c`. Offline `--analyze` with no judge and no provider keys in the environment.
Apple M6, 12 cores, 32 GiB, macOS. Wall clock is the median of 3 runs. Peak memory is the largest
`maximum resident set size` of the 3 runs.

| Sample | Pin | Wall clock (median; runs) | Max RSS | Entries | Candidates |
|---|---|---|---|---|---|
| juice-shop | `f189f52` | 64.16 s (63.84, 64.16, 64.60) | 255 MiB | 175 | 251 |
| vulnpy | `b81885e` | 7.98 s (8.15, 7.98, 7.89) | 2,170 MiB | 2,214 | 3,350 |
| DVWA | `a1978a2` | 1.01 s (1.06, 1.01, 0.98) | 419 MiB | 174 | 240 |

All three runs of each sample produced the same entry count, candidate count and candidate-ID
order. Each sample checkout was at its pin with an empty `git status --porcelain --ignored`
before and after. DVWA's pin comes from its [detection guide](dvwa-detection-guide.md). The other
pins come from the [sample catalog](../project/vulnerable-sample-apps.md#applications).

## Rerun

Build the scanner once, outside every worktree and sample. Then run each sample three times, from
the container root, with provider keys unset:

```bash
go build -o <scratch>/scan ./cmd/scan
```

```bash
env -u OPENAI_API_KEY -u GEMINI_API_KEY -u JEV_API_KEY /usr/bin/time -l <scratch>/scan --analyze --output-dir _test-findings/<app>/run-<label>/ <DEV_ROOT>/<sample>
```

Sample paths are `<DEV_ROOT>/juice-shop`, `<DEV_ROOT>/vulnpy` and `<DEV_ROOT>/zazzcode/DVWA`.
Read `real` and `maximum resident set size` (bytes on macOS) from the `time` output. Read entry and
candidate counts from the bundle's `findings.json`. Compare medians on the same machine only.

## Phase 1 step 1A: binding write index (2026-11-17)

Same machine and method as the before measurements. The binary was built from `arch-review-clean-up`
after step 1A. `TestArchitectureBaseline` is unchanged. For all three samples, `findings.json` (without `root`)
and `findings.sarif` are byte-identical to the before runs.

| Sample | Wall clock (median; runs) | Change | Max RSS (largest of 3 runs) | Entries | Candidates |
|---|---|---|---|---|---|
| juice-shop | 10.19 s (10.30, 10.19, 10.18) | −84% (6.3× faster) | 276 MiB (median 251) | 175 | 251 |
| vulnpy | 7.83 s (7.87, 7.82, 7.83) | −2% | 2,077 MiB | 2,214 | 3,350 |
| DVWA | 0.97 s (1.06, 0.96, 0.97) | −4% | 414 MiB | 174 | 240 |

The gain comes from replacing two whole-module syntax walks, `bindingReassigned` and the uncached
`contractBindingStable`, with one per-module index. juice-shop peak RSS went up from 255 MiB (max)
and 238 MiB (median) to 276 MiB and 251 MiB, which overlaps run-to-run variance.

After 1A, juice-shop analysis takes 6.2 s of a 10.7 s profiled run. The rest is flow evaluation
(`flow.statement`/`eval`), `walkCalls` and the parent walk in `shadowed` (12%). vulnpy's time is
mostly bundle writing (step 1B).

## Phase 1 step 1B: bundle write buffering and Python mount index (2026-11-17)

Same method. The binary was built after step 1B, which includes the PHP callable-language fix.
`TestArchitectureBaseline` matches the post-fix golden. Compared with the step 1A bundles, juice-shop
and vulnpy `findings.json`, `findings.html` and `findings.sarif` are byte-identical. For DVWA, HTML and
SARIF are identical, and `findings.json` differs only in 169 callable `"language"` values
(`javascript` → `php`, the listed fix).

| Sample | Wall clock (median; runs) | vs before | Max RSS (largest of 3 runs) | Entries | Candidates |
|---|---|---|---|---|---|
| juice-shop | 9.89 s (9.77, 9.89, 9.94) | 64.16 s → 9.89 s (6.5×) | 261 MiB | 175 | 251 |
| vulnpy | 3.49 s (3.49, 3.47, 3.52) | 7.98 s → 3.49 s (2.3×) | 1,955 MiB | 2,214 | 3,350 |
| DVWA | 0.61 s (0.69, 0.60, 0.61) | 1.01 s → 0.61 s (1.7×) | 462 MiB (median 422) | 174 | 240 |

- **Bundle writes are buffered.** The HTML template wrote straight to the file, and on vulnpy 2.37 s
  went to raw `write` syscalls for a 95 MB page. The bundle now writes through a 1 MiB `bufio.Writer`.
- **Python mount calls are indexed per module.** `mountPrefix` and `dynamicMounts` walked every Python
  file for each route. Each module now keeps its possible `register_blueprint`/`include_router`
  calls in walk order, and each caller applies its original filter.

## Phase 1 step 1C: call-site resolution (2026-11-18)

Measured with `ZAZZLES_MEASURE_ROOT=<sample> ZAZZLES_MEASURE_OUT=_test-findings/<app>/run-arch-1c/call-resolution.json
go test ./internal/parse -run TestCallResolutionMeasure -count=1`, offline, at the pins above. The
harness uses the analyzers' own module sets and resolvers, so a class shows what flow can follow
today. Classes:
- `in_repo`: a definition is found;
- `in_repo_member_unresolved`: the root is an in-repository module or class, but the member is not found;
- `package`: an import from outside the repository;
- `builtin`, or `builtin_or_local` for Python identifiers with no module binding;
- `member_on_value`: a method on a value whose type is unknown;
- `dynamic`: any other callee.

### Call sites

| Sample | Language | Sites | in_repo | in-repo member | package | builtin | member_on_value | dynamic / local |
|---|---|---|---|---|---|---|---|---|
| juice-shop | JS/TS | 36,697 | 1,930 | 345 | 7,578 | 6,293 | 12,148 | 7,158 / 1,245 |
| vulnpy | Python | 866 | 164 | 23 | 250 | 131 | 298 | 0 |
| DVWA | PHP | 2,315 | 521 | 18 | 1 | 1,563 | 212 | 0 |

### Call-site gaps on report records, by class

| Sample | Gap kind | Count | in_repo | in-repo member | package | builtin | member_on_value | dynamic |
|---|---|---|---|---|---|---|---|---|
| juice-shop | `unknown_call_result` | 1,272 | 287 | 141 | 326 | 74 | 356 | 87 (+1 local) |
| juice-shop | `middleware_unresolved` | 318 | – | – | – | – | 318 | – |
| juice-shop | `path_unrelated_helper_limit` | 257 | 257 | – | – | – | – | – |
| juice-shop | `unknown_transfer` | 74 | 6 | 5 | 11 | 5 | 39 | 7 (+1 local) |
| juice-shop | `external_response_unresolved` | 71 | – | – | – | 71 | – | – |
| juice-shop | `recursive_helper` | 9 | 9 | – | – | – | – | – |
| vulnpy | `python_dispatch_unresolved` | 523 | – | – | 8 | – | 515 | – |
| vulnpy | `python_call_unresolved` | 131 | – | – | – | 64 | 67 | – |
| vulnpy | `work_limit` | 64 | 64 | – | – | – | – | – |
| DVWA | `php_call_unresolved` | 210 | – | – | – | 210 | – | – |

**What this means for 1D and 1E:**
- **Summaries** close the gaps the expansion limits cause on in-repository callables: 559 on juice-shop
  (`unknown_call_result` 287, `path_unrelated_helper_limit` 257, `recursive_helper` 9, transfer 6)
  and 64 `work_limit` gaps on vulnpy.
- **Receiver typing** is needed for the largest class, methods on values whose type is unknown: 713 on
  juice-shop and 582 on vulnpy. The L3 call index needs `method_on_known_class` resolution,
  using constructors, imports and annotations.
- **Model tables** are needed for package and builtin calls: 337 package and 150 builtin on juice-shop,
  and all 210 DVWA `php_call_unresolved` gaps, which are PHP builtins. Summaries cannot help there.

**Precision caveats** (from the verifier's review):
- The gap tables count only gaps whose span is exactly a call node, so they are lower bounds.
- The tables show each sample's primary language. DVWA also has 167 JS and 20 Python call sites, and
  juice-shop has 22 Python sites.
- Smaller kinds are omitted. For example, vulnpy's 313 `input_validation_unresolved` gaps are all
  `member_on_value`, so the receiver-typing class there is larger than 582.
- PHP method calls (`->`) are always `member_on_value`. A PHP function name that is unique in the
  repository counts as `in_repo` regardless of includes. Any class outside the repository, PHP
  built-in classes included, counts as `package`.
- The JS `builtin` class uses a fixed list of globals, so it is a lower bound.

## Phase 1 step 1D: call index and receiver typing (2026-11-18)

Same method. The binary was built after step 1D. `TestArchitectureBaseline` and every parse golden are
unchanged, because no fixture reaches the typed receivers.

Counts cover gaps on both uses and entries. Uses alone: vulnpy 389 → 75.

| Sample | Gap kind | Before (1B) | After (1D) | AC2 target |
|---|---|---|---|---|
| juice-shop | `unknown_call_result` | 1,272 | 668 | ≤ 800 |
| vulnpy | `python_dispatch_unresolved` | 523 | 81 | ≤ 250 |

Report deltas, compared with the step 1B bundles:

- **juice-shop:** 604 `unknown_call_result` gaps removed (`os.*`, `config.get`, `JSON.stringify`,
  `Math.*`, `new Date()` instance methods, `HintModel.count`). One use also lost 2
  `unknown_control_effect` gaps and 1 `conditional_merge` gap, which existed only because its branches
  differed by those removed gaps. No gaps were added. Candidate IDs are identical and in the same
  order, and finding statuses are unchanged (236 needs_review, 15 poor_practice).
- **vulnpy:** 442 `python_dispatch_unresolved` gaps removed (`response.append` on the module-stable
  local list in `wsgi/app.py`). No gaps were added. 125 `input_validation_candidate` records were
  re-keyed, with the same kind, entry and sink, because their evidence changed. No candidate was
  added or removed by (kind, entry, sink), and finding statuses are unchanged.
- **DVWA:** byte-identical.
- **Recall gain on a new test fixture** (`TestPythonContainerWrite`): a request value appended to a
  local list and returned through `"".join(...)` is now an `xss_candidate`. The 1B binary missed it.

| Sample | Wall clock (median; runs) | vs 1B | Max RSS (largest of 3 runs) |
|---|---|---|---|
| juice-shop | 10.35 s (10.63, 10.35, 10.26) | +4.7% (within AC4's 5%) | 241 MiB |
| vulnpy | 3.57 s (3.60, 3.57, 3.52) | +2.3% | 2,069 MiB |
| DVWA | 0.61 s (0.68, 0.61, 0.60) | 0% | 459 MiB |

What remains on juice-shop is the 1E summary work and framework models: `challenge.save` 280 (a
parameter receiver), `utils.*`/`antiCheat.*` 207 (in-repository), and `req.header` 64 (Node input models, D-10).

## Phase 1 step 1E: JS/TS callable summaries (2026-11-18)

Same method. The binary was built after step 1E. Bundles are in `_test-findings/<app>/run-arch-1e/`.
Each sample was at its pin with an empty `git status --porcelain --ignored` before and after.

Summaries apply only at inline-expansion refusals and at the in-repository `unknown_call_result`
fallthrough, when the callee's summary is closed and every argument it reads is inert
([spec §8b](../specifications/architecture-phase-1-source-index.md#8b-step-1e-contract-jsts-callable-summaries), D-14).
Inline expansion is unchanged wherever it expands.

**Shadow parity (AC2).** `TestSummaryShadowParity` checks every inline expansion against the callee's
summary. It covered 38 expansions on the JS/TS fixtures and 1,155 on juice-shop (448 precise, 10
where a closed summary applies), with no disagreements. A mutation check, which treated every summary as
closed, produced 6 disagreements on juice-shop (a `file_read` and an `unresolved_source` acquired
inside the callee). The oracle therefore detects an unsound summary.

**Golden (AC3).** One fixture use changed: `typescript/path-traversal-expanded`
`/v/irrelevant-helper-budget` lost 3 `path_unrelated_helper_limit` gaps on `tick(0)`. Its candidate
ID is unchanged, while its request and signature digests and the fixture's report and SARIF hashes changed.
No other fixture or parse golden changed. No fixture use has `helper_call_limit` or
`path_unrelated_helper_limit`.

**Report deltas (AC4), compared with the step 1D bundles:**

- **juice-shop:** 207 gaps removed, and none added. All are on the 70 `outbound_http_candidate` uses at the
  `webhook.notify` `fetch` (`lib/webhook.ts`): 67 `path_unrelated_helper_limit` and 70
  `unknown_call_result` on `utils.version()`, plus 70 follow-on `unknown_value` on the `utils`
  namespace receiver. `utils.version` reads only the `package.json` import. Candidate IDs, their
  order, dependencies, context, sinks and finding statuses (236 needs_review, 15 poor_practice) are
  unchanged. Only the 70 findings' `blocking_evidence` lists shrank. No candidate was added,
  removed or re-keyed. The 70 uses match the sample answer key (`docs/samples/juice-shop/findings.json`,
  70 `outbound_http_candidate` uses at `lib/webhook.ts`). The webhook destination is
  `process.env.SOLUTIONS_WEBHOOK`, not request data.
- **vulnpy and DVWA:** `findings.json` is identical to 1D apart from `root`. Neither runs JS/TS summary code.

**Limit-induced gaps on in-repository callables, juice-shop:** 553 after 1D → 416 after 1E. The 553
are `path_unrelated_helper_limit` 257, `recursive_helper` 9 and `unknown_call_result` on
in-repository callees 287. The 1C figure of 559 was measured on the 1B bundles. `TestSummaryRemainingReasons`
attributes every remaining gap to its callee summary's first reason. None is on a closed
callee with inert arguments (the AC4 target):

| Gaps | Gap kind | Callee | First blocking reason |
|---|---|---|---|
| 70 | `unknown_call_result` | `antiCheat.calculateCheatScore` | `unmodeled_call` (`logger.info`, a log sink) |
| 67 + 67 | `path_unrelated_helper_limit`, `unknown_call_result` | `totalCheatScore` | `mutable_module_binding` (`solves`, mutated by `push`) |
| 67 + 67 | `path_unrelated_helper_limit`, `unknown_call_result` | `utils.ctfFlag` | `unmodeled_call` (`crypto.createHmac`) |
| 56 | `path_unrelated_helper_limit` (entries) | `challengeUtils.solveIf` | `unmodeled_call` (the `criteria` closure argument) |
| 8 | `unknown_call_result` | `utils.extractFilename` | `unmodeled_call` (the global `decodeURIComponent`) |
| 7 | `recursive_helper` | `findFilesWithCodeChallenges` | `unmodeled_call` (`fs`) |
| 3 | `unknown_call_result` | `getCtfKey` | `mutable_module_binding` (`cachedCtfKey`) |
| 2 | `recursive_helper` | `sanitizeSecure` | `callee_not_closed` |
| 1 + 1 | `unknown_call_result` | `calculateApplicableDiscount`, `utils.jwtFrom` | `imported_value`, `unsupported_parameters` |

Closing the rest needs store summaries over module state (`solves`, `cachedCtfKey`), effect-table
rows for pure package and builtin calls (`crypto`, `median`, `decodeURIComponent`, string methods), and per-caller
instantiation for closure and request arguments. These are recorded as deferred in the spec.

| Sample | Wall clock (median; runs) | vs 1D | Max RSS (largest of 3 runs) |
|---|---|---|---|
| juice-shop | 10.63 s (10.95, 10.59, 10.63) before the verifier fixes; final binary 11.15 s (11.48, 11.14, 11.21, 11.10, 11.10, 11.17) | +2.7%; final +7.7% (outside AC5's 5%; accepted by the owner 2026-11-18) | 248 MiB; final 242 MiB |
| vulnpy | 3.51 s (3.57, 3.50, 3.51) | −1.7% | 2,057 MiB |
| DVWA | 0.69 s (0.66, 0.72, 0.69); re-time 0.60 s (0.66, 0.60, 0.59, 0.60, 0.59) | +13%; re-time −1.6% | 454 MiB |

The final juice-shop binary adds the verifier's scope fixes. Its output is byte-identical to the earlier 1E bundles, and its median is 11.15 s. Whether that cost comes from the scope checks or from machine state was not isolated (no A/B in one sitting), The owner accepted the juice-shop result on 2026-11-18. vulnpy and DVWA run no JS/TS summary code. DVWA runs no changed code. The first batch's sub-second median was outside 5%, and an immediate
5-run re-time on the same binary gave 0.60 s against 1D's 0.61 s, so the first batch is treated as noise.

## Phase 1 step 1F — Python/PHP summaries and PHP resolution inputs (2026-11-18)

Contract: [source index §8c](../specifications/architecture-phase-1-source-index.md#8c-step-1f-contract-pythonphp-summaries-and-php-resolution-inputs).
Starting HEAD `22f6adc`; contract `dfec39b`. Evaluation was offline with no model calls or
credentials, new dependencies or sample edits. Samples were clean before/after at the original
pins: juice-shop `f189f521266f42c6bd05884468292000cee852ed`, vulnpy
`b81885e58283a3449b578d20c20557aff637e5ea`, DVWA
`a1978a2fed195acd093010af6395f86a281537ca`.

### Acceptance evidence

- **AC1 summaries:** cached parameter-indexed closed expressions/helper chains apply only at
  expansion refusals with inert positional arguments. Return sets conservatively include all read
  parameters. Defaults, variadics/references, decorators, ambient reads, mutation, unsupported syntax
  and cycles remain blocked. Successful inline expansion is unchanged.
- `TestPythonPHPSummaryShadow` checked 7,645 Python and 4,093 PHP expansions (two applicable
  closed/inert expansions each), zero disagreements. `TestSummaryShadowMutation` deliberately
  closes a source-acquiring helper and detects its dependent inline result/use. Table/refusal/limit
  tests cover the subset's boundaries.
- **AC2 effects:** `TestPHPBuiltinContentEffects`, `TestPHPBuiltinContentEffectShadowing`,
  `TestPHPArrayShiftInvalidatesShape` and `TestPHPBuiltinEffectsIgnoreUnrelatedNamespaces`
  cover dependency retention with unknown protection, excluded names, mutating shape invalidation
  and namespace isolation.
- **AC3 resolution:** `TestPHPProjectResolution`, `TestPHPProjectResolutionBounds`,
  `TestPHPLegacyResolutionParity`, `TestPHPServiceTargetRegressions` and
  `TestPHPAbsoluteServiceResource` cover exact FQCN/method and `__invoke`, Composer string/array
  directories, Symfony services/aliases/autowiring resources, Drupal service classes, provenance,
  legacy targets, missing/ambiguous/unsafe targets and unsupported configuration.
  Fixtures: `php/symfony-resolution` and `php/drupal-resolution`. No route adapter is added.
- **AC4 golden:** only those two fixtures are added. Every existing fixture's IDs, request,
  signature, report and SARIF hashes and counts are unchanged.

### Sample deltas against 1E

| Sample | Candidates | Added / removed / re-keyed | Report change |
|---|---:|---|---|
| juice-shop | 251 | 0 / 0 / 0 | JSON unchanged after normalizing root |
| vulnpy | 3,350 | 0 / 0 / 0 | JSON unchanged after normalizing root |
| DVWA | 240 | 0 / 0 / 0 | 210 builtin gaps removed on 92 uses |

Statuses and ordered IDs are unchanged. DVWA changes only `gaps`, `completeness` and input-fact
gap metadata, with dependency, transfer/context evidence and protection facts unchanged.

| Builtin | Removed `php_call_unresolved` gaps |
|---|---:|
| `array_shift` | 165 |
| `json_decode` | 5 |
| `base64_decode` | 16 |
| `base64_encode` | 16 |
| `strrpos` | 4 |
| `addslashes` | 4 |
| **Total** | **210** |

No gap is added. There are no new candidates requiring answer-key adjudication; the
[DVWA](dvwa-detection-guide.md) and [vulnpy](vulnpy-detection-guide.md) expectations are preserved.
Each output's `deltas.json` records bundle paths, field/gap differences, normalized hashes and statuses.

**Remaining vulnpy limits:** all 64 `work_limit` gaps remain at
`src/vulnpy/trigger/util.py:54`, `_get_trigger_module(name)`. Its body assigns a module-name
expression and returns `import_module(module_name)` at lines 23–25. The summary is blocked by
unsupported assignment syntax and an unmodeled dynamic-import call. It is not closed; no applicable
closed/inert sample refusal remains. The owner declined deferral; the completion section below records the closure.

### Performance (AC5)

Same full-bundle method as phase 0: optimized binary, `--analyze --output-dir`, three sequential
runs, `/usr/bin/time -l`, no judge/model configuration. Outputs:
`_test-findings/<app>/run-arch-1f/verified-run-{1,2,3}/`; `measurements.json` records all values.

| Sample | Phase 0 | 1A | 1B | 1D | Final 1E | 1F median (runs) | vs 1E | Max RSS |
|---|---:|---:|---:|---:|---:|---|---:|---:|
| juice-shop | 64.16 s | 10.19 s | 9.89 s | 10.35 s | 11.15 s | **9.34 s** (9.24, 9.34, 9.35) | −16.2% | 244 MiB |
| vulnpy | 7.98 s | 7.83 s | 3.49 s | 3.57 s | 3.51 s | **3.43 s** (3.43, 3.43, 3.43) | −2.3% | 1,994 MiB |
| DVWA | 1.01 s | 0.97 s | 0.61 s | 0.61 s | 0.60 s | **0.62 s** (0.62, 0.61, 0.62) | +3.3% | 466 MiB |

All samples meet the within-5%-of-final-1E criterion. Step 1C was measurement-only.
Fresh performance review found summary construction about 0.10 s CPU versus `shadowed` parent walks
2.14 s (17.5%). Caching immutable `(node ID, name)` queries preserved the answers.
The analysis-only overlay experiment measured 10.80/11.95 s before and 9.49/9.50 s after with
identical report hashes. `TestShadowCacheParity` checked 37,220 fixture/Juice Shop call queries
twice against the old walk. The table uses unprofiled final full-bundle runs.

### Verification and limits (AC6)

The first sandboxed race run could not bind local `httptest` ports; no live provider was involved.
The final contributor gate permits local stub listeners and passes changed-file gofmt, vet, build,
the full race suite and the architecture baseline. Fresh-context technical verification is PASS;
the owner subsequently assigned the dynamic-import/witness completion recorded below. Evidence is recorded in
spec §14 and the local run log.

Fresh review found and fixed decorated/root-shadowed Python helpers, conflicting service definitions,
private/abstract PHP targets, absolute-resource rebasing, config provenance, stale `array_shift`
projections and cross-module namespace exclusions. Regression tests cover these cases.
At initial 1F delivery, full witnesses were still pending. The completion below delivers bounded native
witness instantiation. Broader recursive/state summaries, alias/heap modeling, full YAML and route
adapters remain outside the supported subset.

## Phase 1 completion — Finite imports and concrete witnesses (2026-11-18)

Contract [summary completion](../specifications/architecture-phase-1-summary-completion.md),
committed first as `7119b51`. Implementation `4b01e42`; typed TypeScript end-to-end regression
`912446a`. The owner rejected deferring the 64 import-related limits and authorized finishing
phase 1 here. Symfony/Drupal route adapters remain phases 6/9.

### Concrete witnesses and acceptance

- **AC1:** cached parameter-indexed recipes instantiate dependent returns, native controls and sinks
  with actual caller values and original spans. JS/TS, Python and PHP preserve native parameter,
  assignment, operation, helper-return and sink evidence. The existing closed/inert fast path stays
  first, and successful inline paths are untouched.
- Native differential tests cover fan-out, locals, transforms, command/control, filesystem, code,
  logging, verified SQL and helper DAGs. JS fixture shadow checks 44 expansions, 38 supported complete
  witnesses, zero mismatches. PHP verifies implicit versus explicit return gaps as well as return,
  complete use bytes and context. Python compares the full internal return value (including
  protection/bindings) and serialized public evidence. Deliberately changed parameter/span recipes
  are detected.
- **AC2:** unsupported calls/binding/control/state, async callables without invocation proof, cycles
  and instruction limits reject before any effects. Cache/source-load checks and two-caller
  provenance tests pass. Finalized reports for JavaScript, typed TypeScript, Python and PHP produce
  valid native command facts, exact offline requests and equivalence signatures beyond old depths.
- **AC3:** finite import/selector facts belong to one generated invocation and its exact registry,
  arguments and source target. Typed immutable proof values are separate from dependencies and
  protection; ordinary flow conditions are not folded. Import aliases, shadowing, reassignment,
  reflection/deletion, escaped namespaces, custom receivers, scalar/index type mismatches, wrong
  invocation/arguments/target, nonfinite values and bounded registry-copy failures have negatives.
  The targeted `util.py:54` helper gaps are **64 → 0**.

### Final sample deltas and wire compatibility (AC4)

Compared with delivered 1F's `verified-run-1` bundles:

| Sample | Candidates | Added / removed | Re-keyed | Final delta |
|---|---:|---|---:|---|
| juice-shop | 251 | 0 / 0 | 0 | Normalized JSON unchanged |
| vulnpy | 3,350 | 0 / 0 | 128 | 64 helper-limit and 64 unresolved-getattr gaps removed; no gap added |
| DVWA | 240 | 0 / 0 | 0 | Normalized JSON unchanged; retains 1F's 210 builtin-gap closure |

All previous semantic candidate keys and input-source spans remain. Status distributions are unchanged.
The 128 vulnpy rows change dependency/input-fact evidence and IDs; 64 path rows additionally change
gap, completeness and path metadata. No protection is invented. Changed evidence requires new
judgments; old model answers are not transferred.

An additional offline audit loads the saved reports, restores their supported read views using
`AnalysisReport.BindUses`, and calls `Preview`/`EquivalenceSignature` without network access:

| Sample | Identical request/signature outcomes | Changed outcomes |
|---|---:|---:|
| juice-shop | 251 | 0 |
| vulnpy | 3,222 | 128 |
| DVWA | 240 | 0 |

Preview/signature errors, where already present, are compared too. All non-use request-input,
catalog, file and limitation metadata hashes match. Output: `request-signature-audit.json`.
Every pre-existing architecture golden row is unchanged. Only
`javascript/summary-witnesses` (6 uses, including native commands/raw output/validation) and
`php/summary-witnesses` (4 controlled command/encoded output uses) are added, with no request or
signature errors. The native facts are checked before the baseline update.

### Final performance and cache evidence (AC5)

Same optimized, offline full-bundle method, no credentials passed to the scanner. Three sequential
runs per clean pinned sample, after implementation froze and without concurrent verification load.

| Sample | Phase 0 | 1B | 1D | Final 1E | Initial 1F | Completion median (runs) | vs initial 1F | Max RSS |
|---|---:|---:|---:|---:|---:|---:|---|---:|---:|
| juice-shop | 64.16 s | 9.89 s | 10.35 s | 11.15 s | 9.34 s | **9.21 s** (9.50, 9.21, 9.19) | −1.4% | 253 MiB |
| vulnpy | 7.98 s | 3.49 s | 3.57 s | 3.51 s | 3.43 s | **3.42 s** (3.47, 3.42, 3.41) | −0.3% | 1,952 MiB |
| DVWA | 1.01 s | 0.61 s | 0.61 s | 0.60 s | 0.62 s | **0.60 s** (0.67, 0.60, 0.60) | −3.2% | 459 MiB |

All samples meet the within-5% criterion. Juice Shop is 17.4% faster than final 1E, reversing its
accepted timing increase. A read-only Go overlay recorded caches at set close after timing:

| Primary sample/language | Compiled witness plans | Supported plans | Closed-summary cache entries | Largest expanded plan cost |
|---|---:|---:|---:|---:|
| juice-shop / JS/TS | 23 | 1 | 241 | 69 |
| vulnpy / Python | 11 | 1 | 3 | 18 |
| DVWA / PHP | 12 | 0 | 12 | 4 |

Counts describe lazily requested plans, including unsupported plans retained with reasons; they are
not a repository-wide coverage denominator. Python has two selection-requiring plans. Full native
sink witnesses are demonstrated by the fixtures; existing sample sinks generally already expand
inline. The JSONL also records zero-plan auxiliary language sets. No production instrumentation or
scan output field was added.

### Verification and delivery (AC6)

Changed-file formatting, vet, build, full race suite and the architecture baseline pass. A fresh
independent verifier exercised isolated mutation/alias/receiver/type probes with the race detector
and reviewed final deltas, exact requests, cache counts and timings. Corrections include hidden
receiver subtrees, reassigned helper bindings, inherited implicit-return gaps, async functions,
mutated/deleted/escaped imports, exact scalar/index types, and finite-proof branch joins.

Artifacts: `_test-findings/<app>/run-arch-1f/summary-completion/` contains `run-{1,2,3}/`,
`measurements.json`, `deltas.json`, `request-signature-audit.json` and `plan-cache-counts.jsonl`.
The Juice Shop directory holds the shared scoped/gate logs. All three sample pins and clean status
were checked before/after; no sample edits, model calls, keys, dependencies or worktrees were added.

Phase 1 is complete within the documented bounded source-index/witness contracts. General heap/
module-state summaries, broader control-flow/recursive recipes and full YAML remain unsupported
with explicit gaps; they are not claimed by this evidence. Route adapters remain phases 6/9.
The owner merged PR #24 at `6bf2ca1`; phase 2 has a separate assigned `arch-pipeline-runners` worktree.

## Phase 2 — pipeline and concurrent language runners (2026-11-18)

[Contract](../specifications/architecture-phase-2-pipeline-runners.md). `internal/pipeline` walks the
target once, skips languages with no files, runs the JS/TS, Python and PHP runners concurrently and
merges them through `parse.Assemble` in the fixed order. There are no listed output deltas:
`TestArchitectureBaseline` passes against the phase 1 golden with no update.

### Method

Offline `--analyze`, provider keys unset, `/usr/bin/time -l`, one sitting on the same machine as
phase 0. Three variants were interleaved run by run, three runs each:

- **before**: the starting HEAD `7bb2213` (phase 1 final production code), built with a read-only
  `go build -overlay` of the pre-change sources;
- **default**: this phase, one runner goroutine per selected language;
- **sequential**: this phase with `Workers: 1` forced through a build overlay.

Walk counts come from a stderr counter overlaid on `walk.Walk` for one extra run of each binary.
Sample pins and empty `git status --porcelain --ignored` were checked before and after every batch.

### Results

| Sample | Phase 0 | Final phase 1 (recorded) | Before, same sitting | Default (runs) | Sequential | Max RSS before / default | Walks before → after |
|---|---:|---:|---:|---:|---:|---:|---:|
| juice-shop | 64.16 s | 9.21 s | 9.81 s | **9.79 s** (9.72, 9.79, 9.79) | 9.82 s | 243 / 246 MiB | 3 → 1 |
| vulnpy | 7.98 s | 3.42 s | 3.67 s | **3.69 s** (3.65, 3.69, 3.69) | 3.68 s | 1,993 / 2,094 MiB | 3 → 1 |
| DVWA | 1.01 s | 0.60 s | 0.64 s | **0.62 s** (0.62, 0.62, 0.62) | 0.63 s | 423 / 460 MiB | 3 → 1 |

`findings.json`, `findings.sarif` and `findings.html` are byte-identical across all nine runs of
each sample (before, default and sequential). Entry and candidate counts are unchanged: 175/251,
2,214/3,350 and 174/240.

The same-sitting "before" medians are 4–7% above the recorded phase 1 numbers. The before binary
moved by the same amount, so the difference is machine state, not this phase. Against the
same-sitting before, every sample is within run-to-run noise.

None of the three samples shows a parallel gain, as expected: each is dominated by one language.
Juice Shop loads 657 JS/TS modules and 3 Python files, vulnpy is Python-only apart from one
template, and DVWA analyzes 169 PHP files, 9 JS files and 1 Python file. The removed walks and the
skipped grammars are small next to that one runner. Peak RSS is within the run-to-run spread of
earlier phases. vulnpy and DVWA run two or three runners at once, which can raise the peak slightly.

`BenchmarkPipelineMixed` on `mixed/three-language` (6 × 40 iterations) gives a sequential median of
1.03 ms/op and a default median of 0.77 ms/op, 1.34× faster. Allocations rise from 578 KB to
604 KB per op, for goroutine and slot overhead.

### Acceptance evidence

- **One walk (AC1).** `TestFullScanWalksOnce` counts one walk for `mixed/three-language`. In
  production `internal/parse`, only `parse.go` (route inventory) calls `walk.Walk`.
- **Skip (AC2).** `TestPythonOnlyScanSkipsPHP` never invokes the PHP runner for `python/routes`.
  `TestRunnersWithoutSourcesOpenNoGrammar` shows that the JS runner opens no grammar and loads no
  module there, and that `RunPHP` returns `nil, nil`.
- **Equivalence (AC3).** `TestWorkersEquivalence` compares `Workers: 1` with the default five times
  on all 36 baseline fixtures, under `-race`.
- **Error order (AC4).** `TestEarliestRunnerErrorWins` makes PHP fail first and Python fail second,
  and gets Python's error at 0, 2 and 3 workers.
- **Entry modes (AC5).** The existing `cmd/scan` entry tests pass unchanged.
  `TestEntryModesSelectOneLanguage` confirms that a `.py`, `.php` or JS entry runs one runner.
- **Gate (AC8).** `gofmt` on changed files, `go vet ./...`, `go build ./...`,
  `go test -race ./... -count=1` and `TestArchitectureBaseline` pass.

Artifacts: `_test-findings/<app>/run-arch-2/` holds `run-{1,2,3}/` (first default batch),
`ab/{old,new,seq}-{1,2,3}/`, `walk-count/{old,new}/` and `pins.log`. The Juice Shop directory also
holds `measurements.json`, `bench-pipeline-mixed.txt` and the gate logs.

## Phase 4 — parallel judge requests (2026-11-18)

Stub timing for AC9: `BenchmarkScheduleLatency` (`internal/judge/schedule_parallel_test.go`) runs 40
distinct signatures, each with a local `httptest` stub that waits a fixed 200 ms. The run uses
`--judge-limit` 40 and no RPM/TPM pacing, on an Apple M6 with go1.27.3 and `-benchtime 1x`.

| N | Wall clock | Speed-up over N=1 | Requests | Max in flight |
|---|---|---|---|---|
| 1 | 8.15 s | 1.00× | 40 | 1 |
| 2 | 4.11 s | 1.98× | 40 | ≤2 |
| 4 | 2.09 s | 3.91× | 40 | ≤4 |
| 8 | 1.08 s | 7.56× | 40 | ≤8 |

Wall clock scales with `N` when stub latency dominates and pacing does not bind. Request bytes and
token usage are the same at every `N`. Live provider latency and quota behavior are unverified. No
paid calls were made.

AC1 serial outputs are pinned in `internal/judge/testdata/schedule_serial/`. There are twelve
scenarios, captured from the pre-change scheduler in `15d0f92`. Each file pins the report and
saved traces by SHA-256 and keeps the assessments and limitations readable.

### Live owner-capped check (2026-11-18)

Owner-approved OpenAI `gpt-6-luna` requests against Juice Shop `f189f52`, which was clean before and
after. Offline analysis took 9.5 s in two runs. Judging time is wall clock minus that.

| Run | Requests | Completed | Input tokens | Wall clock | Judging |
|---|---|---|---|---|---|
| Full scan, N=4, RPM 450, TPM 1M | 157 | 157 | 770,517 | 192.1 s | ~183 s (TPM-paced) |
| A/B, N=1, RPM 450, TPM 0 | 40 | 40 | 329,255 | 21.0 s | ~11.5 s |
| A/B, N=4, RPM 450, TPM 0 | 40 | 40 | 329,255 | 12.1 s | ~2.6 s (≈4.4×) |

The same A/B with TPM 1M took 73.8 s at N=1 and 70.6 s at N=4. In both runs the local TPM window was
the bottleneck. The reservation is request bytes plus 4,096, about 24k per Juice Shop request, while
the provider reports about 4.9k input tokens per request. The first 40 reservations total 1.48M, so
request 27 waits for the rolling window at any concurrency. A token-based estimate is a follow-up
outside this phase. Results and every attempt count are in `_test-findings/juice-shop/run-arch-4*`.

Full judged scans followed, with `JUDGE_RPM=4500`, `JUDGE_TPM=0`, a cap of 200 per run, and the
Mac mini M6 with 32 GB RAM. Both samples were clean before and after.

| Target | N | Requests | Completed | Input tokens | Wall clock |
|---|---|---|---|---|---|
| Juice Shop `f189f52` | 1 | 157 | 157 | 770,517 | 43.0 s |
| Juice Shop `f189f52` | 4 | 157 | 157 | 770,517 | 19.0 s |
| OopsSec Store `2d530ef` | 1 | 114 | 116 (2 reused) | 483,076 | 28.2 s |
| OopsSec Store `2d530ef` | 4 | 114 | 116 (2 reused) | 483,076 | 7.2 s |

For each target, N=1 and N=4 had 0 differences in request digests, answers and finding statuses.
Two earlier Juice Shop N=4 scans each stopped on one OpenAI HTTP 503, at 124 and 148 of 157. With
no retries, one transient 503 ends the scan. A single retry of 503 responses is a candidate follow-up.

### Judge retry and token-based TPM estimate

The follow-up deliverable ([spec](../specifications/judge-transient-retry-and-token-estimate.md))
retries HTTP 429, 502, 503 and 504 up to 3 times and a dropped connection once. It also reserves
`ceil(bytes / 3) + 512` input tokens per request instead of bytes plus 4,096. The estimator was
checked offline against the 157 live Juice Shop traces of the full N=4 scan above, recorded as
byte and token pairs in `internal/judge/testdata/tpm_ratio.json`.

| Measure | Bytes + 4,096 | `ceil(bytes / 3) + 512` |
|---|---|---|
| Reserved for 157 requests (reported 770,517) | 3,793,778 | 1,130,669 |
| Reservation ÷ reported tokens, minimum | 4.05× | 1.28× |
| Reservation ÷ reported tokens, maximum | 5.87× | 1.65× |
| Reservation ÷ reported tokens, median | — | 1.51× |

Request bytes ran 12,028–57,912 and reported input tokens 2,748–14,749, a median of 4.17 bytes per
token. The new estimate never underestimates a row. No live scan has been run with the retry or
the new estimate yet.

