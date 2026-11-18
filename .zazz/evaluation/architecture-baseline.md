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
