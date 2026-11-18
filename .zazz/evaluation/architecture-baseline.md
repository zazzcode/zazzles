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
