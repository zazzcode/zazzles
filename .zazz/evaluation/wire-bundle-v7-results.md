# Wire bundle v7 verification

[Implementation contract](../specifications/scan/wire-bundle-v7.md) · [Size design](../architecture/request-size-and-evidence-relevance.md)

Offline measurements cover the eight pinned standard apps and each parser fixture as a root.
Preview includes observation/data-only candidates; the byte tables below count assessed-family requests only.
Historical paid answers were preserved and never copied onto changed evidence.

## Request bytes by sample

| App | Requests before / after | Total before / after | Reduction | After median / p95 / max |
|---|---:|---:|---:|---:|
| ThreatByte | 62 / 62 | 1,772,391 / 1,167,253 | 34.1% | 18,349 / 23,199 / 26,056 |
| juice-shop | 134 / 134 | 4,477,654 / 2,879,367 | 35.7% | 18,498 / 42,588 / 61,735 |
| nodejs-goof | 29 / 29 | 878,218 / 541,510 | 38.3% | 19,743 / 30,404 / 33,016 |
| python-insecure-app | 2 / 2 | 38,450 / 26,933 | 30.0% | 13,466 / 16,347 / 16,347 |
| vuln-demo-app | 15 / 15 | 435,097 / 293,650 | 32.5% | 20,125 / 23,447 / 23,447 |
| vulnerable-flask-app | 30 / 30 | 518,039 / 383,617 | 25.9% | 10,809 / 18,266 / 20,459 |
| vulnerable-typescript-app | 19 / 19 | 355,120 / 267,639 | 24.6% | 12,072 / 22,557 / 22,557 |
| vulnpy | 3260 / 3260 | 102,469,839 / 58,266,085 | 43.1% | 16,876 / 26,935 / 31,239 |

## Request bytes by family

| Family | Requests before / after | Total reduction | After median / p95 / max |
|---|---:|---:|---:|
| command_execution_candidate | 93 / 93 | 40.1% | 23,242 / 27,077 / 27,358 |
| input_validation_candidate | 3241 / 3241 | 41.4% | 16,407 / 19,221 / 23,510 |
| log_sink_candidate | 7 / 7 | 37.4% | 13,709 / 20,867 / 20,867 |
| nosql_query_candidate | 17 / 17 | 20.7% | 42,123 / 61,735 / 61,735 |
| path_traversal_candidate | 458 / 458 | 40.6% | 24,809 / 29,881 / 43,618 |
| sql_query_candidate | 167 / 167 | 41.8% | 21,753 / 24,696 / 41,775 |
| ssrf_candidate | 13 / 13 | 31.3% | 18,231 / 27,993 / 27,993 |
| xss_candidate | 290 / 290 | 33.3% | 16,965 / 22,561 / 33,967 |

## Per-section bytes by family

Each cell is aggregate before → after across sample and parser-fixture previews. The local
digest TSV retains every per-app, per-candidate section measurement. A missing section is zero.

| Family | Components | Evidence rows | Source excerpts | Model facts | Invocation |
|---|---:|---:|---:|---:|---:|
| command_execution_candidate | 178,358 → 15,989 | 877,621 → 157,735 | 344,129 → 150,224 | 78,043 → 12,664 | 181,100 → 175,534 |
| input_validation_candidate | 3,191,594 → 466,648 | 26,085,733 → 4,686,689 | 19,486,477 → 10,341,093 | 0 → 0 | 7,153,779 → 6,852,693 |
| log_sink_candidate | 0 → 997 | 24,061 → 4,444 | 15,994 → 9,112 | 0 → 0 | 19,003 → 11,305 |
| nosql_query_candidate | 28,392 → 3,153 | 99,430 → 52,689 | 181,813 → 145,932 | 35,818 → 35,818 | 35,184 → 31,625 |
| path_traversal_candidate | 923,590 → 72,682 | 4,180,734 → 791,641 | 2,095,798 → 1,076,410 | 456,478 → 96,365 | 886,188 → 819,050 |
| sql_query_candidate | 243,836 → 25,581 | 1,693,799 → 310,135 | 812,140 → 440,647 | 20,294 → 20,294 | 369,166 → 360,142 |
| ssrf_candidate | 23,937 → 2,093 | 53,211 → 9,446 | 23,885 → 11,912 | 9,517 → 1,249 | 23,960 → 20,484 |
| xss_candidate | 453,865 → 52,540 | 1,255,036 → 227,270 | 641,649 → 269,450 | 20,575 → 20,575 | 501,045 → 451,431 |

The duplicate evidence-role ledger and derived trace graph are absent from the compact
wire. Their obligations and path witnesses remain in evidence_coverage and the retained
dependencies/control_edges respectively. Compact schema tables account separately for
shared gap descriptions and source file names.

## Baselines and deltas

- Before implementation, all 360 historical exact replay decisions passed across 11 saved bundles. Baseline HEAD was `137badf`, with only design documentation since `913e045`.
- Saved responses contain no evidence citations: 598 raw responses and 134 Juice Shop rebuild traces had no eN/sN references. Citation acceptance is uncheckable; it was not counted as passing.
- The 32 KiB retention proxy checked 3,874 uses and 4,271 forced omissions without shedding required, gate, control, dependency, control-edge or indexed fact evidence.
- Offline digest inventories contain 4,405 candidates before and 4,405 after. 125 identities were replaced, with matching app/family counts; wrapper dispatch and explicit middleware modeling change invocation provenance. No net discovery-count expansion is claimed.
- Predecessor request hashes were re-recorded for evidence v7, family protocol upgrades, selected-only obligations, catalog logging, compact columns, fact references and prose changes. Report hashes also change with catalog provenance and removed duplicate explanatory facts.
- A final audit after the last conservative dispatch guards reproduced every one of the 4,405 request digests exactly. Route-registration normalization also drops its excerpt columns when replacing route coordinates, preserving equivalent-context reuse without altering requests.
- Dependency/control-edge fidelity tests retain transfer order, sink slot, storage key and edge kinds across family fixtures. Same-line evidence nodes retain character columns in condensed excerpts.

## Paid validation

The 440-request gpt-6-luna authorization charged **434** requests: 406 in the final
eight-app rebuild, seven focused/recheck/path requests, 20 preserved interrupted
exchanges, and one conservative allowance for a possibly unsaved in-flight call.
There were no provider or decoder failures in the completed final runs. All targets
remained clean at their documented pins. No provider/model fallback was used.

| App | Fresh requests | Input tokens |
|---|---:|---:|
| ThreatByte | 52 | 252,519 |
| juice-shop | 134 | 709,889 |
| nodejs-goof | 18 | 96,588 |
| python-insecure-app | 1 | 4,029 |
| vuln-demo-app | 12 | 62,120 |
| vulnerable-flask-app | 13 | 49,487 |
| vulnerable-typescript-app | 6 | 26,044 |
| vulnpy | 170 | 1,004,048 |

Total final-run input: **2,204,724 tokens**. Raw usage records report 0 cache-read
tokens and 1,759,858 cache-write tokens. Static ordering is retained, but these runs
demonstrate no cache-read saving; outer JSON key ordering is not treated as caching evidence.

All **406 final saved decisions replayed exactly** against freshly parsed current
evidence, preserving answers and finding statuses. The original 360 historical path
decisions were proved before the bump; they remain historical and were not relabeled
as v7 responses. Re-recording the full 260-context VulnPy path corpus remains outside
this bounded rebuild. One additional paid VulnPy BZ2File path witness was confirmed.

Critical witnesses:

- Goof `routes/index.js:270`: fresh archive-entry traversal/none-containment answers
  pass the unchanged inconsistency gate and confirm the Zip Slip claim.
- Juice Shop `routes/profileImageUrlUpload.ts:24`: the transparent wrapper resolves;
  the preceding multipart upload factory remains unresolved, so the result stays Review.
- Juice Shop `routes/order.ts:164`: 61,735 bytes with **zero evidence omissions**;
  middleware/control blockers remain, and inconsistent or incomplete protection answers
  do not become a protected result.
- sql.js SQL injection, command injection and credential logging remain confirmed in
  the focused standard-app checks. Protected and inconclusive controls remain explicit.

Fresh model choices are not identical to historical choices. The reports retain those
differences, including new Review outcomes on some previously protected records and
separate construction-practice findings on 15 VulnPy SQL contexts. This is a bounded
regression/evidence check, not an accuracy or ablation claim. No lossy relevance filter
or path slice was adopted.

## Verification checks

- `go test -race ./... -count=1`: all packages passed; parser completed in 489.205 s.
- Final affected-package race checks cover persisted trace round-trip and the final
  conservative dispatch guards; the complete judge package was rerun after replay correction.
- `go vet ./...`, changed-source formatting, `git diff --check` and repository doc checks.
- Seven public sample JSON/HTML/SARIF sets regenerated; metadata/outcome counts agree,
  public roots are normalized and no developer home path is published.
- Independent read-only QA findings resolved: asynchronous/recursive/stale wrappers,
  header/binding summary fidelity, same-line evidence locations, selected obligations,
  and serialized-provenance equality.

## Follow-ups

JavaScript if modeling follows E3 validation in this same worktree/branch. Helper/model relevance filtering requires paired ablation and a new contract after remeasurement. Data-path slicing follows precise branch modeling. None of those lossy changes is enabled by v7.

## Relevance-pressure checkpoint before S4

Among 3,551 assessed-family sample previews, only Juice Shop `routes/order.ts:164`
(61,735 bytes) exceeds 55,000 bytes, 90% of the 65,536-byte limit (58,982.4), or
60,000 bytes. None exceeds the hard limit. Broad lossy filtering is not justified
by the current size distribution alone. Re-measure after S4 and obtain the required
paired ablation evidence before adopting a relevance filter.

These numbers describe the verified core-v7 baseline, not the unverified local S4
prototype. The owner deferred all further paid calibration until the next session.

## S4 and broader W6

E3 continuation, 2026-11-15. Scanner commits `fcd3b0e` (S4 + W6) and `dec3b30` (else-if guard
links). Contracts: [JavaScript conditional flow](../specifications/scan/javascript-if-flow.md),
[relevance tier](../specifications/scan/evidence-relevance-tier.md),
[data-path slicing](../specifications/scan/data-path-slicing.md).

### Offline request deltas (core v7 audit → final)

- **Candidates:** 4,405 before and after; every location keeps its candidate count; no Python
  request changed.
- **Assessed sample requests that changed:**

  | App | Validation | Log | NoSQL | Path | SQL | SSRF | XSS | Command |
  |---|---:|---:|---:|---:|---:|---:|---:|---:|
  | Juice Shop | 72 | 2 | 14 | 12 | 3 | 1 | 4 | – |
  | Goof | 3 | – | 3 | 1 | – | – | 10 | 1 |
  | demo | 1 | – | – | – | 5 | – | 4 | – |
  | TypeScript app | 3 | 1 | – | – | – | – | 1 | – |

  Observation-only records (grouped outbound, `xss_data`) changed candidate ID only.
- **Removed:** generic `unsupported_control_flow` and `branch_exit` gaps at modeled `if`
  statements (161 and 111 in Juice Shop), and the duplicated context and gaps of the old
  shared-flow fallback.
- **Added:** arm preconditions; honest `unsupported_write` and metadata-ambiguity gaps; W6
  fact codes with their notes.
- **Sizes:** Juice Shop request bytes −1.1%. `order.ts:164` 61,735 → 59,057, still the only
  sample request above 55,000 bytes; none above the limit.
- **Broader W6:** byte-neutral on affected requests.
- **Frozen expectations re-recorded with reasons:** string-flow goldens (W6);
  command-predecessor and SQL baselines for GraphQL/gRPC (gap removal, `conditional_false_test`,
  scope code); outbound predecessor SQL/NoSQL (W6).

### Independent QA

A read-only reviewer confirmed three defects, each fixed with regressions:

1. GraphQL/gRPC promotion lost the polarity of a false precondition.
2. The NoSQL `typeof` witness ignored polarity.
3. The `branches` fallback carried arm preconditions out of loop/try bodies.

The handler limits it noted (`switch` cases, labeled statements, brace-less loops) are recorded
and handed to E4.

### Paid evidence (new ledger `_test-findings/e3-s4`, owner cap 400 `gpt-6-luna`, no fallback)

**Calibration.** The fixture is reproduced in the S4 contract's acceptance. 16 answers; 2 SQL
records failed before a model call because `require`-destructured Sequelize has no verified
binding. 12 of 14 declared expectations met:

- Protected: finite command allowlist (shell syntax 0.41/0.41, coverage complete 0.65), NoSQL
  `typeof` rejection, path finite allowlist, SSRF scheme+host allowlist.
- Confirmed: every presence-only, non-exiting, sibling-arm and raw case.

Misses:

- **TypeScript else-if allowlist** confirmed: the guard engine credited only the first link.
  Fixed in `dec3b30`; no sample request changed.
- **Strict-arm guarded `exec`** beside an unguarded sibling `exec`: judged vulnerable (0.67)
  although the facts show a terminating guard. This is model judgment in the conservative
  direction; gates are unchanged.

**JavaScript sample rebuild.** Juice Shop 134, Goof 18, TypeScript app 6, demo 12: 170
requests, no provider/decoder failures, targets clean at pins. Changes versus core v7:

| Record | Core v7 → now | Reason |
|---|---|---|
| Juice Shop `likeProductReviews.ts:25/35/43` NoSQL | Review → confirmed | S4 removed the generic `unknown_control_effect` blocker; the model's vulnerable answer is unchanged |
| Juice Shop `orderHistory.ts:36` NoSQL | confirmed → Review | Borderline `source_coverage` (yes 0.48 → unknown 0.51) |
| Goof `routes/index.js:204` `Todo.findById(req.params.id)` | Review → protected | Source-correct: Express path parameters are strings |
| Goof `views/edit.ejs:20` XSS | protected → Review | Per-path answer unknown (0.36) |
| TypeScript app `server.ts:74` logging | confirmed → Review | `data_class` unknown (0.46) |

**Charged total:** 188 of 400 (18 calibration + 170 rebuild).

**Exact replay:** 406 of 406 at the final HEAD — 170 fresh JavaScript decisions, plus 236 core
Python decisions whose requests are byte-unchanged.

**Published samples:** Juice Shop, Goof and the TypeScript app are republished from these runs.
The Python samples keep their core v7 judgments; re-rendering them produced identical bytes.

**Not done:** the full v7 re-recording of 260 historical VulnPy path contexts needs its own cap.
The E4 all-app rebuild subsumes it.
