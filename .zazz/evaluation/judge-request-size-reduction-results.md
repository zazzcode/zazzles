# Judge request size reduction — results

Contract: [judge request size reduction](../specifications/judge-request-size-reduction.md). Branch
`judge-request-size-reduction`. The baseline scanner is `9f65f5a`, which is `stage` `8dd0460` with the
inventory test added. The candidate is `695ce11` (W13–W16, `evidence_version` 8,
`xss-components-v4`). Samples: DVWA `a1978a2` and Juice Shop `f189f52`. Both had an empty
`git status --porcelain --ignored` before and after every scan. All artifacts are under the
container's `_test-findings/judge-request-size-reduction/`.

**Status: offline criteria AC1–AC7 pass; AC8 fails** (§6 halt, see [AC8](#ac8-paired-live-comparison)).

## Inventories (D-1)

`TestRequestInventory` writes one TSV row per planned request (`base-<app>.tsv` at the baseline
scanner, `cand-<app>.tsv` at the candidate). The baseline reproduces the §1 table exactly, with one
exception. Juice Shop identifier bytes come to 90,542, not 79,883, because every `instance_id` value
counts, following the D-2 definition. AC1–AC3 below are recomputed from the TSVs by `ac123.py`.

| Measure | DVWA before | DVWA after | Juice Shop before | Juice Shop after |
|---|---:|---:|---:|---:|
| Planned requests | 263 | 248 | 157 | 157 |
| Records over the limit before grouping | 8 | 1 | 0 | 0 |
| Path-group requests | 24 | 2 | 0 | 0 |
| Total request bytes | 9,388,206 | 7,529,573 | 3,193,060 | 3,017,436 |
| Median / p95 / largest | 29,760 / 62,006 / 64,805 | 27,215 / 49,098 / 63,066 | 16,613 / 41,307 / 57,915 | 15,896 / 39,893 / 56,799 |
| Requests over 58,982 bytes | 25 | 7 | 0 | 0 |
| Source excerpt text | 2,130,488 | 1,909,369 | 509,181 | 509,181 |
| Identifier bytes | 836,413 | 0 | 90,542 | 0 |
| Question bytes | 1,458,384 | 1,188,942 | 657,153 | 605,353 |
| Size-notice bytes | 33,761 | 1,592 | 0 | 0 |
| Lossy omitted source bytes | 5,874 | 2,333 | 0 | 0 |
| Equivalence classes | 244 | 244 | 157 | 157 |

The DVWA source excerpt total falls only because fewer group requests repeat the same excerpts.
No excerpt was removed from any request.

By workstream, DVWA total bytes fell as follows. After A the total was 8,013,303, and grouping fell
from 24 to 12 requests. After B it was 7,703,997, with one record left over the limit. After C it
was 7,699,773. After D it was 7,529,573.

## AC1 — total size

| Sample | Before | After | Ratio | Bound | Result |
|---|---:|---:|---:|---:|---|
| DVWA | 9,388,206 | 7,529,573 | 80.2% | 90% | Pass |
| Juice Shop | 3,193,060 | 3,017,436 | 94.5% | 97% | Pass |

## AC2 — whole-record size

The table joins records on record ID: 247 for DVWA and 157 for Juice Shop, with no ID mismatch.
No record is larger before budgeting. The smallest saving is 763 bytes on DVWA and 653 bytes on
Juice Shop.

| DVWA record over the limit at baseline (all `xss` at `dvwa/includes/dvwaPage.inc.php:388`) | Before | After | Saved |
|---|---:|---:|---:|
| entry `vulnerabilities/sqli/index.php` | 82,020 | 69,643 | 12,377 |
| entry `vulnerabilities/xss_s/index.php` | 80,794 | 63,066 | 17,728 |
| entry `vulnerabilities/xss_s/index.php` | 78,962 | 62,496 | 16,466 |
| entry `vulnerabilities/xss_s/index.php` | 78,148 | 62,418 | 15,730 |
| entry `vulnerabilities/xss_s/index.php` | 77,129 | 62,173 | 14,956 |
| entry `vulnerabilities/sqli/index.php` | 73,711 | 62,021 | 11,690 |
| entry `vulnerabilities/bac/index.php` | 72,432 | 60,371 | 12,061 |
| entry `vulnerabilities/bac/index.php` | 66,384 | 55,622 | 10,762 |

All eight are at least 8,000 bytes smaller. Seven are now judged whole. The `sqli` record is the
exception: it still needs two group requests, down from five.

## AC3 — shedding and grouping

- DVWA has no `evidence_too_large` and no `path_group_cap`. Group requests fell from 24 to 2, and
  no record plans more groups than at baseline. `TestDVWARequestSizes` passes: one record over the
  limit, grouped into requests of 62,477 and 55,101 bytes.
- Lossy omitted source bytes fell from 5,874 to 2,333, and omitted items from 86 to 40.
- No request drops its resolution questions, on either side.
- One request still sheds context: the first `sqli` group (62,477 bytes). It is smaller than that
  record's largest baseline request (64,805), and its lossy omitted bytes fell.
- Equivalence classes are unchanged: 244 on DVWA and 157 on Juice Shop. No pair merged or split.

## AC4 and AC5 — projection tests

`go test ./internal/judge -run '^TestWireIdentity'` passes all seven tests. The fixture sweep
checks 502 requests and finds no 64-hex run outside source excerpt and evidence text.

`TestWireStructureRoundTrip` passes: 502 fixture requests round-trip, and 10 of them state shared
tails. `TestWireStructureRowsPutTextLast`, `TestWireStructureSharedTails`,
`TestWireStructureCitationsReadExpandedChains`, `TestSizeNotices` and `TestXSSChoiceLabels` pass.
`TestWireV8RejectsVersion7Trace` passes as well: requests carry `evidence_version` 8, and a version
7 request does not replay.

Replaying the saved DVWA run (`_test-findings/dvwa/run-cfg-live`) through `TestReplaySavedRun`
gives 0 replayed and 179 mismatched, as expected.

## AC6 — offline invariance

The eleven unjudged baseline and candidate reports (`base-reports.json`, `cand-reports.json`) are
equal except for one field family. That family is
`uses[].analysis_components.{digest, pack.digest, components[].digest}` on XSS records only: 213
records across the samples, 91 of them on DVWA. These digests hash the XSS component material the
request carries, which is the choice text and the `xss-components-v4` compatibility. The reports
include no request bytes or request digests, because offline runs make no assessment.
`check.py` and `accuracy.py` give byte-identical output for both scanners
(`base-check.txt`/`cand-check.txt`, `base-accuracy.txt`/`cand-accuracy.txt`).

## AC7 — gate

`gofmt -l cmd internal` printed nothing, and `go vet ./...`, `go build ./...` and
`go test -race ./... -count=1` all pass. `TestArchitectureBaseline` passes after its refresh. The
rows that moved were `request_sha256` and `signature_sha256`, which digest the request and the
signed request. `report_sha256` moved on 25 fixtures; across every fixture, the reports differ only
in the XSS component digests above. No ID, kind, count or `sarif_sha256` row changed.

## AC8 — paired live comparison

All four scans ran on 2026-11-20 UTC (2026-11-19 local), back to back. Each used
`--judge openai --judge-model gpt-6-luna` with the default judge limit, `JUDGE_RPM=4500`,
`JUDGE_TPM=1800000` and `--trace-dir`, and only the OpenAI key was passed. Outputs are under
`live/<arm>-<app>/`.

| Arm | Sample | Run | Attempts | Provider input tokens |
|---|---|---|---:|---:|
| B1 | DVWA | `run-2672222759` | 195 | 2,175,448 |
| C | DVWA | `run-3305989315` | 183 | 1,590,248 (−26.9%) |
| B1 | Juice Shop | `run-947949922` | 28 | 211,937 |
| C | Juice Shop | `run-1689055572` | 28 | 196,909 (−7.1%) |

B0 is the saved run whose requests match B1's byte for byte. For DVWA that is
`dvwa/run-cfg-live`, with 173 matching requests. For Juice Shop it is `juice-shop/run-mer-live4`,
with 28.

| Check | DVWA | Juice Shop | Result |
|---|---|---|---|
| Accuracy (positives / found / review / missed / FP), B1 | 11 / 11 / 0 / 0 / 0 | 15 / 15 / 0 / 0 / 0 | — |
| Accuracy, C | 11 / 11 / 0 / 0 / 0 | 15 / 15 / 0 / 0 / 0 | Pass |
| No keyed positive presents lower in C | holds | JS-LOG-01 `server.ts:366`: Confirmed → practice finding | **Fail** |
| No keyed control or protected control is a finding in C | holds | holds | Pass |
| Status changes B0→B1 (identical requests) | 0 / 173 (0.0%) | 0 / 28 (0.0%) | — |
| Status changes B1→C, at most B0→B1 + 2 points | 26 / 186 (14.0%) | 1 / 28 (3.6%) | **Fail** |
| Provider input tokens lower in C | −26.9% | −7.1% | Pass |

Every identical request got the same presented status in B0 and B1, so the noise floor is zero. Changing a
request moves some answers anyway. Every change below had no omissions in either arm. On DVWA, 22
of the 26 changes are XSS records at the shared render sinks `dvwaPage.inc.php:388` and `:496`, and
only their `xss_exposure` answer moved. In 15 it went from unknown to vulnerable, and in 7 from
vulnerable to unknown. The other four DVWA changes are on SQL and command records in `impossible.php`
files, in both directions. The Juice Shop change is a logging record. D changes only XSS requests,
so the non-XSS changes come from A–C. AC8 therefore fails on more than XSS records, which means
the OQ-2 XSS-only rerun does not apply. No further paid call was made.

### Every B1→C difference

#### DVWA

| # | Kind | Sink | Entry file | B1 | C | Answers that changed (B1 → C) | Omissions B1/C |
|---|---|---|---|---|---|---|---|
| 1 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `setup.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 2 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/authbypass/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 3 | sql_query | `vulnerabilities/brute/source/impossible.php:79` | `vulnerabilities/brute/index.php` | Protected | Inconclusive | `injection_protection` protected → vulnerable | 0/0 |
| 4 | sql_query | `vulnerabilities/brute/source/impossible.php:90` | `vulnerabilities/brute/index.php` | Protected | Inconclusive | `injection_protection` protected → unknown | 0/0 |
| 5 | sql_query | `vulnerabilities/brute/source/impossible.php:96` | `vulnerabilities/brute/index.php` | Inconclusive | Protected | `injection_protection` vulnerable → protected; `protection` insufficient → sufficient | 0/0 |
| 6 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/csrf/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 7 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/csrf/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 8 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/exec/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 9 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/exec/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 10 | command_execution | `vulnerabilities/exec/source/impossible.php:26` | `vulnerabilities/exec/source/impossible.php` | Inconclusive | Protected | `protection_coverage` incomplete → complete; `shell_syntax_protection` vulnerable → protected | 0/0 |
| 11 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/fi/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 12 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/javascript/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 13 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/javascript/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 14 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/javascript/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 15 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/javascript/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 16 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/javascript/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 17 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/open_redirect/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 18 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/open_redirect/source/info.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 19 | xss | `dvwa/includes/dvwaPage.inc.php:496` | `vulnerabilities/sqli_blind/cookie-input.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |
| 20 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/sqli_blind/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 21 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/sqli_blind/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 22 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/weak_id/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 23 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/weak_id/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 24 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/weak_id/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 25 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/xss_d/index.php` | practice finding | Confirmed | `xss_exposure` unknown → vulnerable | 0/0 |
| 26 | xss | `dvwa/includes/dvwaPage.inc.php:388` | `vulnerabilities/xss_d/index.php` | Confirmed | practice finding | `xss_exposure` vulnerable → unknown | 0/0 |

#### Juice Shop

| # | Kind | Sink | Entry file | B1 | C | Answers that changed (B1 → C) | Omissions B1/C |
|---|---|---|---|---|---|---|---|
| 1 | log_sink | `server.ts:366` | `server.ts` | Confirmed | practice finding | `log_exposure` vulnerable → unknown | 0/0 |

## Investigation of the AC8 changes (offline, no paid calls)

Scripts and outputs are under `live/`: `reqdiff.py`, `margins.py`, `reqdiff.txt` and `margins.txt`.

**What the model received.** `reqdiff.py` compares the B1 and C request of every record sent as a
single request: 179 on DVWA and 28 on Juice Shop. It first expands C's rows and shared tails back
to the version 7 form and drops identifiers and aliases from both. After that, the requests differ
in only three places, whether or not the record's status changed:
- `evidence_version`
- the instruction's schema sentences
- the XSS choice descriptions

No evidence row, excerpt, dependency, gap, fact or question instruction differs.

**Size actually sent.** On the same records, sent as single requests in both arms:

| Sample | Requests | Bytes | Provider input tokens | Per-request token cut |
|---|---:|---|---|---|
| DVWA | 179 | 6,135,031 → 5,351,005 (−12.8%) | 1,837,058 → 1,495,989 (−18.6%) | median 13.0%, min 7.1%, max 34.1% |
| Juice Shop | 28 | 841,230 → 795,031 (−5.5%) | 211,937 → 196,909 (−7.1%) | median 5.4%, min 3.6%, max 19.7% |

Every request is smaller in C. Tokens fall more than bytes because hex identifiers tokenize
poorly. The DVWA total cut (−26.9%) also includes 12 fewer path-group requests.

**Which answers moved.** The changed answers were close calls in B1. Of the 22 XSS changes, 17
had a B1 `xss_exposure` margin (top probability minus runner-up) of 0.25 or less. A typical pair
was unknown 0.54 against vulnerable 0.43. On records whose status did not change, the median
margin for that question is 0.60. The non-XSS changes had B1 margins between 0.01 and 0.40, and
the Juice Shop log record had 0.19. Because the evidence is the same in both arms, these answers
are sensitive to request wording, not to missing content.

**Source review of the non-XSS changes.** The changes do not all go one way:
- `brute/source/impossible.php:79`, `:90` and `:96` are PDO prepared statements with bound
  parameters, so Protected is correct for all three. B1 got two of the three right (79, 90). C got
  one right (96).
- `exec/source/impossible.php:26` is reached only after the impossible level's octet validation.
  C's Protected is correct and B1's Inconclusive is not.
- JS-LOG-01 (`server.ts:366`) is a keyed positive. B1's Confirmed is correct; C answered unknown.

The 22 XSS changes are at DVWA's shared page renderers, which are outside the answer key. They go
both ways: 15 became Confirmed and 7 dropped to a practice finding.

## Attribution runs (owner-authorized, 2026-11-20 UTC)

The owner authorized attribution runs after the investigation. Two intermediate scanners were
built from this branch: A only (`89bba85`) and A+B (`1e780dc`). Each judged DVWA
(`--judge-limit 200`) and Juice Shop (`--judge-limit 40`) on the AC8 terms, for 427 requests in
all. The runs are `a-dvwa` `run-3829170039`, `ab-dvwa` `run-1591442415`, `a-juice-shop`
`run-2585986664` and `ab-juice-shop` `run-402673210`. C adds nothing to a single request beyond
D, so the step from A+B to C isolates the XSS labels. `attribute.py` → `attribution.txt`.

| Step | DVWA status changes (of 186) | Juice Shop (of 28) | DVWA input tokens after the step |
|---|---|---|---:|
| B1 → A (identity) | 30 (16.1%): 24 xss, 2 sql, 2 command, 1 path, 1 upload | 1 (path) | 1,704,023 (from 2,175,448) |
| A → A+B (structure) | 25 (13.4%): 15 xss, 5 sql, 3 command, 1 path, 1 upload | 2 (log, path) | 1,614,930 |
| A+B → C (XSS labels) | 19 (10.2%), all xss | 0 | 1,590,248 |

Every step moves about the same share of records, in every family it touches. Of the 26 DVWA
B1→C changes, 11 first moved at A, 10 at B and 5 at D. A further 24 records changed at an
intermediate step and returned to their B1 status by C. JS-LOG-01 first moved at B.

Keyed accuracy held at every step, with one exception per intermediate arm:
- **A:** protected control PC-CMD-02 (`exec/source/impossible.php`) presented as a finding. It is
  Inconclusive in B1 and correctly Protected in C.
- **A+B:** JS-LOG-01 presented as a practice finding, as it does in C.

No workstream drives a direction. Any request change, including lossless ones, re-draws the
close-call answers.

**How certain the verdicts are (B1).** Median top-choice probability of the verdict question:

| Family | Answer | Records | Median | Share ≥ 0.70 |
|---|---|---:|---:|---:|
| SQL | vulnerable / protected | 38 / 14 (DVWA) | 0.86 / 0.82 | 89% / 71% |
| Command | vulnerable | 17 (DVWA) | 0.88 | 76% |
| Path | vulnerable | 14 (DVWA), 4 (Juice Shop) | 0.83 / 0.82 | 79% / 100% |
| XSS | vulnerable | 9 (Juice Shop) | 0.85 | 89% |
| XSS | vulnerable / unknown | 59 / 19 (DVWA) | 0.69 / 0.56 | 49% / 0% |
| Logging | vulnerable / unknown | 1 / 1 (Juice Shop) | 0.56 / 0.50 | 0% |

76 of the 78 judged DVWA XSS records are the one shared page renderer
(`dvwaPage.inc.php:388`). It is judged once per entry, and its sources are `$_COOKIE['theme']` and
`$_COOKIE['security']`. Their median P(vulnerable) is 0.60.

**Evidence-quality defects in the low-confidence requests:**
- **SQL, `brute/source/impossible.php`.** The request has the query literal, the
  `bindParam(..., PDO::PARAM_STR)` line and `execute()`, but not the `$db->prepare(` call that
  makes the literal the prepared statement. Its sink binding points at `dvwaDatabaseConnect()`.
  Answers sat near a three-way tie (protected 0.37, vulnerable 0.31, unknown 0.31).
- **XSS, shared renderer.** The record states one output context, `html_text`, for the whole
  `echo`. The cookie values actually land in quoted attributes (`<body class="…">` and
  `data-help-url='…'`). The sink row is the entire ~3 KB template string, and the theme path
  repeats that same row as eight transfers, so the request does not show where in the template
  each value lands.
- **Rules.** The XSS rules and the PHP input material name `$_COOKIE` as a cookie origin but do
  not say how a cookie source bears on exposure. The model splits between vulnerable and unknown.
- **Noise.** The SQL request is 21 mostly one-line fragments rather than the contiguous handler,
  plus about 2.8 KB of unrelated `dvwaPage.inc.php` helper excerpts.

## Open for the owner

The size reduction is real, and the model receives the same evidence it did before. The AC8
failure is close-call answers being re-drawn by any change to the request. The attribution runs
show no workstream with a systematic effect. Two decisions remain:
- AC8: accept it, or revise it so the comparison of close-call answers is judged on keyed rows
  and confidence rather than a zero noise floor.
- Whether to take up the evidence-quality defects above. They are outside this contract.
