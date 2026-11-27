# OWASP Juice Shop sample

[All samples](../README.md) · [HTML](https://zazzcode.github.io/zazzles/juice-shop/findings.html) · [JSON](findings.json) ·
[SARIF](findings.sarif) · [Provenance](metadata.json) ·
[Results](../../../.zazz/evaluation/juiceshop-hardening-results.md#final-full-run) ·
[Scanner comparison](../../scan/scanner-comparison.md#owasp-juice-shop)

## Current report (2026-11-27, Google Gemini)

A full scan of revision `f189f52` with scanner `81d4731` (`stage` through PR #56) and Google
Gemini `gemini-decision-1` produced 305 records across 194 entries. The report presents
**49 Confirmed, 1 practice finding, 6 Protected and 249 Review**. These are static source
judgments, not runtime exploit confirmation. [Run record](../../../.zazz/evaluation/gemini-sample-runs-20261127.md#owasp-juice-shop)

- **Answer key:** 36 of the 41 positives of Code Scan's own key are found: 35 Confirmed and the
  `b2bOrder` code execution (`JS-CODE-02`) as a practice finding. Sensitive logging (`JS-LOG-01`)
  and the profile-image SSRF (`JS-SSRF-01`), practice findings in the previous report, are now
  Confirmed. Five rows stay in Review: the `/support/logs` directory listing (`JS-CONF-03`,
  `server.ts:302`, weakness left unknown) and the four mass-assignment rows of the generated
  `server.ts:529` routes (`JS-MASS-02` to `05`). Of the comparison's extended 75-row key this
  report finds 40 ([scanner comparison](../../scan/scanner-comparison.md#owasp-juice-shop)).
- **False positives:** three locations. The `.well-known` listing (`server.ts:294`) is still
  Confirmed. The null-byte file read (`routes/fileServer.ts:32`) is now a Confirmed path
  traversal, although the owner's decision of 2026-11-24 is that it cannot leave its directory.
  The Swagger UI at `server.ts:307` is reported as information exposure; it serves the published
  B2B API description. Liking another user's review (`routes/likeProductReviews.ts:35`, `:50`) is
  no longer a finding, and the `orderHistory.ts:36` NoSQL record is in Review.
- **Not covered:** the committed signing key (`lib/insecurity.ts:21`). No analyzer covers secrets.
- **Usage:** 84 completed assessments, 406,475 input tokens, zero failures. 221 records were not
  sent to the model; they stay in Review or carry a model-free result.

The report is the canonical JSON the scanner wrote to standard output in that run, with the root
replaced by the public sample label.

## Previous report (2026-11-24, gpt-6-luna)

A full scan of revision `f189f52` with scanner `3318e27` (PR #50) and OpenAI `gpt-6-luna` produced
305 records across 194 entries. The report presents **51 Confirmed, 3 practice findings,
3 Protected and 248 Review**. These are static source judgments, not runtime exploit confirmation.

- **Answer key:** all 41 positives of Code Scan's own key are found. The comparison's extended
  Juice Shop key has 75 rows, of which this report finds 45
  ([what it misses](../../scan/scanner-comparison.md#what-code-scan-misses)). 38 are Confirmed and 3 are practice findings:
  sensitive logging (`JS-LOG-01`), the profile-image SSRF (`JS-SSRF-01`) and the `b2bOrder` code
  execution (`JS-CODE-02`).
- **False positives:** four locations in the
  [source review](../../../.zazz/evaluation/scanner-false-positives.json) of 2026-11-25: liking
  another user's review (`routes/likeProductReviews.ts:35` and `:50`), the `.well-known` listing
  (`server.ts:294`), and a NoSQL finding whose value is always a string (`routes/orderHistory.ts:36`).
- **New since the previous report:** insecure configuration, information exposure, weak password
  hashing, account enumeration, mass assignment, missing authorization, and path, code and SSRF
  cases that were in Review or had no record.
- **Not covered:** the committed signing key (`lib/insecurity.ts:21`). No analyzer covers secrets.
- **Usage:** 84 requests, 381,728 input tokens, zero failures. 221 records were not sent to the
  model; they stay in Review or carry a model-free result.

The report is the canonical JSON the scanner wrote to standard output in that run, with the root
replaced by the public sample label. Later fixes on PR #50 left the offline Juice Shop report
byte-identical, so its requests are unchanged.

## Previous report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 175 entries, 251 analysis records: **23 Confirmed, 227 Review, 0 Protected, 1 practice**.
- 28 requests, 28 completed assessments, 211,937 input tokens. No provider failures. 34 records are not sent because their scanner blocker has no question the model could answer.
- **Answer key:** 15 of 15 expected positives found; no keyed control is a finding.
- New Confirmed records outside the key match known challenge routes (`$where` NoSQL in `trackOrder.ts` and `showProductReviews.ts`, review update/like routes, the `redirect.ts` allowlist, the `dataErasure.ts` layout). They are not source-reviewed here.

## Previous report (rebuilt 2026-11-15)

[HTML](https://zazzcode.github.io/zazzles/juice-shop/findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

All analyzers were run at pinned revision `f189f521266f` with OpenAI `gpt-6-luna`. Express middleware
stages, URL and upload inputs, and Node `http`/`https` SSRF are included. The target remained clean.
These are static source judgments.

- **Records:** 246. **Judged:** 153, in 153 requests (758,312 input tokens).
- **Outcomes among judged records:** 22 confirmed vulnerabilities, 1 poor practice, 0 protected, 0 not applicable, 130 inconclusive (Review).
- **Unassessed records shown:** 93; provider/decoder failures: 0.
- **Notable:** middleware-chain and URL/upload acquisition expand validation and XSS coverage (for example dataErasure). Multipart `uploadToMemory.single('file')` remains unresolved. The large NoSQL request at `order.ts:164` is still assessed with shared input facts.

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

## Command-injection acceptance scan (2026-11-07)

The report linked above is now a full source-transmitting scan with OpenAI Decisions `gpt-6-luna` at scanner
revision `6f5cb711fe06…` (no family filter; the target stayed clean at pin `f189f521266f…`). It has 167 entries
and 208 records: 10 Findings, 198 Review and 0 Protected, from
117 provider requests (926,572 input tokens). No direct command-injection positive is expected or reported: the source-reviewed boundaries (profile SSTI, b2bOrder `vm`/notevil RCE, the build-time `npm root -g` constant) produced no command record, and they are not reported as Protected ([review](../../../.zazz/evaluation/juice-shop/command-injection-review.md)).
Observation-only and unsupported records remain visible and unassessed; no application is declared safe and no
runtime exploitation is claimed. See the [acceptance results](../../../.zazz/evaluation/command-injection-results.md)
and [metadata](metadata.json). Earlier sections below describe previous published snapshots and are superseded by the counts here.

## Previous published snapshot

[All samples](../README.md) · [HTML](https://zazzcode.github.io/zazzles/juice-shop/findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) ·
[Source-reviewed reference](xss-answer-key.md) · [Provenance](metadata.json)

Refreshed 2026-11-01 from the [upstream application](https://github.com/juice-shop/juice-shop), revision
`f189f521266f42c6bd05884468292000cee852ed`, using the `xss-response` working sources and binary identified in metadata.
The original checkout remains unchanged. Remediation exercises use an independent copy.

The current report contains 152 server/API entries, 9 browser/client entries, and 197 use records: 7 Findings and 190 Review records. One XSS construction finding is the browser query → Angular trust bypass → search template flow. Other client/API-origin and collection/dialog links remain Review. No Protected records are asserted by this extraction snapshot.

All implemented analyzer families remain visible; this is not an XSS-only route filter. HTML has
separate Server/API and Browser/client-side sections and a Hide protected results control. The
filter changes presentation only; JSON/SARIF retain all evidence. Counts are per use, categories
overlap, and no-findings does not mean an application is safe.

This refresh is offline. Historical model judgments were not carried onto changed evidence/rules;
their earlier versions remain in Git history. No live model calls were made for this target in this
session. Source-reviewed expected properties are in the reference above, not inferred from finding
counts or comments. See the [static baseline/copy policy](../reference-policy.md).

Upstream source excerpts are attributed under the [included license](UPSTREAM-LICENSE.txt).
