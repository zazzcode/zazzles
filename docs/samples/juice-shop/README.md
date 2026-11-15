# OWASP Juice Shop sample



## Current report (rebuilt 2026-11-15)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

All analyzers were run at pinned revision `f189f521266f` with OpenAI `gpt-6-luna`, evidence wire v7, precise JavaScript conditional flow and guidance-owned fact codes on the analyzer-assessment-coverage branch. The target remained clean. These are static source judgments.

- **Records:** 222. **Judged:** 134, in 134 requests (698,288 input tokens).
- **Outcomes among judged records:** 21 confirmed vulnerabilities, 1 poor practice, 0 protected, 0 not applicable, 112 inconclusive (Review).
- **Unassessed records shown:** 88; provider/decoder failures: 0.
- **Wrapped SSRF:** transparent async forwarding resolves at `utils.asyncHandler`; the remaining multipart upload factory is unresolved, so `routes/profileImageUrlUpload.ts:24` remains Review. The largest NoSQL request, `order.ts:164`, fits without shedding evidence and retains its claim blockers. Precise conditional modeling removed the generic branch blocker from the `likeProductReviews.ts` NoSQL records, which are now confirmed; `orderHistory.ts:36` is Review on a borderline source-coverage answer.

[Wire v7 verification and limits](../../../.zazz/evaluation/wire-bundle-v7-results.md).

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

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) ·
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
