# Vulnerable TypeScript app sample



## Current report (rebuilt 2026-11-21)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the prototype pollution scanner
(`6006eaa`, [results](../../../.zazz/evaluation/pollution-write-shapes-results.md#ac8-live-judgment)). The reference checkout stayed clean. These are static source judgments, not
runtime exploit confirmation.

- 19 entries, 27 analysis records: **8 Confirmed, 19 Review, 0 Protected**.
- 8 requests, 8 completed assessments, 30,454 input tokens. No provider failures. All 8 saved
  traces replay with the same request digest and outcome.
- **Answer key:** 7 of 7 expected positives found; no keyed control is a finding.
- New: the Lodash 4.17.4 merge at `src/server.ts:246` is Confirmed prototype pollution
  (CWE-1321). The seven other outcomes match the previous report.

## Previous report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`df540c3`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 19 entries, 26 analysis records: **7 Confirmed, 19 Review, 0 Protected**.
- 7 requests, 7 completed assessments, 29,898 input tokens. No provider failures. 1 records are not sent because their scanner blocker has no question the model could answer.
- **Answer key:** 6 of 6 expected positives found; no keyed control is a finding.
- All six keyed positives are Confirmed, including `eval` at `src/server.ts:137` and the open redirect at `src/server.ts:239`, which the previous report could not score.

## Previous report (rebuilt 2026-11-15)

[HTML](https://zazzcode.github.io/zazzles/vulnerable-typescript-app/findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

All analyzers were run at pinned revision `7f8b240a2f02` with OpenAI `gpt-6-luna`, including
standalone input validation and Node `http`/`https` SSRF where those sinks exist. The target remained
clean. These are static source judgments.

- **Records:** 24. **Judged:** 19, in 19 requests (61,777 input tokens).
- **Outcomes among judged records:** 5 confirmed vulnerabilities, 0 poor practice, 0 protected, 0 not applicable, 14 inconclusive (Review).
- **Unassessed records shown:** 5; provider/decoder failures: 0.

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

## Command-injection acceptance scan (2026-11-07)

The report linked above is now a full source-transmitting scan with OpenAI Decisions `gpt-6-luna` at scanner
revision `6f5cb711fe06…` (no family filter; the target stayed clean at pin `7f8b240a2f02…`). It has 19 entries
and 21 records: 3 Findings, 18 Review and 0 Protected, from
16 provider requests (65,808 input tokens). **Command injection:** `GET /api/ping` → `src/server.ts:90` `exec(`ping -c 3 ${host}`)` is a completed, gated `confirmed_vulnerability` (shell syntax, CWE-78; the documented TS-CMDI-01).
Observation-only and unsupported records remain visible and unassessed; no application is declared safe and no
runtime exploitation is claimed. See the [acceptance results](../../../.zazz/evaluation/command-injection-results.md)
and [metadata](metadata.json). Earlier sections below describe previous published snapshots and are superseded by the counts here.

## Previous published snapshot

[All samples](../README.md) · [HTML](https://zazzcode.github.io/zazzles/vulnerable-typescript-app/findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) ·
[Expected vulnerabilities and file/line locations](../../../.zazz/evaluation/vulnerable-typescript-app-detection-guide.md) · [XSS/source controls](xss-answer-key.md) · [Provenance](metadata.json)

Refreshed 2026-11-01 from the [upstream application](https://github.com/ryanmcmorrowsnyk/vulnerable-typescript-app), revision
`7f8b240a2f02beba099da3632d1ba679ff8bc32f`, using the `xss-response` working sources and binary identified in metadata.
The original checkout remains unchanged. Remediation exercises use an independent copy.

The current report contains 19 route entries and 19 uses: one reflected-XSS Finding at GET /api/search (src/server.ts:117) and 18 Review records. There are no identified browser entries or Protected records in this snapshot.

All implemented analyzer families remain visible; this is not an XSS-only route filter. HTML has
separate Server/API and Browser/client-side sections and a Hide protected results control. The
filter changes presentation only; JSON/SARIF retain all evidence. Counts are per use, categories
overlap, and no-findings does not mean an application is safe.

This refresh is offline. Historical model judgments were not carried onto changed evidence/rules;
their earlier versions remain in Git history. No live model calls were made for this target in this
session. Source-reviewed expected properties are in the reference above, not inferred from finding
counts or comments. See the [static baseline/copy policy](../reference-policy.md).

Upstream source excerpts belong to the upstream authors; the upstream repository ships no license file, so none is included here.
