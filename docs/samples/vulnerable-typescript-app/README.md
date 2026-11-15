# Vulnerable TypeScript app sample



## Current report (rebuilt 2026-11-14)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Every analyzer was run on the pinned revision `7f8b240a2f02` with OpenAI `gpt-6-luna`, using the scanner from the analyzer-engine-hardening branch. The target stayed clean. Static source judgments only; nothing was run or exploited.

- **Records:** 24. **Judged:** 18, in 18 requests (82,948 input tokens).
- **Outcomes:** 4 confirmed vulnerabilities, 0 poor practice, 0 protected, 14 inconclusive (Review).
- **Command injection:** `GET /api/ping` at `src/server.ts:90` is a **confirmed vulnerability**.
- **Path traversal:** `GET /api/files` at `src/server.ts:104` is a **confirmed vulnerability**.
- **Not assessed by design (6):** one outbound HTTP observation and five API-data records with no rendering claim.

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

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) ·
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
