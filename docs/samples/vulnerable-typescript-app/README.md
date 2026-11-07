# Vulnerable TypeScript app sample

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

Upstream source excerpts are attributed under the [included license](UPSTREAM-LICENSE.txt).
