# OSS OopsSec Store sample

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) ·
[SARIF](findings.sarif) · [Provenance](metadata.json) ·
[Detection guide](../../../.zazz/evaluation/oss-oopssec-store-detection-guide.md)

## Current report (published 2026-11-16)

Fresh full static analysis of [kOaDT/oss-oopssec-store](https://github.com/kOaDT/oss-oopssec-store)
at `2d530ef3c0e668022c93fd2c03b52eef4691a6c3` (v2.25.0), a Next.js 15 App Router app
with Prisma, better-sqlite3, pino and zod. The reference checkout stayed clean during evaluation.

- 129 entries, 116 analysis records: **15 Confirmed, 101 Review, 0 Protected**.
  HTML displays 99 Review rows because two outbound observations are grouped into related records;
  canonical JSON retains all 116 records.
- 107 completed OpenAI `gpt-6-luna` assessments: 15 Confirmed and 92 inconclusive.
  All implemented analyzers were included, including standalone input validation (466,404 input tokens).
- 9 observation-only outbound records remain unassessed. No provider failures. 29 separate practice observations.

Every required positive in the supported answer key is Confirmed: four SQL cases (including both
better-sqlite3 operations), file reads/listing, screenshot SSRF, password and gift-card recipient-email
logging, and four client XSS cases. Counts are per operation, so 13 required answer-key cases yield
15 Confirmed records. The gift-card logging case is the owner-added `OOPS-LOG-02`.

The fresh run `run-2413679240` used 107 paid requests and replayed 107/107 exactly. Publication only
replaces the JSON root with the public sample label and exports HTML/SARIF offline. No target execution.
Metadata records the original JSON hash and assessment usage.

## Limits and controls

MCP destination flow, analytics stored XSS, guarded upload/file paths, the database-backed markdown
path and the unlinked server HTML output remain Review. Constant HTML, React-encoded input,
react-markdown defaults and the fixed-prefix iframe produce no XSS record. Practice observations
are model-free and separate from vulnerability findings.

XXE, authentication/authorization, cryptography, CSRF, races, prompt injection and dependency
vulnerabilities are outside the implemented analyzers. Raw-SQL-to-Prisma stored links, broader
React context/props and the remaining Next.js practice checks are deferred. These source judgments
do not establish runtime exploitation or exhaustive coverage. See the
[Next.js support limits](../../nextjs-support.md) and [reference policy](../reference-policy.md).

Source excerpts belong to the upstream authors. The upstream MIT license is preserved in
[UPSTREAM-LICENSE.txt](UPSTREAM-LICENSE.txt).
