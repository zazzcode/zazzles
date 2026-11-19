# vuln-nextjs lab sample

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) ·
[SARIF](findings.sarif) · [Provenance](metadata.json) ·
[Detection guide](../../../.zazz/evaluation/vuln-nextjs-detection-guide.md)

## Current report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 37 entries, 54 analysis records: **12 Confirmed, 35 Review, 7 Protected**.
- 27 requests, 27 completed assessments, 132,645 input tokens. No provider failures.
- **Answer key:** 13 of 13 expected positives found; no keyed control is a finding.
- All 13 lab positives are found, including the code-execution and open-redirect rows the previous report could not score; no safe control is red.

## Previous report (published 2026-11-16)

Fresh full static analysis of the owner-maintained [zazzcode/vuln-nextjs](https://github.com/zazzcode/vuln-nextjs)
lab at revision `ea10efb` (full pin in metadata), using Next.js 13 Pages Router, PGlite, zod
and DOMPurify. The reference checkout stayed clean during this evaluation. The living lab can change; this report describes the pinned revision.

- 36 entries, 50 analysis records: **10 Confirmed, 33 Review, 7 Protected**.
- 42 completed OpenAI `gpt-6-luna` assessments: 10 Confirmed, 7 Protected, 25 inconclusive.
  All implemented analyzers were included, including standalone input validation (177,900 input tokens).
- 8 unassessed API data-transfer observations remain visible; these have no rendering claim to judge. No provider failures. 5 separate practice observations.

All 10 supported required positives are Confirmed: three SQL, one command, one path, one SSRF and
four XSS cases. Of 14 supported safe-control source rows, 6 are Protected, 6 remain Review and 2
React-text outputs produce no record; none is red. The seventh Protected report record is the
parameterized SQL operation in `pages/api/xss/comments.js`, rather than another safe-control row.

The fresh run `run-2372184294` used 42 paid requests and replayed 42/42 exactly. Publication replaces
only the JSON root with the public sample label and exports HTML/SARIF offline. No target execution.
Metadata records the original JSON hash and assessment usage.

## Living expectations and limits

The source of truth is the lab's
[`tests/expected-scanner-findings.json` at the report pin](https://github.com/zazzcode/vuln-nextjs/blob/ea10efb/tests/expected-scanner-findings.json),
generated from `lib/catalog.json`. Re-pin and re-evaluate changed source before publishing new results.
A safe control is scoped to its listed CWE; unrelated issues are separate claims.

The command safe control, zod notes SQL, safe SSRF, DOMPurify outputs and escaped script JSON remain
Review. React-text controls produce no XSS record. Code injection (`JS-001/002`), open redirect
(`REDIR-001`) and dependency/SCA (`SCA-001`) have no implemented analyzer family. The nested
React2Shell App Router target is a separate project. Try/catch flow, child-component props and some
other entry forms remain bounded; see [Next.js support](../../nextjs-support.md).

These are static source judgments, not runtime exploit confirmation or exhaustive recall. Follow the
[reference policy](../reference-policy.md); repair an independent copy, leaving references unchanged.
Source excerpts belong to the upstream authors; the upstream license is preserved in
[UPSTREAM-LICENSE.txt](UPSTREAM-LICENSE.txt).
