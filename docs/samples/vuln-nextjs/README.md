# vuln-nextjs JavaScript and TypeScript lab

[All samples](../README.md) · [Lab source](https://github.com/zazzcode/vuln-nextjs) ·
[Detection guide](../../../.zazz/evaluation/vuln-nextjs-detection-guide.md)

vuln-nextjs is the project’s maintained Next.js sample for JavaScript and TypeScript. The lab
includes the Pages Router application and fixture suites that cover particular weaknesses.
Each published report records the lab revision, scan scope and expected cases so readers can
compare results as the lab grows.

## Published reports

| Scan scope | Lab pin and date | HTML | JSON | SARIF | Provenance and results |
|---|---|---|---|---|---|
| Full Pages Router app | `ea10efb` · 2026-11-19 | [HTML](https://zazzcode.github.io/zazzles/vuln-nextjs/findings.html) | [JSON](findings.json) | [SARIF](findings.sarif) | [Metadata](metadata.json) · [13 of 13 expected findings](#full-application-scan) |
| Prototype pollution fixture export | `8d26f52` · 2026-11-21 | [HTML](https://zazzcode.github.io/zazzles/vuln-nextjs/reports/prototype-pollution/findings.html) | [JSON](reports/prototype-pollution/findings.json) | [SARIF](reports/prototype-pollution/findings.sarif) | [Metadata](reports/prototype-pollution/metadata.json) · [14 of 15 in-scope cases Confirmed](#prototype-pollution-fixture-scan) |

<a id="current-report-rebuilt-2026-11-19"></a>

## Full application scan

The 2026-11-19 full scan at `ea10efb` used OpenAI `gpt-6-luna` with the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 37 entries, 54 analysis records: **12 Confirmed, 35 Review, 7 Protected**.
- 27 requests, 27 completed assessments, 132,645 input tokens. No provider failures.
- All 13 expected in-scope cases were found. Twelve were Confirmed, including the two code
  injection cases and open redirect. The stored XSS case `XSS-002` was a practice finding.
- None of the 16 scored controls produced a finding.

<a id="previous-report-published-2026-11-16"></a>

### Earlier full application scan

The 2026-11-16 scan used the same lab pin, with Next.js 13 Pages Router, PGlite, zod and
DOMPurify. The reference checkout stayed clean during this evaluation.

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

## Prototype pollution fixture scan

The 2026-11-21 judged scan used the lab’s CWE-1321 fixture export at `8d26f52`, OpenAI
`gpt-6-luna` and scanner `6006eaa`. The same scan on 2026-11-20 at `d68fec6` produced a
byte-identical report. The fixtures are TypeScript text files in the lab.
Its export command writes them as one Next.js 13 project with a lockfile that pins Lodash 4.17.4,
`dset` 3.1.3 and `merge-deep` 3.0.2:

```bash
node scripts/export-prototype-pollution-fixtures.mjs --combined
```

These are static source judgments. The lab separately confirms each fixture's label by running
it in Node with its payload.

- 24 entries, 63 analysis records: **14 Confirmed, 47 Review, 2 Protected**.
- 19 prototype pollution records, all assessed: 19 requests, 48,693 input tokens, no provider
  failures. All 19 saved traces replay with the same request digest and outcome. The 37 input-validation and 7 rendering-flow records are observations with no claim
  to send, and stay in Review.
- No false positive and no false Protected against the lab's ground truth.

### Prototype pollution records against the ground truth

| Source | Exploitable | Scanner path | Outcome |
|---|---|---|---|
| `pages/api/merge.ts`, Lodash `merge` 4.17.4 | Yes | Raw | Confirmed |
| `pages/api/lodash-set.ts`, Lodash `set` 4.17.4 | Yes | Raw | Confirmed |
| `pages/api/lodash-defaults-deep.ts`, Lodash `defaultsDeep` 4.17.4 | Yes | Raw | Confirmed |
| `pages/api/lodash-zip.ts`, Lodash `zipObjectDeep` 4.17.4 | Yes | Raw | Confirmed |
| `app/api/settings/route.ts`, nested computed write | Yes | Raw | Confirmed |
| `pages/api/deep-merge.ts`, merge over `Object.getOwnPropertyNames` | Yes | Raw | Confirmed |
| `pages/api/set-path.ts`, array path | Yes | Raw | Confirmed |
| `pages/api/unflatten.ts`, dotted keys | Yes | Raw | Confirmed |
| `pages/api/reduce-path.ts`, regular-expression split and `reduce` | Yes | Raw | Confirmed |
| `pages/api/deny-path-partial.ts`, deny-list for `__proto__` only | Yes | Raw, `constructor` open | Confirmed, bypass identified |
| `pages/api/preferences.ts`, slot created when absent | Yes | Raw | Confirmed |
| `pages/api/vendored.ts`, library source kept in the repository | Yes | Raw, write in `lib/tiny-merge.ts` | Confirmed |
| `app/api/profile/route.ts`, bracket-flattened keys | Yes | Raw | Confirmed |
| `app/api/flags/route.ts`, `reduce` merge | Yes | Raw | Confirmed |
| `pages/api/set-path-compared.ts`, comparison without a type test | Yes | Review | Review |
| `pages/api/deny-path.ts`, whole-path deny-list | No | Guarded | Protected |
| `pages/api/set-path-checked.ts`, type test and deny-list | No | Guarded | Protected |
| `pages/api/guarded.ts`, per-level key guard | No | Guarded | Review |
| `pages/api/preferences-known.ts`, write behind a `Map` lookup | No | Review | Review |

Fourteen of the fifteen exploitable sources with a record are Confirmed. The fifteenth,
`set-path-compared.ts`, stays in Review: its guard compares array parts without a type test, the
scanner does not credit it, and it does not claim the bypass either. `guarded.ts` is safe and
stays in Review because the model answered that coverage was incomplete with low confidence
(0.49 against 0.31), which contradicts the recorded guard. `preferences-known.ts` is safe behind
a lookup the scanner does not read.

### Sources without a record

| Source | Exploitable | Why there is no record |
|---|---|---|
| `pages/api/dset.ts`, `dset` 3.1.3 (CVE-2024-21529) | Yes | Known gap: an installed dependency other than Lodash. A dependency audit reports it |
| `pages/api/merge-deep.ts`, `merge-deep` 3.0.2 (CVE-2021-26707) | Yes | The same known gap |
| `pages/api/parse.ts`, JSON parsing | No | No write |
| `pages/api/read-path.ts`, read-only walk | No | No write |
| `pages/api/shallow.ts`, one-level copy | No | No write to a prototype |

The patched pins (Lodash 4.17.21, `dset` 3.1.4, `merge-deep` 3.0.3) are separate lab projects,
because one lockfile resolves one version. Their Lodash calls have no record in an offline scan.

## Living expectations and limits

For the full application scan, the source of truth is the lab’s
[`tests/expected-scanner-findings.json` at the report pin](https://github.com/zazzcode/vuln-nextjs/blob/ea10efb/tests/expected-scanner-findings.json),
generated from `lib/catalog.json`. Re-pin and re-evaluate changed source before publishing new results.
A safe control applies to the weakness named by its key. The fixture export has its own
[lab expectations](https://github.com/zazzcode/vuln-nextjs/blob/8d26f52/docs/vulnerabilities/prototype-pollution.md)
and [prototype pollution coverage limits](../../scan/detection-capabilities/prototype-pollution.md).

Dependency auditing for `SCA-001` is outside the scored cases. The nested React2Shell App Router
target is a separate project. Try/catch flow, child-component props and some other entry forms
remain bounded. [Next.js support](../../scan/nextjs-support.md)

These are static source judgments, not runtime exploit confirmation or exhaustive recall. Follow the
[reference policy](../reference-policy.md); repair an independent copy, leaving references unchanged.
Source excerpts belong to the upstream authors; the upstream license is preserved in
[UPSTREAM-LICENSE.txt](UPSTREAM-LICENSE.txt).
