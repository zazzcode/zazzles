# vuln-nextjs prototype pollution sample

[All samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) ·
[SARIF](findings.sarif) · [Provenance](metadata.json) ·
[Analysis rules](../../analysis/prototype-pollution.md) ·
[Lab guide](https://github.com/zazzcode/vuln-nextjs/blob/8d26f52/docs/vulnerabilities/prototype-pollution.md)

## Current report (2026-11-21)

One judged scan of the prototype pollution (CWE-1321) fixtures in the owner-maintained
[zazzcode/vuln-nextjs](https://github.com/zazzcode/vuln-nextjs) lab at `8d26f52`, with OpenAI
`gpt-6-luna` and the scanner at `6006eaa`. The same scan on 2026-11-20 at `d68fec6` produced a
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

## Prototype pollution records against the ground truth

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

## Sources without a record

| Source | Exploitable | Why there is no record |
|---|---|---|
| `pages/api/dset.ts`, `dset` 3.1.3 (CVE-2024-21529) | Yes | Known gap: an installed dependency other than Lodash. A dependency audit reports it |
| `pages/api/merge-deep.ts`, `merge-deep` 3.0.2 (CVE-2021-26707) | Yes | The same known gap |
| `pages/api/parse.ts`, JSON parsing | No | No write |
| `pages/api/read-path.ts`, read-only walk | No | No write |
| `pages/api/shallow.ts`, one-level copy | No | No write to a prototype |

The patched pins (Lodash 4.17.21, `dset` 3.1.4, `merge-deep` 3.0.3) are separate lab projects,
because one lockfile resolves one version. Their Lodash calls have no record in an offline scan.

## Limits

The report shows the affected pins only. The [known gaps](../../detection-capabilities/prototype-pollution.md)
apply. Source excerpts belong to the lab; its license is preserved in
[UPSTREAM-LICENSE.txt](UPSTREAM-LICENSE.txt).
