# Precision and noise baseline

[Contract](../specifications/accuracy-false-positive-noise.md) ·
[Checker](recall-gap-inventory/check.py) · [Protected controls](recall-gap-inventory/protected-controls.json) ·
[Recall inventory](recall-gap-inventory.md)

This record gives the false-positive contract its precision denominator. It sits next to the
phase 5 recall floor and uses the same pinned corpus, scan command and checker. Expected labels
stay in the checker and its JSON files; none reaches scanner or model input.

## Method

Offline scans of the eleven pinned samples (same pins and clean-checkout rule as the
[recall inventory](recall-gap-inventory.md#corpus-and-pins)), scanner `895f049` (`stage` `39c5483`
plus the contract), 2026-11-19. Reproduce with the inventory's scan command, then:

```bash
python3 .zazz/evaluation/recall-gap-inventory/check.py <reports.json> --lab <vuln-nextjs-at-pin> --json <out.json> --precision-markdown <precision.md>
```

```bash
python3 .zazz/evaluation/recall-gap-inventory/test_check.py
```

The checker prints one `precision <app> <family>` line per family and sample. Measures:

| Measure | Meaning |
|---|---|
| Keyed true / false | Findings matched by a positive key row, or matched only by a control row (a false finding) |
| Unkeyed | Records that match no key row: the population whose truth is unknown |
| Test path | Records whose sink is under a test, spec, fixture, Cypress or e2e path |
| No-origin construction | SQL/NoSQL construction records with no request, storage, file, fetched, browser or API-response dependency |
| Undecidable validation | Standalone validation records that cannot pass the validation policy gate (not named by `--checks`) |
| Shared-sink fan-out | Records at a kind and sink span reached from two or more entries (outbound observations excluded; they are already grouped) |
| Same entry+sink extra | Records beyond the first per entry, kind and sink span |
| Own-API request origin, literal-only storage, closed type map | Keyed noise anchors (`noise_rows` in `cases.json`) still carrying their class condition |
| Stored origin unresolved | Records blocked by `storage_origin_unresolved` |
| Unknown ctx raw | XSS records with output context `unknown` and protection `raw` |
| Control as finding / Protected / Review | Outcome of each record matched by the protected-control set |
| Fixed-outcome requests, substantive discarded | Judged reports only: requests whose outcome a scanner blocker had already fixed, and how many of those discarded a definite model answer |

A judged precision row must name its provider, model and question version, so the same corpus can
be re-measured when the model changes. Offline rows have no assessment.

## Offline baseline (scanner `895f049`)

Checker recall summary, unchanged from phase 5: 91 `candidate_with_witness`, 30 `control_pass`,
4 `resolved`, 25 `candidate_present`, 11 `assessment_dependent`, 13 `excluded` (174 rows).

| Measure | vuln-demo-app | vulnerable-typescript-app | nodejs-goof | juice-shop | oss-oopssec-store | vuln-nextjs | vulnpy | ThreatByte | python-insecure-app | vulnerable-flask-app | dvwa | Total |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Records | 19 | 26 | 32 | 251 | 128 | 54 | 3350 | 62 | 2 | 30 | 240 | 4194 |
| Findings | 10 | 1 | 2 | 15 | 14 | 7 | 109 | 5 | 1 | 4 | 183 | 351 |
| Keyed true | 10 | 1 | 2 | 14 | 11 | 7 | 86 | 4 | 1 | 4 | 16 | 156 |
| Keyed false | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Unkeyed | 6 | 18 | 16 | 233 | 105 | 28 | 3264 | 45 | 0 | 24 | 207 | 3946 |
| Unkeyed findings | 0 | 0 | 0 | 1 | 1 | 0 | 23 | 0 | 0 | 0 | 163 | 188 |
| Test path | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| No-origin construction | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 33 | 34 |
| …as finding | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 33 | 34 |
| Undecidable validation | 2 | 13 | 13 | 95 | 87 | 19 | 2830 | 3 | 1 | 17 | 0 | 3080 |
| Shared-sink fan-out | 4 | 0 | 0 | 10 | 38 | 0 | 3336 | 0 | 0 | 0 | 196 | 3584 |
| Same entry+sink extra | 1 | 0 | 0 | 0 | 4 | 0 | 6 | 0 | 0 | 0 | 60 | 71 |
| Own-API request origin | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| Stored origin unresolved | 2 | 1 | 0 | 17 | 1 | 0 | 0 | 2 | 0 | 0 | 18 | 41 |
| Literal-only storage | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| Unknown ctx raw | 0 | 1 | 0 | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 3 |
| Closed type map | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 1 |
| Control as finding | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Control Protected | 0 | 0 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 2 |
| Control Review | 0 | 0 | 1 | 0 | 0 | 5 | 0 | 3 | 0 | 0 | 4 | 13 |
| Fixed-outcome requests | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |
| Substantive discarded | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

This reproduces the contract's measured baseline: 4,194 records and 351 findings; 3,080 of the
3,087 validation records cannot be decided (ThreatByte's seven can); DVWA has 33 no-origin SQL
findings and 60 of 240 same-entry extras; three unknown-context records show `raw`. One more
no-origin construction finding exists than the contract counted: Juice Shop
`routes/chat.ts:149`, a `$where` string built from a chat-tool argument with no resolved
dependency. The test-path census is zero, and no keyed control presents as a finding.

## Judged fixed-outcome baseline (saved sample reports, openai `gpt-6-luna`)

| Sample | Family | Fixed-outcome requests | Substantive answers discarded |
|---|---|---:|---:|
| Juice Shop | input-validation | 93 | 0 |
| Juice Shop | xss | 19 | 1 |
| Juice Shop | path | 8 | 6 |
| Juice Shop | nosql | 5 | 5 |
| Juice Shop | sql, ssrf | 1, 1 | 0, 1 |
| OopsSec | input-validation | 86 | 0 |
| OopsSec | path, xss, ssrf | 2, 2, 1 | 0, 0, 1 |
| ThreatByte | input-validation | 3 | 0 |
| ThreatByte | sql, xss | 1, 2 | 1, 0 |

These come from the published sample reports under `docs/samples/`, each judged with its own
question versions. They are the baseline the model-assisted evidence resolution contract measures
against.

## After the contract (offline, scanner after W7)

The checker floor is unchanged: 91 `candidate_with_witness`, 30 `control_pass`, 4 `resolved`. No
keyed positive changed status (keyed true findings 156 before and after) and no keyed control
presents as a finding. "Finding rows" counts presented rows after sink grouping; "Findings" is per
record.

| Sample | Records | Finding rows before → after | Presented rows before → after |
|---|---:|---|---|
| vuln-demo-app | 19 | 10 → 6 | 19 → 15 |
| vulnerable-typescript-app | 26 | 1 → 1 | 26 → 26 |
| nodejs-goof | 32 | 2 → 2 | 32 → 32 |
| juice-shop | 251 | 15 → 14 | 182 → 178 |
| oss-oopssec-store | 128 | 14 → 11 | 126 → 95 |
| vuln-nextjs | 54 | 7 → 7 | 54 → 54 |
| vulnpy | 3350 | 109 → 15 | 3350 → 62 |
| ThreatByte | 62 | 5 → 5 | 62 → 62 |
| python-insecure-app | 2 | 1 → 1 | 2 → 2 |
| vulnerable-flask-app | 30 | 4 → 4 | 30 → 30 |
| dvwa | 240 | 183 → 40 | 240 → 87 |

Per-record findings go from 351 to 317: 33 DVWA no-origin SQL constructions and Juice Shop
`routes/chat.ts:149` move to Review (`external_origin_not_established`). The other row reductions are
grouping only; JSON keeps all 4,194 records. Noise classes after: no-origin construction findings
34 → 0, unknown-context raw 3 → 0, own-API request origin 1 → 0 (now a storage origin),
undecidable validation 3,080 (unchanged as records; no longer requested), shared-sink fan-out and
same-entry extras unchanged as records but presented as grouped rows.

