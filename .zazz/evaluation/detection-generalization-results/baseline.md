# Detection generalization — accuracy baseline

The base that [contract §7](../../specifications/detection-generalization/contract.md#7-detection-and-false-positive-accuracy-must-not-fall)
requires. The ledger is [baseline.json](baseline.json). 2026-11-25, `stage` at `6ee8059`. Offline: no paid
call, no scanner change, no key changed. `oss-oopssec-store` and NodeGoat were not opened; their key rows
were filtered out by script.

## 1. Result

| Sample | Confirmed | True | False | Not decidable | Protected | False Protected | True, not Confirmed |
|---|---:|---:|---:|---:|---:|---:|---:|
| Juice Shop | 51 | 47 | 4 | 0 | 3 | 0 | 8 |
| vuln-nextjs | 13 | 13 | 0 | 0 | 9 | 0 | 1 |
| vuln-symfony | 55 | 54 | 1 | 0 | 22 | 1 | 1 |
| DVWA | 159 | 143 | 15 | 1 | 18 | 0 | 20 |
| **Total** | **278** | **257** | **20** | **1** | **52** | **1** | **30** |

False by family: Juice Shop authorization 2 of 10, NoSQL 1 of 7, configuration 1 of 5. vuln-symfony
configuration 1 of 4. DVWA SQL 14 of 37, XSS 1 of 77.

**Frozen by the owner on 2026-11-25**, after the rulings of [§7](#7-owner-rulings). SHA-256 of `baseline.json`:
`9c7d374b5fedca326692c661aef1daacc8bc0af633e04528153912e48773de83`.
It changes only by owner decision, with a new digest here.

Frozen with two open points: the 26 outcomes in §3 that do not belong to the requests the base sends
(`replays_at_base: false`), and the limits of §2. The 26 are judged again before a change is measured on them.

## 2. Method and limits

- Reviewer: one session, which did not design the series or write the first review. It is one reading, not
  two. It had seen the list of the 13 known false positives before it read the source, so the reread of
  those is not blind.
- Every Confirmed and every Protected record was read against the sample source at its pin. `true` means the
  weakness can occur at that location. A `CONDITIONAL` reason needs a configuration or a local address. A
  `BORDERLINE` reason is true only on a wide reading of the claim. Both count as true.
- DVWA XSS: 75 of the 77 Confirmed records share one cause, the theme cookie echoed without escaping
  (`dvwaPage.inc.php:193-194`). They were decided by that cause and checked by script to carry that source.
  Other flows in the same records were not all decided.
- Review sample. Read in full: every `needs_evidence` and `poor_practice` record, and every `needs_review`
  record outside two groups. The two groups are request-field and response-data observations; from them 37
  of 146 were drawn (`random.Random(20261125)`, identifiers sorted): Juice Shop 20 of 95 and 8 of 24,
  vuln-nextjs 6 of 19 and 3 of 8. The other **109 are marked `not_read`**. Repeated records of one operation
  (70 of `lib/webhook.ts:18`, 34 DVWA setup queries) were read once for each operation.
- Runtime behavior was not tested.
- Only the four samples with a judged report named in the handoff are in the ledger. A1 says "any sample":
  nodejs-goof, vuln-demo-app, vulnerable-typescript-app, VulnPy and ThreatByte have **no baseline**.
- Pins matched before and after. Three checkouts were clean; `vuln-nextjs` holds only ignored build output.

## 3. Saved requests against the base

Each sample was scanned offline with the scanner at `6ee8059`, and `judge.Preview` gave each request digest.

| Sample | Records saved and at base | Missing | Judged requests | Same digest | Changed |
|---|---:|---:|---:|---:|---:|
| Juice Shop | 305 | 0 | 84 | 84 | 0 |
| vuln-nextjs | 54 | 0 | 27 | 27 | 0 |
| vuln-symfony | 84 | 0 | 84 | 62 | **22** |
| DVWA | 265 | 0 | 208 | 204 | **4** |

The 26 are authorization (v5 saved, v9 at base) and configuration (v5 or v6 saved, v7 at base), from reports
older than PR #48 and PR #50. In vuln-symfony they are 13 Confirmed and 9 Protected; in DVWA 1 Confirmed
and 3 `needs_evidence`. **Their outcomes at the base are unknown.** A1 to A4 cannot compare them until they
are judged again, which is a paid run and not asked for here. In the ledger they have
`replays_at_base: false`. Both protocols are ones the series changes.

## 4. Disagreements put to the owner

No key was changed. Rulings are in §7.

| # | Item | First review or key | This review | Ledger |
|---:|---|---|---|---|
| 1 | `likeProductReviews.ts:35`, NoSQL | Counted false: contract §7 says NoSQL 2 of 7, 5 records. The list joins by location | The authorization record there is false. The NoSQL record is true, and comparison row `JS-X-NOSQL-04` agrees | true. Juice Shop has 4 false records |
| 2 | vuln-symfony `docker/apache.conf:2`, directory listing | Key `SYM-CONF-01`, positive | Cannot occur: `public/.htaccess` sends every non-file request to `index.php`, with `AllowOverride All` and `mod_rewrite` on | false, key kept |
| 3 | vuln-symfony `config/packages/security.yaml:5`, password hash | Protected | False Protected: it makes the md5 hasher the password hasher. `Md5Hasher.php:15` is Confirmed for it | false_protected |
| 4 | DVWA `csp/source/jsonp.php:12`, reflected XSS | Unkeyed, not listed as false | The response is `application/json` (`:2`); the record says `text/html`. The free callback is another weakness | false |
| 5 | DVWA `api/help/help.php:39`, reflected XSS | Unkeyed | The web server decides `SERVER_NAME` | not_decidable |
| 6 | vuln-nextjs `pages/secure/ssrf.js:26` | Lab key and control `PC-SSRF-01`: safe | The allowed origin comes from the request's own Host header (`:23-24`), so it is a real, narrow SSRF | true_left_in_review |
| 7 | 24 DVWA Confirmed records (SQL, password hash, upload) whose entry is a file under `source/` | Counted by location | Opened directly, that file stops before the operation: no database connection or no page constant. 17 have a true weakness at the location, 7 are false anyway | true or false by location, plus `entry_reaches_operation: false` |
| 8 | vuln-symfony `Mail.php:38` authorization, `BlogController.php:95` XSS | Key: judge decides | Borderline true | true |

Item 7 matters most for A1. If a later change correctly drops those entries, A1 reads it as 17 lost true
findings. For three of the operations, `bac/source/low.php:81`, `bac/source/medium.php:73` and
`upload/source/medium.php:18`, the Confirmed record has the entry that cannot reach the operation, and the
record with the entry that can is left as practice.

The 13 known Code Scan false positives were reread. **All 13 locations hold**; they are 18 false records (4 in
Juice Shop, 14 in DVWA).

## 5. True weaknesses recorded but not Confirmed (A9)

30 records. 12 are the DVWA theme cookie left as practice and 2 more are in Review. The others:

| Sample | Record | Outcome |
|---|---|---|
| Juice Shop | `PUT /api/Addresss/:id` changes any address; `PUT /api/BasketItems/:id` changes any item; `PUT /api/Hints/:id` writes any field | needs evidence |
| Juice Shop | `likeProductReviews.ts:50` NoSQL, same selector as three Confirmed records; `videoHandler.ts:72` stored XSS (row `XSS-09`) | not judged |
| Juice Shop | `profileImageUrlUpload.ts:24` SSRF, `b2bOrder.ts:23` code, `server.ts:366` password in access log (keyed, found as practice) | practice |
| vuln-nextjs | `pages/secure/ssrf.js:26`, item 6 | needs evidence |
| vuln-symfony | `UserPref.php:36` through `ANY /reset`; 11 other entries are Confirmed | needs evidence |
| DVWA | `authbypass/change_user_details.php:48` missing authorization | needs evidence |
| DVWA | Two open redirects, two `bac` SQL records, one upload | practice |

Key row `JS-AUTHZ-01` selects every authorization record at `server.ts:529`, so one Confirmed record
satisfies it and the two left in Review are hidden. Whether the key should name them is the owner's decision.

## 6. Ledger format

One entry for each of the 708 records: identifier, kind, location, entry, saved outcome, `verdict`, `reason`
with source lines, `saved_request_digest`, `base_request_digest`, protocols, `replays_at_base`, and the keys
that select it. `key_rows` lists every key row and control of the four samples with the records it selects.
Verdicts: `true`, `false`, `not_decidable` (Confirmed); `correct_protected`, `false_protected`;
`true_left_in_review`, `nothing_found`, `not_decidable`, `not_read` (all others).

The digests come from a test-only program built with `go build -overlay`, so no file was added to the
module. The generator, program and digests are in `_test-findings/detection-generalization-baseline/`.

## 7. Owner rulings

2026-11-25. Numbers are the items of §4; records carry `owner_ruling`.

| # | Ruling | Effect |
|---:|---|---|
| 1 | True | A1 protects it. Contract §7's Juice Shop row is corrected to 4 records, NoSQL 1 of 7 |
| 2 | False, key kept | A1 does not hold it. `SYM-CONF-01` is unchanged and is a separate decision |
| 3 | False Protected | A2 does not stop it from becoming a finding |
| 4 | False | Counted as a known false positive. `scanner-false-positives.json` is unchanged |
| 5 | Not decidable | Outside A1 and A2 |
| 6 | True, not a control | `PC-SSRF-01` and `SSRF-001-safeControl` carry `a2_control: false`. Key files are unchanged |
| 7 | By location | The 17 stay true with `a1_scope: location`. One may stop being Confirmed only if a record at the same location with an entry that reaches the operation is Confirmed |
| 8 | Both true | A1 protects both |

Ruling 7: for `bac/source/low.php:81`, `bac/source/medium.php:73` and `upload/source/medium.php:18`, no record
with a reachable entry is Confirmed (`reachable_record_confirmed: false`), so these three may not be dropped
until one is.
