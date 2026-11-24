# Scanner comparison — run record

**2026-11-24.** How the [scanner comparison](../../docs/scan/scanner-comparison.md) was produced.
The numbers live in that page and are not repeated here. This record gives the tools, the
inputs, the counting rules and the commands, so the tables can be reproduced.
Contract: [hardening lane, branch 2](../specifications/juiceshop-nextjs-hardening-2.md).

## Documents

| Document | Holds |
|---|---|
| [Scanner comparison](../../docs/scan/scanner-comparison.md) | The summary: one table per application, false positives, totals by class |
| [Semgrep results](semgrep-results.md) | Semgrep CE run identity, rule packs and hashes, results by rule |
| [Bearer results](bearer-results.md) | Bearer build and rule revision, results by rule |
| [Comparison history](comparison-history.md) | The 2026-10-31 and 2026-11-01 results and the authored-controls comparison |
| [Repeat protocol](bearer-comparison.md) | How a comparison run is set up |

## Inputs

| Application | Pin | Answer key | Code Scan report |
|---|---|---|---|
| OWASP Juice Shop | `f189f52` | `recall-gap-inventory/cases.json` (42 positives), [guide](juice-shop-detection-guide.md), and the committed key added in the summary | `a1-acceptance-juice-shop`, scanner `ee777f4`, 85 requests |
| vuln-nextjs | `f5d47de` | The lab's `tests/expected-scanner-findings.json` (13 positives) | `a2-acceptance-vuln-nextjs`, scanner `ee777f4`, 27 requests |
| DVWA | `a1978a2` | `cases.json` (11 positives), [guide](dvwa-detection-guide.md) | `run-4266343441`, scanner `d368a68`, 205 requests ([published copy](../../docs/samples/dvwa/README.md)) |
| vuln-symfony | `086f81f` | `cases.json` (30 positives), [guide](vuln-symfony-detection-guide.md) | `run-1810616125`, scanner `8d97b93`, 84 requests ([published copy](../../docs/samples/vuln-symfony/README.md)) |

Every Code Scan report is a judged run with OpenAI `gpt-6-luna`. The Juice Shop and vuln-nextjs
runs are the acceptance runs of hardening 3, recorded in the
[hardening results](juiceshop-hardening-results.md#hardening-3). The four upload candidates of
Juice Shop were judged in that run and are in Review; they are in no table.

Tool outputs are under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<application>/` in
`semgrep-20261124-1/` and `bearer-20261124-1/`.

**zizmor is not part of the comparison.** It was run on the four samples on 2026-11-24 and then
removed by the owner's decision: it audits GitHub Actions workflow files and does not read
application code, so it cannot be scored against application vulnerabilities.

## Counting rules

1. A row is a known vulnerability: a key row with expectation `positive`.
2. A tool result matches a row when it is in the row's file, its rule maps to the row's weakness
   class, and it is within three lines of the row's line. A row with no line matches on file and
   class. A result near two rows of one class belongs to the nearer one. The rule-to-class map
   is `RULE_CLASS` in [match-scanner-results.py](match-scanner-results.py).
3. Code Scan found a row when its judged outcome is Confirmed, or a practice finding where the
   table says so. A record in Review is a miss.
4. A false positive is a result on code that a key control or a source review shows to be safe.
   They are counted by location. Bearer's `logger_leak` and its `hardcoded_secret` results in
   test files are each one grouped row; the basis is in the
   [Bearer results](bearer-results.md) and the summary.
5. Any other result is unreviewed. It is counted and never called a false positive.

**Rows added to the Juice Shop table.** Eight documented Juice Shop vulnerabilities that a
compared scanner reported and the key did not hold: the open redirect, the profile-image SSRF,
the two code-execution routes, three file-read and file-write paths, and the committed signing
key. Each was read against the source before it was added. Hardening 3 made seven of them rows
of `cases.json` and added the read of another user's basket (`JS-AUTHZ-05`). The committed key
stays a row of the summary only: no analyzer owns it.

**False positives added by the hardening 3 run.** Two Code Scan records that the earlier run
did not report as findings were read against the source and are counted: the second record of
the like route (`routes/likeProductReviews.ts:50`) and the generated
`DELETE /api/Addresss/:id` (`server.ts:529`, behind the explicit handler at `:479`). Three
other records newly Confirmed in that run were read and are real: the read at
`routes/recycles.ts:12` (no authentication on `GET /api/Recycles/:id`) and the generated
deletes of `/api/BasketItems/:id` and `/api/Feedbacks/:id` (sign-in only, no owner test). They
are not key rows and are in no table.

**Corrections made by hand.** The control row `SYM-INFO-N01` is a whole-sample count, not a
location, and is left out of the false-positive table. Bearer's XSS result at
`routes/userProfile.ts:90` is the same output as the keyed row at `:101` and is counted once.

## Reproduce

```bash
# Code Scan outcomes per key row. reports.json maps each application to its judged report.
python3 .zazz/evaluation/recall-gap-inventory/check.py reports.json \
  --lab <DEV_ROOT>/zazzcode/vuln-nextjs --judged --json check.json

# One application's rows and each tool's results.
T=<DEV_ROOT>/zazzcode/zazzles/_test-findings
python3 .zazz/evaluation/match-scanner-results.py check.json juice-shop <DEV_ROOT>/juice-shop/ \
  semgrep=$T/juice-shop/semgrep-20261124-1/results.json \
  bearer=$T/juice-shop/bearer-20261124-1/results.json \
  --cases .zazz/evaluation/recall-gap-inventory/cases.json

python3 .zazz/evaluation/test_match_scanner_results.py
```

`VULN` lines are the table rows. A `SAFE` line with a tool result is a false positive of that
tool. The list after it is the unreviewed remainder by rule.

## Capability inventory

What each scanner demonstrated on these four applications. A cell is the number of known
vulnerabilities found out of those keyed. "No keyed case" means no run exercised the class, so
nothing is claimed for any scanner.

| Weakness class | Known vulnerabilities | Code Scan | Semgrep CE | Bearer |
|---|---:|---:|---:|---:|
| Cross-site scripting | 18 | 18 | 1 | 5 |
| SQL injection | 10 | 10 | 5 | 7 |
| Missing authorization | 10 | 10 | 0 | 0 |
| Insecure configuration | 8 | 8 | 4 | 4 |
| Path traversal | 8 | 7 | 1 | 3 |
| Mass assignment | 7 | 7 | 0 | 0 |
| Code and template injection | 6 | 5 | 2 | 4 |
| OS command injection | 5 | 5 | 2 | 2 |
| Server-side request forgery | 4 | 4 | 0 | 1 |
| NoSQL injection | 3 | 3 | 0 | 0 |
| Information exposure | 3 | 3 | 1 | 1 |
| Weak password hashing | 3 | 3 | 1 | 2 |
| Account enumeration | 3 | 3 | 0 | 0 |
| Open redirect | 3 | 3 | 1 | 2 |
| Unrestricted file upload | 2 | 2 | 0 | 0 |
| Unsafe deserialization | 1 | 1 | 0 | 1 |
| Weak password recovery | 1 | 1 | 0 | 0 |
| Sensitive data in logs | 1 | 1 | 0 | 0 |
| Hardcoded secret | 1 | 0 | 1 | 1 |
| Prototype pollution, argument injection | No keyed case | — | — | — |
| **Total** | **97** | **94** | **19** | **33** |

| Capability | Code Scan | Semgrep CE | Bearer CLI |
|---|---|---|---|
| Languages run here | JavaScript, TypeScript, PHP | The same | The same |
| Flow across files and through stored values | Yes: the stored and cross-tier XSS rows and the helper-held SQL rows depend on it | No in CE; the cross-file engine is Semgrep Pro, not run | Not shown: it found no row that needs it |
| Access rules read from framework configuration and middleware | Yes: the authorization, mass-assignment and enumeration rows depend on it | No such rule fired | No such rule fired |
| Known-safe code left unreported | 5 false positives | 7 | 21 and two grouped rules |
| Committed secrets | No analyzer | Found the keyed row | Found the keyed row |
| Infrastructure files (Terraform, package-manager policy) | Dockerfile, web-server and cron files for PHP projects | Terraform and npm/pnpm rules fired | None fired |
| Output | JSON, HTML, SARIF | JSON, SARIF, text | JSON; SARIF not produced in this run |

This replaces the capability inventory of 2026-10-31, which described a scanner with SQL, NoSQL
and XSS analysis only. Its text is in the [history](comparison-history.md).

## Limits

- The keys were written for Code Scan's evaluation and favor the classes it analyzes. Only the
  Juice Shop table was widened with what the other scanners surfaced.
- DVWA's key covers the low security level. Results on its medium and high levels are
  unreviewed.
- Three of the four Code Scan columns come from runs recorded before this comparison.
- No finding of any scanner was confirmed at run time.
