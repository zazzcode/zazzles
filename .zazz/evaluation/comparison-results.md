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
| [zizmor results](zizmor-results.md) | zizmor version and mode, findings by audit |
| [Comparison history](comparison-history.md) | The 2026-10-31 and 2026-11-01 results and the authored-controls comparison |
| [Repeat protocol](bearer-comparison.md) | How a comparison run is set up |

## Inputs

| Application | Pin | Answer key | Code Scan report |
|---|---|---|---|
| OWASP Juice Shop | `f189f52` | `recall-gap-inventory/cases.json` (34 positives), [guide](juice-shop-detection-guide.md), and eight rows added in the summary | `r10-acceptance-juice-shop`, scanner `29ce9aa`, 76 requests |
| vuln-nextjs | `f5d47de` | The lab's `tests/expected-scanner-findings.json` (13 positives) | `s7-acceptance-vuln-nextjs`, scanner `97709ad`, 27 requests |
| DVWA | `a1978a2` | `cases.json` (11 positives), [guide](dvwa-detection-guide.md) | `run-4266343441`, scanner `d368a68`, 205 requests ([published copy](../../docs/samples/dvwa/README.md)) |
| vuln-symfony | `086f81f` | `cases.json` (30 positives), [guide](vuln-symfony-detection-guide.md) | `run-1810616125`, scanner `8d97b93`, 84 requests ([published copy](../../docs/samples/vuln-symfony/README.md)) |

Every Code Scan report is a judged run with OpenAI `gpt-6-luna`. The Juice Shop and vuln-nextjs
runs are recorded in the [hardening results](juiceshop-hardening-results.md). The upload
producer added after `29ce9aa` records four more Juice Shop candidates that no run has judged;
they are in no table.

Tool outputs are under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<application>/` in
`semgrep-20261124-1/`, `bearer-20261124-1/` and `zizmor-20261124-1/`.

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
key. Each was read against the source before it was added. They are not yet rows of
`cases.json`; adding them is a key change for a later branch, and the three that Code Scan
leaves in Review are the first candidates for analyzer work.

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
| Missing authorization | 9 | 9 | 0 | 0 |
| Insecure configuration | 8 | 8 | 4 | 4 |
| Path traversal | 8 | 7 | 1 | 3 |
| Mass assignment | 7 | 7 | 0 | 0 |
| Code and template injection | 6 | 5 | 2 | 4 |
| OS command injection | 5 | 5 | 2 | 2 |
| Server-side request forgery | 4 | 3 | 0 | 1 |
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
| **Total** | **96** | **92** | **19** | **33** |

| Capability | Code Scan | Semgrep CE | Bearer CLI |
|---|---|---|---|
| Languages run here | JavaScript, TypeScript, PHP | The same | The same |
| Flow across files and through stored values | Yes: the stored and cross-tier XSS rows and the helper-held SQL rows depend on it | No in CE; the cross-file engine is Semgrep Pro, not run | Not shown: it found no row that needs it |
| Access rules read from framework configuration and middleware | Yes: the authorization, mass-assignment and enumeration rows depend on it | No such rule fired | No such rule fired |
| Known-safe code left unreported | 3 false positives | 7 | 21 and two grouped rules |
| Committed secrets | No analyzer | Found the keyed row | Found the keyed row |
| GitHub Actions workflows | Not read | Not run on workflows | Not run on workflows |
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
