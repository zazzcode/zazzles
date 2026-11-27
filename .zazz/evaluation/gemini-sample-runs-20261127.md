# Google Gemini sample runs — 2026-11-27

[Scanner comparison](../../docs/scan/scanner-comparison.md) · [Sample reports](../../docs/samples/README.md) ·
[Comparison run record](comparison-results.md)

One full judged scan of each of five sample applications with Google Gemini `gemini-decision-1`,
requested by the owner on 2026-11-27. These runs replace the published sample reports and add a Gemini column to
the scanner comparison. No scanner code changed. The numbers live in the sample notes and the comparison
page; this record gives the inputs, the commands, the scoring and what moved against the
earlier `gpt-6-luna` reports.

## Inputs

| Application | Pin | Run | Key |
|---|---|---|---|
| OWASP Juice Shop | `f189f52` | `run-1512688242` | `recall-gap-inventory/cases.json` (41 positives) and the [33 added rows](juice-shop-comparison-rows.json) |
| OSS OopsSec Store | `2d530ef` | `run-1482068464` | `cases.json` (13 positives) |
| VulnerableSymfony | `086f81f` | `run-200762536` | `cases.json` (30 positives) |
| DVWA | `a1978a2` | `run-247227625` | `cases.json` (11 positives) |
| VulnPy | `b81885e` | `run-1323650417` | `docs/samples/vulnpy/cases.json` (10 positives, including four deserialization sinks) |

Scanner: `stage` at `81d4731` (through PR #56), built with the worktree's declared Go toolchain.
Every target was at its pin and clean (`git status --porcelain --ignored` empty) before and after
its scan. Output went to `<DEV_ROOT>/zazzcode/zazzles/_test-findings/gemini-20261127/`.

```bash
# Only the Gemini key is passed to the scanner; no request cap and no pacing.
set -a; . ./.env; set +a
unset OPENAI_API_KEY TYPESAFE_API_KEY JUDGE_LIMIT JUDGE_RPM JUDGE_TPM
export JUDGE_DECISION_MODEL=gemini-decision-1
./bin/scan --analyze --json --judge gemini --output-dir "$OUT" "$TARGET" > "$OUT/<app>.stdout.json"
```

The five scans ran one after another with the default concurrency of 4. Every scan exited 0.

| Application | Wall clock | Completed assessments | Attempts and retries | Input tokens | Failures |
|---|---:|---:|---|---:|---:|
| OWASP Juice Shop | 34 s | 84 | no retries | 406,475 | 0 |
| OSS OopsSec Store | 5 s | 29 | no retries | 185,844 | 0 |
| VulnerableSymfony | 6 s | 84 | no retries | 355,480 | 0 |
| DVWA | 177 s | 257 | 266 attempts, 12 transient retries | 2,251,990 | 0 |
| VulnPy | 243 s | 640 | 656 attempts, 16 transient retries | 4,176,758 | 0 |

## Scoring

`recall-gap-inventory/check.py --judged` against each canonical report, and the same against the
published `gpt-6-luna` reports, for the per-row comparison. The 33 Juice Shop rows outside
`cases.json` were scored by a Confirmed or practice finding of the row's class within three lines
of an anchor, the rule the comparison used for its hand-set cells. Gemini finds the same four of
them as `gpt-6-luna`. False positives were checked at the locations of
[scanner-false-positives.json](scanner-false-positives.json), matching the reported class, and
every finding location not in the `gpt-6-luna` report was read against the source.

<a id="owasp-juice-shop"></a>

## OWASP Juice Shop

Found 36 of the 41 positives of Code Scan's own key, and 40 of the comparison's 75 rows
(`gpt-6-luna`: 41 and 45).

| Row | `gpt-6-luna` | Gemini |
|---|---|---|
| `JS-LOG-01` sensitive logging, `server.ts:366` | Practice finding | Confirmed |
| `JS-SSRF-01` profile-image SSRF, `routes/profileImageUrlUpload.ts:24` | Practice finding | Confirmed |
| `JS-CONF-03` `/support/logs` directory listing, `server.ts:302` | Confirmed | Review: weakness answered unknown |
| `JS-MASS-02` to `JS-MASS-05`, generated routes at `server.ts:529` | Confirmed | Review |
| `JS-AUTHZ-N05` control, liking another user's review | Finding | Protected |

False positives at reviewed or newly read locations:

| Location | Gemini | Basis |
|---|---|---|
| `server.ts:294` `.well-known` listing | Confirmed configuration | Keyed control `JS-CONF-N01`; holds only published files |
| `routes/fileServer.ts:32` null-byte file read | Confirmed path traversal (new) | Owner decision of 2026-11-24: the read cannot leave its directory |
| `server.ts:307` Swagger UI | Confirmed information exposure (new) | Read in this session: it serves the published B2B API description |
| `routes/likeProductReviews.ts:35`, `:50` | Not an authorization finding | — |
| `routes/orderHistory.ts:36` | Not a finding | — |

<a id="oss-oopssec-store"></a>

## OSS OopsSec Store

13 of 13 positives Confirmed, no keyed control a finding, as with `gpt-6-luna`. The findings
sit at the same 19 locations; the two practice findings of the earlier report are Confirmed.
Findings outside the key are not reviewed.

<a id="vulnerablesymfony"></a>

## VulnerableSymfony

30 of 30 positives found: 29 Confirmed and `SYM-XSS-03` (`templates/blog/post.html.twig:37`)
as a raw-output practice finding (`gpt-6-luna`: Confirmed). No control is a finding. One new
Confirmed location, `config/packages/security.yaml:5`, selects the MD5 hasher: real, the
configuration site of the keyed `SYM-HASH-01`. Protected rose from 22 to 25 and Review fell from
7 to 3.

<a id="dvwa"></a>

## DVWA

11 of 11 positives Confirmed. The record count grew from 265 to 308 because the scanner now
records the PHP SQL operand facts (PR #52) and contract-free SQL records (PR #56).

- **Reviewed SQL false positives:** four of the nine locations are still Confirmed SQL
  injection (`login.php:47`, `vulnerabilities/bac/source/medium.php:29`,
  `vulnerabilities/xss_s/source/medium.php:19` and `high.php:19`). The other five carry only the
  construction-practice finding. Scanner revision and model both changed, so this does not
  isolate either.
- **Now Confirmed, Review before:** the session cookie without `Secure` and readable by script
  (`dvwa/includes/dvwaPage.inc.php:72`), `allow_url_include` in `php.ini:5` and the unguarded
  user update in `vulnerabilities/authbypass/change_user_details.php:48`. The earlier sample notes
  already called all three real.
- **New Confirmed location:** `dvwa/includes/DBMS/PGSQL.php:66`, the setup insert, builds
  `$_SERVER['PHP_SELF']` into the statement. `PHP_SELF` carries request-chosen path text, so it
  is real. Read in this session; not independently reviewed.

<a id="vulnpy"></a>

## VulnPy

All 10 positives Confirmed. The published `gpt-6-luna` report (scanner `57c29dc`) predates the
deserialization analyzer and found 6; the four Pickle and PyYAML sinks are now Confirmed in 120
contexts. Other families match the earlier report: 196 path (was 195), 90 code
execution, 78 SQL, 61 command, 31 XSS. Findings outside the key are not reviewed.

## Limits

- One run per application and model. Request wording and model sampling move some answers
  between runs; these are not repeat-averaged results.
- The Gemini and `gpt-6-luna` reports differ in scanner revision as well as model.
- vuln-nextjs was not rerun.
- The new false-positive and real-finding readings above were made by the agent that ran the
  scans and have not been checked independently.
