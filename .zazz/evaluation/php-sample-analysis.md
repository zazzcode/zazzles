# PHP samples: expected vs found

Source-reviewed expectations for the two PHP samples compared with what zazzles finds after the
independent review, plus the code-quality (practice and input-validation) findings it reports.
Companion to the [PHP results](php-support-results.md) and the
[DVWA detection guide](dvwa-detection-guide.md).

## Runs of record

| Sample | Pin | Scanner | Paid runs (OpenAI `gpt-6-luna`, no fallback) |
| --- | --- | --- | --- |
| [DVWA](https://github.com/zazzcode/DVWA) | `a1978a2` | `bc40266` | SQL + command `run-820679119` (124 requests), XSS `run-3079080553` (81), path/code/redirect from `run-1812921365` |
| [php-goof](https://github.com/snyk-labs/php-goof) | `24267df` | `bc40266` | `run-3096288209` (14 requests) |

Every record above replays exactly against a fresh analysis at `bc40266` (`TestReplaySavedRun`),
so the per-family runs form one evaluation of the same code. The final commit `6f3c888` changes 8
DVWA records after those runs (server-determined `$_SERVER` keys); they are listed under
[Not re-judged](#not-re-judged). Both checkouts stayed `git status --porcelain` clean.

Outcome terms: **Confirmed** = confirmed vulnerability; **Protected** = protected for the claim;
**Review** = needs evidence (blocked or inconclusive, never a safe verdict); **Practice** = poor
practice without a confirmed exploit.

## php-goof

Six first-party files; `vendor/` is not installed, so the three dependency CVEs the app
demonstrates (league/commonmark link XSS, PHPMailer `validateAddress`, dompdf font RCE) are
outside first-party flow analysis by design.

| Expected (source review) | Location | Zazzles | Match |
| --- | --- | --- | --- |
| SQL injection, `$_GET['edid']` unquoted | `func.php:14` (in all 5 entries that require it) | Confirmed ×5 | ✅ |
| SQL injection, `$_POST['edid']` in UPDATE | `tasks.php:14` | Confirmed | ✅ |
| SQL injection, `$_GET['delid']` unquoted | `tasks.php:28` | Confirmed | ✅ |
| Reflected XSS, `$_GET['edid']` in `value="…"` | `index.php:39` | Review (`xss_context_unresolved`) | ⚠️ judge disagreement |
| Not a first-party XSS: title is `urlencode`d at write | `index.php:37`, `:71` | Review; scanner records the write-side `urlencode` as an attribute/URL control | ✅ no false positive |
| Dependency XSS (commonmark), `urldecode` undoes the write control | `index.php:65` | Review (`render_protection_unresolved`) | ✅ honest limit |
| Not request content: session messages are literals | `index.php:30–31` | no record | ✅ |
| DB-generated `id`/`created_at` | `index.php:66–69` | Review (`storage_origin_unresolved`) | ✅ honest limit |
| Dependency CVEs (PHPMailer, dompdf) | `mail.php`, `pdf.php` | not modeled | out of scope |

`index.php:39` is the one missed supported vulnerability. The scanner establishes
`output_context=html_attribute` from the surrounding inline HTML and sends that markup as
`render_markup_context` evidence; in every paid run after that fix the model answered `html_text` (≈0.85),
and the shared policy refuses a verdict that contradicts the established context. Exposure was
answered `vulnerable` in the later probes. This is a judge-side limitation, recorded as a
follow-up rather than weakened in policy.

## DVWA

### Detection-guide cases

Rows are the [detection guide](dvwa-detection-guide.md) cases; counts are records across the
dispatching `index.php` entry and the directly requestable `source/<level>.php` entries.

| Case | Expected | Records | Zazzles | Match |
| --- | --- | --- | --- | --- |
| SQLI-001 | low/medium/high vulnerable; impossible PDO protected | 11 | 9 Confirmed, 2 Protected | ✅ |
| SQLI-002 | same shape (blind) | 11 | 9 Confirmed, 2 Protected | ✅ |
| AUTH-001 | brute low/medium/high vulnerable; impossible PDO | 11 | 7 Confirmed, 1 Protected, 3 Review | ✅ (impossible helper queries stay Review) |
| AUTH-002 | candidate only: `md5` password + session user | 8 | 6 Review, 2 Protected | ✅ |
| CSRF-001 | SQL candidate; not a SQL injection (`md5` + session user) | 9 | 6 Review, 2 Protected, 1 Confirmed (`test_credentials.php` raw login query) | ✅ |
| CMD-001 | low/medium/high vulnerable (deny-lists leave `\|`); impossible numeric octets | 16 | 16 Confirmed | ⚠️ 4 impossible records Confirmed by the judge |
| XSSR-001 | low/medium/high reflected; impossible `htmlspecialchars` | 4 | 4 Confirmed | ✅ (each record also carries the theme-cookie witness) |
| XSSS-001 write | guestbook INSERT construction | 7 | 2 Confirmed, 1 Protected, 4 Review | ✅ |
| XSSS-001 render | guestbook stored render | 4 | 4 Review (64KB wire limit, unsent) | documented limit |
| UPLD-001 | control outcome: `basename` guards the destination | 8 | 1 Protected, 7 Review (`path_answers_inconsistent`) | ⚠️ judge disagreement |
| FI-001 | low/high vulnerable; medium `str_replace` bypassable; impossible allowlist | 4 | 2 Confirmed, 2 Review | ✅ (medium/impossible stay Review) |
| REDIR-001 | low vulnerable; medium/high prefix checks | 3 | 1 Confirmed, 2 Practice | ✅ |
| CODE-001 | `view_help.php` eval of file content | 2 | 2 Confirmed | ✅ |

**Change against the AC14 pass** (scanner `1deee35`, counted the same way): Confirmed 107 → 115,
Protected 10 → 12, Review 177 → 110 (including unsent records), records 296 → 240 (72
zero-dependency constant-SQL records removed, real flows added). CMD-001 went from 4 to 16 Confirmed: medium/high deny-lists are now modeled. SQLI-001/002
gained medium/high Confirmed once the sibling-gap leak was fixed. AUTH-002 and CSRF-001 stopped
being Confirmed SQL injections once stored-only content was blocked.

### Vulnerabilities found beyond the guide

Source-reviewed, Confirmed at the evaluation of record:

| Finding | Location | Notes |
| --- | --- | --- |
| Cookie-reflected XSS on every page | `dvwa/includes/dvwaPage.inc.php:405` (`<body class="… " . dvwaThemeGet() . ">`) | `$_COOKIE['theme']` unescaped in an attribute; 28 page records rest on this witness alone. Exploiting it requires planting the victim's cookie. |
| Reflected XSS: username | `vulnerabilities/brute/source/*.php` welcome message | `$_GET['username']` echoed |
| Reflected XSS: password fields | `vulnerabilities/captcha/source/{low,medium}.php` hidden inputs | `$_POST['password_new'/'password_conf']` |
| Reflected XSS: id | `vulnerabilities/sqli/source/low.php` (`ID: {$id}`) | `$_REQUEST['id']`; the page also renders stored `first_name`/`last_name` |
| Reflected XSS: `PHP_SELF` | `vulnerabilities/api` page | `$_SERVER['PHP_SELF']` includes attacker `PATH_INFO` |
| Script injection: `include` | `vulnerabilities/csp/source/*.php` | `$_POST['include']` into the page; DVWA relies on its CSP header, which zazzles does not model |
| JSONP callback injection | `vulnerabilities/csp/source/jsonp.php:12` | Recorded as HTML XSS; the response is `application/json` (Content-Type not modeled), so this is a script-inclusion vector rather than HTML-context XSS |
| SQL injection: broken access control | `vulnerabilities/bac/source/{low,medium}.php` | `$_GET['user_id']` interpolated; log INSERTs also take `X-Forwarded-For` |
| SQL injection: login | `login.php:47` | `$_POST` user/password interpolated after `mysqli_real_escape_string`; Confirmed by the judge, defensible only as a construction finding |
| Path traversal: source viewer | `vulnerabilities/view_source.php`, `view_source_all.php` | `$_GET['id']`/`security` compose `file_get_contents` paths |

### Known disagreements and limits

- **CMD-001 impossible (4 records):** every octet passes `is_numeric` before reassembly, so all
  paths are `guarded`. The shared command policy lets a model `vulnerable` answer stand on guarded
  paths (guards can be partial), and the model answered vulnerable. Source review: no command text
  can be injected. PHP 8 numeric strings accept trailing whitespace (including `\n`), so a
  separator can appear but only digits follow it. Treat these as a judge false positive.
- **UPLD-001 (7 Review):** the model answers `vulnerable` despite `basename` on every level; the
  facts say guarded, so policy blocks with `path_answers_inconsistent`. The upload weakness DVWA
  teaches (unrestricted file type) is not a path-traversal claim.
- **XSSS-001 render:** the four guestbook render records exceed the 64KB judge wire limit and stay
  unsent; the INSERT construction is Confirmed and the stored link resolves.
- **`$_COOKIE['security']`:** reaches page output as a raw path in 17 records, but
  `dvwaPage.inc.php:22` resets it to an allowlisted level. Superglobal element writes are not
  modeled. No record's status depends on this path alone.
- **`$_DVWA` unresolved:** `config/config.inc.php` is absent at the pin (only `.dist`), so
  `dvwaDatabaseConnect()` queries (`dvwaPage.inc.php:570`, one per entry) stay Review.

### Not re-judged

Commit `6f3c888` stopped treating server-determined `$_SERVER` keys (`SCRIPT_NAME`, `REMOTE_ADDR`,
…) as request sources. That changes 8 records after the paid runs:

- `dvwa/includes/DBMS/MySQL.php:60` (×2 entries): Confirmed SQL injection from `SCRIPT_NAME`. That
  was a false positive. The records now have no request dependency and a `query_structure_unresolved`
  blocker, so policy keeps them Review without a model call.
- `vulnerabilities/bac/source/{low,medium}.php` log INSERTs (×2 Confirmed, ×2 Review): drop the
  `REMOTE_ADDR` path and keep `$_GET['user_id']` and `X-Forwarded-For`.
- `setup.php` and `vulnerabilities/api/help/help.php` page renders (×2 Review): drop a sibling path.

## Code quality: practice and input validation

These are reported separately from vulnerability verdicts. A practice finding needs no exploit;
validation statements never substitute for sink protection.

| Item | DVWA | php-goof |
| --- | --- | --- |
| SQL text built by interpolation/concatenation (Practice: "A value is built into SQL query text") | 60 | 0 (all 7 are Confirmed injections) |
| Untrusted data reaches raw HTML output without established encoding (Practice) | 38 | 1 |
| Stored value rendered with an unresolved write origin (Review) | 2 | 3 |
| Open-redirect protection relies on prefix/substring checks (Practice) | 2 (`open_redirect` medium/high) | 0 |
| SQL calls that keep values bound (Protected: "SQL values remain separate from query syntax") | 10 | 0 |

Input-validation statements attached to findings:

| Statement | DVWA | php-goof |
| --- | --- | --- |
| Complete enforcement of a field policy not established (SQL findings) | 67 | 7 |
| Field policy not established from the supplied evidence | 72 | 0 |
| Type, conversion or length restriction observed; whether it meets the business requirement still needs review | 10 | 0 |
| XSS: validation is separate from output encoding | 91 | 7 |

No sample establishes a complete server-side field policy. The 10 "restriction observed" records
are `is_numeric`/`intval`/length checks (for example the SQLi and brute-force impossible levels).
They are reported as partial validation, never as query protection. Browser `required`
attributes in php-goof (`index.php` forms) are not server enforcement and are not credited.

## Follow-ups

- Judge context agreement for PHP inline-HTML attributes (php-goof `index.php:39`): the scanner
  facts and markup evidence are correct, but the model keeps answering `html_text`.
- Shared command policy: whether a `vulnerable` answer should stand when every path is guarded by a
  numeric constraint (DVWA exec impossible).
- Model superglobal element writes (`$_COOKIE['security'] = …`) and response `Content-Type`
  headers (JSONP).
- Constant-only stored writers (`INSERT … VALUES ('literal')`) are not indexed, so their reads stay
  unresolved.
