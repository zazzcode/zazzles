# DVWA: expected source vulnerabilities

[DVWA](https://github.com/digininja/DVWA) is an intentionally vulnerable PHP application and the
acceptance target of the [PHP support contract](../specifications/scan/php-support.md). Expectations
below derive from source review of the acceptance pin `a1978a2fed195acd093010af6395f86a281537ca`
and are structural: a required candidate kind with source-attributed evidence at the named sink.
A candidate is not a verdict; protection on impossible-level controls is decided by assessment.
Local reference: `<DEV_ROOT>/zazzcode/DVWA` (must stay `git status --porcelain` clean).

## Required supported positives

Each module dispatches one of four security-level alternatives (low/medium/high/impossible) from
`vulnerabilities/<module>/index.php` through `dvwaSecurityLevelGet()`; the impossible level is a
scoped safe control, not an uncovered path. Paths are relative to the DVWA root; lines cite the
pinned revision.

| Case | Entry / source | Operation and expected defect |
|---|---|---|
| SQLI-001 | `vulnerabilities/sqli/source/low.php:10` (also medium/high; impossible PDO at `:16`) | `$_GET['id']` interpolated into `SELECT ... WHERE user_id = '$id'`; all four alternatives yield `sql_query_candidate` (impossible records binding controls) |
| SQLI-002 | `vulnerabilities/sqli_blind/source/low.php:11` | Same input shape; boolean/blind variants remain interpolated queries |
| AUTH-001 | `vulnerabilities/brute/source/low.php:12` | `$_POST` `user`/`pass` interpolated into `SELECT * FROM users WHERE user = '$user' AND password = '$pass'` |
| AUTH-002 | `vulnerabilities/captcha/source/low.php:61` | Candidate-only, not a Confirmed positive: the UPDATE interpolates `md5($pass_new)` (non-content) and `dvwaCurrentUser()` (session-sourced via `dvwaPage.inc.php:172`), so no raw request→SQL path exists; unresolved session/helper origin honestly stays Review |
| CSRF-001 | `vulnerabilities/csrf/source/low.php:16` | `$_GET['password_new']` interpolated into `UPDATE users SET password = ...` |
| CMD-001 | `vulnerabilities/exec/source/low.php:14` (unix branch `:10`) | `$_REQUEST['ip']` concatenated into `shell_exec('ping -c 4 ' . $target)`; medium/high re-encode but stay raw; impossible `escapeshellarg` records quoted protection |
| DVWA-API-CMD-01 | `vulnerabilities/api/public/index.php:82` → `vulnerabilities/api/src/HealthController.php:84` | `new HealthController($requestMethod, $version, $command)` then `processRequest()`; `switch ($this->command)` selects `checkConnectivity()` on `connectivity`, which reads `json_decode(file_get_contents('php://input'))['target']` and runs `exec("ping -c 4 " . $target)` at `:88`. No control |
| XSSR-001 | `vulnerabilities/xss_r/source/low.php` (+medium/high; impossible `htmlspecialchars`) | `$_GET['name']` echoed at the shared render sink `dvwa/includes/dvwaPage.inc.php:388` (`dvwaHtmlEcho`); reflected candidates are attributed by input-source span, not sink file |
| XSSS-001 | `vulnerabilities/xss_s/source/low.php:17` (write) + `dvwa/includes/dvwaPage.inc.php:610`/`:625` (read/render) | `$_POST` `mtxMessage`/`txtName` → `INSERT INTO guestbook ( comment, name )` (confirmed SQL construction) → `dvwaGuestbook()` `SELECT name, comment` + `mysqli_fetch_row` render; stored link key `php-sql:guestbook.comment`/`.name` resolves to the writing entry. The four render records exceed the 64KB judge wire limit and are judged in path groups (one request per security-level file, packed while it fits). Expected status: Confirmed stored XSS; a construction-practice finding does not satisfy this row |
| UPLD-001 | `vulnerabilities/upload/source/low.php:9` | `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` with the client file name kept, extension included, under `hackable/uploads/`: unrestricted file type (CWE-434), `file_upload_candidate`. `basename()` at `:6` contains the path, so the `path_traversal_candidate` at the same call (`UPLD-001-PATH`) must not be a finding. Medium checks only the client-declared type (`:10`, `:14`); high adds an extension allow-list and `getimagesize` (`:15`–`:17`); impossible generates the name and re-encodes (`:19`, `:33`–`:38`) |
| FI-001 | `vulnerabilities/fi/index.php:36` | `include( $file )` with `$_GET['page']` composed path (`fi/source/low.php`); impossible allowlist keeps the candidate with verified restrictions |
| REDIR-001 | `vulnerabilities/open_redirect/source/low.php:4` | `header ("location: " . $_GET['redirect'])` — lowercase `location:` accepted case-insensitively; impossible `:18` allowlist checks precede the same sink |
| CODE-001 | `vulnerabilities/view_help.php:20`/`:22` | `$_GET['id']`/`locale` compose the `file_get_contents` path whose return is concatenated into `eval('?>' . ... . '<?php ')`; path control is content control, so `code_execution_candidate` and the `php-filesystem-v1` read claim coexist |

### Key corrections

| Date | Row | Was | Now | Source evidence |
|---|---|---|---|---|
| 2026-11-19 | UPLD-001 | `path_traversal_candidate`, positive | `file_upload_candidate`, positive; `UPLD-001-PATH` control for the path claim | `low.php:6` applies `basename()` to the client name, which contains the path; the client extension is kept and no type control precedes `move_uploaded_file` at `:9` |
| 2026-11-19 | XSSS-001 | positive at any finding status | positive with `expect_status: confirmed` | The row is a stored-XSS case; the published report satisfied it with the guestbook INSERT's construction-practice finding only |
| 2026-11-19 | DVWA-API-CMD-01 | not keyed | positive | `HealthController.php:84`–`:88`, reached from `api/public/index.php:82` |

## Scoped safe controls

The impossible security level is the designed control for every module above: PDO prepared
statements (SQLI-001), `md5` token comparison + PDO (AUTH-001/002), anti-CSRF tokens (CSRF-001),
`escapeshellarg` (CMD-001), `htmlspecialchars` (XSSR-001/XSSS-001), generated name and re-encoded image
(UPLD-001, protected control `PC-UPLD-01`), page allowlist (FI-001), host allowlist (REDIR-001), `dvwaHtmlEchoMessages` safe
rendering for CODE-001's help pages. These still produce candidates — with binding, quoting, or
encoding evidence — and the paid judge decides Protected; they are not expected to stay silent.

## Coverage boundaries and acceptance

Structural acceptance (offline): every required positive above produces its candidate kind with
source-attributed dependencies and no selection rejection. Bounded, honest gaps observed at the
pin — each still yields its unresolved-origin finding:

- `php-session:session_token` / `php-session:id` reads (e.g. `login.php:68`,
  `dvwa/includes/dvwaPage.inc.php:496`) stay origin-unresolved: the session write helper
  (`dvwaPage.inc.php:650`) expands in a different entry than its readers, and cross-entry session
  write ordering is not established.
- `php-sql:bac_log.timestamp` read stays origin-unresolved: the `bac_log` INSERT mixes a
  non-dependency `NOW()` column with one interpolation, and exact-count-or-skip attribution
  declines to invent a mapping.
- `view_source.php` / `view_source_all.php` produce `php-filesystem-v1` read claims
  (`file_get_contents` over the show-source flow) without a stronger path claim.
- Shared-sink rendering: XSS sinks physically live in `dvwa/includes/dvwaPage.inc.php:388`;
  module attribution rides input-fact source spans, so sink-file-only grouping undercounts a
  module. `csp` module produces one reflected candidate from its JSONP endpoint.

`ZAZZLES_DVWA=<checkout> go test ./internal/pipeline -run TestDVWASourceKey` verifies the required
positives against a clean checkout at the pinned revision. Expected labels live only in test code
and never enter model inputs. Paid judgment (AC14) is a separate, explicitly budgeted step; its
results belong in `php-support-results.md` and the published sample, not in this guide.
Paid-run interpretation: dispatch alternatives share one candidate — a Confirmed record rests on
its raw (low/medium/high) dependency path while impossible-level sibling paths keep their own
recorded protections; "no impossible-level control is red" therefore means no record whose
dependency sources are exclusively impossible-level is red.

Before a new evaluation, verify the DVWA revision; re-review changed modules and re-pin lines.
Never carry old decisions onto changed evidence.
