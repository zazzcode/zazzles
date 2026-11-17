# DVWA: expected source vulnerabilities

[DVWA](https://github.com/digininja/DVWA) is an intentionally vulnerable PHP application and the
acceptance target of the [PHP support contract](../specifications/php-support.md). Expectations
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
| AUTH-002 | `vulnerabilities/captcha/source/low.php` | Same query shape as AUTH-001; the captcha gate is control flow, not data protection |
| CSRF-001 | `vulnerabilities/csrf/source/low.php:16` | `$_GET['password_new']` interpolated into `UPDATE users SET password = ...` |
| CMD-001 | `vulnerabilities/exec/source/low.php:14` (unix branch `:10`) | `$_REQUEST['ip']` concatenated into `shell_exec('ping -c 4 ' . $target)`; medium/high re-encode but stay raw; impossible `escapeshellarg` records quoted protection |
| XSSR-001 | `vulnerabilities/xss_r/source/low.php` (+medium/high; impossible `htmlspecialchars`) | `$_GET['name']` echoed at the shared render sink `dvwa/includes/dvwaPage.inc.php:388` (`dvwaHtmlEcho`); reflected candidates are attributed by input-source span, not sink file |
| XSSS-001 | `vulnerabilities/xss_s/source/low.php:17` (write) + `dvwa/includes/dvwaPage.inc.php:610`/`:625` (read/render) | `$_POST` `mtxMessage`/`txtName` → `INSERT INTO guestbook ( comment, name )` → `dvwaGuestbook()` `SELECT name, comment` + `mysqli_fetch_row` render; stored link key `php-sql:guestbook.comment`/`.name` resolves to the writing entry |
| UPLD-001 | `vulnerabilities/upload/source/low.php:9` | `move_uploaded_file($_FILES['uploaded']['tmp_name'], $target_path)` with request-derived `name`; impossible level enforces renaming/size checks |
| FI-001 | `vulnerabilities/fi/index.php:36` | `include( $file )` with `$_GET['page']` composed path (`fi/source/low.php`); impossible allowlist keeps the candidate with verified restrictions |
| REDIR-001 | `vulnerabilities/open_redirect/source/low.php:4` | `header ("location: " . $_GET['redirect'])` — lowercase `location:` accepted case-insensitively; impossible `:18` allowlist checks precede the same sink |
| CODE-001 | `vulnerabilities/view_help.php:20`/`:22` | `$_GET['id']`/`locale` compose the `file_get_contents` path whose return is concatenated into `eval('?>' . ... . '<?php ')`; path control is content control, so `code_execution_candidate` and the `php-filesystem-v1` read claim coexist |

## Scoped safe controls

The impossible security level is the designed control for every module above: PDO prepared
statements (SQLI-001), `md5` token comparison + PDO (AUTH-001/002), anti-CSRF tokens (CSRF-001),
`escapeshellarg` (CMD-001), `htmlspecialchars` (XSSR-001/XSSS-001), renamed+validated upload
(UPLD-001), page allowlist (FI-001), host allowlist (REDIR-001), `dvwaHtmlEchoMessages` safe
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

`ZAZZLES_DVWA=<checkout> go test ./internal/parse -run TestDVWASourceKey` verifies the required
positives against a clean checkout at the pinned revision. Expected labels live only in test code
and never enter model inputs. Paid judgment (AC14) is a separate, explicitly budgeted step; its
results belong in `php-support-results.md` and the published sample, not in this guide.

Before a new evaluation, verify the DVWA revision; re-review changed modules and re-pin lines.
Never carry old decisions onto changed evidence.
