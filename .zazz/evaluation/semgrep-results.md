# Semgrep CE results on four samples

**2026-11-24.** Semgrep Community Edition on the four comparison samples. This document records
what the tool reported. Matching against the answer keys and the comparison with Zazzles are
in the comparison summary, which
[branch 2](../specifications/juiceshop-nextjs-hardening-2.md) of the hardening lane writes.
The 2026-11-01 results on three JavaScript samples are in the
[comparison history](comparison-history.md). How to repeat a run:
[Semgrep CE cheat sheet](../../docs/scan/semgrep-ce-cheat-sheet.md).

## Tool and rules

| Item | Value |
|---|---|
| Semgrep | 1.183.0, Community Edition, Homebrew build. No login, no Pro engine |
| Options | `--metrics=off --timeout 30 --dataflow-traces`, offline against the snapshot below |
| Rule snapshot | `<DEV_ROOT>/zazzcode/zazzles/_test-findings/semgrep-rules/20261124/`, downloaded once from `https://semgrep.dev/c/p/<pack>` on 2026-11-24 |
| Rules after merging | 564, all valid (`semgrep scan --validate`) |
| Rule license | Semgrep Rules License v1.0 |

| Pack | File | SHA-256 |
|---|---|---|
| `p/javascript` | `javascript.yaml` | `745b13761f38588a36695be1da76b251369d4f6f61c22122a21e4386eae46b90` |
| `p/typescript` | `typescript.yaml` | `745b13761f38588a36695be1da76b251369d4f6f61c22122a21e4386eae46b90` |
| `p/php` | `php.yaml` | `cefc4af5fccc5406f018fce559c6056f810aea8a7f1ff4b541210839873b3c77` |
| `p/xss` | `xss.yaml` | `38ef42b59fdc6c9a323f008ea796aa6631218a8df77bf99b6599ac32e1bf34ac` |
| `p/owasp-top-ten` | `owasp-top-ten.yaml` | `983513761ad687c438843c13974af3694036898db19170dd50e838e42b017649` |

The registry served the same file for `p/javascript` and `p/typescript`. `p/symfony` does not
exist in the registry (HTTP 404), so no Symfony-specific pack was used. `p/php` is new since the
November snapshot, which had 563 rules.

Exclusions on every run: `node_modules`, `vendor`, `.github`, `dist`, `build`, `var`,
`*.min.js` and `frontend/src/assets/private/three.js`. They match the Zazzles source scope.

## Runs

Raw output is under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<sample>/semgrep-20261124-1/`
(`results.json`, `results.sarif`, `results.txt`). Every run exited 0. Each sample's tracked
files were unchanged before and after.

| Sample | Revision | Files scanned | Results | Errors | Time |
|---|---|---:|---:|---:|---:|
| OWASP Juice Shop | `f189f52` | 1,168 | 30 | 32 | 9 s |
| vuln-nextjs | `f5d47de` | 95 | 7 | 0 | 5 s |
| DVWA | `a1978a2` | 222 | 44 | 2 | 4 s |
| vuln-symfony | `086f81f` | 97 | 8 | 0 | 5 s |

Juice Shop's 32 errors are 16 syntax errors and 16 partial parses in
`data/static/codefixes/*`, which are challenge snippets and not complete TypeScript files.
DVWA's two are partial parses of its `Dockerfile` and one HTML file.

## Results by rule

Rule identifiers are shown without the snapshot path prefix.

### OWASP Juice Shop

| Results | Rule | Locations |
|---:|---|---|
| 6 | `express-sequelize-injection` | `routes/login.ts:34`, `routes/search.ts:23`, and four `data/static/codefixes` snippets |
| 5 | `express-check-directory-listing` | `server.ts:269`, `:290`, `:294`, `:298`, `:302` |
| 4 | `express-res-sendfile` | `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14`, `routes/quarantineServer.ts:14` |
| 1 | `express-open-redirect` | `routes/redirect.ts:18` |
| 1 | `code-string-concat` | `routes/userProfile.ts:65` |
| 1 | `hardcoded-jwt-secret` | `lib/insecurity.ts:54` |
| 5 | `aws-subnet-has-public-ip-address` (Terraform) | Two infrastructure files and three snippets |
| 5 | `insecure-load-balancer-tls-version` (Terraform) | The same five files |
| 2 | `npm-missing-minimum-release-age` | `.npmrc:1`, `frontend/.npmrc:1` |

The result set is the same 30 as on 2026-11-01. Semgrep reported nothing for the NoSQL queries,
the Angular and server XSS sinks, the SSRF at `routes/profileImageUrlUpload.ts:24`, the `md5`
password digest, the error handler, the metrics endpoint or any access-control defect.

### vuln-nextjs

| Results | Rule | Locations |
|---:|---|---|
| 2 | `react-dangerouslysetinnerhtml` | `pages/xss/unsafe/reflected.js:15` and `pages/xss/sanitized/reflected.js:16`, which the lab labels a DOMPurify control |
| 1 | `code-string-concat` | `pages/api/vulnerable-submit.js:15` |
| 4 | Package-manager policy rules | `.npmrc:1`, `pnpm-workspace.yaml:1` |

Semgrep reported nothing for the three PGlite SQL injections, the command injection, the file
read, the SSRF, or the stored, script-context and guestbook XSS rows.

### DVWA

| Results | Rule | Locations |
|---:|---|---|
| 14 | `php.lang.security.injection.tainted-sql-string` | `vulnerabilities/bac/source/*.php` and others |
| 11 | `php.lang.security.injection.tainted-filename` | `instructions.php:26`, `vulnerabilities/fi/source/high.php:7`, `vulnerabilities/view_help.php`, `vulnerabilities/view_source.php` and others |
| 9 | `php.lang.security.injection.tainted-exec` | `vulnerabilities/exec/source/*.php`, `vulnerabilities/api/src/HealthController.php:88` |
| 8 | `php.lang.security.tainted-exec` | The `vulnerabilities/exec/source/*.php` locations again, from a second rule |
| 1 | `php.lang.security.phpinfo-use` | `phpinfo.php:8` |
| 1 | `php.lang.security.injection.echoed-request` | `vulnerabilities/csp/source/jsonp.php:12` |

Two rules report the same command execution lines, including those in
`vulnerabilities/exec/source/impossible.php`, the sample's hardened level.

### vuln-symfony

| Results | Rule | Locations |
|---:|---|---|
| 6 | `php.lang.security.md5-used-as-password` | `src/Command/BlogInitCommand.php:91`, `:101`, `src/Controller/AdminController.php:105`, `src/Controller/LoginController.php:106`, `src/Controller/PasswordResetController.php:78`, `src/Controller/UserController.php:41` |
| 1 | `php.lang.security.phpinfo-use` | `public/info.php:2` |
| 1 | `dockerfile.security.missing-user-entrypoint` | `Dockerfile:57` |

## Limits of this record

- CE taint analysis is single-file and intraprocedural. Cross-file and stored flows need
  Semgrep Pro, which was not run.
- A result count is not a score. Results in test files and challenge snippets are listed above
  where they occur and are not findings in the running application.
- No result here has been reviewed against source beyond its location.
