# Bearer CLI results on four samples

**2026-11-24.** Bearer CLI on the four comparison samples. This document records what the tool
reported. Matching against the answer keys and the comparison with Zazzles are in the
comparison summary, which [branch 2](../specifications/juiceshop-nextjs-hardening-2.md) of the
hardening lane writes. The 2026-10-31 results, including the thirteen authored controls, are in
the [comparison history](comparison-history.md). The repeat protocol is
[bearer-comparison.md](bearer-comparison.md). Bearer is a comparator, not ground truth.

## Tool and rules

| Item | Value |
|---|---|
| Bearer CLI | Built from source at `a7a87529a12af1eb2afaa7864dc043b6ab8d9c4e` (`<DEV_ROOT>/scanners/bearer`), Go 1.27.3, darwin/arm64, `-mod=readonly`. Reports `dev`, `devSHA`. The checkout is unchanged |
| Rules | [Bearer/bearer-rules](https://github.com/Bearer/bearer-rules) at `82c335f781a61a6d8b052394f84fd1d93edec467` (last commit 2026-03-13), cloned to `<DEV_ROOT>/zazzcode/zazzles/_test-findings/bearer-rules/20261124/` |
| Rule loading | `--disable-default-rules --external-rule-dir <snapshot>/rules`. Only the snapshot's rules ran |
| Rules in the snapshot | 100 JavaScript and TypeScript rule files and 81 PHP rule files; the snapshot also holds Go, Java, Python and Ruby rules |
| Scanner | `sast` only, report `security`. No secrets scanner, no privacy report |
| Edition | Open-source CLI. Bearer Pro was not run |

The rules revision is the one the 2026-10-31 run used: the rules repository has not changed
since. The CLI is a later revision than that run's `e3753de`.

Other options: `--disable-version-check`, `--disable-domain-resolution`, an empty configuration
file and an empty ignore file, `--skip-test=false` (test files are scanned), `--force` (no
cache), `--parallel 4`, JSON output. The process environment held only `PATH`, `TMPDIR` and a
scratch `HOME`.

Skipped paths on every run: `node_modules`, `vendor`, `.github`, `dist`, `build`, `var`,
`.next`, `test-results`, `*.min.js` and `frontend/src/assets/private/three.js`. Unlike the
October run, the tool scanned each sample's own tree, not a copy of its JavaScript files.

## Runs

Raw output is under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<sample>/bearer-20261124-1/`
(`results.json`). Every run exited 1, which is Bearer's status for "findings present". SARIF
was not produced. Each sample's tracked files were unchanged after the run.

| Sample | Revision | Findings | Rules that fired | Critical | High | Medium | Low | Time |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| OWASP Juice Shop | `f189f52` | 675 | 29 | 290 | 22 | 39 | 324 | 11 s |
| vuln-nextjs | `f5d47de` | 48 | 12 | 19 | 11 | 1 | 17 | 7 s |
| DVWA | `a1978a2` | 162 | 16 | 20 | 101 | 38 | 3 | 4 s |
| vuln-symfony | `086f81f` | 17 | 6 | 3 | 0 | 14 | 0 | 2 s |

## Results by rule

"Outside tests" counts distinct locations whose path is not under a test directory, a
`*.spec.*` file or `data/static/codefixes`.

### OWASP Juice Shop

| Locations | Outside tests | Rule | Locations outside tests |
|---:|---:|---|---|
| 278 | 263 | `javascript_lang_logger_leak` | Mostly `data/datacreator.ts` and startup code |
| 263 | 3 | `javascript_lang_hardcoded_secret` | `lib/insecurity.ts:42`, `:52`, `:150` |
| 33 | 5 | `javascript_express_exposed_dir_listing` | `server.ts:269`, `:290`, `:294`, `:298`, `:302` |
| 27 | 10 | `javascript_lang_observable_timing` | `lib/insecurity.ts:167`, `routes/2fa.ts` and others |
| 13 | 13 | `javascript_lang_insufficiently_random_values` | `data/datacreator.ts` and others |
| 11 | 2 | `javascript_lang_sql_injection` | `routes/login.ts:34`, `routes/search.ts:23` |
| 5 | 5 | `javascript_lang_path_traversal` | `routes/fileServer.ts:32`, two startup files, `data/staticData.ts:8`, `scripts/package.mjs:62` |
| 4 | 4 | `javascript_express_path_traversal` | `routes/dataErasure.ts:104`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14`, `routes/quarantineServer.ts:14` |
| 3 | 3 | `javascript_express_external_file_upload` | The key, log-file and quarantine servers at `:14` |
| 3 | 3 | `javascript_lang_eval_user_input` | `routes/b2bOrder.ts:22`, `:23`, `routes/userProfile.ts:65` |
| 2 | 2 | `javascript_lang_weak_hash_md5` | `lib/insecurity.ts:41`, `scripts/package.mjs:121` |
| 2 | 2 | `javascript_express_jwt_not_revoked` | `lib/insecurity.ts:52`, `:53` |
| 2 | 2 | `javascript_lang_unsafe_deserialization` | `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90` |
| 2 | 1 | `javascript_lang_jwt_hardcoded_secret`, `javascript_express_hardcoded_secret` (each) | `lib/insecurity.ts:54` |
| 1 | 1 | `javascript_express_server_side_request_forgery`, `javascript_lang_http_url_using_user_input` (each) | `routes/profileImageUrlUpload.ts:24` |
| 1 | 1 | `javascript_express_cross_site_scripting` | `routes/userProfile.ts:101` |
| 1 | 1 | `javascript_lang_raw_html_using_user_input` | `routes/userProfile.ts:90` |
| 1 | 1 | `javascript_express_open_redirect` | `routes/redirect.ts:18` |
| 1 | 1 | `javascript_lang_weak_hash_sha1` | `lib/utils.ts:82` |

Eight more rules fired once to seven times: `dangerous_insert_html`, `dynamic_regex`, `logger`,
`non_literal_fs_filename`, `session`, and three that fired only in test files
(`https_protocol_missing`, `helmet_missing`, `manual_html_sanitization`).

Bearer reported nothing for the NoSQL queries, the Angular XSS sinks, the error handler, the
metrics endpoint, the generated REST resources or any access-control defect. 541 of the 675
findings come from two rules, `logger_leak` and `hardcoded_secret`; 260 of the hardcoded-secret
locations are in test files and challenge snippets.

### vuln-nextjs

| Locations | Rule | Locations |
|---:|---|---|
| 17 | `javascript_lang_logger_leak` | API routes and scripts |
| 15 | `javascript_lang_hardcoded_secret` | 14 in tests; `pages/sql/[operation].js:5` |
| 6 | `javascript_react_dangerously_set_inner_html` | `pages/xss/unsafe/reflected.js:15`, `pages/xss/unsafe/comments.js:29`, `pages/xss/unsafe/script-context.js:16`, and the lab's controls `pages/xss/sanitized/reflected.js:16` and `pages/xss/safe/script-context.js:17` |
| 2 | `javascript_lang_format_string_using_user_input` | `pages/api/vulnerable-exec.js:17`, `pages/api/vulnerable-file-read.js:17` |
| 1 | `javascript_lang_os_command_injection`, `javascript_lang_dynamic_os_command` (each) | `pages/api/vulnerable-exec.js:21` |
| 1 | `javascript_lang_non_literal_fs_filename` | `pages/api/vulnerable-file-read.js:22` |
| 1 | `javascript_lang_eval_user_input` | `pages/api/vulnerable-submit.js:15` |
| 1 | `javascript_express_path_traversal` | `pages/api/secure/file-read.js:15`, the lab's allow-list control |
| 1 | `javascript_lang_http_url_using_user_input`, `javascript_lang_http_insecure` (each) | `pages/secure/ssrf.js:26`, the lab's same-origin control |
| 1 | `javascript_lang_observable_timing` | `scripts/check-scenarios.mjs:56` |

Bearer reported nothing for the three PGlite SQL injections or for the SSRF at
`pages/vulnerable/ssrf.js:22`. It reported the SSRF control and the file-read control.

### DVWA

| Locations | Rule |
|---:|---|
| 76 | `php_lang_raw_html_using_user_input` |
| 20 | `php_lang_weak_hash_md` |
| 10 | `php_lang_sql_injection` |
| 9 | `php_lang_path_using_user_input` |
| 8 | `php_lang_exec_using_user_input` (includes `vulnerabilities/exec/source/impossible.php`) |
| 8 | `php_lang_http_url_using_user_input` |
| 6 | `php_lang_cookie_missing_http_only` |
| 6 | `php_lang_insecure_cookie` |
| 6 | `javascript_lang_dangerous_insert_html` |
| 3 | `php_lang_information_leakage` |
| 3 | `php_lang_open_redirect` |
| 2 | `php_lang_eval_using_user_input` |
| 2 | `php_lang_permissive_allow_origin` |
| 1 | `php_lang_raw_output_using_user_input`, `php_lang_phpinfo`, `python_lang_path_traversal` (each) |

### vuln-symfony

| Locations | Rule | Locations |
|---:|---|---|
| 11 | `php_lang_weak_hash_md` | `src/Command/BlogInitCommand.php`, the admin, login, password-reset and user controllers |
| 2 | `php_symfony_sql_injection` | `src/Repository/PostRepository.php:66`, `src/Repository/UserRepository.php:76` |
| 1 | `php_lang_deserialization_of_user_input` | `src/Services/UserPref.php:36` |
| 1 | `php_lang_cookie_missing_http_only`, `php_lang_insecure_cookie` (each) | `src/Services/UserPref.php:41` |
| 1 | `php_lang_phpinfo` | `public/info.php:2` |

## Limits of this record

- A finding count is not a score. Two rules at one line are one concern.
- Test files and challenge snippets were scanned and are counted in the totals.
- No finding here has been reviewed against source beyond its location. The seven Juice Shop
  dispositions of 2026-10-31 are in the [history](comparison-history.md) and were not repeated.
- The run was not audited for network requests. Version checks and domain resolution were
  disabled by flag.
