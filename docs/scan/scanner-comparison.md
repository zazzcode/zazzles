# Scanner comparison

[Documentation](../README.md) · [Detection capabilities](detection-capabilities.md) · [Sample reports](../samples/README.md)

How Zazzles Code Scan compares with two other static scanners on four intentionally vulnerable
applications, measured against what is known about each application rather than against result
counts. Run on 2026-11-24.

**How to read it.** Each application has one table. Its rows are the application's known
vulnerabilities, from a source-reviewed answer key. Each scanner either found a row or missed
it, and a miss is shown for every scanner, Code Scan included. When a scanner reports something
the key or a source review shows to be safe, that is a false positive and gets its own row in
the second table. A result nobody has reviewed is counted as unreviewed, not as a false positive.

These are development reference applications. The numbers describe these four applications and
these scanner versions. They are not a general accuracy claim.

## Summary

| Application | Known vulnerabilities | Code Scan found | Semgrep CE found | Bearer found | Code Scan false positives | Semgrep CE false positives | Bearer false positives |
|---|---:|---:|---:|---:|---:|---:|---:|
| OWASP Juice Shop | 42 | 41 | 9 | 14 | 3 | 5 | 14 and two grouped rules |
| vuln-nextjs | 13 | 13 | 2 | 7 | 0 | 1 | 4 |
| DVWA | 11 | 11 | 5 | 6 | 0 | 2 | 2 |
| vuln-symfony | 30 | 30 | 2 | 5 | 0 | 0 | 2 |
| **Total** | **96** | **95** | **18** | **32** | **3** | **8** | **22 and two grouped rules** |

False positives are counted by location. A fourth Juice Shop false positive of the judged run,
a generated delete that an explicit handler answers first, is no longer recorded after a fix
made on the same branch and is not counted. Code Scan's found count includes three Juice Shop rows
it reports as a practice finding rather than a confirmed vulnerability. It misses one Juice
Shop row, a committed secret, a class it has no analyzer for. The Juice Shop and vuln-nextjs columns are from the runs of
[hardening 3](../../.zazz/specifications/juiceshop-nextjs-hardening-3.md), which added the read
of another user's basket as a known vulnerability and as a Code Scan finding, moved the
profile-image SSRF from Review to a practice finding, and added two Code Scan false positives.

### By weakness class

Known vulnerabilities found, across the four applications.

| Weakness class | Known vulnerabilities | Code Scan | Semgrep CE | Bearer |
|---|---:|---:|---:|---:|
| Cross-site scripting | 18 | 18 | 1 | 5 |
| SQL injection | 10 | 10 | 5 | 7 |
| Missing authorization | 10 | 10 | 0 | 0 |
| Insecure configuration | 8 | 8 | 4 | 4 |
| Path traversal | 7 | 7 | 0 | 2 |
| Mass assignment | 7 | 7 | 0 | 0 |
| Code and template injection | 6 | 6 | 2 | 4 |
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
| **Total** | **96** | **95** | **18** | **32** |

Code Scan has no analyzer for committed secrets. Prototype pollution and argument injection
have no keyed case in these four applications.

### Scanners

| Scanner | Version | Rules |
|---|---|---|
| Zazzles Code Scan | Branch `juiceshop-nextjs-hardening-3` at `3318e27` for Juice Shop and `ee777f4` for vuln-nextjs; `d368a68` for DVWA; `8d97b93` for vuln-symfony | All analyzer families, judged with OpenAI `gpt-6-luna` |
| Semgrep CE | 1.183.0 | `p/javascript`, `p/typescript`, `p/php`, `p/xss`, `p/owasp-top-ten` (564 rules) |
| Bearer CLI | Source build at `a7a8752` | `bearer-rules` at `82c335f`, default rules off |

Semgrep CE analyzes one file at a time; its cross-file engine is a paid product and was not run.
Bearer Pro was not run.

## OWASP Juice Shop

Pin `f189f52`. Code Scan run `a3-acceptance-juice-shop`, one full scan of 84 requests on the final
code of the branch.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `JS-XSS-01` | xss | `frontend/src/app/search-result/search-result.component.html:11` | Confirmed | Missed | Missed |
| `JS-XSS-02` | xss | `frontend/src/app/track-result/track-result.component.html:9` | Confirmed | Missed | Missed |
| `JS-XSS-03` | xss | `frontend/src/app/last-login-ip/last-login-ip.component.html:10` | Confirmed | Missed | Missed |
| `JS-XSS-04a` | xss | `frontend/src/app/administration/administration.component.html:26` | Confirmed | Missed | Missed |
| `JS-XSS-04b` | xss | `frontend/src/app/administration/administration.component.html:113` | Confirmed | Missed | Missed |
| `JS-XSS-05a` | xss | `frontend/src/app/administration/administration.component.html:60` | Confirmed | Missed | Missed |
| `JS-XSS-05b` | xss | `frontend/src/app/about/about.component.html:51` | Confirmed | Missed | Missed |
| `JS-XSS-06` | xss | `frontend/src/app/product-details/product-details.component.html:18` | Confirmed | Missed | Missed |
| `JS-XSS-07` | xss | `routes/userProfile.ts:101` | Confirmed | Missed | Found |
| `JS-SQL-01` | sql | `routes/login.ts:34` | Confirmed | Found | Found |
| `JS-SQL-02` | sql | `routes/search.ts:23` | Confirmed | Found | Found |
| `JS-NOSQL-01` | nosql | `routes/showProductReviews.ts:36` | Confirmed | Missed | Missed |
| `JS-NOSQL-02` | nosql | `routes/trackOrder.ts:18` | Confirmed | Missed | Missed |
| `JS-NOSQL-03` | nosql | `routes/updateProductReviews.ts:17` | Confirmed | Missed | Missed |
| `JS-LOG-01` | logging | `server.ts:366` | Practice finding | Missed | Missed |
| `JS-CONF-01` | configuration | `server.ts:290` | Confirmed | Found | Found |
| `JS-CONF-02` | configuration | `server.ts:298` | Confirmed | Found | Found |
| `JS-CONF-03` | configuration | `server.ts:302` | Confirmed | Found | Found |
| `JS-EXPO-01` | exposure | `server.ts:710` | Confirmed | Missed | Missed |
| `JS-EXPO-02` | exposure | `routes/metrics.ts:92` | Confirmed | Missed | Missed |
| `JS-HASH-01` | weak-hash | `lib/insecurity.ts:41` | Confirmed | Missed | Found |
| `JS-MASS-01` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-AUTHZ-01` | authorization | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-AUTHZ-02` | authorization | `routes/updateProductReviews.ts:17` | Confirmed | Missed | Missed |
| `JS-ENUM-01` | enumeration | `routes/securityQuestion.ts:15` | Confirmed | Missed | Missed |
| `JS-CONF-04` | configuration | `server.ts:269` | Confirmed | Found | Found |
| `JS-HASH-02` | weak-hash | `lib/insecurity.ts:42` | Confirmed | Missed | Missed |
| `JS-AUTHZ-03` | authorization | `routes/coupon.ts:24` | Confirmed | Missed | Missed |
| `JS-AUTHZ-04` | authorization | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-MASS-02` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-MASS-03` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-MASS-04` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-MASS-05` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-MASS-06` | mass-assignment | `server.ts:529` | Confirmed | Missed | Missed |
| `JS-REDIR-01` | redirect | `routes/redirect.ts:18` | Confirmed | Found | Found |
| `JS-PATH-02` | path | `routes/fileUpload.ts:34` (zip slip) | Confirmed | Missed | Missed |
| `JS-PATH-03` | path | `routes/dataErasure.ts:107` (layout file read) | Confirmed | Missed | Found |
| `JS-CODE-02` | code | `routes/b2bOrder.ts:23` | Practice finding | Missed | Found |
| `JS-SSRF-01` | ssrf | `routes/profileImageUrlUpload.ts:24` | Practice finding | Missed | Found |
| `JS-CODE-01` | code | `routes/userProfile.ts:65` (`eval`) | Confirmed | Found | Found |
| `JS-AUTHZ-05` | authorization | `routes/basket.ts:19` (read of another user's basket) | Confirmed | Missed | Missed |
| `JS-SECRET-01` | hardcoded secret | `lib/insecurity.ts:21`, used at `:54` | **Not covered** | Found | Found |

The rows from `JS-REDIR-01` on were added after the first comparison: seven documented Juice
Shop vulnerabilities that one of the scanners reported, the read of another user's basket, and
the committed key. All but `JS-SECRET-01` are now rows of Code Scan's answer key; no analyzer
owns a committed secret.

### False positives

| Scanner | What was flagged | Location | Why it is safe |
|---|---|---|---|
| Code Scan | Missing authorization | `routes/likeProductReviews.ts:35`, `:50` | Liking another user's review is the feature. The second record, the update of the review's list of likers, was Protected in the earlier run |
| Code Scan, Semgrep CE, Bearer | Directory listing | `server.ts:294` | `.well-known` holds only files published on purpose |
| Semgrep CE, Bearer | Path traversal | `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14`, `routes/quarantineServer.ts:14` | Each handler rejects any name containing `/` before `path.resolve(<directory>, name)`, so the read stays in its directory. The first also has a real defect of another kind: a null byte defeats its file-type allow-list. No scanner reports that as such, and Code Scan leaves the record in Review |
| Bearer | Unsafe deserialization | `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90` | `yaml.load` of the application's own files; `js-yaml` 4 constructs no objects |
| Bearer | Path traversal | `lib/startup/validatePreconditions.ts:199`, `:210`, `data/staticData.ts:8`, `lib/antiCheat.ts:198`, `scripts/package.mjs:62` | The path comes from configuration or a constant, not from a request |
| Bearer | Weak hash | `lib/utils.ts:82`, `scripts/package.mjs:121` | An HMAC for challenge flags and a build checksum; neither stores a password |
| Bearer | Sensitive data in logs (`logger_leak`, one grouped row) | 278 locations | Sampled by category: 167 log an error object or message, 94 a status message, 17 a browser console value. None logs a credential. The one known logging vulnerability (`server.ts:366`) is not among them |
| Bearer | Hardcoded secret (`hardcoded_secret`, one grouped row) | 260 locations in tests and challenge snippets | Test fixtures and teaching snippets. The three hits in application code are real and are row `JS-SECRET-01` |

Unreviewed: Semgrep CE 15 results (Terraform, npm policy and challenge snippets); Bearer about
100 results in other rules (timing comparison, random values, JWT revocation and others).

## vuln-nextjs

Pin `f5d47de`. The key is the lab's own `tests/expected-scanner-findings.json`. Code Scan run
`a2-acceptance-vuln-nextjs`.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `FS-001` | path | `pages/api/vulnerable-file-read.js` | Confirmed | Missed | Found |
| `JS-001` | code | `pages/vulnerable/eval-injection.js` | Confirmed | Missed | Missed |
| `JS-002` | code | `pages/api/vulnerable-submit.js` | Confirmed | Found | Found |
| `OS-001` | command | `pages/api/vulnerable-exec.js` | Confirmed | Missed | Found |
| `REDIR-001` | redirect | `vulnerabilities/open_redirect/source/low.php:4` | Confirmed | Missed | Missed |
| `SQL-001` | sql | `pages/api/sql/unsafe/login.js` | Confirmed | Missed | Missed |
| `SQL-002` | sql | `pages/api/sql/unsafe/products.js` | Confirmed | Missed | Missed |
| `SQL-003` | sql | `pages/api/sql/unsafe/notes.js` | Confirmed | Missed | Missed |
| `SSRF-001` | ssrf | `pages/vulnerable/ssrf.js` | Confirmed | Missed | Missed |
| `XSS-001` | xss | `pages/xss/unsafe/reflected.js` | Confirmed | Found | Found |
| `XSS-002` | xss | `pages/xss/unsafe/stored.js` | Confirmed | Missed | Found |
| `XSS-003` | xss | `pages/xss/unsafe/script-context.js` | Confirmed | Missed | Found |
| `XSS-004` | xss | `pages/xss/unsafe/comments.js` | Confirmed | Missed | Found |

### False positives

The lab labels `pages/secure/redirect.js` a safe control, and Code Scan reports it as a practice
finding. It is not counted as a false positive: the guard `/^\/[^/]/` admits `/\host`, which a
browser resolves to another origin, so the report is correct and the lab's control needs a fix.

| Scanner | What was flagged | Location | Why it is safe |
|---|---|---|---|
| Semgrep CE, Bearer | XSS | `pages/xss/sanitized/reflected.js:16` | The value passes through DOMPurify first |
| Bearer | XSS | `pages/xss/safe/script-context.js:17` | `<` is escaped to `\u003c` before the script context |
| Bearer | Path traversal | `pages/api/secure/file-read.js:15` | An exact filename allow-list |
| Bearer | SSRF | `pages/secure/ssrf.js:26` | Same-origin URL and `/api/` path check |

Unreviewed: Semgrep CE 4 package-manager policy results; Bearer 36 results, of which 17 are
`logger_leak` and 15 `hardcoded_secret` (14 in tests).

## DVWA

Pin `a1978a2`. Code Scan run `run-4266343441`. The key covers the "low" security level of each
module. DVWA's "medium" and "high" levels are also vulnerable by design and its "impossible"
level is the hardened one; results on medium and high are not keyed and are counted as
unreviewed.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `SQLI-001` | sql | `vulnerabilities/sqli/source/low.php` | Confirmed | Found | Found |
| `SQLI-002` | sql | `vulnerabilities/sqli_blind/source/low.php` | Confirmed | Found | Found |
| `AUTH-001` | sql | `vulnerabilities/brute/source/low.php` | Confirmed | Found | Found |
| `CMD-001` | command | `vulnerabilities/exec/source/low.php` | Confirmed | Found | Found |
| `DVWA-API-CMD-01` | command | `vulnerabilities/api/src/HealthController.php:88` | Confirmed | Found | Missed |
| `XSSR-001` | xss | `dvwa/includes/dvwaPage.inc.php:388` | Confirmed | Missed | Missed |
| `XSSS-001` | xss | `dvwa/includes/dvwaPage.inc.php` | Confirmed | Missed | Missed |
| `UPLD-001` | upload | `vulnerabilities/upload/source/low.php:9` | Confirmed | Missed | Missed |
| `FI-001` | path | `vulnerabilities/fi/index.php:36` | Confirmed | Missed | Missed |
| `REDIR-001` | redirect | `vulnerabilities/open_redirect/source/low.php:4` | Confirmed | Missed | Found |
| `CODE-001` | code | `vulnerabilities/view_help.php` | Confirmed | Missed | Found |

### False positives

| Scanner | What was flagged | Location | Why it is safe |
|---|---|---|---|
| Semgrep CE, Bearer | Command injection | `vulnerabilities/exec/source/impossible.php:22`, `:26` | The hardened level: the address is split into four octets and each must be numeric before the command is built. Code Scan records these as Protected |

Unreviewed: Semgrep CE 30 results and Bearer about 150, most on the medium and high levels.
Bearer's 22 XSS results on other "impossible" pages were not checked.

## vuln-symfony

Pin `086f81f`. Code Scan run `run-1810616125`.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `SYM-SQL-01` | sql | `src/Repository/PostRepository.php:67` | Confirmed | Missed | Found |
| `SYM-SQL-02` | sql | `src/Repository/UserRepository.php:77` | Confirmed | Missed | Found |
| `SYM-XSS-01` | xss | `templates/blog/index.html.twig:11` | Confirmed | Missed | Missed |
| `SYM-XSS-02` | xss | `templates/blog/post.html.twig:40` | Confirmed | Missed | Missed |
| `SYM-XSS-03` | xss | `templates/blog/post.html.twig:37` | Confirmed | Missed | Missed |
| `SYM-CMD-01` | command | `src/Services/Analytics.php:32` | Confirmed | Missed | Missed |
| `SYM-CMD-02` | command | `src/Controller/UserController.php:195` | Confirmed | Missed | Missed |
| `SYM-PATH-01` | path | `src/Controller/BlogController.php:95` | Confirmed | Missed | Missed |
| `SYM-PATH-02` | path | `src/Controller/UserController.php:159` | Confirmed | Missed | Missed |
| `SYM-PATH-03` | path | `src/Services/Avatar.php:18` | Confirmed | Missed | Missed |
| `SYM-SSRF-01` | ssrf | `src/Services/Avatar.php:18` | Confirmed | Missed | Missed |
| `SYM-UPLOAD-01` | upload | `src/Controller/UserController.php:99` | Confirmed | Missed | Missed |
| `SYM-SSTI-01` | code | `src/Twig/TemplateFromStringExtension.php:22` | Confirmed | Missed | Missed |
| `SYM-DESER-01` | deserialization | `src/Services/UserPref.php:36` | Confirmed | Missed | Found |
| `SYM-INFO-01` | exposure | `public/info.php:2` | Confirmed | Found | Found |
| `SYM-MASS-01` | mass-assignment | `src/Entity/User.php:59` | Confirmed | Missed | Missed |
| `SYM-AUTHZ-01` | authorization | `src/Controller/AdminController.php:32` | Confirmed | Missed | Missed |
| `SYM-AUTHZ-02` | authorization | `src/Controller/UserController.php:41` | Confirmed | Missed | Missed |
| `SYM-AUTHZ-03` | authorization | `src/Controller/UserController.php:62` | Confirmed | Missed | Missed |
| `SYM-AUTHZ-04` | authorization | `src/Controller/UserController.php:159`; `src/Controller/UserController.php:161` | Confirmed | Missed | Missed |
| `SYM-LOCAL-01` | authorization | `src/Controller/LocalController.php:77` | Confirmed | Missed | Missed |
| `SYM-ENUM-01` | enumeration | `src/Controller/LoginController.php:76`; `src/Controller/LoginController.php:83` | Confirmed | Missed | Missed |
| `SYM-ENUM-02` | enumeration | `src/Controller/PasswordResetController.php:34` | Confirmed | Missed | Missed |
| `SYM-RESET-01` | recovery | `src/Services/Mail.php:35` | Confirmed | Missed | Missed |
| `SYM-HASH-01` | weak-hash | `src/Security/Hasher/Md5Hasher.php:15`; `src/Controller/UserController.php:41` … | Confirmed | Found | Found |
| `SYM-CONF-01` | configuration | `docker/apache.conf:2` | Confirmed | Missed | Missed |
| `SYM-CONF-02` | configuration | `Dockerfile:50`; `Dockerfile:47` … | Confirmed | Missed | Missed |
| `SYM-CONF-03` | configuration | `config/packages/framework.yaml:4` | Confirmed | Missed | Missed |
| `SYM-CONF-04` | configuration | `config/packages/framework.yaml:13` | Confirmed | Missed | Missed |
| `SYM-SSRF-02` | ssrf | `src/Services/Analytics.php:32` | Confirmed | Missed | Missed |

### False positives

| Scanner | What was flagged | Location | Why it is safe |
|---|---|---|---|
| Bearer | Weak hash | `src/Controller/UserController.php:98`, `:138` | `md5(uniqid())` names an uploaded file; nothing is a password |

Unreviewed: Semgrep CE 3 results and Bearer 6 (MD5 in a seeding command, two cookie flags, one
Dockerfile rule).

## Method and limits

- A scanner's result matches a known vulnerability when it is in the same file, its rule is of
  the same weakness class, and it is within three lines of the keyed line.
- Code Scan "found" means a Confirmed finding, or a practice finding where the table says so.
  A record left in Review is a miss.
- The answer keys were written for Code Scan's own evaluation, so they favor the classes it
  analyzes. Juice Shop's key was extended with eight rows the other scanners surfaced. The
  DVWA and vuln-symfony keys were not extended the same way.
- False positives are counted only where a key control or a source review establishes that the
  code is safe.
- Run details, commands and the raw outputs are in the
  [contributor run record](../../.zazz/evaluation/comparison-results.md) and the per-scanner
  documents it links.
