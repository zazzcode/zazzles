# Scanner comparison

[Documentation](../README.md) · [Detection capabilities](detection-capabilities.md) · [Sample reports](../samples/README.md)

How Zazzles Code Scan compares with two other static scanners on four intentionally vulnerable
applications, measured against what is known about each application rather than against result
counts. Code Scan and Bearer were run on 2026-11-24, Semgrep CE on 2026-11-24 and 2026-11-25.

**How to read it.** Each application has one table. Its rows are the application's known
vulnerabilities, from a source-reviewed answer key. Each scanner either found a row or missed
it, and a miss is shown for every scanner, Code Scan included. When a scanner reports something
the key or a source review shows to be safe, that is a false positive and gets its own row in
the second table. A result outside the key that a source review could not show to be safe is not counted.

These are development reference applications. The numbers describe these four applications and
these scanner versions. They are not a general accuracy claim.

## Summary

| Application | Known vulnerabilities | Code Scan found | Semgrep CE found, broad packs | Semgrep CE found, focused packs | Bearer found |
|---|---:|---:|---:|---:|---:|
| OWASP Juice Shop | 42 | 41 | 13 | 9 | 14 |
| vuln-nextjs | 13 | 13 | 7 | 2 | 7 |
| DVWA | 11 | 11 | 6 | 5 | 6 |
| vuln-symfony | 30 | 30 | 8 | 2 | 5 |
| **Total** | **96** | **95** | **34** | **18** | **32** |

**Reviewed false positives**, counted by location:

| Application | Code Scan | Semgrep CE, broad packs | Semgrep CE, focused packs | Bearer |
|---|---:|---:|---:|---:|
| OWASP Juice Shop | 4 | 50 | 5 | 36 and two grouped rules |
| vuln-nextjs | 0 | 3 | 1 | 4 |
| DVWA | 9 | 17 | 7 | 31 |
| vuln-symfony | 0 | 23 | 0 | 2 |
| **Total** | **13** | **93** | **13** | **73 and two grouped rules** |

Semgrep CE was run twice. The **focused** run of 2026-11-24 used five packs. A focused set leaves
out rules a user could run for free, so the **broad** run of 2026-11-25 used 23 registry packs
chosen to fit these stacks. The broad run finds more and reports more safe code. The tables below use
the broad run. Both find counts were scored with the same matching rules, and two broad results
that start more than three lines from the key row but cover it are counted as found
(`JS-NOSQL-01`, `JS-XSS-07`).

False positives were read against the source for all three scanners on 2026-11-25. This raised
Code Scan's count from 3 to 13: nine SQL findings in DVWA, where the input is escaped into a quoted
literal or must be digits, and one NoSQL finding in Juice Shop. Results that
could not be decided from a source read are not counted, so **every count is a lower bound**.
Bearer's is the least complete: 51 of its 76 DVWA cross-site scripting results and its two grouped
rules were not read in full. The review was made by the agent that ran the comparison and has not
been checked independently. Code Scan's found count includes three Juice Shop
rows it reports as a practice finding rather than a confirmed vulnerability. Its practice findings
are not counted as false positives. It misses one Juice Shop row, a committed secret, a class it
has no analyzer for.

**These tools are not the same kind of tool.** Semgrep CE and Bearer are free, run offline and
need no model. Code Scan is free software, but a judged scan calls a paid model provider (84
requests for Juice Shop). Code Scan was also developed against these four applications; Semgrep's
and Bearer's rules were not. An application none of them was tuned on would be a stronger test.

### By weakness class

Known vulnerabilities found, across the four applications.

| Weakness class | Known vulnerabilities | Code Scan | Semgrep CE | Bearer |
|---|---:|---:|---:|---:|
| Cross-site scripting | 18 | 18 | 2 | 5 |
| SQL injection | 10 | 10 | 10 | 7 |
| Missing authorization | 10 | 10 | 0 | 0 |
| Insecure configuration | 8 | 8 | 4 | 4 |
| Path traversal | 7 | 7 | 1 | 2 |
| Mass assignment | 7 | 7 | 0 | 0 |
| Code and template injection | 6 | 6 | 4 | 4 |
| OS command injection | 5 | 5 | 5 | 2 |
| Server-side request forgery | 4 | 4 | 0 | 1 |
| NoSQL injection | 3 | 3 | 2 | 0 |
| Information exposure | 3 | 3 | 1 | 1 |
| Weak password hashing | 3 | 3 | 2 | 2 |
| Account enumeration | 3 | 3 | 0 | 0 |
| Open redirect | 3 | 3 | 1 | 2 |
| Unrestricted file upload | 2 | 2 | 0 | 0 |
| Unsafe deserialization | 1 | 1 | 1 | 1 |
| Weak password recovery | 1 | 1 | 0 | 0 |
| Sensitive data in logs | 1 | 1 | 0 | 0 |
| Hardcoded secret | 1 | 0 | 1 | 1 |
| **Total** | **96** | **95** | **34** | **32** |

Code Scan has no analyzer for committed secrets. Prototype pollution and argument injection
have no keyed case in these four applications.

### Scanners

| Scanner | Version | Rules |
|---|---|---|
| Zazzles Code Scan | Branch `juiceshop-nextjs-hardening-3` at `3318e27` for Juice Shop and `ee777f4` for vuln-nextjs; `d368a68` for DVWA; `8d97b93` for vuln-symfony | All analyzer families, judged with OpenAI `gpt-6-luna` |
| Semgrep CE, broad | 1.183.0, `--oss-only` | 23 packs, 1,379 rules, including `p/default`, `p/security-audit`, `p/nodejsscan` and `p/secrets` ([list](../../.zazz/evaluation/semgrep-results.md#broad-run)) |
| Semgrep CE, focused | 1.183.0 | `p/javascript`, `p/typescript`, `p/php`, `p/xss`, `p/owasp-top-ten` (564 rules) |
| Bearer CLI | Source build at `a7a8752` | `bearer-rules` at `82c335f`, default rules off |

Semgrep CE follows taint inside one function. Its cross-function and cross-file engine is a paid
product and was not run.
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
| `JS-XSS-07` | xss | `routes/userProfile.ts:101` | Confirmed | Found | Found |
| `JS-SQL-01` | sql | `routes/login.ts:34` | Confirmed | Found | Found |
| `JS-SQL-02` | sql | `routes/search.ts:23` | Confirmed | Found | Found |
| `JS-NOSQL-01` | nosql | `routes/showProductReviews.ts:36` | Confirmed | Found | Missed |
| `JS-NOSQL-02` | nosql | `routes/trackOrder.ts:18` | Confirmed | Found | Missed |
| `JS-NOSQL-03` | nosql | `routes/updateProductReviews.ts:17` | Confirmed | Missed | Missed |
| `JS-LOG-01` | logging | `server.ts:366` | Practice finding | Missed | Missed |
| `JS-CONF-01` | configuration | `server.ts:290` | Confirmed | Found | Found |
| `JS-CONF-02` | configuration | `server.ts:298` | Confirmed | Found | Found |
| `JS-CONF-03` | configuration | `server.ts:302` | Confirmed | Found | Found |
| `JS-EXPO-01` | exposure | `server.ts:710` | Confirmed | Missed | Missed |
| `JS-EXPO-02` | exposure | `routes/metrics.ts:92` | Confirmed | Missed | Missed |
| `JS-HASH-01` | weak-hash | `lib/insecurity.ts:41` | Confirmed | Found | Found |
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

| Scanner | Locations | Why it is safe |
|---|---|---|
| Code Scan | 2: `routes/likeProductReviews.ts:35`, `routes/likeProductReviews.ts:50` | Liking another user's review is the feature |
| Code Scan | 1: `server.ts:294` | .well-known holds only published files |
| Code Scan | 1: `routes/orderHistory.ts:36` | NoSQL: the selector value is a route parameter, always a string |
| Semgrep CE (broad) | 4: `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14` and 1 more | Each handler rejects a name containing / |
| Semgrep CE (broad) | 1: `server.ts:294` | .well-known holds only published files |
| Semgrep CE (broad) | 1: `lib/antiCheat.ts:198` | A constant path list |
| Semgrep CE (broad) | 15: `routes/address.ts:18`, `routes/basket.ts:19`, `routes/basketItems.ts:68` and 12 more | NoSQL rule on a Sequelize (SQL) lookup with bound values |
| Semgrep CE (broad) | 1: `routes/captcha.ts:22` | eval of an expression built only from server-chosen numbers |
| Semgrep CE (broad) | 12: `data/datacreator.ts:323`, `data/datacreator.ts:381`, `data/datacreator.ts:756` and 9 more | Random value is not a secret |
| Semgrep CE (broad) | 4: `data/datacreator.ts:350`, `data/datacreator.ts:354`, `frontend/src/app/purchase-basket/purchase-basket.component.ts:60` and 1 more | Not a credential |
| Semgrep CE (broad) | 2: `frontend/src/app/navbar/navbar.component.html:17`, `frontend/src/app/purchase-basket/purchase-basket.component.html:16` | Angular interpolation, not a raw attribute |
| Semgrep CE (broad) | 1: `frontend/src/hacking-instructor/helpers/helpers.ts:49` | Read-only property walk |
| Semgrep CE (broad) | 2: `lib/codingChallenges.ts:77`, `lib/codingChallenges.ts:79` | Pattern built from fixed challenge keys |
| Semgrep CE (broad) | 1: `lib/startup/registerWebsocketEvents.ts:19` | Origin is fixed to a local development host |
| Semgrep CE (broad) | 1: `routes/changePassword.ts:28` | Comparison with null |
| Semgrep CE (broad) | 1: `routes/verify.ts:60` | Challenge check, not an access decision |
| Semgrep CE (broad) | 2: `rsn/rsnUtil.ts:63`, `scripts/package.mjs:121` | Developer script |
| Semgrep CE (broad) | 1: `server.ts:158` | Log prefix is a function name |
| Semgrep CE (broad) | 1: `views/promotionVideo.pug:75` | != in inline script text, not an unescaped output |
| Bearer | 4: `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14` and 1 more | Each handler rejects a name containing / |
| Bearer | 1: `server.ts:294` | .well-known holds only published files |
| Bearer | 5: `data/staticData.ts:8`, `lib/startup/validatePreconditions.ts:199`, `lib/startup/validatePreconditions.ts:210` and 2 more | A constant or configured path |
| Bearer | 12: `data/datacreator.ts:323`, `data/datacreator.ts:381`, `data/datacreator.ts:756` and 9 more | Random value is not a secret |
| Bearer | 2: `lib/codingChallenges.ts:77`, `lib/codingChallenges.ts:79` | Pattern built from fixed challenge keys |
| Bearer | 2: `lib/utils.ts:82`, `scripts/package.mjs:121` | Not a password digest |
| Bearer | 2: `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90` | The application's own files; js-yaml 4 constructs no objects |
| Bearer | 6: `frontend/src/hacking-instructor/helpers/helpers.ts:266`, `routes/2fa.ts:66`, `routes/2fa.ts:111` and 3 more | Comparison with an empty string or a public value |
| Bearer | 2: `frontend/src/app/faucet/faucet.component.ts:121`, `frontend/src/app/faucet/faucet.component.ts:226` | Logs a public balance |

Bearer's `logger_leak` (278 locations) and `hardcoded_secret` (260 locations in tests and snippets) are each one grouped row and were sampled, not read in full.

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## vuln-nextjs

Pin `f5d47de`. The key is the lab's own `tests/expected-scanner-findings.json`. Code Scan run
`a2-acceptance-vuln-nextjs`.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `FS-001` | path | `pages/api/vulnerable-file-read.js` | Confirmed | Missed | Found |
| `JS-001` | code | `pages/vulnerable/eval-injection.js` | Confirmed | Found | Missed |
| `JS-002` | code | `pages/api/vulnerable-submit.js` | Confirmed | Found | Found |
| `OS-001` | command | `pages/api/vulnerable-exec.js` | Confirmed | Found | Found |
| `REDIR-001` | redirect | `pages/vulnerable/redirect.js` | Confirmed | Missed | Missed |
| `SQL-001` | sql | `pages/api/sql/unsafe/login.js` | Confirmed | Found | Missed |
| `SQL-002` | sql | `pages/api/sql/unsafe/products.js` | Confirmed | Found | Missed |
| `SQL-003` | sql | `pages/api/sql/unsafe/notes.js` | Confirmed | Found | Missed |
| `SSRF-001` | ssrf | `pages/vulnerable/ssrf.js` | Confirmed | Missed | Missed |
| `XSS-001` | xss | `pages/xss/unsafe/reflected.js` | Confirmed | Found | Found |
| `XSS-002` | xss | `pages/xss/unsafe/stored.js` | Confirmed | Missed | Found |
| `XSS-003` | xss | `pages/xss/unsafe/script-context.js` | Confirmed | Missed | Found |
| `XSS-004` | xss | `pages/xss/unsafe/comments.js` | Confirmed | Missed | Found |

### False positives

The lab labels `pages/secure/redirect.js` a safe control, and Code Scan reports it as a practice
finding. It is not counted as a false positive: the guard `/^\/[^/]/` admits `/\host`, which a
browser resolves to another origin, so the report is correct and the lab's control needs a fix.

| Scanner | Locations | Why it is safe |
|---|---|---|
| Semgrep CE (broad) | 1: `pages/xss/sanitized/reflected.js:16` | DOMPurify output |
| Semgrep CE (broad) | 2: `scripts/export-prototype-pollution-fixtures.mjs:136`, `scripts/export-prototype-pollution-fixtures.mjs:137` | Build script over the project's own lockfile |
| Bearer | 1: `pages/xss/sanitized/reflected.js:16` | DOMPurify output |
| Bearer | 1: `pages/xss/safe/script-context.js:17` | < is escaped before the script context |
| Bearer | 1: `pages/api/secure/file-read.js:15` | Exact filename allow-list |
| Bearer | 1: `pages/secure/ssrf.js:26` | Same-origin URL and /api/ path check |

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

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
| `CODE-001` | code | `vulnerabilities/view_help.php` | Confirmed | Found | Found |

### False positives

| Scanner | Locations | Why it is safe |
|---|---|---|
| Code Scan | 7: `login.php:47`, `vulnerabilities/brute/source/high.php:20`, `vulnerabilities/brute/source/medium.php:15` and 4 more | SQL: every request value is escaped for, and placed inside, a quoted literal |
| Code Scan | 2: `vulnerabilities/bac/source/medium.php:22`, `vulnerabilities/bac/source/medium.php:29` | SQL: the value must match digits only |
| Semgrep CE (broad) | 2: `vulnerabilities/exec/source/impossible.php:22`, `vulnerabilities/exec/source/impossible.php:26` | Address is rebuilt from four numeric octets |
| Semgrep CE (broad) | 4: `vulnerabilities/bac/source/low.php:22`, `vulnerabilities/bac/source/low.php:35`, `vulnerabilities/bac/source/medium.php:21` and 1 more | SQL: the value is an integer or must match digits only |
| Semgrep CE (broad) | 1: `instructions.php:26` | File name comes from a fixed map |
| Semgrep CE (broad) | 9: `login.php:48`, `vulnerabilities/brute/source/high.php:22`, `vulnerabilities/brute/source/low.php:15` and 6 more | No digest is compared with a loose operator that an input can influence |
| Semgrep CE (broad) | 1: `vulnerabilities/upload/source/impossible.php:54` | Deletes its own temporary file |
| Bearer | 2: `vulnerabilities/exec/source/impossible.php:22`, `vulnerabilities/exec/source/impossible.php:26` | Address is rebuilt from four numeric octets |
| Bearer | 4: `vulnerabilities/bac/source/low.php:23`, `vulnerabilities/bac/source/low.php:36`, `vulnerabilities/bac/source/medium.php:22` and 1 more | SQL: the value is an integer or must match digits only |
| Bearer | 23: `vulnerabilities/bac/source/high.php:65`, `vulnerabilities/bac/source/high.php:68`, `vulnerabilities/bac/source/impossible.php:53` and 20 more | XSS: constant text |
| Bearer | 2: `vulnerabilities/bac/source/low.php:27`, `vulnerabilities/bac/source/medium.php:43` | XSS: the value is an integer or must match digits only |

Bearer's other 51 cross-site scripting results were not read. Results on the medium and high
levels that are vulnerable by design are not false positives and are not keyed.

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## vuln-symfony

Pin `086f81f`. Code Scan run `run-1810616125`.

| ID | Class | Location | Code Scan | Semgrep CE | Bearer |
|---|---|---|---|---|---|
| `SYM-SQL-01` | sql | `src/Repository/PostRepository.php:67` | Confirmed | Found | Found |
| `SYM-SQL-02` | sql | `src/Repository/UserRepository.php:77` | Confirmed | Found | Found |
| `SYM-XSS-01` | xss | `templates/blog/index.html.twig:11` | Confirmed | Missed | Missed |
| `SYM-XSS-02` | xss | `templates/blog/post.html.twig:40` | Confirmed | Missed | Missed |
| `SYM-XSS-03` | xss | `templates/blog/post.html.twig:37` | Confirmed | Missed | Missed |
| `SYM-CMD-01` | command | `src/Services/Analytics.php:32` | Confirmed | Found | Missed |
| `SYM-CMD-02` | command | `src/Controller/UserController.php:195` | Confirmed | Found | Missed |
| `SYM-PATH-01` | path | `src/Controller/BlogController.php:95` | Confirmed | Missed | Missed |
| `SYM-PATH-02` | path | `src/Controller/UserController.php:159` | Confirmed | Found | Missed |
| `SYM-PATH-03` | path | `src/Services/Avatar.php:18` | Confirmed | Missed | Missed |
| `SYM-SSRF-01` | ssrf | `src/Services/Avatar.php:18` | Confirmed | Missed | Missed |
| `SYM-UPLOAD-01` | upload | `src/Controller/UserController.php:99` | Confirmed | Missed | Missed |
| `SYM-SSTI-01` | code | `src/Twig/TemplateFromStringExtension.php:22` | Confirmed | Missed | Missed |
| `SYM-DESER-01` | deserialization | `src/Services/UserPref.php:36` | Confirmed | Found | Found |
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

| Scanner | Locations | Why it is safe |
|---|---|---|
| Semgrep CE (broad) | 14: `templates/admin/index.html.twig:59`, `templates/base.html.twig:29`, `templates/base.html.twig:31` and 11 more | URL generated by path() |
| Semgrep CE (broad) | 2: `templates/admin/index.html.twig:49`, `templates/admin/index.html.twig:52` | Attribute is one of two constants |
| Semgrep CE (broad) | 2: `src/Controller/UserController.php:98`, `src/Controller/UserController.php:138` | md5 names an uploaded file |
| Semgrep CE (broad) | 5: `.env:34`, `.env:35`, `docker/.env.local:18` and 2 more | Commented-out setting |
| Bearer | 2: `src/Controller/UserController.php:98`, `src/Controller/UserController.php:138` | md5 names an uploaded file |

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## Method and limits

- A scanner's result matches a known vulnerability when it is in the same file, its rule is of
  the same weakness class, and it is within three lines of the keyed line.
- Code Scan "found" means a Confirmed finding, or a practice finding where the table says so.
  A record left in Review is a miss.
- The answer keys were written for Code Scan's own evaluation, so they favor the classes it
  analyzes. Juice Shop's key was extended with eight rows the other scanners surfaced. The
  DVWA and vuln-symfony keys were not extended the same way.
- A result outside the key is not a false positive. The keys are not complete lists of each
  application's vulnerabilities, so results outside them were sorted: real but not keyed,
  false positive, undecided, or outside application code (tests, challenge snippets,
  Terraform, containers, package policy). Only false positives are counted.
- A false positive is a result where the reported weakness cannot occur at that location. It is
  counted once per file and line.
- Run details, commands and the raw outputs are in the
  [contributor run record](../../.zazz/evaluation/comparison-results.md) and the per-scanner
  documents it links.
