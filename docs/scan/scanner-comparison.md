# Scanner comparison

[Documentation](../README.md) · [Detection capabilities](detection-capabilities.md) · [Sample reports](../samples/README.md)

How Zazzles Code Scan compares with two other static scanners on four intentionally vulnerable
applications, measured against what is known about each application rather than against result
counts. Code Scan with OpenAI `gpt-6-luna` and Bearer were run on 2026-11-24, Semgrep CE on
2026-11-25. Code Scan was run again with Google Gemini `gemini-decision-1` on 2026-11-27 on
Juice Shop, DVWA and VulnerableSymfony, and on two applications the other scanners were not
scored on: OSS OopsSec Store and VulnPy ([run record](../../.zazz/evaluation/gemini-sample-runs-20261127.md)).

**How to read it.** Each application has one table. Its rows are the application's known
vulnerabilities, from a source-reviewed answer key. Each scanner either found a row or missed
it, and a miss is shown for every scanner, Code Scan included. When a scanner reports something
the key or a source review shows to be safe, that is a false positive and gets its own row in
the second table. A result outside the key that a source review could not show to be safe is not counted.

These are development reference applications. The numbers describe these four applications and
these scanner versions. They are not a general accuracy claim.

## Summary

| Application | In answer key | Code Scan, Gemini | Code Scan, gpt-6-luna | Semgrep CE found | Bearer found |
|---|---:|---:|---:|---:|---:|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | 75 | 40 | 45 | 19 | 15 |
| [vuln-nextjs](https://github.com/zazzcode/vuln-nextjs) | 13 | Not rerun | 13 | 7 | 7 |
| [DVWA](https://github.com/digininja/DVWA) | 11 | 11 | 11 | 6 | 6 |
| [VulnerableSymfony](https://github.com/Secureaks/VulnerableSymfony) (vuln-symfony) | 30 | 30 | 30 | 8 | 5 |
| **Total, four applications** | **129** | **81 of 116 run** | **99** | **40** | **33** |
| [OSS OopsSec Store](https://github.com/kOaDT/oss-oopssec-store) | 13 | 13 | 13 | Not scored | Not scored |
| [VulnPy](https://github.com/Contrast-Security-OSS/vulnpy) | 10 | 10 | 6 | Not scored | Not scored |

The Gemini column is one full judged scan per application with scanner `81d4731` (`stage`
through PR #56). The `gpt-6-luna` column is the published run named in each application's
section, on an earlier scanner, so the two columns differ in model and scanner revision. The
`gpt-6-luna` VulnPy report predates the deserialization analyzer; its four missed rows are the
deserialization sinks. OopsSec and VulnPy are scored on Code Scan's own key only.

**Reviewed false positives**, counted by location:

| Application | Code Scan, Gemini | Code Scan, gpt-6-luna | Semgrep CE | Bearer |
|---|---:|---:|---:|---:|
| OWASP Juice Shop | 3 | 4 | 50 | 36 and two grouped rules |
| vuln-nextjs | Not rerun | 0 | 3 | 4 |
| DVWA | 4 | 9 | 17 | 31 |
| vuln-symfony | 0 | 0 | 23 | 2 |
| **Total** | **7 of three applications** | **13** | **93** | **73 and two grouped rules** |

Gemini's Juice Shop count adds two locations no earlier review held as Code Scan results: the
null-byte file read (`routes/fileServer.ts:32`), which the owner ruled on 2026-11-24 cannot leave
its directory, and the Swagger UI at `server.ts:307`, reported as information exposure. Both
were read in the session that made the Gemini run. Findings outside the OopsSec and VulnPy keys
are not reviewed.

The answer key is not a complete list of an application's vulnerabilities. Juice Shop documents 116
challenges. Many are puzzles, seeded passwords, outdated components or a second way to use one
flaw. On 2026-11-25 its key was extended from 42 to 75 rows with every distinct weakness in
first-party code that a challenge, a `vuln-line` marker, the detection guide or any scanner points
to, whether or not a scanner found it. The [33 added rows](../../.zazz/evaluation/juice-shop-comparison-rows.json)
lower every scanner's share, Code Scan's most. **The other three keys were not extended this way**,
so they still favor Code Scan.

Semgrep CE ran with 23 registry packs chosen to fit these stacks. A smaller set reports less of
both: five packs run on 2026-11-24 found 18 of the rows in the key at that time, with 13 reviewed
false positives ([run record](../../.zazz/evaluation/semgrep-results.md)). Four rows are counted as
found by hand: `JS-NOSQL-01` and `JS-XSS-07` for Semgrep, where the result covers the keyed line but
starts more than three lines above it, and `JS-HASH-02` for Semgrep and Bearer, whose hardcoded-key
results describe that row's constant key.

False positives were read against the source for all three scanners on 2026-11-25. This raised
Code Scan's count from 3 to 13: nine SQL findings in DVWA, where the input is escaped into a quoted
literal or must be digits, and one NoSQL finding in Juice Shop. Results that
could not be decided from a source read are not counted, so **every count is a lower bound**.
Bearer's is the least complete: 51 of its 76 DVWA cross-site scripting results and its two grouped
rules were not read in full. The review was made by the agent that ran the comparison and has not
been checked independently. Code Scan's `gpt-6-luna` found count includes three Juice Shop
rows it reports as a practice finding rather than a confirmed vulnerability. Its practice findings
are not counted as false positives. What it misses is explained [below](#what-code-scan-misses).

**These tools are not the same kind of tool.** Semgrep CE and Bearer are free, run offline and
need no model. Code Scan is free software, but a judged scan calls a paid model provider (84
requests for Juice Shop). Code Scan was also developed against these four applications; Semgrep's
and Bearer's rules were not. An application none of them was tuned on would be a stronger test.

### By weakness class

Rows of the answer keys found by Code Scan with `gpt-6-luna`, across the four applications.

| Weakness class | In answer key | Code Scan | Semgrep CE | Bearer |
|---|---:|---:|---:|---:|
| Cross-site scripting | 19 | 18 | 3 | 5 |
| Missing authorization | 16 | 13 | 0 | 0 |
| SQL injection | 10 | 10 | 10 | 7 |
| Insecure configuration | 10 | 8 | 5 | 4 |
| Mass assignment | 7 | 7 | 0 | 0 |
| Path traversal | 7 | 7 | 1 | 2 |
| Code and template injection | 6 | 6 | 4 | 4 |
| Information exposure | 5 | 3 | 1 | 1 |
| OS command injection | 5 | 5 | 5 | 2 |
| NoSQL injection | 4 | 4 | 3 | 0 |
| Server-side request forgery | 4 | 4 | 0 | 1 |
| Unrestricted file upload | 2 | 2 | 0 | 0 |
| Business logic | 4 | 0 | 0 | 0 |
| Weak password hashing | 3 | 3 | 3 | 3 |
| Account enumeration | 3 | 3 | 0 | 0 |
| Open redirect | 3 | 3 | 1 | 2 |
| Hardcoded secret | 3 | 0 | 3 | 1 |
| Authentication flaws | 3 | 0 | 0 | 0 |
| Weak password recovery | 2 | 1 | 0 | 0 |
| Rate limits and CAPTCHA | 2 | 0 | 0 | 0 |
| Input validation | 3 | 0 | 0 | 0 |
| Sensitive data in logs | 1 | 1 | 0 | 0 |
| Cross-site request forgery | 1 | 0 | 0 | 0 |
| XML external entities | 1 | 0 | 0 | 0 |
| Token verification | 1 | 0 | 0 | 0 |
| Resource exhaustion | 1 | 0 | 0 | 0 |
| Weak cryptography | 1 | 0 | 0 | 0 |
| Race condition | 1 | 0 | 0 | 0 |
| Unsafe deserialization | 1 | 1 | 1 | 1 |
| **Total** | **129** | **99** | **40** | **33** |

### What Code Scan misses

With `gpt-6-luna`, Code Scan misses 30 rows, all in Juice Shop. The other keys were not extended,
so this says nothing about misses there. The Gemini run misses the same 30 and five more, all
left in Review: the `/support/logs` directory listing (`JS-CONF-03`) and four mass-assignment
rows of the generated routes at `server.ts:529` (`JS-MASS-02` to `JS-MASS-05`). It reports
VulnerableSymfony's `SYM-XSS-03` as a practice finding, which counts as found.

**No analyzer, 18 rows.** Hardcoded secrets (3), business logic (4), authentication flaws (3), rate
limits and CAPTCHA (2), and one each of cross-site request forgery, XML external entities, token
verification, resource exhaustion, weak cryptography and race condition. Some of these are natural
analyzer work: XML external entities, token verification, hardcoded secrets and cross-site request
forgery each have a source pattern to find. Business rules and races do not have one in general.

**An existing analyzer falls short, 12 rows.**

| Row | Class | Gap |
|---|---|---|
| `JS-X-AUTHZ-09` | Missing authorization | The repeated-key check is not modelled |
| `JS-X-AUTHZ-10` | Missing authorization | The masked selector is not modelled |
| `JS-X-MASS-07` | Missing authorization | A create is not an authorization operation in JavaScript. The insert is a NoSQL query in Review |
| `JS-X-EXPO-03` | Information exposure | No record for a property chosen by the request in a response |
| `JS-X-EXPO-04` | Information exposure | No record for JSONP |
| `JS-X-XSS-09` | Cross-site scripting | Recorded and left in Review: the stored value has no linked writer |
| `JS-X-UPLOAD-02` | Input validation | The route's upload record, in Review, is about executable storage. The type test in a later handler is not read |
| `JS-X-RESET-01` | Weak password recovery | The recovery claim exists for PHP only |
| `JS-X-CONF-05` | Insecure configuration (poor practice) | CORS is outside the configuration claims |
| `JS-X-CONF-06` | Insecure configuration | Flags are read for two session libraries. A `res.cookie` call is left out, and an absent flag is not recorded |
| `JS-X-VALID-01` | Input validation | No record for the model setter |
| `JS-X-VALID-02` | Input validation | Three field records, not sent to the model for missing evidence |

Four of the twelve have a record nearby. `JS-X-XSS-09` is recorded and left in Review. `JS-X-MASS-07` and
`JS-X-UPLOAD-02` have a record of another claim in Review, and `JS-X-VALID-02` has three field records
that were not sent. The others have no record for the weakness. The causes were
[traced through the scanner](../../.zazz/evaluation/detection-generalization-research.md#3-trace) offline.

**Corrected on 2026-11-25.** A second reading of these rows changed seven. `JS-X-UPLOAD-01` said that upload
size is not enforced on the server. It is, at 200,000 bytes (`server.ts:722`), so the row was removed and is
kept as a control: a result that says otherwise there is a false positive. `JS-X-UPLOAD-02` and
`JS-X-MASS-07` changed class, `JS-X-CONF-05` is a poor practice, and three causes were wrong. Semgrep's
credit for `JS-X-CONF-05` stands. No scanner's found count changed.

Prototype pollution and argument injection have no keyed case in these four applications.

### Scanners

| Scanner | Version | Rules |
|---|---|---|
| Zazzles Code Scan, Gemini | `stage` at `81d4731` (through PR #56) for Juice Shop, DVWA, vuln-symfony, OopsSec and VulnPy | All analyzer families, judged with Google Gemini `gemini-decision-1`, default judge limit |
| Zazzles Code Scan, gpt-6-luna | Branch `juiceshop-nextjs-hardening-3` at `3318e27` for Juice Shop and `ee777f4` for vuln-nextjs; `d368a68` for DVWA; `8d97b93` for vuln-symfony | All analyzer families, judged with OpenAI `gpt-6-luna` |
| Semgrep CE | 1.183.0, `--oss-only` | 23 packs, 1,379 rules, including `p/default`, `p/security-audit`, `p/nodejsscan` and `p/secrets` ([list](../../.zazz/evaluation/semgrep-results.md#broad-run)) |
| Bearer CLI | Source build at `a7a8752` | `bearer-rules` at `82c335f`, default rules off |

Semgrep CE follows taint inside one function. Its cross-function and cross-file engine is a paid
product and was not run.
Bearer Pro was not run.

## OWASP Juice Shop

Pin `f189f52`. Code Scan `gpt-6-luna` run `a3-acceptance-juice-shop`, one full scan of 84 requests on
the final code of the branch. Code Scan Gemini run `run-1512688242`, 84 completed assessments.

| ID | Class | Location | Code Scan, gpt-6-luna | Code Scan, Gemini | Semgrep CE | Bearer |
|---|---|---|---|---|---|---|
| `JS-XSS-01` | xss | `frontend/src/app/search-result/search-result.component.html:11` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-02` | xss | `frontend/src/app/track-result/track-result.component.html:9` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-03` | xss | `frontend/src/app/last-login-ip/last-login-ip.component.html:10` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-04a` | xss | `frontend/src/app/administration/administration.component.html:26` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-04b` | xss | `frontend/src/app/administration/administration.component.html:113` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-05a` | xss | `frontend/src/app/administration/administration.component.html:60` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-05b` | xss | `frontend/src/app/about/about.component.html:51` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-06` | xss | `frontend/src/app/product-details/product-details.component.html:18` | Confirmed | Confirmed | Missed | Missed |
| `JS-XSS-07` | xss | `routes/userProfile.ts:101` | Confirmed | Confirmed | Found | Found |
| `JS-SQL-01` | sql | `routes/login.ts:34` | Confirmed | Confirmed | Found | Found |
| `JS-SQL-02` | sql | `routes/search.ts:23` | Confirmed | Confirmed | Found | Found |
| `JS-NOSQL-01` | nosql | `routes/showProductReviews.ts:36` | Confirmed | Confirmed | Found | Missed |
| `JS-NOSQL-02` | nosql | `routes/trackOrder.ts:18` | Confirmed | Confirmed | Found | Missed |
| `JS-NOSQL-03` | nosql | `routes/updateProductReviews.ts:17` | Confirmed | Confirmed | Missed | Missed |
| `JS-LOG-01` | logging | `server.ts:366` | Practice finding | **Confirmed** | Missed | Missed |
| `JS-CONF-01` | configuration | `server.ts:290` | Confirmed | Confirmed | Found | Found |
| `JS-CONF-02` | configuration | `server.ts:298` | Confirmed | Confirmed | Found | Found |
| `JS-CONF-03` | configuration | `server.ts:302` | Confirmed | **Missed (Review)** | Found | Found |
| `JS-EXPO-01` | exposure | `server.ts:710` | Confirmed | Confirmed | Missed | Missed |
| `JS-EXPO-02` | exposure | `routes/metrics.ts:92` | Confirmed | Confirmed | Missed | Missed |
| `JS-HASH-01` | weak-hash | `lib/insecurity.ts:41` | Confirmed | Confirmed | Found | Found |
| `JS-MASS-01` | mass-assignment | `server.ts:529` | Confirmed | Confirmed | Missed | Missed |
| `JS-AUTHZ-01` | authorization | `server.ts:529` | Confirmed | Confirmed | Missed | Missed |
| `JS-AUTHZ-02` | authorization | `routes/updateProductReviews.ts:17` | Confirmed | Confirmed | Missed | Missed |
| `JS-ENUM-01` | enumeration | `routes/securityQuestion.ts:15` | Confirmed | Confirmed | Missed | Missed |
| `JS-CONF-04` | configuration | `server.ts:269` | Confirmed | Confirmed | Found | Found |
| `JS-HASH-02` | weak-hash | `lib/insecurity.ts:42` | Confirmed | Confirmed | Found | Found |
| `JS-AUTHZ-03` | authorization | `routes/coupon.ts:24` | Confirmed | Confirmed | Missed | Missed |
| `JS-AUTHZ-04` | authorization | `server.ts:529` | Confirmed | Confirmed | Missed | Missed |
| `JS-MASS-02` | mass-assignment | `server.ts:529` | Confirmed | **Missed (Review)** | Missed | Missed |
| `JS-MASS-03` | mass-assignment | `server.ts:529` | Confirmed | **Missed (Review)** | Missed | Missed |
| `JS-MASS-04` | mass-assignment | `server.ts:529` | Confirmed | **Missed (Review)** | Missed | Missed |
| `JS-MASS-05` | mass-assignment | `server.ts:529` | Confirmed | **Missed (Review)** | Missed | Missed |
| `JS-MASS-06` | mass-assignment | `server.ts:529` | Confirmed | Confirmed | Missed | Missed |
| `JS-REDIR-01` | redirect | `routes/redirect.ts:18` | Confirmed | Confirmed | Found | Found |
| `JS-PATH-02` | path | `routes/fileUpload.ts:34` (zip slip) | Confirmed | Confirmed | Missed | Missed |
| `JS-PATH-03` | path | `routes/dataErasure.ts:107` (layout file read) | Confirmed | Confirmed | Missed | Found |
| `JS-CODE-02` | code | `routes/b2bOrder.ts:23` | Practice finding | Practice finding | Missed | Found |
| `JS-SSRF-01` | ssrf | `routes/profileImageUrlUpload.ts:24` | Practice finding | **Confirmed** | Missed | Found |
| `JS-CODE-01` | code | `routes/userProfile.ts:65` (`eval`) | Confirmed | Confirmed | Found | Found |
| `JS-AUTHZ-05` | authorization | `routes/basket.ts:19` (read of another user's basket) | Confirmed | Confirmed | Missed | Missed |
| `JS-SECRET-01` | hardcoded secret | `lib/insecurity.ts:21`, used at `:54` | **Not covered** | **Not covered** | Found | Found |
| `JS-X-NOSQL-04` | nosql | `routes/likeProductReviews.ts:25`, `routes/likeProductReviews.ts:35`, `routes/likeProductReviews.ts:43` (review selected by an unchecked body value) | Confirmed | Confirmed | Found | Missed |
| `JS-X-AUTHZ-06` | authorization | `routes/recycles.ts:12` (any recycling request can be read without sign-in) | Confirmed | Confirmed | Missed | Missed |
| `JS-X-AUTHZ-07` | authorization | `server.ts:529` (DELETE /api/Feedbacks/:id has no owner test) | Confirmed | Confirmed | Missed | Missed |
| `JS-X-AUTHZ-08` | authorization | `server.ts:529` (DELETE /api/BasketItems/:id has no owner test) | Confirmed | Confirmed | Missed | Missed |
| `JS-X-AUTHZ-09` | authorization | `routes/basketItems.ts:42`, `routes/basketItems.ts:49` (A repeated BasketId passes the check and writes another basket) | Missed | Missed | Missed | Missed |
| `JS-X-AUTHZ-10` | authorization | `routes/dataExport.ts:33` (orders are selected by an email with its vowels masked, so another user can match) | Missed | Missed | Missed | Missed |
| `JS-X-MASS-07` | authorization | `routes/createProductReviews.ts:26` (review author comes from the body, with no sign-in check) | Missed | Missed | Missed | Missed |
| `JS-X-EXPO-03` | exposure | `routes/currentUser.ts:31` (A requested field can be the password hash) | Missed | Missed | Missed | Missed |
| `JS-X-EXPO-04` | exposure | `routes/currentUser.ts:58` (the current user is readable cross-origin through JSONP) | Missed | Missed | Missed | Missed |
| `JS-X-XSS-09` | xss | `routes/videoHandler.ts:71`, `routes/videoHandler.ts:72` (subtitle file is written into a script element) | Missed | Missed | Found | Missed |
| `JS-X-UPLOAD-02` | input-validation | `routes/fileUpload.ts:65`, `routes/fileUpload.ts:68` (the client's type rule is not enforced; other files are discarded) | Missed | Missed | Missed | Missed |
| `JS-X-RESET-01` | recovery | `routes/resetPassword.ts:41` (password reset by a reusable security answer) | Missed | Missed | Missed | Missed |
| `JS-X-CONF-05` | configuration | `server.ts:183`, `server.ts:184` (CORS allows every origin, without credentials; poor practice) | Missed | Missed | Found | Missed |
| `JS-X-CONF-06` | configuration | `frontend/src/app/login/login.component.ts:113`, `routes/updateUserProfile.ts:42` (session token cookie without HttpOnly) | Missed | Missed | Missed | Missed |
| `JS-X-SECRET-02` | hardcoded secret | `frontend/src/app/login/login.component.ts:68`, `frontend/src/app/login/login.component.ts:69` (working test credentials in the client) | **Not covered** | **Not covered** | Found | Missed |
| `JS-X-SECRET-03` | hardcoded secret | `data/static/users.yml:151` (committed TOTP secret of a seeded account) | **Not covered** | **Not covered** | Found | Missed |
| `JS-X-CSRF-01` | csrf | `routes/updateUserProfile.ts:17`, `routes/updateUserProfile.ts:38` (cookie-authenticated profile change without a CSRF token) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-XXE-01` | xxe | `lib/xml.ts:35`, `routes/fileUpload.ts:80` (XML parsed with entity substitution and DTD loading) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-JWT-01` | token-verification | `lib/insecurity.ts:52`, `lib/insecurity.ts:55` (token verified without an algorithm list) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-DOS-01` | resource-exhaustion | `routes/fileUpload.ts:114` (uploaded YAML expands without a limit) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-CRYPTO-01` | weak-crypto | `lib/insecurity.ts:97`, `lib/insecurity.ts:99` (coupon is an encoding, not a signature) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-AUTH-01` | authentication | `routes/changePassword.ts:39` (current password check is skipped when it is absent) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-AUTH-02` | authentication | `frontend/src/app/oauth/oauth.component.ts:31` (OAuth account password derived from the email) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-AUTH-03` | authentication | `models/user.ts:73` (no password policy) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-AUTO-01` | anti-automation | `server.ts:374` (rate limit keyed by a request header) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-AUTO-02` | anti-automation | `routes/captcha.ts:37`, `routes/captcha.ts:38` (A solved CAPTCHA can be reused) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-RACE-01` | race | `routes/likeProductReviews.ts:31`, `routes/likeProductReviews.ts:50` (like check and update can be raced) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-LOGIC-01` | business-logic | `routes/deluxe.ts:43` (unknown payment mode upgrades for free) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-LOGIC-02` | business-logic | `routes/order.ts:198`, `routes/order.ts:201` (coupon date comes from the client) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-LOGIC-03` | business-logic | `routes/basketItems.ts:43`, `routes/order.ts:144` (negative quantity gives a negative total) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-LOGIC-04` | business-logic | `routes/chat.ts:179`, `routes/chat.ts:184` (coupon limit exists only in the model tool description) | **Not covered** | **Not covered** | Missed | Missed |
| `JS-X-VALID-01` | input-validation | `models/feedback.ts:57`, `models/feedback.ts:58` (zero-star rating accepted) | Missed | Missed | Missed | Missed |
| `JS-X-VALID-02` | input-validation | `server.ts:436`, `server.ts:449`, `server.ts:450` (empty or mismatched registration accepted) | Missed | Missed | Missed | Missed |

The rows from `JS-REDIR-01` to `JS-SECRET-01` were added after the first comparison. The `JS-X-`
rows were added on 2026-11-25 from Juice Shop's own challenges and markers and from results of any
scanner. "Not covered" means Code Scan has no analyzer for the class. The null-byte file read
(`routes/fileServer.ts:32`) stays out of the table by the owner's decision of 2026-11-24.

### False positives

| Scanner | Locations | Why it is safe |
|---|---|---|
| Code Scan, gpt-6-luna | 2: `routes/likeProductReviews.ts:35`, `routes/likeProductReviews.ts:50` | Liking another user's review is the feature |
| Code Scan, gpt-6-luna | 1: `server.ts:294` | .well-known holds only published files |
| Code Scan, gpt-6-luna | 1: `routes/orderHistory.ts:36` | NoSQL: the selector value is a route parameter, always a string |
| Code Scan, Gemini | 1: `server.ts:294` | .well-known holds only published files |
| Code Scan, Gemini | 1: `routes/fileServer.ts:32` | The handler rejects a name containing /, so the read cannot leave its directory |
| Code Scan, Gemini | 1: `server.ts:307` | Swagger UI serves the published B2B API description, not internal state |
| Semgrep CE | 4: `routes/fileServer.ts:32`, `routes/keyServer.ts:14`, `routes/logfileServer.ts:14` and 1 more | Each handler rejects a name containing / |
| Semgrep CE | 1: `server.ts:294` | .well-known holds only published files |
| Semgrep CE | 1: `lib/antiCheat.ts:198` | A constant path list |
| Semgrep CE | 15: `routes/address.ts:18`, `routes/basket.ts:19`, `routes/basketItems.ts:68` and 12 more | NoSQL rule on a Sequelize (SQL) lookup with bound values |
| Semgrep CE | 1: `routes/captcha.ts:22` | eval of an expression built only from server-chosen numbers |
| Semgrep CE | 12: `data/datacreator.ts:323`, `data/datacreator.ts:381`, `data/datacreator.ts:756` and 9 more | Random value is not a secret |
| Semgrep CE | 4: `data/datacreator.ts:350`, `data/datacreator.ts:354`, `frontend/src/app/purchase-basket/purchase-basket.component.ts:60` and 1 more | Not a credential |
| Semgrep CE | 2: `frontend/src/app/navbar/navbar.component.html:17`, `frontend/src/app/purchase-basket/purchase-basket.component.html:16` | Angular interpolation, not a raw attribute |
| Semgrep CE | 1: `frontend/src/hacking-instructor/helpers/helpers.ts:49` | Read-only property walk |
| Semgrep CE | 2: `lib/codingChallenges.ts:77`, `lib/codingChallenges.ts:79` | Pattern built from fixed challenge keys |
| Semgrep CE | 1: `lib/startup/registerWebsocketEvents.ts:19` | Origin is fixed to a local development host |
| Semgrep CE | 1: `routes/changePassword.ts:28` | Comparison with null |
| Semgrep CE | 1: `routes/verify.ts:60` | Challenge check, not an access decision |
| Semgrep CE | 2: `rsn/rsnUtil.ts:63`, `scripts/package.mjs:121` | Developer script |
| Semgrep CE | 1: `server.ts:158` | Log prefix is a function name |
| Semgrep CE | 1: `views/promotionVideo.pug:75` | != in inline script text, not an unescaped output |
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
| Semgrep CE | 1: `pages/xss/sanitized/reflected.js:16` | DOMPurify output |
| Semgrep CE | 2: `scripts/export-prototype-pollution-fixtures.mjs:136`, `scripts/export-prototype-pollution-fixtures.mjs:137` | Build script over the project's own lockfile |
| Bearer | 1: `pages/xss/sanitized/reflected.js:16` | DOMPurify output |
| Bearer | 1: `pages/xss/safe/script-context.js:17` | < is escaped before the script context |
| Bearer | 1: `pages/api/secure/file-read.js:15` | Exact filename allow-list |
| Bearer | 1: `pages/secure/ssrf.js:26` | Same-origin URL and /api/ path check |

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## DVWA

Pin `a1978a2`. Code Scan `gpt-6-luna` run `run-4266343441`; Gemini run `run-247227625`. The key covers the "low" security level of each
module. DVWA's "medium" and "high" levels are also vulnerable by design and its "impossible"
level is the hardened one; results on medium and high are not keyed and are counted as
unreviewed.

| ID | Class | Location | Code Scan, gpt-6-luna | Code Scan, Gemini | Semgrep CE | Bearer |
|---|---|---|---|---|---|---|
| `SQLI-001` | sql | `vulnerabilities/sqli/source/low.php` | Confirmed | Confirmed | Found | Found |
| `SQLI-002` | sql | `vulnerabilities/sqli_blind/source/low.php` | Confirmed | Confirmed | Found | Found |
| `AUTH-001` | sql | `vulnerabilities/brute/source/low.php` | Confirmed | Confirmed | Found | Found |
| `CMD-001` | command | `vulnerabilities/exec/source/low.php` | Confirmed | Confirmed | Found | Found |
| `DVWA-API-CMD-01` | command | `vulnerabilities/api/src/HealthController.php:88` | Confirmed | Confirmed | Found | Missed |
| `XSSR-001` | xss | `dvwa/includes/dvwaPage.inc.php:388` | Confirmed | Confirmed | Missed | Missed |
| `XSSS-001` | xss | `dvwa/includes/dvwaPage.inc.php` | Confirmed | Confirmed | Missed | Missed |
| `UPLD-001` | upload | `vulnerabilities/upload/source/low.php:9` | Confirmed | Confirmed | Missed | Missed |
| `FI-001` | path | `vulnerabilities/fi/index.php:36` | Confirmed | Confirmed | Missed | Missed |
| `REDIR-001` | redirect | `vulnerabilities/open_redirect/source/low.php:4` | Confirmed | Confirmed | Missed | Found |
| `CODE-001` | code | `vulnerabilities/view_help.php` | Confirmed | Confirmed | Found | Found |

### False positives

| Scanner | Locations | Why it is safe |
|---|---|---|
| Code Scan, gpt-6-luna | 7: `login.php:47`, `vulnerabilities/brute/source/high.php:20`, `vulnerabilities/brute/source/medium.php:15` and 4 more | SQL: every request value is escaped for, and placed inside, a quoted literal |
| Code Scan, gpt-6-luna | 2: `vulnerabilities/bac/source/medium.php:22`, `vulnerabilities/bac/source/medium.php:29` | SQL: the value must match digits only |
| Code Scan, Gemini | 3: `login.php:47`, `vulnerabilities/xss_s/source/medium.php:19`, `vulnerabilities/xss_s/source/high.php:19` | SQL: every request value is escaped for, and placed inside, a quoted literal |
| Code Scan, Gemini | 1: `vulnerabilities/bac/source/medium.php:29` | SQL: the value must match digits only |
| Semgrep CE | 2: `vulnerabilities/exec/source/impossible.php:22`, `vulnerabilities/exec/source/impossible.php:26` | Address is rebuilt from four numeric octets |
| Semgrep CE | 4: `vulnerabilities/bac/source/low.php:22`, `vulnerabilities/bac/source/low.php:35`, `vulnerabilities/bac/source/medium.php:21` and 1 more | SQL: the value is an integer or must match digits only |
| Semgrep CE | 1: `instructions.php:26` | File name comes from a fixed map |
| Semgrep CE | 9: `login.php:48`, `vulnerabilities/brute/source/high.php:22`, `vulnerabilities/brute/source/low.php:15` and 6 more | No digest is compared with a loose operator that an input can influence |
| Semgrep CE | 1: `vulnerabilities/upload/source/impossible.php:54` | Deletes its own temporary file |
| Bearer | 2: `vulnerabilities/exec/source/impossible.php:22`, `vulnerabilities/exec/source/impossible.php:26` | Address is rebuilt from four numeric octets |
| Bearer | 4: `vulnerabilities/bac/source/low.php:23`, `vulnerabilities/bac/source/low.php:36`, `vulnerabilities/bac/source/medium.php:22` and 1 more | SQL: the value is an integer or must match digits only |
| Bearer | 23: `vulnerabilities/bac/source/high.php:65`, `vulnerabilities/bac/source/high.php:68`, `vulnerabilities/bac/source/impossible.php:53` and 20 more | XSS: constant text |
| Bearer | 2: `vulnerabilities/bac/source/low.php:27`, `vulnerabilities/bac/source/medium.php:43` | XSS: the value is an integer or must match digits only |

Bearer's other 51 cross-site scripting results were not read. Results on the medium and high
levels that are vulnerable by design are not false positives and are not keyed.

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## vuln-symfony

Pin `086f81f`. Code Scan `gpt-6-luna` run `run-1810616125`; Gemini run `run-200762536`. The Gemini run
has no reviewed false positive.

| ID | Class | Location | Code Scan, gpt-6-luna | Code Scan, Gemini | Semgrep CE | Bearer |
|---|---|---|---|---|---|---|
| `SYM-SQL-01` | sql | `src/Repository/PostRepository.php:67` | Confirmed | Confirmed | Found | Found |
| `SYM-SQL-02` | sql | `src/Repository/UserRepository.php:77` | Confirmed | Confirmed | Found | Found |
| `SYM-XSS-01` | xss | `templates/blog/index.html.twig:11` | Confirmed | Confirmed | Missed | Missed |
| `SYM-XSS-02` | xss | `templates/blog/post.html.twig:40` | Confirmed | Confirmed | Missed | Missed |
| `SYM-XSS-03` | xss | `templates/blog/post.html.twig:37` | Confirmed | **Practice finding** | Missed | Missed |
| `SYM-CMD-01` | command | `src/Services/Analytics.php:32` | Confirmed | Confirmed | Found | Missed |
| `SYM-CMD-02` | command | `src/Controller/UserController.php:195` | Confirmed | Confirmed | Found | Missed |
| `SYM-PATH-01` | path | `src/Controller/BlogController.php:95` | Confirmed | Confirmed | Missed | Missed |
| `SYM-PATH-02` | path | `src/Controller/UserController.php:159` | Confirmed | Confirmed | Found | Missed |
| `SYM-PATH-03` | path | `src/Services/Avatar.php:18` | Confirmed | Confirmed | Missed | Missed |
| `SYM-SSRF-01` | ssrf | `src/Services/Avatar.php:18` | Confirmed | Confirmed | Missed | Missed |
| `SYM-UPLOAD-01` | upload | `src/Controller/UserController.php:99` | Confirmed | Confirmed | Missed | Missed |
| `SYM-SSTI-01` | code | `src/Twig/TemplateFromStringExtension.php:22` | Confirmed | Confirmed | Missed | Missed |
| `SYM-DESER-01` | deserialization | `src/Services/UserPref.php:36` | Confirmed | Confirmed | Found | Found |
| `SYM-INFO-01` | exposure | `public/info.php:2` | Confirmed | Confirmed | Found | Found |
| `SYM-MASS-01` | mass-assignment | `src/Entity/User.php:59` | Confirmed | Confirmed | Missed | Missed |
| `SYM-AUTHZ-01` | authorization | `src/Controller/AdminController.php:32` | Confirmed | Confirmed | Missed | Missed |
| `SYM-AUTHZ-02` | authorization | `src/Controller/UserController.php:41` | Confirmed | Confirmed | Missed | Missed |
| `SYM-AUTHZ-03` | authorization | `src/Controller/UserController.php:62` | Confirmed | Confirmed | Missed | Missed |
| `SYM-AUTHZ-04` | authorization | `src/Controller/UserController.php:159`; `src/Controller/UserController.php:161` | Confirmed | Confirmed | Missed | Missed |
| `SYM-LOCAL-01` | authorization | `src/Controller/LocalController.php:77` | Confirmed | Confirmed | Missed | Missed |
| `SYM-ENUM-01` | enumeration | `src/Controller/LoginController.php:76`; `src/Controller/LoginController.php:83` | Confirmed | Confirmed | Missed | Missed |
| `SYM-ENUM-02` | enumeration | `src/Controller/PasswordResetController.php:34` | Confirmed | Confirmed | Missed | Missed |
| `SYM-RESET-01` | recovery | `src/Services/Mail.php:35` | Confirmed | Confirmed | Missed | Missed |
| `SYM-HASH-01` | weak-hash | `src/Security/Hasher/Md5Hasher.php:15`; `src/Controller/UserController.php:41` … | Confirmed | Confirmed | Found | Found |
| `SYM-CONF-01` | configuration | `docker/apache.conf:2` | Confirmed | Confirmed | Missed | Missed |
| `SYM-CONF-02` | configuration | `Dockerfile:50`; `Dockerfile:47` … | Confirmed | Confirmed | Missed | Missed |
| `SYM-CONF-03` | configuration | `config/packages/framework.yaml:4` | Confirmed | Confirmed | Missed | Missed |
| `SYM-CONF-04` | configuration | `config/packages/framework.yaml:13` | Confirmed | Confirmed | Missed | Missed |
| `SYM-SSRF-02` | ssrf | `src/Services/Analytics.php:32` | Confirmed | Confirmed | Missed | Missed |

### False positives

| Scanner | Locations | Why it is safe |
|---|---|---|
| Semgrep CE | 14: `templates/admin/index.html.twig:59`, `templates/base.html.twig:29`, `templates/base.html.twig:31` and 11 more | URL generated by path() |
| Semgrep CE | 2: `templates/admin/index.html.twig:49`, `templates/admin/index.html.twig:52` | Attribute is one of two constants |
| Semgrep CE | 2: `src/Controller/UserController.php:98`, `src/Controller/UserController.php:138` | md5 names an uploaded file |
| Semgrep CE | 5: `.env:34`, `.env:35`, `docker/.env.local:18` and 2 more | Commented-out setting |
| Bearer | 2: `src/Controller/UserController.php:98`, `src/Controller/UserController.php:138` | md5 names an uploaded file |

[All locations](../../.zazz/evaluation/scanner-false-positives.json)

## Method and limits

- A scanner's result matches a known vulnerability when it is in the same file, its rule is of
  the same weakness class, and it is within three lines of the keyed line.
- Code Scan "found" means a Confirmed finding, or a practice finding where the table says so.
  A record left in Review is a miss.
- The answer keys were written for Code Scan's own evaluation, so they favor the classes it
  analyzes. Juice Shop's was extended from independent sources. The vuln-nextjs, DVWA and
  vuln-symfony keys were not.
- A result outside the key is not a false positive. The keys are not complete lists of each
  application's vulnerabilities, so results outside them were sorted: real but not keyed,
  false positive, undecided, or outside application code (tests, challenge snippets,
  Terraform, containers, package policy). Only false positives are counted.
- A false positive is a result where the reported weakness cannot occur at that location. It is
  counted once per file and line.
- Run details, commands and the raw outputs are in the
  [contributor run record](../../.zazz/evaluation/comparison-results.md) and the per-scanner
  documents it links.
