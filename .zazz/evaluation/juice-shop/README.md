# Juice Shop documented challenges and Bearer review

Pinned target: v20.3.0, `f189f521266f42c6bd05884468292000cee852ed`.
All **116 documented challenges** are indexed from `data/static/challenges.yml`, including category,
description, difficulty, disabled environments and source/test references in
[expected-challenges.jsonl](expected-challenges.jsonl). Every key has a non-registry source reference.
This is the complete challenge registry at that revision, **not** a complete list of expected SAST
findings: several challenges require business intent, runtime state, dependencies or non-code clues.
Independent human labels and per-challenge SAST detectability remain pending. Source annotations and
tests are useful evidence; a challenge observer alone is not proof of exploitation or persistence.

[The comparison](../bearer-results.md) records both target scans and the original/additional controls.
[The full Bearer ledger](bearer-review.jsonl) preserves all 671 findings with source hashes, rule,
location, scope, exact documented vulnerable-line overlap where present, and review status.
Automatic reference/line matches are navigation aids, not correctness decisions.
[Summary counts](inventory-summary.json) and [explicit review decisions](review-decisions.json) are
versioned separately from the ignored raw reports.

## Command-execution classification

The [command-injection reference](command-injection-review.md) distinguishes direct process-API
command injection from the documented SSTi/JavaScript-execution challenges and records a constant
packaging-command control. It supplies independent classification for the full judged
Command Injection Analyzer acceptance; no new detector or scan result is claimed by that review.

## External exercise report

[Corisco pentest summary](coriscope-pentest-summary.md) summarizes all eleven categories in the
user-selected 2024 report, preserves attributed scores/CWE IDs, and maps comparison candidates to
our pinned inventory. Its claims are external evaluation evidence, not automatic scanner verdicts.
SQL/NoSQL judgment against known-positive, protected, and unknown cases takes priority over logger-leak.

## Initial source review

| Rule and location | Source-inspected disposition | Reason |
|---|---|---|
| logger_leak, lib/startup/validateConfig.ts:45 | False positive for sensitive-data leak | Constant public documentation URL passed through a color formatter |
| logger_leak, lib/startup/validateConfig.ts:47 | False positive for sensitive-data leak | Constant configuration-error message passed through a color formatter |
| hardcoded_secret, lib/insecurity.ts:52 | False positive for secret classification | JWT verifier receives public verification material from jwt.pub; the separate hardcoded private key remains a real concern |
| sql_injection, routes/login.ts:34 | Supported potential | Request email directly interpolates into SQL text |
| sql_injection, routes/search.ts:23 | Supported potential | Request criteria interpolates after length restriction, which does not prevent SQL syntax |
| SSRF and HTTP URL, routes/profileImageUrlUpload.ts:24 | Supported potential; one grouped concern | Request URL reaches fetch; authenticated-user requirement does not constrain destination |

**Sensitive-data logging, 2026-11-01.** Juice Shop writes cleartext passwords to its access log:
`GET /rest/user/change-password` carries `current`/`new`/`repeat` in the query string and
`morgan('combined')` (`server.ts:366`) records the URL. None of Bearer's 278 logger findings covers
this (false negative); its credential-looking logger lines log fixture keys, already-masked emails,
or constant text. zazzles now reports the change-password case as a finding and the security-question
email query as Review. The remaining Bearer logger rows were not individually adjudicated.

These seven raw finding decisions contain three false positives and four supported potential rule
results (three grouped source/sink concerns). They are agent source inspections, not independent
human review or runtime confirmation. The other **664 findings remain pending**, so 3/671 is a lower
bound on observed false findings, not an estimated false-positive rate. Two protected custom-validator
controls also produced Bearer SQL false positives outside this application inventory.

Scope is separately recorded: 329 application/support findings, 278 test findings and 64 training
snippet findings. Test and training findings are not automatically false positives. They also must
not inflate production vulnerability counts. Caller/guard/library context is needed before dismissing
other findings; dynamic logs, YAML loading, file paths and JWT policies remain review candidates.

## Reproduce the inventory

Requires Python 3 and Ruby's standard-library YAML parser; no target code is executed.
The script checks the exact target revision and rejects tracked source modifications.

```bash
python3 .zazz/evaluation/inventory-juice-shop.py \
  --target <DEV_ROOT>/juice-shop \
  --bearer-report .zazz/ephemeral/bearer-comparison/final/bearer-juice-shop.json \
  --output .zazz/evaluation/juice-shop
```

The inventory below is generated navigation for every registry entry; maintained metadata and
references live in JSONL. No unreviewed row asserts a scanner miss or a protected route.

## Complete documented registry

| Challenge key | Name | Category | Definition |
|---|---|---|---|
| accessLogDisclosureChallenge | Access Log | Observability Failures | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L40) |
| adminSectionChallenge | Admin Section | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L66) |
| aiDebuggingChallenge | AI Debugging | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1556) |
| basketAccessChallenge | View Basket | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1212) |
| basketManipulateChallenge | Manipulate Basket | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L720) |
| captchaBypassChallenge | CAPTCHA Bypass | Broken Anti Automation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L194) |
| changePasswordBenderChallenge | Change Bender's Password | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L205) |
| changeProductChallenge | Product Tampering | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L902) |
| chatbotGreedyInjectionChallenge | Greedy Chatbot Manipulation | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1542) |
| chatbotPromptInjectionChallenge | Chatbot Prompt Injection | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1529) |
| christmasSpecialChallenge | Christmas Special | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L218) |
| closeNotificationsChallenge | Mass Dispel | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1483) |
| continueCodeChallenge | Imaginary Challenge | Cryptographic Issues | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L561) |
| csafChallenge | Security Advisory | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1492) |
| csrfChallenge | CSRF | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1387) |
| dataExportChallenge | GDPR Data Theft | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L529) |
| dbSchemaChallenge | Database Schema | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L291) |
| deprecatedInterfaceChallenge | Deprecated Interface | Security Misconfiguration | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L306) |
| directoryListingChallenge | Confidential Document | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L263) |
| dlpPasswordSprayingChallenge | Leaked Access Logs | Observability Failures | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L575) |
| dlpPastebinDataLeakChallenge | Leaked Unsafe Product | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L591) |
| easterEggLevelOneChallenge | Easter Egg | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L323) |
| easterEggLevelTwoChallenge | Nested Easter Egg | Cryptographic Issues | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L760) |
| emailLeakChallenge | Email Leak | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L334) |
| emptyUserRegistration | Empty User Registration | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L343) |
| ephemeralAccountantChallenge | Ephemeral Accountant | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L356) |
| errorHandlingChallenge | Error Handling | Security Misconfiguration | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L370) |
| exposedCredentialsChallenge | Exposed Credentials | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1501) |
| exposedMetricsChallenge | Exposed Metrics | Observability Failures | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1350) |
| extraLanguageChallenge | Extra Language | Broken Anti Automation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L395) |
| feedbackChallenge | Five-Star Feedback | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L405) |
| fileWriteChallenge | Arbitrary File Write | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L83) |
| forgedCouponChallenge | Forged Coupon | Cryptographic Issues | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L420) |
| forgedFeedbackChallenge | Forged Feedback | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L433) |
| forgedReviewChallenge | Forged Review | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L447) |
| forgottenBackupChallenge | Forgotten Sales Backup | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L494) |
| forgottenDevBackupChallenge | Forgotten Developer Backup | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L480) |
| freeDeluxeChallenge | Deluxe Fraud | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1375) |
| geoStalkingMetaChallenge | Meta Geo Stalking | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1429) |
| geoStalkingVisualChallenge | Visual Geo Stalking | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1440) |
| ghostLoginChallenge | GDPR Data Erasure | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L517) |
| hiddenImageChallenge | Steganography | Security through Obscurity | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1094) |
| httpHeaderXssChallenge | HTTP-Header XSS | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L542) |
| iacLeakedKeyChallenge | Login Cloud Admin | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1581) |
| jwtForgedChallenge | Forged Signed JWT | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L461) |
| jwtUnsignedChallenge | Unsigned JWT | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1147) |
| knownVulnerableComponentChallenge | Vulnerable Library | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1227) |
| leakedApiKeyChallenge | Leaked API Key | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1515) |
| lfrChallenge | Local File Read | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1469) |
| localXssChallenge | DOM XSS | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L276) |
| loginAdminChallenge | Login Admin | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L618) |
| loginAmyChallenge | Login Amy | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L635) |
| loginBenderChallenge | Login Bender | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L649) |
| loginJimChallenge | Login Jim | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L678) |
| loginRapperChallenge | Login MC SafeSearch | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L693) |
| loginSupportChallenge | Login Support Team | Security Misconfiguration | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L709) |
| manipulateClockChallenge | Expired Coupon | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L381) |
| misplacedIacFiles | Misplaced IaC Files | Security Misconfiguration | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1363) |
| misplacedSignatureFileChallenge | Misplaced Signature File | Observability Failures | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L734) |
| missingEncodingChallenge | Missing Encoding | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1322) |
| negativeOrderChallenge | Payback Time | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L845) |
| nftMintChallenge | Mint the Honey Pot | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L139) |
| nftUnlockChallenge | NFT Takeover | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L128) |
| noSqlCommandChallenge | NoSQL DoS | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L774) |
| noSqlOrdersChallenge | NoSQL Exfiltration | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L791) |
| noSqlReviewsChallenge | NoSQL Manipulation | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L805) |
| nullByteChallenge | Poison Null Byte | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1454) |
| oauthUserPasswordChallenge | Login Bjoern | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L665) |
| passwordHashLeakChallenge | Password Hash Leak | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L12) |
| passwordRepeatChallenge | Repetitive Registration | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L933) |
| persistedXssFeedbackChallenge | Server-side XSS Protection | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1077) |
| persistedXssUserChallenge | Client-side XSS Protection | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L248) |
| premiumPaywallChallenge | Premium Paywall | Cryptographic Issues | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L859) |
| privacyPolicyChallenge | Privacy Policy | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L875) |
| privacyPolicyProofChallenge | Privacy Policy Inspection | Security through Obscurity | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L892) |
| rceChallenge | Blocked RCE DoS | Insecure Deserialization | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L176) |
| rceOccupyChallenge | Successful RCE DoS | Insecure Deserialization | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1106) |
| redirectChallenge | Allowlist Bypass | Unvalidated Redirects | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1251) |
| redirectCryptoCurrencyChallenge | Outdated Allowlist | Unvalidated Redirects | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L818) |
| reflectedXssChallenge | Reflected XSS | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L916) |
| registerAdminChallenge | Admin Registration | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L51) |
| resetPasswordBenderChallenge | Reset Bender's Password | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L948) |
| resetPasswordBjoernChallenge | Reset Bjoern's Password | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L963) |
| resetPasswordBjoernOwaspChallenge | Bjoern's Favorite Pet | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L99) |
| resetPasswordJimChallenge | Reset Jim's Password | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L977) |
| resetPasswordMortyChallenge | Reset Morty's Password | Broken Anti Automation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L992) |
| resetPasswordUvoginChallenge | Reset Uvogin's Password | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1416) |
| restfulXssChallenge | API-only XSS | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L25) |
| retrieveBlueprintChallenge | Retrieve Blueprint | Sensitive Data Exposure | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1003) |
| scoreBoardChallenge | Score Board | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1046) |
| securityPolicyChallenge | Security Policy | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1062) |
| ssrfChallenge | SSRF | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1017) |
| sstiChallenge | SSTi | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1033) |
| supplyChainAttackChallenge | Supply Chain Attack | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1122) |
| svgInjectionChallenge | Cross-Site Imaging | Security Misconfiguration | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1337) |
| systemPromptExtractionChallenge | System Prompt Extraction | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1569) |
| timingAttackChallenge | Multiple Likes | Broken Anti Automation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L746) |
| tokenSaleChallenge | Blockchain Hype | Security through Obscurity | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L115) |
| twoFactorAuthUnsafeSecretStorageChallenge | Two Factor Authentication | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1134) |
| typosquattingAngularChallenge | Frontend Typosquatting | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L505) |
| typosquattingNpmChallenge | Legacy Typosquatting | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L602) |
| unionSqlInjectionChallenge | User Credentials | Injection | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1181) |
| uploadSizeChallenge | Upload Size | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1158) |
| uploadTypeChallenge | Upload Type | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1168) |
| usernameXssChallenge | CSP Bypass | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L232) |
| videoXssChallenge | Video XSS | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1195) |
| vulnerableDockerImageChallenge | Vulnerable Infrastructure | Vulnerable Components | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1593) |
| weakPasswordChallenge | Password Strength | Broken Authentication | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L833) |
| web3SandboxChallenge | Web3 Sandbox | Broken Access Control | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L161) |
| web3WalletChallenge | Wallet Depletion | Miscellaneous | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L150) |
| weirdCryptoChallenge | Weird Crypto | Cryptographic Issues | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1237) |
| xssBonusChallenge | Bonus Payload | XSS | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1401) |
| xxeDosChallenge | XXE DoS | XXE | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1281) |
| xxeFileDisclosureChallenge | XXE Data Access | XXE | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1264) |
| yamlBombChallenge | Memory Bomb | Insecure Deserialization | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1297) |
| zeroStarsChallenge | Zero Stars | Improper Input Validation | [registry](https://github.com/juice-shop/juice-shop/blob/f189f521266f42c6bd05884468292000cee852ed/data/static/challenges.yml#L1309) |

Latest scanner work: [SQL/NoSQL judgment calibration](query-judgment-calibration.md), including
conditional false-positive correction and remaining acceptance checks. Earlier tables are historical.
