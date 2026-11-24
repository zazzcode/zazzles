# Juice Shop and Next.js hardening 1 — results

Branch `juiceshop-nextjs-hardening-1` of the [lane](../specifications/juiceshop-nextjs-hardening-1.md),
draft [PR #48](https://github.com/zazzcode/zazzles/pull/48). Scanner commit of the acceptance
runs: `97709ad` (the code of the branch; later commits change documents only). Samples: OWASP Juice
Shop at `f189f521266f42c6bd05884468292000cee852ed`, vuln-nextjs at
`f5d47de3b684f532141b8b4127060189c236dfd6`. Provider and model: OpenAI `gpt-6-luna`, default judge
limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`, no fallback, only the OpenAI key passed to the scanner
process. The [detection guide](juice-shop-detection-guide.md) holds the answer key.

## Judged runs

Eight of the eight runs allowed by §6 are used. Each run folder is under
`_test-findings/juiceshop-nextjs-hardening/judged/` (outside the repository).

| # | Folder | Scanner | Scope | Requests | Input tokens | Result |
|---:|---|---|---|---:|---:|---|
| 1 | `s2-exposure-configuration` | `8383df8` | `--only-family exposure,configuration` | 9 | 18,240 | EXPO-02 Confirmed; EXPO-01 and configuration needs evidence (missing role, then `setting_effect` unknown) |
| 2 | `s2b-exposure-configuration` | `8383df8` + fixes | same | 9 | 18,533 | EXPO-01, EXPO-02 Confirmed; configuration still `setting_effect` unknown |
| 3 | `s2c-configuration` | + `deployed_file` evidence | `--only-family configuration` | 5 | 11,539 | CONF-01 to 03 Confirmed |
| 4 | `s3-account` | `f531911` | `--only-family account` | 7 | 13,655 | HASH-01 and ENUM-01 Confirmed |
| 5 | `s4-authorization` | S4 working tree before `3a9fdff` | `--only-family authorization` | 7 | 22,548 | AUTHZ-02 Confirmed; N01 and N02 Protected |
| 6 | `s5-mass-authorization` | S5 working tree before `9072073` | `--only-family mass-assignment,authorization` | 63 | 164,538 | Generated-resource records needs evidence (`dispatch_binding` missing). Fixed after the run |
| 7 | `s7-acceptance-juice-shop` | `97709ad` | Full scan | 109 | 425,771 | Every required positive Confirmed; controls as expected |
| 8 | `s7-acceptance-vuln-nextjs` | `97709ad` | Full scan | 27 | 121,218 | 13 of 13 keyed cases witnessed |

First failing stage of each failed row: run 1 evidence missing (the entry of a middleware mount has
no callable, so the role `dispatch_binding` had no evidence); runs 1 and 2 question wording against
facts (the `in_effect` answer asks for a recorded mapping fact, which the adapter now records as
`deployed_file` evidence); run 6 evidence missing (the same role on a generated endpoint).

## Juice Shop key (acceptance run 7)

| ID | Anchor | Status |
|---|---|---|
| `JS-CONF-01` | `server.ts:290` | Confirmed |
| `JS-CONF-02` | `server.ts:298` | Confirmed |
| `JS-CONF-03` | `server.ts:302` | Confirmed |
| `JS-EXPO-01` | `server.ts:710` | Confirmed |
| `JS-EXPO-02` | `routes/metrics.ts:92` | Confirmed |
| `JS-HASH-01` | `lib/insecurity.ts:41` | Confirmed (two records: model accessor and SQL login) |
| `JS-MASS-01` | `server.ts:529`, `POST /api/Users` | Confirmed; `role` carried as a `name_hint` |
| `JS-AUTHZ-01` | `server.ts:529`, `PUT /api/Products/:id` | Confirmed |
| `JS-AUTHZ-02` | `routes/updateProductReviews.ts:17` | Confirmed |
| `JS-ENUM-01` | `routes/securityQuestion.ts:15` | Confirmed |
| `JS-AUTHZ-N01`, `N02` | `routes/address.ts:29`, `routes/payment.ts:70` | Protected (`ownership_check`, `query_scope`) |
| `JS-AUTHZ-N03`, `N04`, `JS-ENUM-N01`, `JS-MASS-N01` | `changePassword.ts:51`, `updateUserProfile.ts:38`, `login.ts:34` | No record |

The existing Juice Shop rows keep their statuses: 9 XSS, 2 SQL, 3 keyed and 7 reported NoSQL
findings and the sensitive-logging row are Confirmed, and `check.py` finds no keyed false
positive in any family.

Recorded with any status, as §3 says: 5 `serve-index` mounts (all Confirmed), swagger-ui-express
(`server.ts:307`, Review), 28 generated mass-assignment and 28 generated authorization records for
14 models (16 and 10 Confirmed), `lib/insecurity.ts:42` (an HMAC a model accessor stores, Confirmed),
`routes/delivery.ts:34` (an account-enumeration record on a delivery-method lookup, Confirmed),
`routes/coupon.ts:24` and `routes/likeProductReviews.ts:35` (authorization, Confirmed).

## vuln-nextjs (acceptance run 8)

13 of 13 keyed cases are witnessed offline; 27 requests as in the 2026-11-19 report. The practice
finding of the catalog is the redirect control `pages/secure/redirect.js`, reported as a poor
practice as before. An offline scan records every record identifier of the baseline scan of the same
revision (54 records, 37 entries).

## Offline measures (AC11 to AC13)

| Check | Result |
|---|---|
| DVWA and vuln-symfony reports | Byte-identical to the baseline scan after removing the run identifier (`cmp` of 44,121,503 and 3,983,818 bytes) |
| `TestArchitectureBaseline`, `TestDVWASourceKey`, `TestSymfonySourceKey`, Juice Shop and Goof tests | Pass; no row of `architecture-baseline.json` changed |
| Juice Shop records | 255 baseline records keep their identifier and content; 332 records in all (+77); entries 175 to 218 |
| nodejs-goof | One added `info_exposure_candidate` (the `errorhandler` registration); no existing record changed |
| `TestNextJSVulnLab` at `f5d47de` | Pass |

## Lead review after the acceptance run (2026-11-24)

A source review of acceptance run 7 against the access rules of the sample found Confirmed
records on endpoints that reject every caller, and one enumeration record on a catalog lookup.
Three causes, each fixed with a fixture:

| Cause | Fix | Test |
|---|---|---|
| An `express-jwt` middleware whose `secret` is a fresh random value accepts no request, but was read as ordinary authentication. Generated update and delete endpoints behind it were recorded and Confirmed | `EntryAccess.rejects_all` is set from that library contract. An unreachable generated endpoint makes no claim, and the handler producers skip such an entry | `TestExpressRejectsAll`, `TestExpressGeneratedReachability` |
| A registration written as `app.route(path).put(mw)`, and an `app.use` on the same path pattern as the endpoint, were not read as covering a generated endpoint | Both forms are read | the same tests |
| An attribute that a registered middleware overwrites was listed as request-chosen in a generated mass-assignment record | The attribute is left out of the writable fields | `TestExpressGeneratedReachability` |
| Account enumeration recorded a lookup by primary key alone | A lookup must name an attribute other than the surrogate key | `account-express/primary/lookups.ts`, `/ticket-number/:id` |

Offline effect on Juice Shop: 332 records become 299 (the 255 baseline records are unchanged).
33 records are gone: 32 generated-resource records on unreachable endpoints and the delivery
lookup.

Judged run 9 (`r9-review-authz-mass-account`, `--only-family mass-assignment,authorization,account`,
35 requests, 90,373 input tokens), made on the owner's word that focused runs may continue:

| Family | Run 7 Confirmed | Run 9 Confirmed | Removed as false positives |
|---|---:|---:|---|
| Mass assignment | 16 | 6 | `PUT` on Users, Feedbacks, Complaints, Recycles, SecurityAnswers, PrivacyRequests and Cards (all unreachable); `POST` Addresss and Cards and `PUT` Addresss (the privileged field is overwritten) |
| Authorization | 10 | 5 | `PUT` and `DELETE` on Users, `DELETE` on Hints and PrivacyRequests (unreachable) |
| Account enumeration | 2 | 1 | The delivery-method lookup |
| Password hashing | 3 | 3 | — |

Every required positive of the key is still Confirmed and `JS-AUTHZ-N01` and `N02` are still
Protected. `DELETE /api/BasketItems/:id` moved from Confirmed to Review between the two runs with
no change to its evidence. The full acceptance scan was not repeated after these fixes: the
exposure and configuration results are those of run 7, whose code did not change.

Judged run 10 (`r10-acceptance-juice-shop`, scanner `29ce9aa`, full scan, 76 requests, 341,565
input tokens) repeats the acceptance scan on the fixed code. 299 records: 45 Confirmed, 3
Protected, 2 poor practice and 249 Review. Every required positive of the key is Confirmed and
no control is a finding. Against run 7, the only record present in both whose status differs is
`DELETE /api/BasketItems/:id` (Confirmed to Review); the other 15 Confirmed records of run 7 that
are absent here are the false positives above (three of them are recorded again without the
overwritten attribute, as Review). Before this branch the sample had 22 Confirmed
records, so the branch adds 23: 5 configuration, 3 exposure, 3 password hashing, 1 account
enumeration, 5 authorization and 6 mass assignment. This run replaces run 7 as the acceptance
result.

### Source review of the Confirmed records outside the key

Run 10 has twelve Confirmed records of the new families that the key does not hold. Each was
read against the sample's source at the pin.

| Record | Source | Verdict |
|---|---|---|
| Authorization, `routes/coupon.ts:24` | `BasketModel.findByPk(params.id)` then `basket.update({ coupon })`; the chain requires a login and nothing compares the basket's owner | True positive: a signed-in user changes another user's basket |
| Authorization, `routes/likeProductReviews.ts:35` | `$inc: { likesCount: 1 }` on the review `req.body.id` names | **False positive.** Liking another user's review is the feature; the review is not the caller's object to own |
| Authorization, `PUT /api/Hints/:id` | No middleware is registered for `PUT`; `server.ts:403` says it is allowed | True positive, low impact: anyone rewrites a hint's `text` and `unlocked` without a login |
| Mass assignment, `POST /api/Feedbacks` | `UserId` is a model attribute; `routes/verify.ts:30` shows the sample's own forged-feedback challenge is this write | True positive |
| Mass assignment, `POST /api/Complaints` | Login required, `UserId` taken from the body | True positive: a complaint filed as another user |
| Mass assignment, `POST /api/Recycles` | Login required, `UserId` and `AddressId` from the body | True positive |
| Mass assignment, `POST /api/PrivacyRequests` | Login required, `UserId` and `deletionRequested` from the body | True positive |
| Mass assignment, `POST /api/SecurityAnswers` | No middleware for `POST`; `UserId` and `answer` from the body | True positive: an answer is created for a chosen user id |
| Configuration, `server.ts:269` | `serve-index` of `infrastructure` (Dockerfile, compose file, Terraform) | True positive |
| Configuration, `server.ts:294` | `serve-index` of `.well-known` (`security.txt`, CSAF advisories) | **False positive** as a vulnerability: the listing is enabled, and the directory holds only files published on purpose |
| Password hashing, `lib/insecurity.ts:42` | HMAC-SHA256 with a constant key, stored by the security answer's accessor | True positive for the weakness; the model called the input a password and it is a recovery answer |
| Information exposure, `routes/metrics.ts:92` (second record) | The second registration of `GET /metrics` (`server.ts:704`, `:759`) | Duplicate of `JS-EXPO-02` |

Ten are true positives, of which one is a duplicate, and two are false positives. The nine
distinct true positives are candidates for the answer key; adding them is a key change with
this table as its source evidence.

Still open: a generated endpoint that an explicit handler for the same method and path answers
first is recorded (Review); a password-hash record whose digest lives in a model accessor is
attached to an unrelated entry; the Confirmed records outside the key
(`routes/coupon.ts:24`, `routes/likeProductReviews.ts:35`, `PUT /api/Hints/:id`, and the generated
creates that accept `UserId`) have not been source-reviewed.

## Not built, and deviations

- **Upload (D-10, AC9 second half).** Cause established: the family is registered for JavaScript and
  TypeScript but `langjs` has no producer of `file_upload_candidate`
  ([§1.2](../specifications/juiceshop-nextjs-hardening-1.md#12-causes)). The producer, a memory-storage
  contract and its fixtures are not built.
- **Deployment-file readers for a JavaScript project (D-9, third row).** Not built; binds no
  criterion.
- **Entry access `none`.** Stored as no record, so existing reports are unchanged (spec halt 1);
  `expressEntryAccess` reads the absence as `none`.
- **Census (D-6).** Only the `credential` role (set accessor or SQL comparison) and `name_hint`.
- **Account enumeration** records any verified model, so a delivery-method lookup is recorded.
- Every other reading is under "Deviations" of the run log
  (`.zazz/ephemeral/juiceshop-nextjs-hardening-run-log.md`, not committed).
