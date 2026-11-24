# Juice Shop detection guide

Source reviewed at `f189f521266f42c6bd05884468292000cee852ed` in the local checkout of
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop). Paths are relative to the sample
root. The existing Juice Shop rows (cross-site scripting, SQL and NoSQL injection, logging) live
in the [sample catalog](../project/vulnerable-sample-apps.md#owasp-juice-shop) and in
[`recall-gap-inventory/cases.json`](recall-gap-inventory/cases.json). This guide holds the rows the
[Juice Shop and Next.js hardening lane](../specifications/juiceshop-nextjs-hardening-1.md) adds.
A challenge's existence is not a label: every row below was read in source.

## Required positives

Each is a witnessed candidate offline and a Confirmed finding in the judged acceptance run.

| ID | Kind | Anchor | Evidence |
|---|---|---|---|
| `JS-CONF-01` | `configuration_candidate`, directory listing | `server.ts:290` | `serve-index` of `ftp` mounted for every caller |
| `JS-CONF-02` | same | `server.ts:298` | `serve-index` of `encryptionkeys` |
| `JS-CONF-03` | same | `server.ts:302` | `serve-index` of `logs` |
| `JS-EXPO-01` | `info_exposure_candidate` | `server.ts:710` | `errorhandler()` registered with no environment condition |
| `JS-EXPO-02` | `info_exposure_candidate` | `routes/metrics.ts:92` | `register.metrics()` sent on `GET /metrics`, access `none` |
| `JS-HASH-01` | `password_hash_candidate` | `lib/insecurity.ts:41` | `md5` digest stored by the `password` accessor (`models/user.ts:73`) and compared by the login statement (`routes/login.ts:34`) |
| `JS-MASS-01` | `mass_assignment_candidate` | `server.ts:529` | Generated create for the user model, access `none`, attribute `role` carried as a `name_hint` |
| `JS-AUTHZ-01` | `authorization_candidate`, `object_level` | `server.ts:529` | Generated update of the product model selected by `:id`. The chain has no authentication middleware (`server.ts:398` is a comment) while create and delete have one |
| `JS-AUTHZ-02` | same | `routes/updateProductReviews.ts:17` | Collection `update` selected by `req.body.id`, no ownership key |
| `JS-ENUM-01` | `account_enumeration_candidate` | `routes/securityQuestion.ts:15` | Lookup by `query.email`; `{ question }` or `{}` |

### Added after source review (2026-11-24)

Each row was Confirmed by the judged scan and then read against the source at the pin. The
evidence for each is in the
[results](juiceshop-hardening-results.md#source-review-of-the-confirmed-records-outside-the-key).

| ID | Kind | Anchor | Evidence |
|---|---|---|---|
| `JS-CONF-04` | `configuration_candidate`, directory listing | `server.ts:269` | `serve-index` of `infrastructure`: Dockerfile, compose file and Terraform |
| `JS-HASH-02` | `password_hash_candidate` | `lib/insecurity.ts:42` | HMAC-SHA256 with a constant key, stored by the security answer's accessor |
| `JS-AUTHZ-03` | `authorization_candidate`, `object_level` | `routes/coupon.ts:24` | `findByPk(params.id)` then `update`; login required, no owner comparison |
| `JS-AUTHZ-04` | same | `server.ts:529`, `PUT /api/Hints/:id` | Generated update with no middleware registered for `PUT` |
| `JS-MASS-02` | `mass_assignment_candidate` | `server.ts:529`, `POST /api/Feedbacks` | `UserId` from the body; the sample's forged-feedback challenge (`routes/verify.ts:30`) |
| `JS-MASS-03` | same | `server.ts:529`, `POST /api/Complaints` | Login required, `UserId` from the body |
| `JS-MASS-04` | same | `server.ts:529`, `POST /api/Recycles` | Login required, `UserId` and `AddressId` from the body |
| `JS-MASS-05` | same | `server.ts:529`, `POST /api/PrivacyRequests` | Login required, `UserId` and `deletionRequested` from the body |
| `JS-MASS-06` | same | `server.ts:529`, `POST /api/SecurityAnswers` | No middleware for `POST`; `UserId` and `answer` from the body. `UserId` is unique, so the write succeeds only for a user with no answer |

### Added for hardening 3 (2026-11-24)

Rows of [hardening 3 §3](../specifications/juiceshop-nextjs-hardening-3.md#3-key-rows). The first
seven are the documented vulnerabilities the [scanner comparison](../../docs/scan/scanner-comparison.md)
listed outside the key; each was read against the source at the pin.

| ID | Kind | Anchor | Evidence |
|---|---|---|---|
| `JS-REDIR-01` | `open_redirect_candidate` | `routes/redirect.ts:18` | `res.redirect(query.to)` after an allow-list test that matches a substring of the URL |
| `JS-PATH-01` | `path_traversal_candidate` | `routes/fileServer.ts:32` | `res.sendFile(path.resolve('ftp/', file))`. The file-type test at `:26` runs before the name is cut at a null byte (`:27`), so the test does not hold for the name that is read |
| `JS-PATH-02` | same | `routes/fileUpload.ts:34` | An archive entry's path is joined to the upload directory and written; the test at `:33` is a substring test on the resolved path |
| `JS-PATH-03` | same | `routes/dataErasure.ts:107` | `req.body.layout` selects the template file that is rendered |
| `JS-SSRF-01` | `ssrf_candidate` | `routes/profileImageUrlUpload.ts:24` | `fetch(req.body.imageUrl)` with no destination test |
| `JS-CODE-01` | `code_execution_candidate` | `routes/userProfile.ts:65` | `eval` of a substring of the stored username |
| `JS-CODE-02` | same | `routes/b2bOrder.ts:23` | `body.orderLinesData` evaluated in a `vm` context. A practice finding today; the judged criterion exempts it (hardening 3 §6) |
| `JS-AUTHZ-05` | `authorization_candidate`, read | `routes/basket.ts:19` | `findOne({ where: { id } })` with `id` from `req.params`, result sent; the basket model belongs to the user model and no owner key is in the selector |

## Known false positives

Reported as Confirmed by the judged scan of 2026-11-24 and judged safe on source review. Since
hardening 3 they are the control rows `JS-AUTHZ-N05` and `JS-CONF-N01` below.

| Record | Anchor | Why it is safe |
|---|---|---|
| `authorization_candidate` | `routes/likeProductReviews.ts:35` | Liking another user's review is the feature; the review is not the caller's to own |
| `configuration_candidate`, directory listing | `server.ts:294` | `.well-known` holds only files published on purpose (`security.txt`, advisories) |

The hardening 3 acceptance run added two more, neither a key row: the second update of the like
route (`routes/likeProductReviews.ts:50`) and the generated `DELETE /api/Addresss/:id`
(`server.ts:529`), which the explicit handler at `server.ts:479` answers first.

## Controls

None may be a finding. `guarded` rows must end Protected.

| ID | Anchor | Expectation |
|---|---|---|
| `JS-AUTHZ-N01` | `routes/address.ts:29` | Recorded with `ownership_check`, `query_scope`: `UserId` is overwritten by a chain middleware (`server.ts:479`). `guarded` |
| `JS-AUTHZ-N02` | `routes/payment.ts:70` | Same (`server.ts:469`). `guarded` |
| `JS-AUTHZ-N03` | `routes/changePassword.ts:51` | No record: the instance is selected through a server-side keyed store |
| `JS-AUTHZ-N04` | `routes/updateUserProfile.ts:38` | No record: same reason |
| `JS-ENUM-N01` | `routes/login.ts:34` | No enumeration record: a login |
| `JS-MASS-N01` | `routes/updateUserProfile.ts:38` | No record: object literal with one named property |
| `JS-PATH-N01` | `routes/keyServer.ts:14` | Recorded, not a finding: the handler rejects a name that contains `/` before `path.resolve('encryptionkeys/', name)` |
| `JS-PATH-N02` | `routes/logfileServer.ts:14` | Same, directory `logs/` |
| `JS-PATH-N03` | `routes/quarantineServer.ts:14` | Same, directory `ftp/quarantine/` |
| `JS-AUTHZ-N05` | `routes/likeProductReviews.ts:35` | Recorded, not a finding: the update increments a counter by a constant, and liking another user's review is the feature |
| `JS-CONF-N01` | `server.ts:294` | Recorded, not a finding: `.well-known` holds only files published on purpose |

## Recorded, any status

Counted in the results and binding no criterion: the other `serve-index` mount (`server.ts:294`, a
known false positive above), `swagger-ui-express` at `server.ts:307`, the generated resources of the other fifteen
models, the upload routes at `server.ts:337` to `:340`, and whatever the deployment-file readers
record.

## Reviewed and not covered

XML external entities, token verification without an algorithm list, committed keys, YAML and XML
expansion, password reset by security answer, authentication cookie flags, CORS, missing rate
limits, business-rule validation and vulnerable dependencies have no analyzer. See decision D-11
of the lane specification. A read of a record another user owns is row `JS-AUTHZ-05`.
