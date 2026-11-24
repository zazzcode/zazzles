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

## Known false positives

Reported as Confirmed by the judged scan of 2026-11-24 and judged safe on source review. They
are not key rows; they are listed so a comparison counts them against the scanner.

| Record | Anchor | Why it is safe |
|---|---|---|
| `authorization_candidate` | `routes/likeProductReviews.ts:35` | Liking another user's review is the feature; the review is not the caller's to own |
| `configuration_candidate`, directory listing | `server.ts:294` | `.well-known` holds only files published on purpose (`security.txt`, advisories) |

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

## Recorded, any status

Counted in the results and binding no criterion: the other `serve-index` mount (`server.ts:294`, a
known false positive above), `swagger-ui-express` at `server.ts:307`, the generated resources of the other fifteen
models, the upload routes at `server.ts:337` to `:340`, and whatever the deployment-file readers
record.

## Reviewed and not covered

XML external entities, token verification without an algorithm list, committed keys, YAML and XML
expansion, password reset by security answer, authentication cookie flags, CORS, missing rate
limits, business-rule validation, vulnerable dependencies and reads of another user's record have
no analyzer. See decision D-11 of the lane specification.
