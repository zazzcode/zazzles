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

Counted in the results and binding no criterion: the other `serve-index` mounts (`server.ts:269`,
`:294`), `swagger-ui-express` at `server.ts:307`, the generated resources of the other fifteen
models, the upload routes at `server.ts:337` to `:340`, and whatever the deployment-file readers
record.

## Reviewed and not covered

XML external entities, token verification without an algorithm list, committed keys, YAML and XML
expansion, password reset by security answer, authentication cookie flags, CORS, missing rate
limits, business-rule validation, vulnerable dependencies and reads of another user's record have
no analyzer. See decision D-11 of the lane specification.
