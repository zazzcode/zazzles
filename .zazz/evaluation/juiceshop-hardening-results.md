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

## Upload

Built after the judged runs (D-10, AC9). **Not judged:** the eight runs of §6 were used before
the producer existed, so the statuses below are offline. A judged `--only-family upload` run
(four requests) is the owner's to start.

Offline scan of Juice Shop at the pin, compared with a scan by the scanner one commit earlier
(`22c4407`): 299 records become 303, every earlier record keeps its identifier and content, the
195 entries are unchanged. Offline reports of DVWA and vuln-symfony are byte-identical after the
run identifier is removed. The four added records:

| Route | Anchor | Operation | Stored name | Extension | Type controls | Destination served | Offline status |
|---|---|---|---|---|---|---|---|
| `POST /file-upload` | `server.ts:337` | `multer.memoryStorage.single` | unknown | unknown | none | unknown | Review |
| `POST /profile/image/file` | `server.ts:338` | `multer.memoryStorage.single` | unknown | unknown | none | unknown | Review |
| `POST /profile/image/url` | `server.ts:339` | `multer.memoryStorage.single` | unknown | unknown | none | unknown | Review |
| `POST /rest/memories` | `server.ts:340` | `multer.diskStorage.single` | mixed | allow_listed | `client_declared_type` (`server.ts:733`) | yes (`frontend/dist/frontend/assets/public/images/uploads`, under the static mount at `server.ts:316`) | Review |

One row of `scan/cli/testdata/architecture-baseline.json` moves, as AC11 allows for a JavaScript
row: `internal/langjs/testdata/typescript/path-traversal-expanded`. That fixture has two `multer`
memory-storage routes, so it gains two `file_upload_candidate` records (29 uses become 31) and
its report and SARIF hashes change. Its 29 earlier uses keep identifier, request digest,
signature and order, and no other row changes.

What the records do not say:

- **Memory storage writes no file.** The three memory records carry the handlers that receive
  the buffer as evidence and a coverage note; the handler's own write (`routes/fileUpload.ts:34`,
  `routes/profileImageFileUpload.ts:42`) is a path record, as before. The policy cannot confirm
  or protect a record whose three facts are unknown, so these stay Review in a judged run too.
- **The report summary** reads "stored by multer.memoryStorage.single" for a memory record. The
  sentence is shared by every language and was not changed.
- **`POST /rest/memories`** stores under a table extension (`png` or `jpg`), so the policy has
  no path to Confirmed for it. A file with client-chosen bytes and an image extension is served.

Not recorded: a `multer` instance imported from another module, an option spread, a third-party
storage engine, `express-fileupload`, and a middleware on a mount with no route entry (an
`upload_entry_missing` gap).

## Not built, and deviations

- **Deployment-file readers for a JavaScript project (D-9, third row).** Not built; binds no
  criterion.
- **Entry access `none`.** Stored as no record, so existing reports are unchanged (spec halt 1);
  `expressEntryAccess` reads the absence as `none`.
- **Census (D-6).** Only the `credential` role (set accessor or SQL comparison) and `name_hint`.
- **Account enumeration** records any verified model, so a delivery-method lookup is recorded.
- Every other reading is under "Deviations" of the run log
  (`.zazz/ephemeral/juiceshop-nextjs-hardening-run-log.md`, not committed).

## Hardening 3

Branch `juiceshop-nextjs-hardening-3` of the
[specification](../specifications/juiceshop-nextjs-hardening-3.md), draft
[PR #50](https://github.com/zazzcode/zazzles/pull/50). Scanner commit of the acceptance runs:
`ee777f4`; later commits change documents only. Samples, provider, model and limits as above.
Protocols after this branch: `authorization-components-v9`, `configuration-components-v7`.

### What was built

| Decision | Built | Effect on Juice Shop |
|---|---|---|
| D-1 destructured request parameter | Yes | Five path records lose `request_projection_unresolved`. One, `routes/fileServer.ts:32`, is sent. The three path controls stay blocked by the `serve-index` mount on their prefix |
| D-2 namespace import callee | Yes | 70 records lose an `unknown_value` gap on a namespace binding |
| D-3 verified middleware | Yes, for a `multer` binding without a custom `fileFilter` and the authentication list | Three records on the upload routes lose `unresolved_factory` |
| D-4 literal heap write | Yes, for ssrf, path and code | The SSRF record at `routes/profileImageUrlUpload.ts:24` has no blocker and is sent |
| D-5 sink inside `try` | Cause recorded, no change | The `try` is coverage, not a blocker. The record is held by a guard and the code policy |
| D-6 middleware the resolver cannot read | Cause recorded, no change | Neither sample construct is one the decision allows; both allowed constructs already resolve |
| D-7 reads of an owned record | Yes | Three new records: `routes/basket.ts:19`, `routes/address.ts:18`, `routes/recycles.ts:12` |
| D-8 what an update writes | Yes (`written_values`) | Ten update records carry the fact |
| D-9 what a listed directory holds | Yes (`directory_contents`) | Five `serve-index` records carry the fact |
| D-10 anchored redirect pattern | `String.match` now classified like `RegExp.test`; no new form | None on these samples |
| D-11 protocol identifiers | Yes | DVWA and vuln-symfony keep every record identifier; only `analysis_components` of the two families changes. Thirteen PHP rows of the architecture baseline move in request and signature digest only |

### Judged runs

Four family runs and two full runs, the bound of §5 of the specification. Folders are under
`_test-findings/juiceshop-nextjs-hardening/h3/judged/`.

| # | Folder | Scanner | Scope | Requests | Input tokens | Result |
|---:|---|---|---|---:|---:|---|
| 1 | `f1-path-ssrf-code-authz-conf` | `c121a58` | path, ssrf, code, authorization, configuration | 32 | 130,998 | PATH-01 and CODE-01 Review; SSRF-01 practice finding; basket read `access_adequacy` unknown; both false positives still Confirmed |
| 2 | `f2-authz-conf` | `b959d26` | authorization, configuration | 24 | 71,926 | Basket read Confirmed, both like records Protected; the coupon update and the `logs` listing became unknown |
| 3 | `f3-authz` | `e94682c` | authorization | 19 | 60,527 | Coupon Confirmed; like records Confirmed; basket read unknown (0.45 against 0.45) |
| 4 | `f4-authz` | `ee777f4` | authorization | 19 | 60,926 | Basket read (0.86), coupon (0.65) and `JS-AUTHZ-02` Confirmed; like records Confirmed |
| 5 | `a1-acceptance-juice-shop` | `ee777f4` | Full scan | 85 | 384,674 | 37 of 42 keyed positives Confirmed, 3 practice findings, 2 in Review; 2 keyed controls are findings |
| 6 | `a2-acceptance-vuln-nextjs` | `ee777f4` | Full scan | 27 | 121,218 | 13 of 13 Confirmed; no record changed status; the redirect control is still a practice finding |

For an entry that requires sign-in and lists no role, the model's `access_adequacy` answer is
close to a three-way tie, and small changes of wording move rows across it. Runs 1 to 4 tried
four wordings. The one kept makes every owned-record row firm and leaves the like records
findings; the wording of run 2 did the opposite. None held both.

### Key rows, before and after

Before is `r10-acceptance-juice-shop` (scanner `29ce9aa`); after is `a1-acceptance-juice-shop`.

| Row | Anchor | Before | After |
|---|---|---|---|
| `JS-REDIR-01` | `routes/redirect.ts:18` | Confirmed | Confirmed |
| `JS-PATH-01` | `routes/fileServer.ts:32` | Review, not sent | Review, sent |
| `JS-PATH-02` | `routes/fileUpload.ts:34` | Confirmed | Confirmed |
| `JS-PATH-03` | `routes/dataErasure.ts:107` | Confirmed | Confirmed |
| `JS-SSRF-01` | `routes/profileImageUrlUpload.ts:24` | Review, not sent | Practice finding |
| `JS-CODE-01` | `routes/userProfile.ts:65` | Review | Review |
| `JS-CODE-02` | `routes/b2bOrder.ts:23` | Practice finding | Practice finding |
| `JS-AUTHZ-05` | `routes/basket.ts:19` | No record | Confirmed |
| `JS-PATH-N01` to `N03` | `keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14` | Review, not sent | Review, not sent |
| `JS-AUTHZ-N05` | `routes/likeProductReviews.ts:35` | Confirmed (false positive) | Confirmed (false positive) |
| `JS-CONF-N01` | `server.ts:294` | Confirmed (false positive) | Confirmed (false positive) |

The 34 rows keyed before this branch keep their status: 33 Confirmed and `JS-LOG-01` a practice
finding. On vuln-nextjs the 13 keyed cases are Confirmed as before.

Findings went from 44 Confirmed and 2 practice to 50 Confirmed and 3 practice. The records that
became findings, each read against the source:

| Record | Status | Source review |
|---|---|---|
| `routes/basket.ts:19`, `GET /rest/basket/:id` | Confirmed | `JS-AUTHZ-05` |
| `routes/profileImageUrlUpload.ts:24` | Practice finding | `JS-SSRF-01` |
| `routes/recycles.ts:12`, `GET /api/Recycles/:id` | Confirmed | Real: the route has no authentication middleware (`server.ts:416`) and returns the recycle row a request id selects |
| `server.ts:529`, `DELETE /api/BasketItems/:id` | Confirmed | Real: sign-in only (`server.ts:387`), no owner test. In Review before; Confirmed in an earlier run of branch 1 |
| `server.ts:529`, `DELETE /api/Feedbacks/:id` | Confirmed | Real: sign-in only (`server.ts:389`), any user deletes any feedback |
| `routes/likeProductReviews.ts:50` | Confirmed | **False positive.** The second update of the like route. Protected before |
| `server.ts:529`, `DELETE /api/Addresss/:id` | Confirmed | **False positive.** The explicit handler at `server.ts:479` deletes only the caller's address and always answers, so the generated delete is not reached. In Review before |

The new read at `routes/address.ts:18` is Protected (its selector carries the owner key a chain
middleware sets). The four upload records are in Review.

### Open rows

Each was stopped under the blocked item protocol. None was relabeled and no rule was written to
pass it.

| Row | First failing stage | Evidence | Decision needed |
|---|---|---|---|
| `JS-CODE-01` | Policy gate | Every operand path is `guarded` by the enclosing test `username?.match(/#{(.*)}/) !== null`; `judge/code_redirect.go` confirms only a `raw` path. The model answers `whole_program / none / incomplete`. The `try` statements are coverage gaps | A guard classification for an unanchored pattern in the code family, or a policy rule for a path guarded only by controls the model answers `none` for |
| `JS-PATH-01` | Model answer | The flow-gap question on the null-byte helper is answered `value_constrained`; `containment_control` is split between `none` (0.34) and `finite_allowlist` (0.31). On source review the handler rejects `/` before `path.resolve('ftp/', name)`, as the three controls do; the null byte defeats the file-type allow-list inside `ftp/` | Whether the row is a path-traversal positive |
| `JS-SSRF-01` | Model answer | The flow is `raw` with no guard recorded; the model answers `destination_restriction: prefix_only`, reading the `url.match(...)` condition of an unrelated statement as a restriction. Reported as a practice finding, not Confirmed | A change to the ssrf request, which D-11 excludes from this branch |
| `JS-AUTHZ-N05` | Question wording, then model answer | The record carries `request_dependent: no, operators: [$inc]`. The three questions have no answer for "any signed-in caller may do this to any record" | A question or a policy rule that separates a fixed write from an owned-record write |
| `JS-CONF-N01` | Model answer | The record carries "holds 2 entries: csaf/, security.txt"; the model answers `weakens` | Whether the scanner may state what `.well-known` is (RFC 8615), or the model is to judge from names |
| vuln-nextjs `REDIR-001-safeControl` | Key row | The guard `/^\/[^/]/` admits `/\host`; a browser resolves that to another origin (WHATWG URL, relative-slash state). The scanner has recorded `redirect_predicate_bypass: slash_backslash` on this record since before this branch | Whether the lab's row is a safe control |
| Three path controls | Not sent | Each keeps `applicable_middleware_unresolved` from the `serve-index` mount. If sent, `judge/path.go` treats a separator-only guard as an unsafe witness, so a `vulnerable` answer would be Confirmed | Whether a separator test on a file read is containment |
| Generated `DELETE /api/Addresss/:id` | Evidence missing | Whether an explicit handler registered first ends the response is not read (§6 of the specification) | Follow-on work |
