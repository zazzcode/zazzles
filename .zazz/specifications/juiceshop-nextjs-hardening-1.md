# Juice Shop and Next.js hardening 1 — existing analyzers on JavaScript and TypeScript

- **Lane** `juiceshop-nextjs-hardening`, a sibling worktree of the bare repository. Two stacked
  branches (§0). This document also holds the lane rules; [branch 2](juiceshop-nextjs-hardening-2.md)
  refers to them.
- **Branch** `juiceshop-nextjs-hardening-1`, on `stage`.
- **Baseline** `stage` at `4fb2ea8` (merge of [PR #47](https://github.com/zazzcode/zazzles/pull/47)).
  Every path is relative to the repository root.
- **Feature** JavaScript and TypeScript support in Code Scan.
- **Owner request** 2026-11-24: repeat the exercise of the
  [Symfony lane](symfony-more-analyzers.md) for OWASP Juice Shop and vuln-nextjs. Add no analyzer.
  Improve the existing analyzers so they cover the defects those samples hold.
- **Deliverable Owner** The human user.
- **Run log** `.zazz/ephemeral/juiceshop-nextjs-hardening-run-log.md` (gitignored), one section per
  branch.
- **Review artifact** One draft PR into `stage`.

## 0. Lane model

| Order | Branch | Specification | Delivers | Base |
|---:|---|---|---|---|
| 1 | `juiceshop-nextjs-hardening-1` | this document | Five analyzer families extended to JavaScript and TypeScript, the upload gap, the Juice Shop answer key, judged results | `stage` |
| 2 | `juiceshop-nextjs-hardening-2` | [-2](juiceshop-nextjs-hardening-2.md) | Scanner comparison on four samples, reorganized comparison documents, README link | Branch 1 |

Both branches live in this worktree. Branch 2 is stacked because its Zazzles columns are the
judged results of branch 1.

**Lane setup. Done on 2026-11-24.** Both branches exist and are pushed. The branch 1 session
verifies this with `gh stack view --json` and `git log` and does not repeat it. The commands
that were run:

```bash
git config rerere.enabled true
git branch -m juiceshop-nextjs-hardening juiceshop-nextjs-hardening-1
gh stack init --base stage juiceshop-nextjs-hardening-1
```

The first commit of branch 1 (`586ee97`) is the documentation written with this lane: both
specifications, the [specification index](spec-index.md) rows and the [README](README.md)
entry. Branch 2 was added with `gh stack add juiceshop-nextjs-hardening-2` and holds the
scanner detail documents of its Part A. `gh stack rebase` fails in this repository
("branch stage is checked out in multiple worktrees"), so this lane rebases with Git. Before
branch 1's PR is marked for review, move branch 2 onto it and return:

```bash
OLD=$(git merge-base juiceshop-nextjs-hardening-1 juiceshop-nextjs-hardening-2)
git rebase --onto juiceshop-nextjs-hardening-1 "$OLD" juiceshop-nextjs-hardening-2
git push --force-with-lease origin juiceshop-nextjs-hardening-2
git checkout juiceshop-nextjs-hardening-1
```

This replaces the `gh stack rebase` and `gh stack sync` steps of the Symfony lane's rebase rule.
Branch 2 touches no file branch 1 touches except the two specification indexes.

**Rules taken from the Symfony lane.** These sections of the
[Symfony lane contract](symfony-more-analyzers.md) apply to both branches with "the sample" read
as Juice Shop and vuln-nextjs, and are not repeated here:

- §0 "Rebase rule".
- §2.1 Generality. Its first, third and fifth bullets apply as written; "PHP" reads "JavaScript
  and TypeScript" and the cited components are Node.js, Express, Sequelize, Mongoose and the
  libraries named in §2.
- §2.6 Extend before adding.
- §2.7 "Statuses" and "Policy order". The policies exist; this branch does not rewrite them.
- §4 Agent implementation rules, with the report folder
  `<DEV_ROOT>/zazzcode/zazzles/_test-findings/juice-shop/run-<id>/` (and `vuln-nextjs/`).
- §4.2 Unattended operation and the blocked item protocol.

## 1. Capability

Five analyzer families are registered for PHP only: `exposure`, `mass-assignment`,
`authorization`, `account` and `configuration`
(`scan/internal/analysispacks/families.go`). An offline scan of Juice Shop at the baseline
records 255 candidates and none of these five kinds. It also records no `file_upload_candidate`,
although the `upload` family is registered for JavaScript and the sample has four upload routes.

This branch makes the JavaScript adapter (`scan/internal/langjs`) record evidence for those
families on Express applications that use Sequelize or a Mongo-style collection, and closes the
upload gap. It adds no family, no candidate kind, no finding type and no question name.

### 1.1 Baseline measurement

Scanner `4fb2ea8`, offline, Juice Shop at `f189f52`, vuln-nextjs at `f5d47de`.

| Sample | Entries | Records | Kinds recorded |
|---|---:|---:|---|
| Juice Shop | 175 | 255 | `input_validation` 95, `outbound_http` 70, `xss` 28, `xss_data` 24, `path_traversal` 13, `nosql_query` 11, `prototype_write` 4, `sql_query` 3, `log_sink` 2, `code_execution` 2, `open_redirect` 2, `ssrf` 1 |
| vuln-nextjs | 37 | 54 | `input_validation` 19, `sql_query` 10, `xss_data` 8, `xss` 7, and 2 each of `command_execution`, `path_traversal`, `code_execution`, `open_redirect`, `ssrf` |

vuln-nextjs has no known gap: every row its lab keys for an existing family is Confirmed in the
judged run of 2026-11-19 ([sample catalog](../project/vulnerable-sample-apps.md#vuln-nextjs)).
The local lab has moved from the recorded pin `ea10efb` to `f5d47de`. In this branch it is the
regression measure and is re-pinned (§3 AC12).

### 1.2 Causes

| Gap | Cause | Kind |
|---|---|---|
| No `exposure`, `mass-assignment`, `authorization`, `account` or `configuration` record | The families list `lang.PHP` only and `langjs` has no code that builds their facts | Scope limit, widened here |
| No `file_upload_candidate` on Juice Shop | **Established 2026-11-24 (slice S6).** `Families()` registers `upload` for JavaScript and TypeScript with the contracts `node-express-fileupload` and `node-multer-disk`, but no code in `scan/internal/langjs` builds a `file_upload_candidate`. `grep -rn file_upload_candidate scan/internal` finds producers in `langphp/upload.go` and `langpy/upload.go` only. `scan/internal/langjs/path_upload_binding.go` verifies a memory-storage `multer.single` binding for the path family and records nothing for the upload family. The registration is a scope claim that no adapter fulfils; it is not a filter or a gate. A JavaScript producer needs the facts of `analysis.UploadFacts` (stored-name and extension origins, type controls, destination served, operand paths over a request dependency for the uploaded content) built from the multer binding and the handler, and a contract for memory storage, which neither existing Node contract describes | Missing producer |

## 2. Decisions

**D-1. Registration.** Each of the five families adds `lang.JavaScript` and `lang.TypeScript` to
its `Languages` and gets a JavaScript language component. Kinds, question names, finding types,
CWE lists and policies are unchanged. *Why:* the owner asked for no new analyzer, and the
questions these families ask do not depend on the language. *Constraint:* no PHP request changes
by one byte (§5 halt 1). If a JavaScript record cannot be expressed with a family's existing
facts and questions, record the shape that is missing in the run log and the results document
and do not record that candidate. Do not add a question.

**D-2. Entry access for Express.** Each Express entry gets the `EntryAccess` record of
[Symfony lane §2.3](symfony-more-analyzers.md#23-facts-a-lower-branch-exposes), built from the
route's middleware chain as `middleware_context.go` and `middleware_summary.go` already resolve
it, including `app.use` mounts whose path covers the route.

| `authentication` | When |
|---|---|
| `required` | A verified authentication middleware precedes the handler on the chain. Closed list: the `express-jwt` middleware (default export and `expressjwt`), `passport.authenticate(...)`, and `requiresAuth()` of `express-openid-connect`. A local function that returns one of these calls counts, through `transparent_wrappers.go` |
| `unresolved` | No listed middleware precedes the handler, and a local middleware on the chain ends the response on one branch and calls `next()` on another. The middleware is recorded as a guard, with a kind from the closed guard-kind list when its condition compares a value read from a verified token or session, and as a gap otherwise |
| `none` | Neither of the above |

`Sources` names the middleware call and the registration line. Fastify, Hapi, Next.js, GraphQL
and gRPC entries get no access record in this branch. *Why Express only:* both samples' access
rules that matter are Express chains, and each other framework has its own contract.
*Why a closed library list:* a middleware is an authentication check because of the library
contract, never because of its name.

**D-3. Authorization.** An `authorization_candidate` with facet `object_level` is recorded for a
state change on a record the request selects. All must hold:

- The operation is a Sequelize `Model.update`, `Model.destroy`, `Model.increment` or
  `Model.decrement` with a `where` option; an instance `update`, `destroy` or `save` on a value
  returned by `findByPk` or `findOne`; or an `update` or `remove` on a Mongo-style collection
  the `nosql` family already models.
- A key of the `where` object, the `findByPk` argument or the collection selector carries a
  request dependency that reaches it without passing through a server-side keyed store
  (`keyed_store_lookup.go`) or a verified token claim.

The subject is `model:<name>` or `collection:<name>` with provenance `request_selected`. Guards:

- `ownership_check`, form `query_scope`, when another key of the same selector takes a value
  that is not request-selected: a verified token claim, a keyed-store lookup, or a request field
  that a middleware on this entry's chain overwrites before the handler.
- The entry's `EntryAccess` (D-2) and its middleware guards.

Guards never suppress the record. The scanner does not decide whether a guard is enough.

A request field that a chain middleware overwrites is request-selected on an entry whose chain
lacks that middleware. *Why:* the same handler is safe behind the middleware and unsafe without
it, and only the chain says which.

*Not covered:* reads. Symfony lane OQ-5 limits reads to those returning a census field, and D-6
gives JavaScript no `login_identifier` or `role_source` role. Function-level claims that need a
`role_source` field are also out.

**D-4. Mass assignment.** A `mass_assignment_candidate` is recorded when a whole request bag
reaches a model write with no field list:

| Operation | Whole bag | Field list that prevents the record |
|---|---|---|
| Sequelize `Model.create(x)`, `Model.build(x)`, `Model.bulkCreate(x)`, `Model.update(x, …)`, instance `update(x)` and `set(x)` | `x` is `req.body`, `req.query`, an alias of one, or an object spread of one with no later override of every model attribute | A `fields` option with a literal array, or `x` built as an object literal of named properties |
| Mongoose `new Model(x)`, `Model.create(x)`, `findByIdAndUpdate(id, x)`, `updateOne(filter, x)` | Same | `x` built as an object literal of named properties |
| `Object.assign(instance, x)` where `instance` is a model instance | Same | — |
| Generated resource (D-5) | Always | D-5 |

The record lists the model's attributes as the writable fields, with their census roles (D-6).

**D-5. Generated REST resources.** A `resource({ model, endpoints, … })` call of `finale-rest` or
`epilogue` generates create and update handlers that write request body fields to model
attributes. For each generated create and update endpoint, record one
`mass_assignment_candidate` at the `resource` call, with the entry's `EntryAccess`. Record an
`authorization_candidate` (D-3) for each generated update and delete endpoint, whose selector is
the route's `:id` parameter.

Before coding, read the library's documentation for which options limit writable attributes, and
cite it in the code comment and in §2 here. `excludeAttributes` is recorded as an option of the
call and is not treated as a write limit unless the documentation says it is. A resource whose
`endpoints` or `model` is not a literal or a statically resolved binding in a loop over a
literal array records a gap and no candidate. *Why the loop form:* a table of models iterated
into `resource` calls is the common shape, and the scanner already folds constant origins
(`const_origin_fold.go`).

**D-6. Security-field census for Sequelize and Mongoose.** Roles are established by evidence,
never by a name:

| Role | Established by |
|---|---|
| `credential` | A model attribute whose `set` accessor stores the result of a hash operation; an attribute assigned from a `bcrypt`, `bcryptjs`, `argon2` or `scrypt` call or a `crypto.createHash` digest; or a column a SQL login statement compares with such a digest |
| `name_hint` | The closed hint list of [branch 1 D-4](symfony-more-analyzers-1.md) of the Symfony lane |

`login_identifier`, `role_source` and `recovery_secret` are not established for JavaScript in
this branch. *Why:* each needs a framework contract (a user provider, a roles method) that
Express applications do not have, and a rule that reads the name `role` is the vocabulary
matching the lane forbids. A privileged-looking attribute reaches the decision model as a
`name_hint`, which is what a hint is for.

**D-7. Account family.**

- **Weak password hashing.** `password_hash_candidate` at a digest operation whose result
  reaches a `credential` field (D-6). Fast digests: `crypto.createHash` with `md5`, `sha1`,
  `sha224`, `sha256`, `sha384` or `sha512`, and `crypto.createHmac` with a constant key. The
  digest call is followed through one helper function, using the existing callable summaries.
  Use the existing basis names: `sql_credential_column` for a column a SQL statement compares
  or writes, and the existing ORM basis for a model attribute. If no existing basis fits the
  accessor form, that is D-1's "missing shape". No record for `bcrypt`, `argon2`, `scrypt` or
  `crypto.pbkdf2`.
- **Account enumeration.** `account_enumeration_candidate` when an entry with
  `authentication: none` looks a record up by a request value through a modeled finder
  (`sequelize_finders.go`, Mongoose finders), and the branches on the result send responses
  that differ in status or in body shape. An entry that compares a credential in the same
  lookup is a login and is excluded, as in PHP.
- **Recovery delivery.** Not built. The kind is about a recovery secret sent to a
  request-chosen recipient. Neither sample has that flow.

**D-8. Information exposure.** `info_exposure_candidate` at these operations, each with the
entry's or the mount's access record and any environment condition that dominates the call:

| Operation | Contract |
|---|---|
| The `errorhandler` package's middleware passed to `app.use` | Its documentation states it is for development and sends the stack trace |
| A response that writes `register.metrics()` or `client.register.metrics()` of `prom-client` | Process and runtime metrics |
| `swaggerUi.setup(...)` of `swagger-ui-express` passed to `app.use` or a route | The API description |
| A response whose body is `process.env`, an error's `stack`, or `process.memoryUsage()` and its siblings on the list the PHP family uses for server state | Server state |

A condition on `process.env.NODE_ENV` that dominates the registration is recorded as a guard.

**D-9. Configuration.** Existing check identifiers only. Find them in
`scan/internal/analysis/configuration.go`.

| Check (existing) | JavaScript evidence |
|---|---|
| Directory listing (CWE-548) | A `serve-index` call passed to `app.use`. Joined facts: the mount path, the directory argument, the access record of the mount, and each middleware before it on the same `app.use` |
| Session cookie readable by script, session cookie on insecure transport (CWE-1004, CWE-614) | The `cookie` option of `express-session` and the options of `cookie-session` with `httpOnly: false` or `secure: false`, literal or through the dominating-assignment resolver of [branch 5 D-1](symfony-more-analyzers-5.md) ported to JavaScript values |
| Deployment-file checks | Unchanged readers (`scan/internal/deployconf`). They now also run for a JavaScript project |

A `res.cookie(name, value)` call is not recorded. *Why:* that a cookie carries the session is
not established by its name, the rule PHP applies to `setcookie`. Request composition for a
JavaScript configuration record uses the current protocol identifier. If a JavaScript record
needs a fact kind the instruction does not describe, the protocol identifier moves, and that is
allowed only if no PHP request changes; otherwise it is halt 1.

**D-10. Upload.** After the cause is established (§1.2), the `upload` family records a
`file_upload_candidate` for `multer` bindings with memory storage and disk storage, on
`single`, `array`, `fields` and `any`. Facts are the existing ones, including
`destination_served` from an `express.static` or `serve-index` mount that covers the
destination.

**D-11. Reviewed and not built.** Source review of Juice Shop at the pin. No existing analyzer
owns these, and none is added:

| Defect | Location | Why not |
|---|---|---|
| XML external entities | `lib/xml`, `routes/fileUpload.ts:80` | No analyzer for CWE-611 |
| Token verification with no algorithm list; unsigned and key-confusion tokens | `lib/insecurity.ts:52` | No analyzer for CWE-347 |
| Committed private key, HMAC key and cookie secret | `lib/insecurity.ts:21`, `:42`, `server.ts:317` | Committed secrets are outside Code Scan |
| YAML and XML expansion (denial of service) | `routes/fileUpload.ts:114` | `js-yaml` 4 `load` constructs no objects; not CWE-502 |
| Password reset by security answer | `routes/resetPassword.ts:35` | Not a delivery claim (D-7) |
| Authentication token cookie with no flags | `lib/insecurity.ts:192`, `routes/updateUserProfile.ts:42` | D-9 |
| CORS for every origin, missing CAPTCHA and rate limits, business-rule validation, vulnerable dependencies, reads of another user's record | — | No analyzer; D-3 for reads |

## 3. Sample answer key

Source-reviewed at Juice Shop `f189f521266f42c6bd05884468292000cee852ed` on 2026-11-24. Slice S0
freezes these rows into `.zazz/evaluation/recall-gap-inventory/cases.json` and a new
`.zazz/evaluation/juice-shop-detection-guide.md`, with the existing Juice Shop rows of the
[sample catalog](../project/vulnerable-sample-apps.md#owasp-juice-shop). S0 opens each anchor
in the sample and corrects a line number that is off; it never changes a row's expectation. A
row that looks wrong on source review is halt 3.

**Required positives.** Each must be a witnessed candidate offline and Confirmed in the judged
acceptance run.

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

**Controls.** None may be a finding. `guarded` rows must end Protected.

| ID | Anchor | Expectation |
|---|---|---|
| `JS-AUTHZ-N01` | `routes/address.ts:29` | Recorded with `ownership_check`, `query_scope`: `UserId` is overwritten by a chain middleware (`server.ts:479`). `guarded` |
| `JS-AUTHZ-N02` | `routes/payment.ts:70` | Same (`server.ts:469`). `guarded` |
| `JS-AUTHZ-N03` | `routes/changePassword.ts:51` | No record: the instance is selected through a server-side keyed store |
| `JS-AUTHZ-N04` | `routes/updateUserProfile.ts:38` | No record: same reason |
| `JS-ENUM-N01` | `routes/login.ts:34` | No enumeration record: a login |
| `JS-MASS-N01` | `routes/updateUserProfile.ts:38` | No record: object literal with one named property |

**Recorded, any status.** These are counted in the results and bind no criterion: the other
`serve-index` mounts (`server.ts:269`, `:294`), `swagger-ui-express` at `server.ts:307`, the
generated resources of the other fifteen models, the upload routes at `server.ts:337` to `:340`,
and whatever the deployment-file readers record.

## 4. Slices and acceptance criteria

Slices run in this order. Each ends with its fixtures green, the package tests green and one
commit. Fixtures live under `scan/internal/langjs/testdata/<family>-express/`, with a
**transfer project** per family that uses different model, route, middleware and message names
and Mongoose where the first uses Sequelize.

| Slice | Delivers | Criteria |
|---|---|---|
| S0 | Verify the lane setup, key freeze | AC1 |
| S1 | Entry access for Express (D-2) | AC2 |
| S2 | `configuration` and `exposure` (D-8, D-9) | AC3, AC4 |
| S3 | Census, `account` (D-6, D-7) | AC5, AC6 |
| S4 | `authorization` (D-3) | AC7 |
| S5 | `mass-assignment` and generated resources (D-4, D-5) | AC8 |
| S6 | `upload` (D-10) | AC9 |
| S7 | Whole-sample acceptance, documentation | AC10 to AC14 |

1. **AC1.** `cases.json` and the detection guide hold every row of §3. `python3
   .zazz/evaluation/recall-gap-inventory/check.py` reports the ten positives as missing and no
   existing row changed. Verified by that command and `test_check.py`.
2. **AC2.** Table-driven test `TestExpressEntryAccess` in `scan/internal/langjs`: one row per
   line of the D-2 table, plus a mount-level `app.use(path, middleware)`, a wrapper function
   returning a listed middleware, a route registered before the mount (access `none`), and a
   router mounted under a guarded prefix.
3. **AC3.** Configuration cases: a `serve-index` mount (recorded); the same behind a listed
   authentication middleware (recorded, access `required`); `express.static` alone (no record);
   `express-session` with `secure: false` and `httpOnly: false` literal, through a variable, and
   `true` (two records, two records, none). Each has a hardened sibling.
4. **AC4.** Exposure cases: one row per line of the D-8 table, each with a sibling under an
   `if (process.env.NODE_ENV !== 'production')` condition (recorded with the guard) and a
   sibling that sends a constant (no record).
5. **AC5.** Password-hash cases: `md5` through a helper into a model accessor (candidate at the
   digest); `sha256` compared in a SQL login statement (candidate, `sql_credential_column`);
   `bcrypt.hash` (no record); `md5` of a file for a checksum that reaches no credential field
   (no record).
6. **AC6.** Enumeration cases: lookup by a request value with two response shapes on an
   unauthenticated entry (candidate); the same with one response for both branches (no record);
   the same behind a listed authentication middleware (no record); a login (no record).
7. **AC7.** Authorization cases: one per operation of D-3 with a request-selected key and no
   guard; one with a second key from a verified token claim (`ownership_check`, `query_scope`);
   a field overwritten by a chain middleware (guard) and the same handler on a chain without it
   (no guard); an instance selected through a keyed store (no record); a `where` built only from
   constants (no record).
8. **AC8.** Mass-assignment cases: one per row of the D-4 table; each prevention column entry
   as a no-record sibling; a `finale-rest` resource in a loop over a literal array (one
   candidate per create and update endpoint, with access from a chain registered for that
   path); a resource with a computed model (gap, no candidate).
9. **AC9.** The cause of the upload gap is in §1.2 and the run log. Upload cases: memory and
   disk storage on `single`, `array`, `fields` and `any`; a destination under an
   `express.static` mount (`destination_served`); a route with no `multer` middleware (no
   record).
10. **AC10.** Every new case fails before its slice's change and passes after it. The failing
    output is in the run log.
11. **AC11.** `TestArchitectureBaseline`, `TestDVWASourceKey`, `TestSymfonySourceKey` and the
    existing Juice Shop and Goof tests pass. An offline scan of DVWA and of vuln-symfony at
    this branch's head is byte-identical to one at the baseline, compared with `cmp` on the
    JSON reports after removing the run identifier. Every baseline row that moves is a
    JavaScript row and is explained in the PR.
12. **AC12.** vuln-nextjs is re-pinned to `f5d47de` in the sample catalog and its metadata.
    `ZAZZLES_VULN_NEXTJS=<checkout> go test ./scan/internal/langjs -run TestNextJSVulnLab`
    passes, and an offline scan keeps every record identifier of a baseline scan of the same
    revision.
13. **AC13.** An offline Juice Shop scan records every required positive of §3 as a witnessed
    candidate, meets every control's offline expectation, and keeps every record identifier of
    the baseline scan (255 records).
14. **AC14.** Judged acceptance (§6): every required positive of §3 and every Confirmed row of
    the sample catalog's Juice Shop table is Confirmed, and no control is a finding. The
    vuln-nextjs judged run keeps all 13 in-scope keyed cases as the catalog records them.
15. **AC15.** No rule, fixture or test names a sample's path, model, route or message. Verified
    by `grep -rn 'juice\|Basket\|ftp/legal' scan/internal/langjs --include='*.go'` returning only
    lines that existed at the baseline.

**Documentation in S7.** [Detection capabilities](../../docs/scan/detection-capabilities.md)
(languages per class), the five class pages under `docs/scan/detection-capabilities/`, the
matching guides under `docs/scan/analysis/`, the
[sample catalog](../project/vulnerable-sample-apps.md), the refreshed sample reports under
`docs/samples/juice-shop/` and `docs/samples/vuln-nextjs/`, a new
`.zazz/evaluation/juiceshop-hardening-results.md`, and the
[implementation plan](../project/implementation-plan.md). Run `doc-check`.

## 5. Halt conditions

Each starts the blocked item protocol of Symfony lane §4.2.

1. A PHP request, a DVWA or Symfony keyed outcome, or an existing row of
   `scan/cli/testdata/architecture-baseline.json` changes.
2. An existing Juice Shop, Goof, TypeScript-app or vuln-nextjs record changes identifier or
   offline expectation.
3. A required positive cannot be reached without a rule that names the sample, or a row looks
   wrong on source review.
4. A family needs a new question, kind or finding type (D-1).
5. The same test fails five iterations in a row with no new diagnosis between them.
6. The judged-run bound of §6 is reached with AC14 unmet.
7. A paid call would be needed outside §6.

## 6. Judged runs

Provider, model and limits are those of
[AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls): `--judge openai --judge-model
gpt-6-luna`, the default judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`. No fallback.

| Run | When | Scope |
|---|---|---|
| Family checkpoint | After each of S2 to S6 | `--only-family <family>` on Juice Shop |
| Acceptance | S7, on the commit submitted for review | Full scan of Juice Shop; full scan of vuln-nextjs |

The bound is 8 judged runs in the branch, or two consecutive full runs with no row changing
status. A failed row is traced to its first failing stage (evidence missing, evidence wrong,
question wording, policy gate) and fixed with a fixture that reproduces it. Each run is logged
in the run log and in the results document: run identifier, scanner commit, scope, request
count, input tokens and the status of each row in scope.

## 7. Scope

The diff stays inside `scan/`, `docs/`, `.zazz/` and `README.md`.

| Path | Change | Reason |
|---|---|---|
| `scan/internal/analysispacks/families.go` and the language component files beside it | Modified | D-1 |
| `scan/internal/langjs/` (new files per family, each under the size threshold of the [code structure standard](../standards/code-structure.md)) | New and modified | D-2 to D-10 |
| `scan/internal/langjs/testdata/` | New | §4 fixtures |
| `scan/internal/analysis/`, `scan/internal/judge/`, `scan/internal/report/` | Modified only where a site switches on language | D-1 |
| `scan/cli/testdata/architecture-baseline.json` | Added rows only | AC11 |
| `.zazz/evaluation/recall-gap-inventory/`, `.zazz/evaluation/juice-shop-detection-guide.md`, `.zazz/evaluation/juiceshop-hardening-results.md` | Modified and new | §3, §6 |
| Documents listed under "Documentation in S7" | Modified | S7 |

**Out of scope.** A new analyzer family or kind. Next.js, Fastify, Hapi, GraphQL and gRPC entry
access. Python. Any PHP behavior. The comparison documents of branch 2. Everything in D-11.

## 8. Open questions for the owner

| ID | Question | Recommended, and assumed unless the owner says otherwise |
|---|---|---|
| OQ-1 | Paid judged runs | As §6: up to 8 runs, OpenAI `gpt-6-luna`. **Needs the owner's word before the first run** |
| OQ-2 | One PR for five families | Kept as one branch because no family wiring is new. If the diff passes what a reviewer can hold, the owner splits the stack at the S3/S4 boundary |
| OQ-3 | The D-11 list | Stays out. Token verification (CWE-347) and XML entities (CWE-611) are the two strongest candidates for a later analyzer |

## 9. Definition of done

- [ ] Every criterion of §4 is met with its command output in the run log.
- [ ] The contributor gate passes: `gofmt -l cmd scan` prints nothing, `go vet ./...`,
      `go build ./...`, `go test -race ./... -count=1`.
- [ ] A fresh-context, read-only Verifier Agent reran AC11 to AC15.
- [ ] The draft PR into `stage` is open with the results table and any "Blocked" section.
- [ ] Samples are unchanged: `git status --porcelain --ignored` is empty in each.

## 10. Change log

### 2026-11-24 — Drafted

Written from an offline scan of both samples at `4fb2ea8`, a source read of Juice Shop at its
pin and the family registry. No code changed.
