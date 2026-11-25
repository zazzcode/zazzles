# Juice Shop and Next.js hardening 3 — misses, blocked records, reads and false positives

- **Lane rules** [Branch 1 §0](juiceshop-nextjs-hardening-1.md#0-lane-model), including its Git
  rebase steps and the sections of the Symfony lane it adopts. They apply here and are not
  repeated.
- **Branch** `juiceshop-nextjs-hardening-3`, stacked on `juiceshop-nextjs-hardening-2`.
- **Owner request** 2026-11-24: implement the four improvements the
  [scanner comparison](../../docs/scan/scanner-comparison.md) points to, and write down the
  remaining follow-on work. No analyzer is added.
- **Review artifact** One draft PR, based on branch 2.
- **Run log** `.zazz/ephemeral/juiceshop-nextjs-hardening-run-log.md`, a new section.

## 1. Capability

The comparison scored Code Scan at 38 of 42 known Juice Shop vulnerabilities with two false
positives, and one false positive on vuln-nextjs. This branch closes the three misses that an
existing analyzer already records, reports reads of a record another user owns, and removes the
three false positives. Each cause below was read from the judged report
`r10-acceptance-juice-shop` and the code at `80fff0c`.

### 1.1 Causes

| Item | Record | Cause |
|---|---|---|
| Miss | Path traversal, `routes/fileServer.ts:32` | `handler()` in `scan/internal/langjs/analysis.go` accepts only an identifier as the request parameter. The handler destructures it (`({ params, query }: Request, …)`), so the record gets the blocker `request_projection_unresolved` and is never sent. Two more blockers follow on the same path: `unknown_value` for a namespace import (`import * as security`) and `unknown_transfer` for a call of its exported helper |
| Blocked | Path traversal, `routes/keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14` | The same destructured request parameter |
| Miss | SSRF, `routes/profileImageUrlUpload.ts:24` | Two blockers. `unresolved_factory` at the registration: a `multer` middleware call with an argument (`upload.single('file')`) is read as a handler factory whose arguments need binding. `unsupported_write` at `:20`: an assignment of a literal to a property of `req.app.locals`, which the URL does not flow through |
| Miss | Code execution, `routes/userProfile.ts:65` | The record is sent. The model answers `code_control: whole_program`, `code_restriction: none` and `protection_coverage: incomplete`, and the policy needs complete coverage. The `eval` is inside a `try` inside an `if`; the flow records `unsupported_control_flow: try_statement` and `branch_exit` gaps on the path |
| Blocked | NoSQL, `routes/order.ts:164`; path, `server.ts:277` | `applicable_middleware_unresolved` with detail "no direct returned function" and "handler binding is shadowed": a middleware on the chain is a factory whose body the resolver does not read, or a local binding it treats as shadowed |
| Not reported | Read of another user's basket, `routes/basket.ts:19` | Branch 1 D-3 covers state changes only |
| False positive | Authorization, `routes/likeProductReviews.ts:35` | The update writes `$inc: { likesCount: 1 }`. The record does not say that the request chooses no written value |
| False positive | Directory listing, `server.ts:294` | The record does not say what the listed directory holds |
| False positive | Open redirect (practice finding), vuln-nextjs `pages/secure/redirect.js:10` | The guard is `/^\/[^/]/.test(to)` with a second test that rejects a scheme. The model answered `destination_restriction: prefix_or_substring` |

## 2. Decisions

**D-1. A destructured request parameter.** `handler()` accepts an object pattern as the first
parameter. Each property of the pattern is a request projection: `{ params }` binds `params` to
`req.params`, `{ body: b }` binds `b` to `req.body`, and a nested pattern binds one level
further. A rest element, a computed key or a default value keeps the existing blocker. Reuse
`plainOrDestructuredParameters` in `enumeration.go`; do not write a second reader. *Why:* the
form is ordinary Express TypeScript and the enumeration, authorization and mass-assignment
producers already read it.

**D-2. A namespace import and a call of its exported function.** A member of a namespace import
(`import * as ns from './module'`) that resolves to an exported function of a scanned module is
a known callee. The existing helper flow (`helper_flow.go`, `helper_resolution.go`) follows it
under its existing limits. If it cannot, the gap stays. No new summary engine.

**D-3. Verified middleware is not a handler factory.** On a registration, an argument that is a
verified `multer` binding call (`path_upload_binding.go`), or a call on the closed
authentication list of branch 1 D-2, is middleware with known behavior. It records no
`unresolved_factory` gap. Every other call with arguments keeps the gap.

**D-4. A heap write that the operand does not pass through.** An `unsupported_write` gap does
not block a claim when both hold: the assigned value is a literal, and no dependency of the
claim's operand reads the written member chain between the write and the sink. Implement it in
the family's `gapCovered` hook for the `ssrf`, `path` and `code` families only. *Why not
everywhere:* the pollution family reads these gaps as its evidence
(`pollution_writes.go`), and query families have their own rule.

**D-5. A sink inside `try`.** Read `try_flow.go` first. If the `try` block of the profile
record is traversed by `tryStatement` and the gap comes from a nested statement, extend that
traversal to the nested statement kind. The sink being inside a `try` whose `catch` does not
rethrow is recorded as it is today. If the remaining gaps are `branch_exit` only, the record
needs no engine change: record the model's stated reason from a fresh judged run and treat the
fix as D-9's (evidence wording). Do not change the code-family policy.

**D-6. Middleware the chain resolver cannot read.** For the two details in §1.1, establish with
a fixture which construct fails, and extend `handler()` only if the construct is one of: a
factory whose body is a single `return` of a function inside a block that also declares
constants; a binding that an inner scope shadows at a different call. Anything else stays
blocked and is recorded in the results. This item is two records; it does not justify a wider
change.

**D-7. Reads of an owned record.** An `authorization_candidate` with the existing read facet
(`data_exposure`) is recorded when all hold:

- The operation is a Sequelize `findOne`, `findByPk` or `findAll`, or a Mongoose `findById` or
  `findOne`, and the entry sends the result or a value derived from it in the response.
- The selector carries a request-selected key, by the rule of branch 1 D-3.
- The model is **owned**: a `belongsTo` association (Sequelize) or a `ref` path (Mongoose)
  links it to a model that holds a `credential` attribute (branch 1 D-6).
- No other key of the selector takes a value that is not request-selected.

Guards and access are recorded as in D-3 of branch 1; none suppresses the record. *Why owned
models only:* a read of a catalog row by id is not an access-control claim, and the association
is a framework contract, not a name. *Not covered:* a model with no association to an account
model, list endpoints with no selector, and reads whose result is not sent.

**D-8. What a state change writes.** An authorization record for an update carries, as a fact,
whether any written value depends on the request. For a Mongo-style update document it also
names the update operators used (`$set`, `$inc`, `$push`). The instruction states what the fact
means. It states no answer. *Why a fact and not a rule:* an increment by a constant is harmless
on a like counter and harmful on a balance, and the source does not say which this is.

**D-9. What a listed directory holds.** A directory-listing record joins up to eight file names
found under the listed directory at the scan root, sorted, with the total count. A directory
that is absent or empty is stated as such. *Why:* whether a listing exposes anything depends on
its contents, and the scanner can read them.

**D-10. An anchored relative-path test as a redirect guard.** `redirect_guards.go` classifies a
`RegExp.test` or `String.match` guard on the destination by its literal pattern. A pattern
anchored at the start with `^\/` followed by a class that excludes `/` (and `\\` where present)
admits only a same-origin path and is recorded with that form. A pattern that is unanchored, or
that allows `//`, keeps today's classification. Cite the WHATWG URL parsing rule for
scheme-relative URLs in the code comment.

**D-11. Protocol identifiers.** D-8 and D-9 change what an authorization and a configuration
request carry. Each family takes a new protocol identifier. *Constraint:* every PHP request of
those families changes identifier too, so the recorded PHP runs stay as recorded under the old
identifier and are not rerun here. An offline scan of DVWA and of vuln-symfony must keep every
record identifier; only `analysis_components` and the request digest of those two families may
change. Any other PHP difference is a halt.

## 3. Key rows

Slice S0 adds these to `recall-gap-inventory/cases.json` and the
[Juice Shop guide](../evaluation/juice-shop-detection-guide.md) before any code changes. The
first eight are the rows the comparison already lists.

| ID | Kind | Anchor | Expectation |
|---|---|---|---|
| `JS-REDIR-01` | `open_redirect_candidate` | `routes/redirect.ts:18` | Positive (Confirmed today) |
| `JS-PATH-01` | `path_traversal_candidate` | `routes/fileServer.ts:32` | Positive |
| `JS-PATH-02` | same | `routes/fileUpload.ts:34` | Positive (Confirmed today) |
| `JS-PATH-03` | same | `routes/dataErasure.ts:107` | Positive (Confirmed today) |
| `JS-SSRF-01` | `ssrf_candidate` | `routes/profileImageUrlUpload.ts:24` | Positive |
| `JS-CODE-01` | `code_execution_candidate` | `routes/userProfile.ts:65` | Positive |
| `JS-CODE-02` | same | `routes/b2bOrder.ts:23` | Positive; a practice finding today (§6) |
| `JS-AUTHZ-05` | `authorization_candidate`, read | `routes/basket.ts:19` | Positive |
| `JS-PATH-N01` to `N03` | `path_traversal_candidate` | `routes/keyServer.ts:14`, `logfileServer.ts:14`, `quarantineServer.ts:14` | Not a finding: the name is rejected when it contains `/` |
| `JS-AUTHZ-N05` | `authorization_candidate` | `routes/likeProductReviews.ts:35` | Not a finding |
| `JS-CONF-N01` | `configuration_candidate` | `server.ts:294` | Not a finding |

The committed signing key (`JS-SECRET-01` in the comparison) is not keyed: no analyzer owns it.
The vuln-nextjs control `REDIR-001-safeControl` is already in the lab's key.

## 4. Slices and acceptance criteria

One commit per slice. Fixtures follow branch 1 §4: synthetic, with a transfer project, and no
sample name.

| Slice | Delivers | Criteria |
|---|---|---|
| S0 | Key rows | AC1 |
| S1 | D-1, D-2 | AC2 |
| S2 | D-3, D-4 | AC3 |
| S3 | D-5, D-6 | AC4 |
| S4 | D-7 | AC5 |
| S5 | D-8, D-9, D-10, D-11 | AC6 |
| S6 | Acceptance, documents, comparison refresh | AC7 to AC10 |

1. **AC1.** The rows of §3 are in the key. `check.py` reports the new positives that are not
   Confirmed today as not confirmed, and changes no existing row.
2. **AC2.** A handler with `({ params })`, `({ body: b })` and a nested pattern records the
   same dependency its plain form records; a rest element keeps the blocker. A value passed
   through `ns.helper(x)` of a scanned module keeps its dependency; through an unscanned module
   it keeps the gap.
3. **AC3.** A route with a verified `multer` call and a listed authentication call before the
   handler records no `unresolved_factory`; an unknown `make(option)` call still does. A literal
   written to an unrelated member before the sink does not block an SSRF, path or code claim; a
   write to a member the operand later reads still does; a pollution fixture is unchanged.
4. **AC4.** The cause of each record of D-5 and D-6 is in the run log with the construct that
   failed, and each fixed construct has a case that fails before the change.
5. **AC5.** Read cases: an owned model read by a request key and sent (candidate); the same with
   an owner key from a verified token claim (guard, `query_scope`); a model with no association
   to an account model (no record); a result that is not sent (no record); a key through a
   keyed store (no record).
6. **AC6.** An update whose document is `$inc` by a constant carries "no written value depends
   on the request"; one that sets a request value carries the opposite. A listing record names
   the files of its directory. The anchored pattern of D-10 is classified as a same-origin path
   test; `/^\//`, `/\/safe/` and a pattern allowing `//` are not.
7. **AC7.** `TestArchitectureBaseline`, `TestDVWASourceKey`, `TestSymfonySourceKey` and
   `TestNextJSVulnLab` pass. Every baseline row that moves is explained in the PR. An offline
   scan of DVWA and of vuln-symfony keeps every record identifier (D-11).
8. **AC8.** An offline Juice Shop scan keeps the 303 record identifiers of a scan at `80fff0c`,
   except records of the two families of D-11 whose content changed, and witnesses every
   positive of §3.
9. **AC9.** Judged acceptance: every positive of §3 except `JS-CODE-02` is Confirmed, every
   earlier Juice Shop positive keeps its status, and none of the five controls of §3 is a
   finding. On vuln-nextjs the 13 keyed cases keep their status and `REDIR-001-safeControl` is
   not a finding.
10. **AC10.** The Juice Shop and vuln-nextjs tables, the totals and the README section of the
    [scanner comparison](../../docs/scan/scanner-comparison.md) are regenerated from the new
    runs with the commands of the [run record](../evaluation/comparison-results.md#reproduce),
    and the local summary in the project container root (`scanner-comparison-summary.md`, not
    tracked) agrees with them.

**A control that becomes a finding is a failed criterion.** D-1 sends four path records that
are blocked today. Three of them are controls. If the model confirms one, find the missing
evidence (the `includes('/')` test must reach the model as a guard) before any other work.

## 5. Halt conditions and judged runs

The halt conditions of [branch 1 §5](juiceshop-nextjs-hardening-1.md#5-halt-conditions) apply,
with D-11's stated exception for the two protocol identifiers.

Judged runs use the provider, model and limits of branch 1 §6. Up to four `--only-family` runs
on Juice Shop while fixing, then one full Juice Shop scan and one full vuln-nextjs scan. The
owner agreed on 2026-11-24 that focused paid runs that solve a stated problem may be made.

## 6. Follow-on work, not in this branch

Recorded so it is not lost. Each needs its own decision before it is built.

| Item | What is known |
|---|---|
| Practice findings that are real vulnerabilities | `routes/b2bOrder.ts:23` (code run in a `vm` context) and the password in a logged URL (`server.ts:366`) are reported below Confirmed. Whether the policy or the evidence is at fault is not established |
| Entry access outside Express | Authorization, mass assignment and enumeration record nothing on Next.js, Fastify or Hapi. Each framework needs its own access contract |
| Authorization on raw SQL | Held-out test: vuln-demo-app has a documented missing admin check on a `DELETE` built as SQL text and records nothing. The JavaScript rule reads Sequelize and Mongo operations only. PHP already reads a request-selected row from a `WHERE` clause ([Symfony branch 5 D-2](symfony-more-analyzers-5.md)) |
| Mass assignment without an ORM | Held-out test: vulnerable-typescript-app spreads `req.body` into an object pushed onto an in-memory array and records nothing. The rule reads ORM writes only |
| Access facts on Next.js | Held-out test: oss-oopssec-store has documented broken access control and records nothing from the five families |
| Upload records | Built on branch 1, never judged. Four Juice Shop records wait for a run |
| Deployment-file checks for JavaScript projects | Branch 1 D-9, third row: not built |
| Password-hash record on an unrelated entry | A digest in a model accessor rides the lowest-numbered entry |
| A generated endpoint behind an explicit handler | Fixed on this branch after the judged run: an earlier handler for the same method and path that declares no `next` parameter always answers, so the generated endpoint makes no claim. A handler that declares `next` is still not read |
| A verdict that changes between runs | `DELETE /api/BasketItems/:id`: Confirmed, then Review, on identical evidence |
| Census roles for JavaScript | `login_identifier` and `role_source` are not established, so function-level authorization claims are not made |
| Wider keys for DVWA and vuln-symfony | About 190 results of the other scanners there are unreviewed. Reviewing them is how Code Scan's misses on PHP would show |
| Curated copies of the comparison's raw outputs | Done on this branch: `docs/samples/<sample>/{semgrep,bearer}/20261124-comparison-01/` |
| Classes with no analyzer | Committed secrets, token verification without an algorithm list, XML external entities, GitHub Actions workflows. Out of scope while no analyzer is added |

### Held-out test

Offline scans of four applications that were not used to develop the lane, baseline `4fb2ea8`
against this branch. No earlier record is missing or changed in any of them.

| Application | Stack | Records | New records |
|---|---|---|---|
| oss-oopssec-store | Next.js, Prisma | 128 to 128 | None |
| vulnerable-typescript-app | Express, in-memory data | 27 to 29 | Two session-cookie flags (`secure: false`, `httpOnly: false`), a documented defect of that application |
| nodejs-goof | Express, Mongoose | 36 to 37 | The `errorhandler` registration, under `app.get('env') == 'development'` |
| vuln-demo-app | Express, raw SQL | 19 to 19 | None |

The test found one defect, fixed here: an environment guard written with Express's
`app.get('env')` setting was not recorded, so the nodejs-goof record carried no guard. It also
shows that the five families reach little beyond Express with an ORM. That is the subject of
the generality review proposal, a local planning document in the project container root
(`detection-generality-review-proposal.md`, listed in `proposals-index.md`, not tracked).

## 7. Scope

| Path | Change |
|---|---|
| `scan/internal/langjs/` | Modified: `analysis.go`, the flow and helper files, `redirect_guards.go`, `authorization.go`, `configuration` producers, the `gapCovered` hooks of three families. New fixtures and tests |
| `scan/internal/analysis/`, `scan/internal/judge/`, `scan/internal/analysispacks/` | Modified for the facts and instructions of D-8, D-9 and the identifiers of D-11 |
| `scan/cli/testdata/architecture-baseline.json` | Rows that move are explained in the PR |
| `.zazz/evaluation/`, `docs/scan/`, `README.md` | Key rows, results, class pages, the refreshed comparison |

**Out of scope.** A new analyzer family, kind or question. Python and PHP behavior beyond D-11.
Everything in §6.

## 8. Definition of done

- [ ] Every criterion of §4 is met with its command output in the run log. **Not met.** AC1 to
  AC7 and AC10 are met. AC8 is met except the offline witness of `JS-PATH-01`. AC9 is not met:
  see the [results](../evaluation/juiceshop-hardening-results.md#open-rows).
- [x] The contributor gate passes.
- [x] The draft PR is open on branch 2's head with the before-and-after table.
- [x] Samples are unchanged.

## 9. Change log

### 2026-11-24 — Two key decisions by the owner

`JS-PATH-01` is not a path-traversal positive: the name is rejected when it contains `/`, so the
read cannot leave its directory, and what the null byte defeats is a file-type allow-list. The
row's expectation is Review. vuln-nextjs's `REDIR-001-safeControl` is reported correctly, since
its guard admits `/\host`; it is no longer counted as a false positive, and the lab's control is
the owner's to fix. The comparison now reads 95 of 96 known vulnerabilities with three Code
Scan false positives.

### 2026-11-24 — Code policy, owner decision

D-5 said "Do not change the code-family policy". The owner lifted that after the acceptance
runs: in the code family the model's restriction answer settles whether a condition on a
guarded path protects the operand. `JS-CODE-01` is Confirmed in a code-family run. The rule and
its risk are in the [results](../evaluation/juiceshop-hardening-results.md#code-policy-change-owner-decision-2026-11-24).

### 2026-11-24 — Lead review

Two fixes after the acceptance runs, each with a test and no judged run: an environment guard
written as `app.get('env')` is recorded (`TestExpressEnvSettingGuard`), and a generated
endpoint that an earlier handler without a `next` parameter answers makes no claim
(`TestExpressGeneratedAnsweredFirst`). The second removes the generated
`DELETE /api/Addresss/:id` record, one of the two false positives the acceptance run added.
Offline, Juice Shop goes from 306 records to 305 and nothing else changes. §6 gains three gaps
and the held-out test.

### 2026-11-24 — Drafted

Written from the judged Juice Shop report `r10-acceptance-juice-shop`, the vuln-nextjs
acceptance report and the code at `80fff0c`. One claim made before the diagnosis is corrected
here: the records blocked on middleware are 5, not "many", and their cause is a handler or
factory the resolver cannot read, not a missing access chain. The larger group is the 5 path
records blocked on a destructured request parameter (D-1). No code changed.

### 2026-11-24 — Implemented; judged acceptance not met

Slices S0 to S6 are committed. Scanner commit of the acceptance runs: `ee777f4`. The judged-run
bound of §5 is used (four family runs, two full runs). Results and every open row are in the
[results](../evaluation/juiceshop-hardening-results.md#hardening-3).

What the implementation found that this document states differently:

- **§1.1, blocked path records.** D-1 sends one path record, not four. The three controls keep
  `applicable_middleware_unresolved` from the `serve-index` mount on their prefix.
- **§1.1 and D-5, `routes/userProfile.ts:65`.** The `try` is not the cause. `tryStatement` runs
  only for a Next.js project; in Express the statement is explored and leaves coverage gaps.
  Every operand path is guarded by the enclosing regular-expression test, and the code policy
  confirms only a raw path.
- **D-6.** Neither sample construct is one of the two the decision allows, and both of those
  already resolve. `isAuthorized()` is a factory whose body is a library middleware call; the
  `serve-index` middleware is a constant of the enclosing function.
- **D-10.** The classification existed in `redirect_normalization.go` for `RegExp.test`, and it
  records that `/^\/[^/]/` admits `/\host`. Only `String.match` was added. The vuln-nextjs
  control this decision was written for is bypassable on source review.
- **D-8 and D-9.** Both facts reach the model and neither changed the false positive it was
  written for. Two further false positives appeared in the acceptance run.

Deviations, each with its reason, are in the run log sections S0 to S5 and summarized in the PR.
