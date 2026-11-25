# Detection generalization: where Code Scan's known misses start

[Strategy options](detection-generalization-strategy.md) · [Series of
specifications](../specifications/detection-generalization/README.md) · [Scanner
comparison](../../docs/scan/scanner-comparison.md#what-code-scan-misses) · [Comparison
rows](juice-shop-comparison-rows.json)

2026-11-25. Research only: no scanner change and no paid model call. Scanner source at `021bad2`. Its
`scan/` and `cmd/` trees are the same as `stage` at `e2a7a80`. Juice Shop at `f189f52`, read-only.

## 1. Result

1. **No row fails first at a model answer.** Eight rows have no record for the weakness, three stop at
   evidence and two at claim scope. A request was sent for two records (three rows), and neither asked what
   the row is about. One of the claim-scope rows is not a weakness as written.
2. **Node authorization requests mostly omit the handler.** Of the 10 authorization requests in the
   published run that have a handler, 7 carry at most 2 of its lines. Four records on a probe app, two
   correctly guarded and two with broken checks, come out with the same empty guard list. This causes misses
   and is a source of false positives on correct code.
3. **The 13 rows do not test the proposal's main idea.** Recognizing an unknown library is the cause in one
   row (CORS). Most of the 13 fail on claims and evidence. Library recognition is the main limit elsewhere:
   five access and state families record nothing on three of the five other Node applications (§5). Both
   tracks are needed and they need different tests.
4. **Seven rows should be corrected before anyone builds on them** (§2).
5. **The largest limit is recognition of what is already modelled.** Most ordinary model definitions and SQL
   drivers are not recognized ([strategy §2](detection-generalization-strategy.md#2-evidence)). The
   [series](../specifications/detection-generalization/README.md) starts there, not with the 13 rows.

The 13 rows are not held out any more: the capabilities below were derived after reading them. They are an
acceptance check. A real held-out test is in §7.

## 2. Are the rows right?

Each row was read in source. "Source" is whether the weakness is there as written.

| Row | Source | Correction |
|---|---|---|
| `AUTHZ-09` repeated key | Yes. The check reads the first value and the write uses the last | None |
| `AUTHZ-10` masked selector | Yes. Orders store the masked address and are selected by it, so two addresses that differ only in vowels share orders | None |
| `MASS-07` review author | Yes, but it is not mass assignment. Named fields are written and the author is the request's. The entry also has no authentication | **Class**: authorization (forged owner) |
| `EXPO-03` requested field | Yes. The requested field can be the caller's own password hash | None |
| `EXPO-04` JSONP | Yes in source. A browser that treats a cookie without `SameSite` as `Lax` does not send it on the cross-site script request | Note the condition |
| `XSS-09` subtitles | Only through another weakness: an archive entry that overwrites the file | None; state the dependency |
| `UPLOAD-01` size | **No.** `multer` is built with `limits: { fileSize: 200000 }` (`server.ts:722`), so the server enforces a size. The client's lower limit of 100,000 is what is not enforced | **Reword or drop.** A scanner that reports "size not enforced" here is wrong |
| `UPLOAD-02` type | Partly. The type test has no effect on control flow, but a file of another type is kept in memory and discarded with 204. Nothing is stored | **Reword** as a client rule the server does not enforce. **Cause**: the route has a record (`server.ts:337`, judged, Review) |
| `RESET-01` security answer | Yes: a stored answer is the only proof. "Guessable" is not a source fact | **Cause**: Node has no recovery producer at all; the claim exists for PHP only |
| `CONF-05` CORS | Weak. `cors()` allows every origin and does not allow credentials, so a browser does not expose cookie-authenticated responses | **Severity**: practice, not vulnerability |
| `CONF-06` cookie | Yes on the server anchor. A cookie that browser script sets can never be `HttpOnly` | **Cause**: Node flags are read for `express-session` and `cookie-session`; `res.cookie` is left out by a stated decision (`langjs/configuration.go`) |
| `VALID-01` zero stars | Yes, small. The only statement of the rule is the client slider (`min="1"`) | None |
| `VALID-02` registration | Yes. The middleware sends 400 and still calls `next()`. Password repeat is checked on the client only | **Cause**: the fields have three records (`server.ts:437`), not sent for missing evidence |

These are static readings. Nothing was run.

## 3. Trace

Method: the scanner was built from `021bad2` and run offline on Juice Shop. It produced the same 305 records
as the published report. Requests were rebuilt offline from that report. The digests of all 18
authorization, all 15 mass-assignment, the configuration, exposure and enumeration requests match the
published run, so for those families the text below is the exact model input. NoSQL, path and upload digests
did not match when rebuilt from saved JSON; nothing here rests on those requests.

| Row | First failing stage | What happens |
|---|---|---|
| `AUTHZ-09` | Not discovered | Node authorization knows updates and deletes of a found record. A create is not an operation. Next: the value passes a streaming parser and array pushes, which the one-step origin helper does not follow; and in-handler checks are not recorded for writes |
| `AUTHZ-10` | Not discovered | A Mongo-style `find` is not a protected read, and a row selected by a caller value is not recorded by rule |
| `MASS-07` | Claim scope | Recorded and judged as NoSQL injection. No claim asks whose identity is written |
| `EXPO-03` | Not discovered | Node exposure reads process state, metrics and stacks. The response exists as an XSS data record with the key `field` unresolved |
| `EXPO-04` | Not discovered | `jsonp` is only a response method in the enumeration and exposure rules. What it does cross-origin is not a fact |
| `XSS-09` | Evidence | Recorded. The file key is unresolved and no writer is linked; the policy then rightly sends no request |
| `UPLOAD-01` | Claim scope | The claim is executable storage. Limits are not read (and the row is wrong, §2) |
| `UPLOAD-02` | Evidence | Memory storage records every fact as `unknown`; checks in later handlers are not read. The model answered `unknown` three times, correctly |
| `RESET-01` | Not discovered | No Node recovery producer. The password write is not an authorization record either: its record is selected through two lookups and the origin helper follows one. Confirmed on the probe (p5, p5b) |
| `CONF-05` | Not discovered | `cors` appears only in a list of middleware with known behavior |
| `CONF-06` | Not discovered | Excluded by decision, and an absent flag is never recorded |
| `VALID-01` | Not discovered | A generated endpoint has no field records, and a client rule is not read in JavaScript |
| `VALID-02` | Evidence | Three records, each missing `input_source`, `field_policy`, `invoked_callable` and `control_flow`. Not sent |

### 3.1 What an authorization request contains

| Record | Handler lines in source | Lines in the request |
|---|---:|---:|
| `address.ts:29`, `payment.ts:70`, `coupon.ts:24` | 3, 3, 9 | 0 |
| `address.ts:18`, `basket.ts:19` | 4, 11 | 1 |
| `recycles.ts:12`, `updateProductReviews.ts:17` | 6, 10 | 2 |
| `orderHistory.ts:36` | 4 | 4 |
| `likeProductReviews.ts:35`, `:50` | 19 | 17 |
| 8 generated endpoints | none | none |

A line counts when it has 18 or more characters, is not a comment and contains no double quote. A handler
appears in full only when another rule happens to carry it. A local access middleware is sent as its
**name**: the request for an entry guarded by `gateFalls` contains no line of `gateFalls`.

### 3.2 Probe

A 16-route Express, Sequelize and Mongoose app written for this note, scanned offline. It is kept outside
the repository. Input-validation, outbound and XSS data records are left out of the table.

| Case | Expected | Recorded |
|---|---|---|
| p1 owner check that returns 403 | Guarded | Authorization, **guards: none** |
| p2 the same check without `return` | Not guarded | Authorization, guards: none |
| p3 the check reads another record | Not guarded | Authorization, guards: none |
| p11 role check that returns | Guarded | Authorization, guards: none |
| p6a local middleware that stops | Guarded | Access `unresolved`, body not sent |
| p6b the same middleware without `return` | Not guarded | Access `unresolved`, body not sent |
| p4a, p4b create with the owner from the request (Sequelize, Mongoose) | Candidate | Nothing |
| p4c the same with `pg` `INSERT` and bound values | Candidate | SQL record only |
| p5 credential change through two lookups | Candidate | Nothing |
| p5b through one lookup | Candidate | Authorization |
| p7 token in `res.cookie` without flags | Candidate | Nothing |
| p9 projection chosen by the request; p9b whole account in a response; p10 `jsonp` | Candidate | Nothing |
| `cors({ origin: true, credentials: true })` | Candidate | Nothing |

For p1 and p11 the question text forbids the right answer: "answer none only when no guard is recorded", and
`adequate` with an empty list is a contradiction. With access `inadequate` (the instruction for a login
without roles) the policy gives Confirmed for correct code. That last step is a reading of the policy, not a
judged run.

The same probe written with `require` instead of `import` recorded no authorization, account or password
record at all: model bindings resolve from ES module exports only.

PHP is better here: `langphp/authorization_guards.go` records dominating checks and drops one that does not
exit. The dropped check is not stated as a fact, and a second helper step is unclassified.

## 4. General capabilities

Each is defined from language and framework semantics. No name, route, field or path from any application
appears in a rule.

| # | Capability | What it records | Rows |
|---|---|---|---|
| A | **Check evidence** | Every test between entry and operation: the values it reads, how they relate to the operation's operands, and what the failing side does (stops, responds and continues, continues) | `VALID-02` (empty fields); needed by `AUTHZ-09`, `RESET-01` |
| B | **Ownership on create** | A stored record whose identity field takes a request value. A field is an identity field when an association says so, or another entry scopes a selector on it by a caller value | `MASS-07`, `AUTHZ-09` |
| C | **Credentialed cookie and cross-origin policy** | A cookie an access check reads, with its flags (an absent flag has a documented default); the origin policy, its credentials setting and script-readable responses, joined to how entries authenticate | `CONF-06`, `EXPO-04`, `CONF-05` as practice |
| D | **One value flow for operation families** | Authorization, mass assignment, account and exposure take origins from the shared flow in place of their own one-step helper | Enables `RESET-01`, `AUTHZ-09`, `EXPO-03` |
| E | **Model-resolved unknown calls** | A request-derived value at a call with no contract is an unresolved operation; the model says what the callee does, the policy checks the answer against the recorded construction (the proposal's candidate) | None of 13 |
| F | **Proof of a credential change** | A write to a credential field with the facts of what proves the caller: session, one-time secret, or a reusable stored value | `RESET-01` |
| G | **Response projection** | A response whose property names come from the request, or that carries a credential field; the mirror of mass assignment | `EXPO-03` |
| H | **Client rule, server enforcement** | A constraint the project's own client declares for a request field, joined to the server path of that field. Python already does this for forms | `VALID-01`, `VALID-02` (repeat), `UPLOAD-01`, `UPLOAD-02` as reworded |
| I | **Upload bytes after memory storage** | Follow the buffer to a store or to nothing | Makes `UPLOAD-02` decidable as protected |
| J | **File write to file read link** | An uncontained write as a possible writer of a read in the same tree | `XSS-09` |

### 4.1 Not worth fixing, or not a source question

- **`UPLOAD-01`**: not a defect as written. It belongs in the control set.
- **`AUTHZ-10`**: visible in source, rare in general. Recording every caller-scoped read so that an unusual
  transform shows would add a record per such read. Revisit only if A makes those records cheap.
- **`XSS-09`**: Review is the honest result without J, and J links findings that are already reported.
- **`CONF-05`**: a practice record. Confirming an open origin policy without credentials would be a general
  false positive on every public API.
- **`RESET-01` "guessable"**: source shows that a reusable answer is the proof. It does not show that the
  answer can be guessed. F should say only the first.
- **`VALID-01`**: a business rule. It becomes a source question only through H.

## 5. The wider limit, measured

Offline records on the other Node samples, same binary:

| Application | Entries | Authorization, mass assignment, account, exposure, configuration |
|---|---:|---:|
| oss-oopssec-store (Next.js, Prisma) | 131 | 0 |
| vuln-demo-app (Express, SQL) | 14 | 0 |
| vulnerable-typescript-app (Express, in memory) | 20 | 2 (configuration) |
| nodejs-goof (Express, Mongoose) | 20 | 1 (exposure) |
| vuln-nextjs (Next.js) | 37 | 0 |
| Juice Shop (Express, Sequelize, MarsDB) | 194 | 46 |

The closed lists behind this are short: 3 authentication libraries, 2 model libraries, 4 static writes, 3
instance writes, 2 collection writes, 3 read methods, 3 exposure libraries, 3 configuration libraries, 1
upload library. This supports capability E as the second track. In the proposal's terms: authentication,
model and driver lists are *recognition* (E); ownership, checks and projections are *shape* (A, B, G);
cookie, origin and digest defaults are *contract* (C).

## 6. Effort and ranking

The ranked order, with probability, gain, evidence and risk, is in the [series
index](../specifications/detection-generalization/README.md#2-ranking). How the capabilities above map to
it:

| Capability | Specification |
|---|---|
| A check evidence | 02 handler checks, 04 local middleware, 11 rejection without stop |
| B ownership on create | 06 |
| C cookie and cross-origin | 08, 09 |
| D one value flow | 05, for record selection only |
| E model-resolved calls | 03, for SQL |
| F credential-change proof | 10 |
| G response projection | 07 |
| H client rule, I upload bytes, J file link | None ([reasons](../specifications/detection-generalization/README.md#3-no-specification)) |
| Not in the first list | 00 operation inventory experiment, 01 storage identity |

Two changes came from measurement after the first draft. Storage identity was added and ranks first. A check
that rejects without stopping was the first draft's headline and ranks last: it does not occur in the five
other Node samples.

## 7. Evaluation

The [series protocol](../specifications/detection-generalization/contract.md#3-held-out-protocol) is the one
to follow. Its reasons:

**Held-out applications.** None may be used during development, and no repository document refers to them
today. Suggested, stacks from general knowledge and to be confirmed when pinned: OWASP NodeGoat (Express,
native MongoDB driver), DVNA (Express, Sequelize), and two ordinary applications that are not meant to be
vulnerable, one Express with Mongoose and one Express with Prisma. Downloading them needs the owner's
approval.

**Keys first.** One session writes the key from source before any scan and commits its hash to the
evaluation record. A second session, which has not seen the scanner's output, checks it. Every row says
vulnerable, controlled or not decidable from source.

**Controls for false positives.** Three kinds: each held-out app's correct checks, keyed as controls; the
two ordinary applications, where every new Confirmed record is reviewed; and minimal pairs (a check that
stops and the same check that does not).

**Recall of the sample by the model.** Famous samples are likely in the model's training data. Scan a copy
with renamed identifiers, paths, routes and messages and with comments removed. Outcomes should not move.
This measures memory and name reliance, which no unmodified sample can.

## 8. Branching

| Option | For | Against |
|---|---|---|
| Here, on PR 51's branch | Rows and key in place | Mixes scanner code into a documentation PR that another session is editing |
| Stacked on PR 51 | Corrected rows available now | Rebases while PR 51 moves; nothing in `scan/` depends on it |
| **New branch from `stage` after PR 51 merges** | Clean diff, corrected key, no rebase | Waits for PR 51 |

**Recommendation: the third. The owner chose it on 2026-11-25.** PR 51 changes no file under `scan/` or
`cmd/` (checked), so a branch from `stage` can start earlier without stacking if waiting costs more. The
shared conflict would be `spec-index.md` and documentation. Each specification gets its own branch.

**Overlap.** The injection false-positive work proposes one fact row per SQL operand and ties a guard to the
operand. Spec 02 records checks for operations. Both need a check's condition, the values it reads and
whether a value changes after it. Agree that part of the record before either starts. Spec 02 owns "what the
failing side does"; the injection work owns "what the check constrains the text to".

## 9. Limits

Static reading only. No judged run, so no statement here says how the model answers with better evidence.
The probe is small and written by the same session. Effort is judgment. Python was not probed and has no
authorization, mass-assignment or account producer.
