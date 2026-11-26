# Detection generalization 19 — database package operations

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Asked for by the owner**, 2026-11-25: the judge should decide a MongoDB call as it does SQL, with no adapter per driver form,
  client set-up, helper or code shape; the solution must serve MongoDB in general, SQL and later databases, not one lab.
  Mid-session: record the learnings, and test Juice Shop and NodeGoat.
- **Branch** `generalized-nosql-detection` from `stage` `a855b4a`. Nothing is committed. **Review artifact** one draft PR, when the owner asks.
- **Status** implemented and measured; **not ready to merge**: criterion AC6 fails. [Results](../../evaluation/detection-generalization-results/19.md) ·
  [learnings](../../project/learnings/database-package-operations.md).

## Capability

A call whose receiver or callee derives from a database client package, and that receives request data, is a record of that
package's query language. The scanner states the definition path from the import to the call. The decision model says what
the call is and what the request controls in it.

## Semantics

**S-1. Package origin** (`langjs/package_origin.go`). A backwards search from the callee: a name to every definition and assignment
in its scope, a member to the value it is read from, a call to what the called function of the repository returns, or else to the
value whose method or function it is, a parameter to the arguments at its calls, a callback parameter to the value that takes the
callback, `this.x` and `new C().x` to the class or constructor function, an import to the module's export or to the package. It is a
**may-fact**: one path exists. It lists no driver method, client form or variable name. `storePackages` maps a package to a query
language; `mongodb` is its one entry.

**S-2. Recording.** Additive. The flow handles the call exactly as before, marks no request field as consumed and changes no other
record. Code the flow does not enter (a method of the application's own class or constructor function, the expression a loop
iterates, a renamed destructured property, a closure argument) is walked on a copy of the flow that keeps only these records.
Nothing runs unless a file of the target names a package of the table.

**S-3. Reading limits.** For these records the scanner's own limits (`unknown_transfer`, `unsupported_callback`,
`condition_helper_unresolved` and the like) are shown to the model and listed in `completeness.judged_limits`. A record with one is
never Protected. An entry chain that is not established still blocks.

**S-4. Protocol** `document-operation-v2`, selected by contract `mongodb-document-query-v1` and for no other NoSQL record: one request
with the query-language notes, an entry note, the call, the receiver path, the request values and the source; two questions,
`operation` and `request_control` (is there an input that changes the operation beyond what the code lists). Finding: a database query with such an input. Protected: `data_only` at 0.95 or above and no
judged limit. Otherwise Review.

**S-4a. Source shown.** The handler, the helpers the flow entered, and the module-level definitions of the constants and
functions they use (`referenced_definition`, found by the same definition search). A statement on the receiver path is not repeated.

**S-5. Entries** (connector rules, deterministic). A Next.js route helper that passes its own parameter, used once, to a verified
forwarding wrapper. An Express app passed to a function of another module. A handler or middleware that is a method of an object
constructed from a class or constructor function of the repository.

**S-6. Flow soundness.** A join of a request value with an object literal keeps the request value under each field.

Not covered: Python and PHP; Mongoose and MarsDB (they keep their contracts and protocol); other databases and SQL drivers
without a contract (one table entry and one language note each, not enabled: no local sample has such a call).

## Scope

`langjs`: `package_origin.go`, `package_origin_flow.go`, `express_passed_receiver.go` (new); `next_handlers.go`, `analysis.go`,
`flow.go`, `conditional_flow.go`, `checks.go`, `helper_flow.go`, `modules.go`. `judge`: `document_operation.go` (new), and one branch
each in `client.go`, `injection.go`, `validation.go`, `policy.go`, `equivalence.go`. `analysispacks/nosql.go`, `analysis/analysis.go`
(`judged_limits`, additive). Tests beside each. Documents: this page, the results, the learnings.
Updated: the NoSQL capability page, the vuln-nextjs detection guide, the sample catalog, `.zazz/architecture/query-judgment.md`.
**Not yet updated** (owed before a PR): the NoSQL analysis guide, the series index and the implementation plan.

## Acceptance criteria

| AC | Criterion | Result |
|---|---|---|
| AC1 | The 57 vulnerable lab routes are recorded and sendable with no list of driver methods or client forms | **Met**: 57 of 57 (`stage`: 0) |
| AC2 | G1, G2: nine samples, no record missing, added or changed | **Met**: 0, 0, 0 |
| AC3 | G5, G6: Juice Shop scan time within 10%; format, vet, build, race tests | **Met**: 28.0 s against 27.6 s |
| AC4 | Forms written by another session behave as designed | **Met**: 52 forms and look-alikes |
| AC5 | Paid: no vulnerable route Protected; at least 70% of vulnerable routes Confirmed | **Met**: 0; 52 of 57 on Gemini with protocol v2 (v1: 50 on Gemini, 46 on gpt-6-luna) |
| AC6 | Paid: at least 95% of Confirmed routes are vulnerable (contract A5) | **Not met, close**: 52 of 56 (93%) on Gemini with protocol v2 (v1: 88% on Gemini, 73% on gpt-6-luna) |
| AC7 | A held-out application | **Partly**: NodeGoat, 0 records before entry work; 7 after, 3 of 4 Confirmed true. No key was written before the scan |

## Stop rule

A vulnerable route Protected, or under 70% Confirmed, reverts the protocol. Neither fired. AC6 is a merge block under contract §7:
the remedy is evidence that clears safe code in general, never a rule, wording or threshold for a record. The owner decides.

## Change log

### 2026-11-25 — Written with the implementation and its measurements

Three paid checks and three probes: 647 requests in all. AC6 fails; nothing is committed.

### 2026-11-25 — Value facts tried for AC6 and reverted

Owner asked to reduce false positives. Four proven value facts, 15 requests: 3 of 8 flagged controls cleared and two safe
records newly Confirmed, within noise. Reverted. AC6 is unchanged at 72%. What reads the evidence is the limit: the open
decisions are another judge model for this protocol, or a policy that may use a proven fact.

### 2026-11-25 — Complete source, the question, and Gemini

Owner: sufficient and correct information and questions are the issue. Referenced definitions added (39 requests changed, net
zero on gpt-6-luna, kept). A reworded question cleared six controls and five more vulnerable routes; not built. The unchanged
request on Gemini gemini-decision-1: 50 of 57 Confirmed, 7 controls Confirmed, none Protected. Earlier learnings pages copied
from `detgen-14-sql-calls-redesign` into `.zazz/project/learnings/`. 957 requests in all.

### 2026-11-25 — Protocol v2

The reworded question on Gemini: 52 of 57 Confirmed, 4 controls Confirmed, none Protected (93%). Built in. Not run through the
scanner on gpt-6-luna. Committed and pushed at the owner's word; no pull request opened. 1,085 requests in all.
