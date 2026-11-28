# Detection generalization 03 — SQL calls without a contract

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing. **Effort** medium to large. **Review
  artifact** one draft PR.

## Capability

A call that receives a string built from request data, on a value from a third-party package with no written
contract, becomes a SQL record. The model says what the callee does with each argument, given the import and
the call, and cites them. The scanner checks the answer against the construction it already holds and
applies the existing SQL policy. SQL injection then does not need a contract per driver.

## Required reading

[Strategy §2 and option C](../../../evaluation/detection-generalization-strategy.md#4-options); [model-assisted
resolution](../model-assisted-evidence-resolution.md) invariants, D-1, D-2, D-7, D-9 and its
[results](../../../evaluation/model-resolution-results.md); [database
injection](../../../../docs/scan/analysis/database-injection.md); [query
judgment](../../../architecture/query-judgment.md). Code: `langjs/query_shape.go` (`queryKind`), `flow.go`,
`sql_libraries.go`, `judge/resolution.go`, `citation.go`, `injection.go`.

## Semantics

**Candidate, from the program only.** (1) An argument is a string, or an object property, whose value is a
template, concatenation or join with at least one request dependency. (2) Its constant parts, read in order,
begin a SQL statement by the SQL grammar's verb and a following clause word. (3) The callee is a member, or
a chain of members and calls, of a value whose binding starts at a package import; or a scanned function
whose parameter reaches such a call unchanged, one step. Request text alone is not enough, and neither is a
method name.

**Question.** For the callee: does the argument at this position execute as SQL text (`executes`,
`prepares_then_executes`, `bound_only`, `not_sql`, `unknown`), and which argument, if any, carries bound
values. Choices are closed. The answer cites the import and the call.

**Check.** The cited import must be the callee's binding. A tagged template is `bound_only` only if the
source is a tagged template. A named binding argument must exist. An answer that a recorded contract
contradicts is discarded.

**Outcome.** A verified `executes` or `prepares_then_executes` discharges `sink_binding_unverified` and
marks the record model-resolved. The construction decides as today. Only a finding or Review can follow: **a
model-resolved callee never gives Protected**. `not_sql` removes nothing; the record stays Review and is not
counted as SQL in summaries.

## Scope

`langjs/query_shape.go`, `flow.go`, a new `sql_unknown_call.go`, tests and fixtures; `analysis` resolution
record use; `analysispacks` SQL questions (protocol of SQL only); `judge/resolution.go`, `injection.go`,
`citation.go`; `report` provenance text. Out of scope: NoSQL, PHP and Python, ORM query builders whose SQL
is not a string in source, dynamic imports, new contracts, and the meaning of identifiers in SQL text.

## Decisions

- **D-1. SQL text is recognized by SQL, not by callee.** *Why:* it is the one part that holds across
  drivers.
- **D-2. Extend the resolution protocol.** *Why:* citation, one request, replay and provenance exist.
  *Rejected:* a library table written by the model offline; it would be a closed list again and
  unreviewable.
- **D-3. Same request.** The question joins the record's assessment. *Why:* no added request per call.
- **D-4. No Protected.** *Why:* a wrong claim that a driver binds values would hide a defect.
- **D-5. Verified contracts win.** *Why:* deterministic evidence stays stronger.

## Fixtures

Positive: the 16 unrecorded or blocked probe forms, plus a batch call, a pool client and a transaction
callback. Negative: SQL-like text logged, emailed, returned, compared, or sent to a search service; a
constant SQL string; a request value passed only in a values argument; a tagged template; a local class with
`query`; a package function that formats text.

## Held-out

One application on a driver absent from the fixtures, one on an ORM's raw call, and one ordinary
application.

## False-positive controls and G7 bound

Every added record on the samples is read. At most 3 added records per sample unless each is a SQL call.
Ordinary application: no Confirmed record whose text is not executed as SQL.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Each positive form records, each negative does not | `go test ./scan/internal/langjs -run TestSQLUnknownCall` |
| AC2 | Stubbed answers: verified, uncited, contradicting, `not_sql`, `unknown` give the stated outcomes; none is Protected | `go test ./scan/internal/judge -run TestSQLCallResolution` |
| AC3 | Records with a contract keep identifiers and requests (G1, G2) | Comparison |
| AC4 | Replay of a model-resolved record is exact | Replay test |
| AC5 | Paid checkpoints pass | Results |
| AC6 | Pages: SQL injection; its guide; `query-judgment.md`, `trace-judgment.md`, `technical-approach.md` | `doc-check` |
| AC7 | G3 to G7 | Commands |

## Paid checkpoints

1. Fixtures, two repeats. Cap 90. Pass: at least 14 of 16 forms answered correctly in both repeats; no
   negative answered as executing SQL.
2. Held-out. Cap 60. Pass: every keyed SQL positive Confirmed or Review with its blocking fact, at least 80%
   Confirmed; no keyed control Confirmed.

## Stop rule

Stop when checkpoint 1 gives fewer than 12 of 16, or any negative Confirmed, or repeats disagree on more
than two forms. Stop when a held-out driver is answered wrong with a citation that verifies: the check is
then too weak. Do not add a contract for a failing driver to pass.

## Juice Shop check

No row of the 13 is expected to change. The two keyed SQL findings stay.

## Open question

**OQ-1.** Send a call in an unknown package function that only *looks* like SQL formatting? Default: yes,
and let the model answer `not_sql`; count the cost at checkpoint 1.

## First failing test and order

`TestSQLUnknownCall/pool_query_no_contract`. Then candidate rule, question, verifier, policy, checkpoints.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
