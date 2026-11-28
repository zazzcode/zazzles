# Detection generalization 13 — storage calls without a contract

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** 02, 03, 04, 12. **Effort** medium to large.
  **Review artifact** one draft PR.

## Capability

A state change on a record the request selects is recorded for any storage library. The program shows a call
on a third-party client that receives a request value; the model says whether it stores, changes or deletes,
and which argument selects the record. Today two model libraries and one collection rule are known. An
update through a verified Prisma client, or a bound `UPDATE … WHERE id = ?`, records no authorization claim.

## Required reading

Spec 03 (the resolution mechanism); [strategy](../../../evaluation/detection-generalization-strategy.md)
options C and D; `langjs/authorization.go`, `sql_libraries.go`; `langphp/authorization.go` (request-selected
row in SQL); [model-assisted resolution](../model-assisted-evidence-resolution.md).

## Semantics

**Candidate**, from the program only: in an entry, a call whose receiver chain starts at a package import,
with at least one request-derived argument or property, whose result is awaited, returned or ignored, and
which no contract covers. Or a SQL text that begins `UPDATE`, `DELETE` or `INSERT` whose bound or built
`WHERE` value is request-derived (no model question needed for a verified SQL call).

**Question**, closed: effect (`reads`, `creates`, `updates`, `deletes`, `not_storage`, `unknown`) and the
argument or property that selects the record (one choice per argument, or `none`). It cites the import and
the call.

**Check.** The cited import is the receiver's binding and the cited argument carries a request dependency.
Then the record is an authorization record with a model-resolved operation, judged with spec 02 and 04
evidence. **A model-resolved operation can give a finding or Review, never Protected.** A resolved `reads`,
`not_storage` or `unknown` makes no authorization record.

## Scope

New `langjs/storage_calls.go`, authorization wiring, `judge/resolution.go` and authorization material for
the Node contract, tests and fixtures. Out of scope: reads, mass assignment, in-memory collections, Python,
PHP, new contracts.

## Decisions

- **D-1. Reuse 03's question and verifier.** *Why:* one mechanism, measured once.
- **D-2. One request per record, two stages only if the plan shows it is needed.** *Why:* frugal runs.
- **D-3. Candidate bound:** eight per entry, sorted by source; more is a gap. *Why:* cost.

## Fixtures

Positive: six storage libraries of different shapes (object options, chained builder, positional, callback,
repository class, tagged template). Negative: mail, queue, cache, search and payment clients with the same
shapes; a logger; a pure formatter; a local class.

## Held-out

One pool application on a storage library absent from the fixtures, one ordinary application, and
oss-oopssec-store.

## False-positive controls and G7 bound

Every non-storage client in the pool. Count resolved `not_storage` as cost. At most 2 authorization records
per 10 entries.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix candidates and rejections | `go test ./scan/internal/langjs -run TestStorageCalls` |
| AC2 | Stubbed answers give the stated outcomes; none is Protected | `go test ./scan/internal/judge -run TestStorageCallResolution` |
| AC3 | Records with a contract unchanged; G1 to G7 | Comparison |
| AC4 | Planned requests per sample stated before any run | Offline plan |
| AC5 | Paid checkpoints and contract §7 | Results |
| AC6 | Pages: missing authorization; its guide; `application-security-analyzers.md`, `trace-judgment.md` | `doc-check` |

## Paid checkpoints

1. Fixtures, two planned repeats. Cap 80. Pass: every storage effect right in both; no non-storage client
   called storage. 2. Held-out. Cap 100. Pass: contract §7; at least 60% of keyed positives Confirmed; no
   keyed control Confirmed.

## Stop rule

Stop when a non-storage client is called storage with a citation that verifies, when repeats disagree on
more than one fixture, or when the plan exceeds three added requests per entry on any sample.

## Juice Shop check

No change expected.

## First failing test and order

`TestStorageCalls/object_options_update`. Start only if spec 03 passed its checkpoints.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
