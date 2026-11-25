# Detection generalization 06 — ownership on create

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** 01 and 02. **Effort** medium. **Review
  artifact** one draft PR. If 00 passes, its inventory supplies the operations and D-1 changes.

## Capability

A stored record whose **identity field** takes a request value is an authorization record: the caller may be
choosing whose record it is. Today a create is not an operation in JavaScript, and a named-field insert is
only an injection record.

## Required reading

`langjs/authorization.go`, `authorization_reads.go` (association evidence), `mass_assignment.go`,
`sql_libraries.go` (Prisma client); [authorization](../../../docs/scan/analysis/authorization.md); [mass
assignment](../../../docs/scan/analysis/mass-assignment.md); CWE-639; specs 01 and 02.

## Semantics

**Operation.** Sequelize `create`, `bulkCreate`, `build` followed by `save`; Mongoose `create`, `new`
followed by `save`; a verified collection's insert; a verified Prisma client's `create` and `createMany`.
Only bindings spec 01 or an existing rule verifies.

**Identity field**, one of, with its evidence: a foreign key of a declared association to a model with a
credential attribute (one step, or two through an owned model); a schema reference to it; a field that
**another entry** uses to scope a selector by a caller value. A name sets nothing; a name hint may be sent
labelled as a hint.

**Value.** `request` with its source, `caller`, `constant`, `server`, or `unknown`. The record is made when
it is `request`, or `unknown` in an entry that reads the request. A whole-bag write stays a mass-assignment
record and is not repeated. Checks come from spec 02.

## Scope

New `langjs/create_ownership.go`; `authorization.go` wiring; tests and fixtures; authorization questions and
contract text; `judge/authorization.go` for the operation `create` on the Node protocol. Out of scope: raw
SQL `INSERT`, in-memory collections, PHP, updates of an identity field.

## Decisions

- **D-1. Extend authorization.** *Why:* it is the caller's right to the record. *Rejected:* a
  mass-assignment shape; keys are fixed.
- **D-2. Peer evidence for identity.** *Why:* schemaless stores declare nothing, and another entry's scoping
  shows what the application treats as an owner. Limit: eight peers, as `peer_access`.
- **D-3. A delegated create is the model's question.** Entry access, checks and peers are sent. *Why:* an
  administrator acting for a user is correct code.

## Fixtures

Positive: each operation; each identity basis; value through a constant, a destructured body, a member
assignment before `save`. Negative: caller value; constant; an entry with no request input; a foreign key to
a catalogue model; a field never used as scope and with no association; a body value checked against the
caller (stopping check recorded); a whole-bag write.

## Held-out

One application with user-owned records on a store the fixtures do not use, and one ordinary application
with delegated creation.

## False-positive controls and G7 bound

Delegated creation, system imports and public submissions are keyed controls. At most one added record per 5
creating entries in a sample that is not read and explained.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix facts | `go test ./scan/internal/langjs -run TestCreateOwnership` |
| AC2 | No record without an identity basis; no record from a name alone | `TestCreateOwnershipBasis` |
| AC3 | Policy for `create` with and without checks | `go test ./scan/internal/judge -run TestCreateOwnershipPolicy` |
| AC4 | G1 to G7 | Comparison |
| AC5 | Paid checkpoints pass | Results |
| AC6 | Pages: missing authorization, mass assignment; guides; `application-security-analyzers.md` | `doc-check` |

## Paid checkpoints

1. Fixtures and added sample records. Cap 60. 2. Held-out. Cap 60. Pass: no keyed control Confirmed;
   contract §7 holds; at least 60% of keyed positives Confirmed.

## Stop rule

Stop when under half of held-out keyed positives get a record (the identity bases are too narrow), or
contract §7 fails, or a delegated-creation control is Confirmed at either checkpoint. Do not widen the name
hints.

## Juice Shop check

`JS-X-MASS-07` should have a record through peer evidence. `JS-X-AUTHZ-09` may stay undiscovered: its value
passes a streaming parser. Reported.

## First failing test and order

`TestCreateOwnership/association_field_from_body`. Then operations, bases, facts, policy, checkpoints.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
