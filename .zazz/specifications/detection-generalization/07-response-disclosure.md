# Detection generalization 07 — response disclosure

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** 01. **Effort** medium. **Review artifact**
  one draft PR. If 00 passes, its `respond` effect replaces D-1's producer.

## Capability

A response that carries a credential field of a stored record, or whose property names the request chooses
on a stored record, is a disclosure record. Today Node disclosure covers process state, metrics and stack
traces; PHP already records census fields in a response.

## Required reading

`langjs/exposure.go`, `mass_assignment.go` (`securityFields`), `account.go` (credential attributes),
`xss_response.go`, `keyed_store_lookup.go`; [authorization](../../../docs/scan/analysis/authorization.md)
`data_exposure`; [information exposure](../../../docs/scan/analysis/information-exposure.md); CWE-200,
CWE-201.

## Semantics

**Emitted value.** The argument of a body-sending method of the verified response, or a returned response
object, traced inside the handler to a record read through a verified model, or a keyed store whose writer
stores one.

**Two shapes.** `credential_in_response`: the record is sent whole, or a credential field is among the sent
members, and no recorded projection removes it. `request_projection`: a computed member of the record, with
a key whose origin is the request, reaches the response.

**Removal facts:** a literal projection, a destructured omission, a serializer method on the model that
drops the field, an attributes option on the read, a literal key allow-list. They are evidence. A credential
is the census role (a digest stored by a set accessor), not a name.

## Scope

New `langjs/response_disclosure.go`; authorization `data_exposure` facts on the Node protocol; tests and
fixtures; `judge/authorization.go`. Out of scope: logs, templates, GraphQL, email or phone as personal data,
process state.

## Decisions

- **D-1. Extend `data_exposure`.** *Why:* PHP's facet already asks it. *Rejected:* a new exposure kind.
- **D-2. The caller's own record is a separate subject.** `session_user` is recorded, and the question asks
  whether the field is one a client needs. *Why:* a caller's own hash is still a disclosure, with another
  severity.
- **D-3. Serializer source is sent.** *Why:* projection is often in the model.

## Fixtures

Positive: whole record; list; nested in an object; member copied in a loop by a request key; keyed-store
record. Negative: literal projection; omission by rest; model serializer; attributes option; allow-listed
keys; a record with no credential field; a request key on a constant object.

## Held-out

One application that returns accounts and one ordinary one with a serializer convention.

## False-positive controls and G7 bound

Each keyed serializer and projection. At most one added record per 10 responding entries per sample, all
read.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestResponseDisclosure` |
| AC2 | No record without a census credential or a request key | `TestResponseDisclosureBasis` |
| AC3 | G1 to G7 | Comparison |
| AC4 | Paid checkpoint passes | Results |
| AC5 | Pages: information exposure, missing authorization; guides; `application-security-analyzers.md` | `doc-check` |

## Paid checkpoints

Fixtures, added sample records and held-out. Cap 80. Pass: no keyed projection Confirmed; contract §7 holds;
at least 60% of keyed positives Confirmed or in Review with the blocking fact.

## Stop rule

Stop when fewer than half of held-out credentials reach the census (the role is too narrow), a serializer
control is Confirmed, or contract §7 fails. Do not add field names.

## Juice Shop check

`JS-X-EXPO-03` may have a record; linking its keyed store to the account model is the hard part. Reported.

## First failing test and order

`TestResponseDisclosure/whole_account`. Then emission trace, removal facts, request projection, held-out.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
