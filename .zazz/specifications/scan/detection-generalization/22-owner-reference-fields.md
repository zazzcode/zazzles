# Detection generalization 22 — owner references and server-assigned keys in mass assignment

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and are not
  repeated. **Approved by the owner, 2026-11-27** ("Approve spec 22"). Decisions D-4 to D-6 are taken as proposed.
- **Branch** `docs-cleanup`, by the owner's word of 2026-11-27 ("you are now authorized to change code in this
  worktree-branch"). This departs from the lane worktrees of the [delivery plan](delivery-plan.md#1-worktrees).
- **Asked for by the owner**, 2026-11-27: plan the scanner evidence fix for the Juice Shop rows that the two judges
  answer differently.
- **Evidence** [Gemini sample runs, model or scanner](../../../evaluation/gemini-sample-runs-20261127.md#juice-shop-model-or-scanner):
  with byte-identical requests, `gpt-6-luna` Confirmed `JS-MASS-02` to `05` at 0.07 to 0.64 and Gemini answered
  `no_sensitive_field` at 0.52 to 0.74. The question is open on the evidence sent; this specification adds the source
  facts that close it.
- **Order** independent of 01 and 02; see [D-4](#decisions) for 06. **Effort** small to medium. **Review artifact**
  one draft PR to `stage`. **Drafted** 2026-11-27 from `85f39fd` (scanner code as `stage` `81d4731`).

## Capability

A whole-body write to a stored model already records the request-chosen keys and a census of the target's fields
([mass assignment](../../../../docs/scan/analysis/mass-assignment.md#security-field-census)). In JavaScript the census
knows only `credential` and `name_hint`. This specification adds two source facts to that record:

1. **Owner reference.** A field of the target that is the foreign key of a declared association to an account
   model (a model with a `credential` attribute) carries the role `owner_reference`, with the association as
   evidence. Choosing it chooses whose record is written.
2. **Overwritten keys on every whole-body write.** A generated finale-rest write already leaves out an attribute that
   a middleware registered for the endpoint assigns before the write (`overwrittenFields`, `chain_overwrite`
   evidence and a note). A handwritten `Model.create(req.body)` or `new Model(req.body)` does not. This specification
   applies the same rule to the stages before a handwritten handler and to assignments in the handler before the
   write.

## Why both parts, and why together

Measured on the development samples (counts only, `grep` over source, 2026-11-27): Juice Shop is the only one with a
Sequelize `belongsTo`, a body-key assignment in a stage and a whole-body ORM write. Its account model has eleven owned
models. On three routes (`POST /api/Addresss`, `PUT /api/Addresss/:id`, `POST /api/Cards`) a stage assigns
`req.body.UserId` from the verified token before the generated write, and the existing rule already leaves `UserId`
out of those records. On the four keyed routes (`JS-MASS-02` to `05`) and on `POST /api/SecurityAnswers` no stage does,
and `UserId` is sent with only a `name_hint`. Part 1 closes that. Part 2 keeps part 1 from turning a handwritten
create with the same guard into a finding, which contract [§1.8 precision before reach](contract.md#1-shared-invariants)
requires in the same change; no development sample has that form, so fixtures carry it.

**Not a design input under the held-out protocol.** The rows above are Juice Shop rows, which
[§3](contract.md#3-held-out-protocol) reserves for a last acceptance check. This specification was motivated by them,
so Juice Shop is not evidence that it generalizes. Since the owner's decision of 2026-11-27 that no held-out run is
required ([contract §3](contract.md#3-held-out-protocol)), the fixtures, the gates, the reserved control's counts and the
Juice Shop acceptance runs decide it, and the results say that accuracy elsewhere is not measured.

## Required reading

`langjs/mass_assignment.go` (`securityFields`), `langjs/authorization_reads.go` (the owned-model search and its
`owner_association` evidence), `langjs/resources.go` (generated endpoints and the chain they carry),
`langjs/http_dispatch_context.go` (`httpPredecessors`), `analysis/mass_assignment.go` (roles),
`analysispacks/mass_assignment.go` (questions), the mass-assignment branch of `judge/client.go`;
[application-security analyzers](../../../architecture/application-security-analyzers.md);
[mass assignment rules](../../../../docs/scan/analysis/mass-assignment.md); specification [06](06-create-ownership.md)
(its identity field); Sequelize [associations](https://sequelize.org/docs/v6/core-concepts/assocs/) (default and
`foreignKey` names); Mongoose [populate](https://mongoosejs.com/docs/populate.html) (`ref` paths).

## Semantics

**S-1. Owner reference.** For each attribute of the census target:

| Basis | Foreign key name | Evidence |
|---|---|---|
| `Target.belongsTo(Account, opts)`, Sequelize, `Account` holds a credential attribute | `opts.foreignKey` when it is a string literal or `{ name: '<literal>' }`; with no `foreignKey`, the documented default, the camel-cased target name plus `Id` (`Ship.belongsTo(Captain)` gives `captainId`); `as` replaces the target name | The `belongsTo` call |
| A Mongoose schema path with `ref: '<Account model>'` | The path itself | The schema path |

The account model is the one the existing owned-model search already accepts (it holds a `credential` attribute).
One association step only. An association whose options are not literal records `owner_reference_unresolved` on the
target and no role. A field name sets nothing; a `name_hint` stays a separate role on the same field.

**S-2. Overwritten keys on handwritten writes.** For a whole-body write recorded by `massCall` or `massNew`, the
attributes that `overwrittenFields` finds assigned on the entry's earlier matching stages (`httpPredecessors`) are left
out of the written attributes with their `chain_overwrite` evidence and the existing note, exactly as for a generated
endpoint. An assignment `req.body.<name> = …` in the handler body before the write call, on its straight-line path,
counts the same way. A conditional assignment, an alias of `req.body` or a computed key is not followed and leaves the
attribute in. The scanner records the assignment; it does not decide where its value comes from, as today.

**S-3. The record.** `mass_assignment.security_fields` gains the role `owner_reference` with the association as its
evidence item. An unresolved association records `owner_reference_unresolved`. No new record field.

**S-4. The request.** Only a record with an `owner_reference` role uses question version
`mass-assignment-components-v2`. Its `field_impact` text adds: "an owner_reference field is the foreign key of a
declared association to the account model, from the association contract; a request that chooses it chooses whose
record is written." The policy accepts v1 and v2 alike. Every other mass-assignment request stays byte-identical
([invariant 7](contract.md#1-shared-invariants)).

## Invariants

1. The census role comes from the association contract, never from a name.
2. No scanner rule decides a verdict or drops a record ([invariant 2](contract.md#1-shared-invariants)). Part 2
   reuses the existing overwrite rule unchanged.
3. A mass-assignment record with no `owner_reference` role and no newly overwritten attribute keeps its request byte
   for byte (G2).
4. PHP, Python and other families are unchanged.

## Scope

| Path | Change |
|---|---|
| `scan/internal/langjs/owner_reference.go` (new) | S-1, built on the owned-model search, which it shares with specification 06 |
| `scan/internal/langjs/mass_assignment.go` | The role in `securityFields`; S-2 in `massCall` and `massNew` |
| `scan/internal/analysis/mass_assignment.go` | `RoleOwnerReference` and the gap kind (additive) |
| `scan/internal/analysispacks/mass_assignment.go`, `judge/` (`validation.go`, `injection.go`, `mass_assignment.go`) | v2 question text, selected per record (S-4); the policy accepts both versions |
| Tests and `langjs/testdata/mass-assignment/owner/` | The fixtures below |
| Documents | [Mass assignment rules](../../../../docs/scan/analysis/mass-assignment.md), the [capability page](../../../../docs/scan/detection-capabilities/mass-assignment.md), [application-security analyzers](../../../architecture/application-security-analyzers.md), the implementation plan, the series index, the results file |

Out of scope: PHP and Doctrine `ManyToOne` (a later specification, with its own fixtures); two-step
ownership through an owned model (06 owns it); named-field creates (06); stages in another framework.

## Decisions

- **D-1. A census role, not a new claim.** *Why:* the claim is already the mass-assignment claim; what the model lacks
  is which field matters. *Rejected:* an authorization record per whole-body create, which 06 rules out for whole-bag
  writes.
- **D-2. Both parts in one change.** *Why:* §1.8; a handwritten create guarded the way the generated ones are would
  otherwise become a finding with the role. *Rejected:* the role first, the handwritten overwrite later.
- **D-3. Reuse the existing overwrite rule.** *Why:* it is the rule generated endpoints already use, tested, and the
  report stays one shape. *Rejected:* a new `server_assigned_keys` list that shows the assignment and leaves the
  attribute in; it changes every guarded generated record's request and moves a decision the scanner already makes.
- **D-4. Shared with 06.** *Proposed:* S-1 is written as the identity-field component 06 needs (its first basis), so
  06 reuses it instead of a second search. 06 keeps its peer-evidence basis.
- **D-5. The question change is per record.** *Proposed:* v2 for records carrying either fact, as invariant 7
  requires. *Rejected:* rewording `field_impact` for the family; it would move every mass-assignment answer in three
  languages.
- **D-6. The standing judge.** *Proposed:* paid checkpoints on both judges, since the gap being closed is a
  disagreement between them. Each run needs the owner's word.

## Fixtures

Written from the Sequelize and Mongoose documentation, not from Juice Shop:

| Kind | Forms |
|---|---|
| Positive | `belongsTo` with the default key; `foreignKey: 'ownerId'`; `foreignKey: { name: 'accountId' }`; a Mongoose `ref`; each written by a generated create and by a handler's `Model.create(req.body)` |
| Negative | The same owned models written by a handwritten create after a stage that assigns the key; the assignment inside the handler before the write; an association to a catalogue model with no credential; a non-literal `foreignKey` (gap, no role); a field named `userId` with no association (name hint only) |
| Kept as is | A conditional assignment before the write: the attribute stays in and carries the role |

## Held-out

Not required (owner, 2026-11-27; [contract §3](contract.md#3-held-out-protocol)). The reserved control
`oss-oopssec-store` is checked by counts only: it has no mass-assignment record, so it can show no harm and nothing more.

## G7 bound

On the nine samples, only mass-assignment records whose target has an association to an account model change. Juice
Shop: at most the eleven owned targets; every other sample unchanged.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | S-1 on every positive and negative fixture | `go test ./scan/internal/langjs -run TestOwnerReference` |
| AC2 | S-2 on every stage and handler fixture | `go test ./scan/internal/langjs -run TestMassOverwrittenHandwritten` |
| AC3 | v2 selected only for records with the role; every other record of the nine samples equal to base | `go test ./scan/internal/judge -run TestMassAssignmentProtocol`; offline record comparison (G2) |
| AC4 | G1 to G7 | Comparison |
| AC5 | Paid, fixtures: every positive Confirmed and no negative Confirmed, on both judges | Results |
| AC6 | Reserved control `oss-oopssec-store`, counts only: no record missing, added or changed. (Replaces the held-out run, owner 2026-11-27) | Counts script |
| AC7 | Juice Shop acceptance check, read last: `JS-MASS-02` to `05` Confirmed and `POST /api/Addresss`, `PUT /api/Addresss/:id` and `POST /api/Cards` not findings, on both judges. With no held-out run, this is the only real-application check; reported, labelled a development sample | Results |
| AC8 | Pages updated | `doc-check` |

## Paid checkpoints

1. Fixtures, only records whose request changed: about 24 requests per judge, cap 60.
2. Juice Shop full scans for AC7, one per judge (about 84 requests each), at the end.

## Stop rule

Stop when a negative fixture with an overwritten key is Confirmed on either judge, or
contract §7 fails. Do not add a list of token
expressions or widen the name hints.

## First failing test and order

`TestOwnerReference/belongs_to_default_key`. Then the `foreignKey` forms, Mongoose `ref`, the handwritten overwrite,
v2 selection, the offline comparison, the paid checkpoints.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents). The implementation needs its own feature
worktree under the container, created on the owner's word; `docs-cleanup` takes no code.

## Implementation and review change log

**Status (2026-11-27):** implemented on `docs-cleanup`; offline gates G1 to G7 pass ([results](../../../evaluation/detection-generalization-results/22.md)). AC5: Gemini passes; `gpt-6-luna` Confirms every v2 record and no overwritten one, but also one name-hint-only v1 control that this change does not touch. AC6 met (reserved control unchanged). AC7 met on both judges: `JS-MASS-02` to `05` Confirmed, the guarded routes not findings, no other record moved. Ready for review.

### 2026-11-27 — Approved

Approved as drafted. The held-out application is still to be chosen by the key agent; AC6 waits for it.
Built on `docs-cleanup` instead of a lane worktree, by the owner's word the same day.

### 2026-11-27 — Held-out run removed

The owner removed held-out application runs from the series ("remove the need for held out app runs... we only have
what we have"). AC6 is now the reserved control's counts, met: `oss-oopssec-store` has 128 records and no
mass-assignment record before and after, none missing, added or changed. The stop rule loses its held-out clause.

### 2026-11-27 — Corrected before code

Reading `resources.go` showed that generated finale-rest writes already leave out attributes a registered middleware
overwrites (`overwrittenFields`). Juice Shop's three guarded routes are already clear, so the planned
`server_assigned_keys` fact was not needed. Part 2 is now that existing rule applied to handwritten writes (D-3), and
S-4 selects v2 on the role alone. The Sequelize default key follows the documentation (camel case). Goals, criteria and
the stop rule are unchanged in substance.
