# Detection generalization 01 — storage identity across module forms

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing to build; its paid checkpoint and
  merge wait for 02 and 04. *Why:* it adds authorization records on new projects, and without check evidence
  a guarded handler there could be Confirmed. **Effort** small to medium. **Review artifact** one draft PR.

## Capability

A Sequelize or Mongoose model, or a collection the scanner already verifies, keeps its identity when it is
defined and imported in any ordinary JavaScript module form. Authorization, mass assignment, account and
stored-value analysis read that identity, so they record on projects where today they record nothing. No
library is added and no list of operations grows.

## Required reading

[Strategy §2](../../evaluation/detection-generalization-strategy.md#2-evidence); `langjs/xss_storage.go`
(`modelIdentity`), `framework_models.go` (`exportedName`), `commonjs.go`, `modules.go`, `mass_assignment.go`
(`modelAttributes`); [source index](../architecture-phase-1-source-index.md); [mass
assignment](../../../docs/scan/analysis/mass-assignment.md#javascript-and-typescript),
[authorization](../../../docs/scan/analysis/authorization.md#javascript-and-typescript).

## Semantics

Identity follows a **binding**, never a name. These forms are equal when every step is resolved:

| Step | Forms |
|---|---|
| Definition | class with `init`; `sequelize.define`; `mongoose.model(name, schema)`; destructured `model`; `new Schema` inline or by constant |
| Definition function | A scanned function that defines and returns a model, called once with a verified client |
| Export | named, `export default`, re-export, `module.exports = x`, `module.exports = { x }`, `exports.x =` |
| Import | named, default, namespace member, `require`, destructured `require`, a member of an object that a module exports |
| Registry | `mongoose.model(name)` with one argument resolves to the one definition of that literal name in the scanned project; with none or several it stays unresolved |

A reassigned, shadowed, dynamic or conditional binding is unresolved, as today. The Sequelize and Mongoose
documentation for each definition form is cited in code.

## Scope

`scan/internal/langjs/`: `xss_storage.go`, `framework_models.go`, `mass_assignment.go`, a new
`storage_identity.go`, tests, `testdata/storage-identity/`. Out of scope: new libraries, the `Collection`
name rule of `queryKind` (OQ-1), changes to any question, policy or request schema.

## Decisions

- **D-1. One resolver, shared.** The four consumers call it. *Why:* each reads a subset today, and the fix
  must not be repeated. *Rejected:* a form per family.
- **D-2. Attributes come with identity.** The attribute list and its evidence resolve through the same
  steps. *Why:* a record without attributes is undecidable for mass assignment.
- **D-3. Identity key is module and binding, unchanged for resolved forms.** *Why:* gate G1.

## Fixtures

Positive: the 12-form matrix (one route pair per form), each in JavaScript and TypeScript where legal, names
used by no sample. Negative, one per step: shadowed import; reassigned export; two definitions of one
registry name; a class named like a model with no library base; a plain object with `create`; a definition
function called with two clients; a dynamic `require`; a test-file definition.

## Held-out

One CommonJS Sequelize application and one CommonJS Mongoose application from the pool, keyed for state
changes selected by the request, whole-bag writes and correct controls.

## False-positive controls and G7 bound

Every added record on the nine development samples is read. No more than 2 added records per 10 entries in
any sample, or a stated reason for each above it. On ordinary applications, no added record whose operation
is not a real storage call on the stated model.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | All 12 forms record the same kinds as the single-file form | `go test ./scan/internal/langjs -run TestStorageIdentityForms` |
| AC2 | No negative records | `TestStorageIdentityRejects` |
| AC3 | Base records and requests unchanged; additions listed (G1, G2) | Offline comparison |
| AC4 | Held-out: at least 70% of keyed storage operations have a record; every added record's operation and model are right on review | Results |
| AC5 | Paid checkpoint passes | Results |
| AC6 | Pages: missing authorization, mass assignment, cross-site scripting; their guides; `application-security-analyzers.md` | `doc-check` |
| AC7 | G3 to G7 | Commands |

## Paid checkpoints

After AC1 to AC4: the added records of nodejs-goof and the two held-out applications, families
authorization, mass assignment and account, one arm (base has none). Cap 80. Pass: no keyed control
Confirmed; contract §7 holds.

## Stop rule

Stop when fewer than 10 of 12 forms resolve without an application-specific exception; or held-out AC4 is
under 70%; or contract §7 fails; or scan time breaks G5.

## Juice Shop check

No row of the 13 is expected to change. No keyed finding may change.

## Open question

**OQ-1.** `queryKind` starts a NoSQL record from `Collection` in a receiver name. That is a name rule.
Replace it here by identity for verified collections (may drop records), or leave it?

## First failing test and order

`TestStorageIdentityForms/commonjs_named_export`. Then the resolver, consumers one at a time with G1 and G2
after each, fixtures, samples, held-out, checkpoint, documents.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
