# Detection generalization 00 — operation inventory experiment

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing. **Effort** small, offline. **Review
  artifact** one draft PR with the results only. The prototype is not merged.

## Capability

Answers one question: can a JavaScript and TypeScript scan list an entry's operations **by effect**, from
language and verified-import facts, with little enough noise that a table from effect to question could
replace per-family producers? It produces numbers and a decision, not a product change.

## Required reading

[Strategy](../../evaluation/detection-generalization-strategy.md) H1, H4 and options D, E; PHP state changes
in [entry access](../../architecture/entry-access-and-authorization.md#operations); [abandoned
graph](../../architecture/repository-graph.md#graph-data-model-attempted-and-abandoned), reason 2.

## Semantics

An operation is a call or assignment reached from an HTTP entry with one effect:

| Effect | Established by |
|---|---|
| `store_create`, `store_read`, `store_update`, `store_delete` | A method of a value bound to a verified storage client or model (existing bindings only) |
| `store_unknown` | An awaited call on a value bound to a third-party package, no contract |
| `respond` | A body-sending method of the verified response parameter, or the handler's returned response object |
| `set_cookie`, `set_header` | The documented methods of the same response |
| `file_write`, `file_read`, `outbound`, `execute` | Existing verified bindings |
| `local` | A call to a scanned function; followed one step |

No effect is inferred from a name. A call whose receiver does not resolve is counted as `unresolved`.

## Scope

| Path | Change |
|---|---|
| A test-only overlay in the scratch area, saved with the results | New, not merged |
| `.zazz/evaluation/detection-generalization-results/00.md` | New |

Out of scope: any product code, any request, any change of a producer.

## Decisions

- **D-1. Overlay, not a package.** *Why:* the question is whether to build it; merged scaffolding would
  decide by inertia.
- **D-2. Hand-labelled truth.** Two agents each list the operations of 40 handlers, drawn by a fixed seed
  over the five Node development samples, before the prototype runs. *Why:* counting what the prototype
  finds against itself proves nothing.
- **D-3. Effects only, no questions.** *Why:* a question table is easy to fit to samples; its noise is
  bounded by the count of operations first.

## Fixtures

Positive: each effect once, through `import`, `require`, alias, one local step. Negative: a shadowed import;
a same-named method on a plain object; a response method on a non-response value; a storage method on a
request value.

## Held-out

The reserved control (oss-oopssec-store: Next.js and Prisma) or an unseen pool application that is **not**
Express with an ORM. 20 handlers labelled by the key agent.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Labels committed to the results before the prototype's first run | Results history |
| AC2 | Per effect: labelled, found, wrong, `unresolved`, for samples and held-out | Results table |
| AC3 | Operations per entry: median and 90th percentile; the share already covered by a record | Same |
| AC4 | Extra scan time | Same |
| AC5 | A decision against the rule below, and which lists it would replace | Owner review |
| AC6 | No file outside the results changed | `git diff --stat` |

## False-positive controls

Wrong effects count as false. An `unresolved` call is not a success. The median count per entry bounds the
records an obligation table could create.

## Paid checkpoints

None.

## Stop rule

Do not build the inventory, and keep the producers of 06 to 10, when **any** holds: recall on labelled
storage, respond and cookie operations under 80% on samples or under 65% on the held-out application; more
than 5% of found operations carry a wrong effect; over half of store operations are `store_unknown` (then
03's mechanism comes first); median over 6 operations per entry after removing covered ones; scan time over
10% more.

If it passes, the owner decides whether a new specification replaces producers in 06, 07, 08 and 10.

## Juice Shop check

For the eight undiscovered rows, whether the operation is in the inventory. Reported, not a criterion.

## First step

The labels of AC1. Then the prototype, the tables, the decision.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
