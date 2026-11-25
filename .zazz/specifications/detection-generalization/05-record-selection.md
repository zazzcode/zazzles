# Detection generalization 05 — record selection through several steps

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing. **Effort** medium. **Review
  artifact** one draft PR.

## Capability

A protected write or read is recorded when the request selects its record through more than one step: a
value found by one lookup selects the next. Today the origin helper follows one constant. Two lookups hide a
write.

## Required reading

`langjs/enumeration.go` (`requestValue`, `localConst`), `authorization.go`, `authorization_reads.go`,
`flow.go`; [conditional flow](../../../docs/scan/analysis/README.md#javascript-conditional-flow); probe
cases p5 and p5b in [research §3.2](../../evaluation/detection-generalization-research.md#32-probe).

## Semantics

Selection origin is a chain inside one handler: request value → local binding → selector of a recognized
finder → member of its result → selector of the next. Each link is evidence. Four links. A keyed server
store or a caller value ends the chain as `caller`. A reassigned, conditional or unresolved link gives
`unknown` and no record, as today. Branch arms follow the conditional-flow rules. A chain through a record
the **caller** owns is not request-selected.

## Scope

New `langjs/selection_origin.go`; its use in `authorization.go` and `authorization_reads.go`; tests and
fixtures. Out of scope: enumeration and mass assignment, helper calls, other families, replacing
`requestValue` for its other users.

## Decisions

- **D-1. Selection only.** *Why:* it is the smallest place the limit hides records. *Rejected:* moving four
  families to the shared flow at once; identifiers and requests would move together.
- **D-2. Chain recorded, not summarized.** *Why:* the model sees which lookup decided.
- **D-3. One-step chains keep today's record bytes.** *Why:* G1 and G2.

## Fixtures

Positive: two and three lookups; destructured body; alias; a `where` inside an included relation. Negative:
first lookup by caller value; reassigned variable; a constant link; link inside a sibling arm; five links; a
finder on an unrecognized value.

## Held-out

One vulnerable application and one ordinary application, keyed by every write reached through two or more
lookups.

## False-positive controls and G7 bound

Keyed: writes whose intermediate record is the caller's. At most one added record per 10 entries per sample,
all read.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestSelectionOrigin` |
| AC2 | One-step records byte-identical | G1, G2 comparison |
| AC3 | Held-out: at least 70% of keyed multi-step writes recorded; none selected by the caller recorded | Results |
| AC4 | Paid checkpoint passes; G3 to G7 | Results |
| AC5 | Pages: missing authorization; its guide; `application-security-analyzers.md` | `doc-check` |

## Paid checkpoints

Fixtures, added sample records and held-out. Cap 70. Pass: no keyed control Confirmed; contract §7 holds.

## Stop rule

Stop when fewer than three held-out or sample handlers outside Juice Shop contain a multi-step selection
(the shape is then not general), when AC3 fails, or when a caller-selected record is recorded.

## Juice Shop check

The write behind `JS-X-RESET-01` should have a record. Its weakness is spec 10's claim.

## First failing test and order

`TestSelectionOrigin/two_lookups`. Then chain, wiring, comparison, held-out.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
