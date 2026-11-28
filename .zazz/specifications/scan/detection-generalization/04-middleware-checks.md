# Detection generalization 04 — local middleware as evidence

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** 02. **Effort** small. **Review artifact** one
  draft PR.

## Capability

An application's own middleware on the chain is sent as source with its checks as facts, in place of its
name. The model can judge whether it restricts the caller. Today a middleware that stops and one that does
not give the same record, with access `unresolved` and no body.

## Required reading

Spec 02; `langjs/express_access.go` (`respondsOrContinues`, `chainItems`), `resources.go`; [entry
access](../../../architecture/entry-access-and-authorization.md); [research
§3.2](../../../evaluation/detection-generalization-research.md#32-probe).

## Semantics

The operation of a middleware is each call of its `next` parameter without an argument. Spec 02's record
applies with that operation, and a check counts for the chain only when it holds at **every** such call.
`next(error)` is an answering arm: it does not end the function. Order and mount rules are today's. A chain
item is `unresolved` when its body is not in the scan. Express: middleware must end the cycle or call `next`
([guide](https://expressjs.com/en/guide/writing-middleware.html)).

## Scope

`langjs/express_access.go`, `check_evidence.go`, `resources.go`, tests and fixtures; authorization material
in `analysispacks`; `judge/authorization.go`, `client.go`, `bundle.go`. Out of scope: new authentication
contracts, other frameworks, multi-step helpers beyond spec 02's one step, other families' use of the fact.

## Decisions

- **D-1. Authentication stays `unresolved`.** *Why:* the scanner does not know that a check authenticates.
  The model cites the check.
- **D-2. `access_adequacy: adequate` on `unresolved` access needs a cited stopping check.** *Why:* today the
  model can answer it from a name.
- **D-3. Bodies: three middleware, 60 lines each**, with a gap past the limit. *Why:* request size; the
  first three restricting items are nearest the entry.
- **D-4. Generated endpoints** take earlier registrations for the same method and path as their chain.
  *Why:* they have no handler to read.

## Fixtures

Stops; does not stop; two `next()` with one unguarded; array; factory returning one; imported;
constant-bound; `next(err)` with and without return; mounted on a covering, a pattern and a non-covering
path. Negative: a logging middleware; one that only sets a value; a rate limiter (its package has no body
here, gap); unresolved import.

## Held-out

One application with its own access middleware and one ordinary application, chain by chain.

## False-positive controls and G7 bound

No record added. Keyed correct chains are controls.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | The matrix gives the expected facts | `go test ./scan/internal/langjs -run TestMiddlewareChecks` |
| AC2 | No request names a local middleware without its body or a gap | `TestMiddlewareRequestSource` |
| AC3 | `unresolved` access is never adequate without a cited stopping check | `go test ./scan/internal/judge -run TestMiddlewarePolicy` |
| AC4 | G1 to G7; only authorization requests whose chain has a local middleware change | Comparison |
| AC5 | Held-out facts: 90% right or `unresolved`; no wrong `stops` | Results |
| AC6 | Paid checkpoint passes | Results |
| AC7 | Pages: missing authorization; its guide; `entry-access-and-authorization.md` | `doc-check` |

## Paid checkpoints

Fixtures and held-out, before and after. Cap 100. Pass: no stopping caller check Confirmed; no non-stopping
or non-caller check Protected; contract §7 holds.

## Stop rule

Stop when fewer than 80% of stopping and non-stopping pairs separate, a non-caller check (feature flag,
method test) is accepted as protection, or the held-out facts contain a wrong `stops`.

## Juice Shop check

No keyed finding lost. Records whose access is `unresolved` are listed before and after.

## First failing test and order

`TestMiddlewareChecks/stops_and_falls_through`. Then producer, source, policy, held-out, checkpoint.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
