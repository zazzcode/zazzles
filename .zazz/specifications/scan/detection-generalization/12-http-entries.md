# Detection generalization 12 — operation families on every HTTP entry

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** 02 and 04. **Effort** medium to large.
  **Review artifact** one draft PR.

## Capability

Authorization, mass assignment and account enumeration read an HTTP entry of any framework the scanner
already recognizes. Today the producers accept Express only: the same model update and whole-body create
that record on Express record nothing in a Next.js route handler or a Fastify route, although both entries
are found.

## Required reading

[Strategy §7](../../../evaluation/detection-generalization-strategy.md#7-second-pass);
`langjs/authorization.go`, `authorization_reads.go`, `mass_assignment.go`, `enumeration.go`, `node_http.go`,
`node_input_facts.go`, `next_handlers.go`, `next_stages.go`; [Node
inputs](../../../../docs/scan/analysis/node-inputs.md), [Next.js](../../../../docs/scan/analysis/nextjs.md).

## Semantics

A producer asks the entry, not a framework: which values are request values and which part of the request;
which call or return sends the response; which callable runs; which stages run before it. The existing input
facts and entry contexts answer these. A request value is an acquisition the input facts verify, never a
parameter called `req`. A framework whose context lacks an answer gives a gap and no record. Access before
the handler is stage evidence, judged as in spec 04; it is `unresolved` unless a listed contract establishes
it.

## Scope

The producers above, a new `langjs/entry_context.go`, tests and `testdata/http-entries/`. Out of scope: new
framework adapters, server actions and component rendering, GraphQL and gRPC, new storage (01, 13),
questions and policy.

## Decisions

- **D-1. One entry view for all producers.** *Why:* four files each test for Express. *Rejected:* a branch
  per framework in each.
- **D-2. Express records keep their bytes.** *Why:* gates G1 and G2; this widens and does not redesign.
- **D-3. After 02 and 04.** *Why:* new entries with no check evidence would report guarded handlers.

## Fixtures

The same routes on Express, Next.js App and Pages handlers, Fastify and Hapi: request-selected update and
delete, whole-body create, named create, lookup with two responses; each guarded and unguarded; a wrapper
that checks and stops, and one that does not. Negative: a page component; a static route; a non-request
parameter called `req`; a local helper called `params`.

## Held-out

One pool application not on Express, and oss-oopssec-store as held-out positives and controls for these
families.

## False-positive controls and G7 bound

Every keyed wrapper and in-handler check. Read every added record on the development samples; at most 2 per
10 entries.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Equal routes give equal facts on every fixture framework | `go test ./scan/internal/langjs -run TestHTTPEntryProducers` |
| AC2 | Negatives record nothing | `TestHTTPEntryRejects` |
| AC3 | Express records, requests and identifiers unchanged; G1 to G7 | Comparison |
| AC4 | Held-out: 70% of keyed operations on supported storage recorded; no record on a wrong subject | Results |
| AC5 | Paid checkpoint and contract §7 | Results |
| AC6 | Pages: missing authorization, mass assignment, account enumeration; guides; `entry-access-and-authorization.md`; Next.js support | `doc-check` |

## Paid checkpoints

Fixtures and held-out, planned repeats two. Cap 120. Pass: contract §7; no keyed control Confirmed; at least
60% of keyed positives Confirmed.

## Stop rule

Stop when a framework needs an exception in a producer (the entry view is wrong), AC4 is under 70%, or a
guarded handler is Confirmed.

## Juice Shop check

No change.

## First failing test and order

`TestHTTPEntryProducers/nextjs_update`. Then the view, Express parity, one framework at a time.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
