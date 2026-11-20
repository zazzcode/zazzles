# Request size and evidence relevance

[Architecture](README.md#7-evidence-bundle-contract) · [Trace judgment](trace-judgment.md) · [Evidence and claims](evidence-and-claims.md)

This document owns the design for keeping decision requests small and relevant. It covers how
evidence is selected and represented, and what happens when a request is too large. It records the
measured baseline, each strategy with its invariants and risks, the tiering model, and an evidence
ledger. Update the ledger and the strategy status when a strategy is implemented or measured; the
design text changes only when evidence shows it is wrong.

## Why size matters

Size is a cost, a hard limit and an accuracy problem.

- **Cost.** Input tokens are paid for on every request. A typical request is 15–45 KB.
- **Hard limit.** The scanner refuses to send a request over `requestLimit` (65,536 bytes,
  `internal/judge/budget.go`). This is the scanner's own constant, not a confirmed provider limit.
- **Accuracy.** Irrelevant evidence changes answers. A correctly guarded JavaScript command route was
  answered `vulnerable` at low confidence because repeated, unrelated control-flow gaps reached the
  model; the same guard in Python was answered `protected_for_claim` (recorded in the assessment-coverage
  handoff, Appendix A). Removing noise is an accuracy measure, not only a saving.

Bytes overstate cost. The largest Juice Shop request, `routes/order.ts:164` at 65,235 bytes, was
17,087 input tokens. Part of the byte count is JSON-in-JSON escaping: the evidence document is a
string inside the provider envelope, so every quote and newline in it is escaped.

## Measured baseline

Offline measurement of every request the scanner would build (8 sample applications plus every parser
fixture as its own root; 4,404 candidates; base commit `9b17b17`, before the request budget):

| Measure | Value |
|---|---|
| Requests over 65,536 bytes | 1 (Juice Shop `routes/order.ts:164`, NoSQL) |
| Its size | 119,336 bytes uncompacted, 72,580 after the existing lossless compaction |
| Next largest | VulnPy path 64,964; VulnPy templating XSS 63,064; Juice Shop `updateProductReviews.ts:17` 62,864 |
| Typical p95 per app and family | 13–57 KB; no Python sample over the limit |

Compacted sections of `routes/order.ts:164` (bytes): source excerpts 19,225; compact-wire tables 7,178;
evidence 5,582; model facts 3,753; trace graph 3,615; analysis guidelines 3,256; evidence coverage
2,967; instruction 1,728; invocation 1,673; components 1,666; evidence roles 1,450; input facts 1,286.

Why it is large. The claim is narrow (can request data shape the inserted document?), but context is
gathered for the whole entry, not for the data path:

- the whole 155-line checkout handler, including many unrelated Sequelize calls;
- helper bodies that never touch the inserted document (`lib/insecurity.ts`, `lib/utils.ts`,
  `routes/verify.ts`, `lib/antiCheat.ts`, `lib/challengeUtils.ts`, `routes/metrics.ts`);
- four Sequelize model classes, irrelevant to a MarsDB insert;
- about 30 global middleware registrations and bodies, most of which cannot change `req.body`;
- repeated gaps from the JavaScript `if` walk (the same `unsupported_control_flow` and
  `unknown_control_effect` text at every `if`).

What the request budget shed to fit it (29 items, 7,233 source bytes, listed in the record's
`evidence_omissions`): `middleware_handler` and `helper_definition` bodies in `routes/verify.ts`,
`lib/insecurity.ts`, `lib/antiCheat.ts`, `lib/utils.ts`, `lib/challengeUtils.ts` and `routes/metrics.ts`;
three `server.ts` registrations; and the four Sequelize model and library bindings. This is the same set
a relevance filter would have excluded, which supports strategies S2 and S3 below (selection strategies are labeled S; wire representation strategies W).

## Principles

1. **Lossless and noise-removing strategies are always on.** They lose nothing the model needs and save
   on every call.
2. **Lossy strategies are adaptive.** They run only above a size tier, and every omission is visible in
   the request (a gap the model can weigh), in the record (`assessment.evidence_omissions`) and in the
   decision trace.
3. **Never shed what decides the claim.** The sink, required-role evidence, roles a gate reads,
   control-kind evidence, dependency sources and transfers, control-edge endpoints, and facts indexed by
   family facts are never removed. Excerpts are never cut mid-item.
4. **Classify by role, not by name.** No strategy may name a sample application, file or framework to
   decide what to keep. A framework list may only *add* evidence, never decide that something is safe to
   drop, unless the decision is derived from source (see S3).
5. **Deterministic.** The same input gives the same bytes. Ordering uses stable keys, never map
   iteration. The tier and the omissions are recorded so that a replay rebuilds identical bytes.
6. **Original evidence is preserved.** Strategies change only the model-facing text. Saved evidence,
   report spans, hashes and identities keep the original bytes.
7. **One protocol bump per batch.** Changes that move request bytes for existing candidates are
   batched into one versioned bump (`evidence_version`, family protocol versions), because each bump
   invalidates every saved exact replay.

## Tiering model

| Tier | Trigger | Strategies |
|---|---|---|
| Always | every request | W1–W6 wire representation; S3 middleware summary; S4 gaps removed at source |
| Soft | request over the soft threshold: about 90% of `requestLimit` (59–60 KB today; see "Choosing the soft threshold") | S2 relevance filter for helpers and models; S1 data-path slice once proven |
| Hard | request still over `requestLimit` | role-based shedding (implemented); then the `evidence_too_large` floor |

Known costs of tiers: a cliff effect, where two near-identical candidates on either side of a threshold
get differently shaped evidence. The omission gap keeps this visible, and calibration pairs should
include one candidate on each side. Determinism is unaffected.

## Choosing the soft threshold

Requests that each threshold would affect, measured on 3,582 sample-application requests after the
assessment-coverage changes and before E3:

| Soft threshold | Requests affected | Where |
|---|---:|---|
| 50 KB | 113 | 90 VulnPy path; 23 across Juice Shop (path, NoSQL, XSS, SSRF) and nodejs-goof |
| 55 KB | 65 | 51 VulnPy path; 14 others |
| 60 KB | 55 | 51 VulnPy path (near-identical generated routes at about 64 KB); 3 Juice Shop NoSQL; 1 Juice Shop XSS |

**Decision (proposed):** set the soft tier at about 90% of `requestLimit`, expressed as a fraction so it
follows the limit if the unit changes. **Why:** the soft tier exists for the records closest to the hard
limit, which grow over it with small source changes. A lower threshold applies lossy filtering to twice
as many records across three applications, and each one needs calibration evidence that answers are
stable. **Re-measure** after the always-on strategies (W1–W7, S3, S4) land: E3 alone is expected to
bring today's 64 KB requests to about 42–48 KB, after which the soft tier should affect very few records.
Choose the final value from that distribution and record it in the evidence ledger.
**Rejected alternative:** 50 KB. It doubles the affected set before the always-on savings are known.

## Strategies

Each strategy lists where it lives, its invariants, its risks, how to measure it, and its status.
Status values: `implemented`, `planned`, `proposed`, `rejected`.

### Hard tier: role-based shedding and the floor — implemented

- **Where:** `internal/judge/budget.go` (`budgetUse`, `withoutContext`, `omissionGap`), called from
  `budgetedPayload` in `internal/judge/client.go`. The report wording is in `internal/report/findings.go`.
- **Behavior:** it runs only when the compact form is still over the limit. Context evidence is shed in
  this order: items whose text is contained in another supplied item (lossless), then other-file context
  (largest first), then same-file context (furthest from the sink first). Context indices held by
  Command, Path and outbound facts are remapped. An `evidence_omitted_for_size` coverage gap names every
  omitted span. If what remains is still over the limit, nothing is sent; the reason starts with
  `evidence_too_large:` and lists the bytes by section, and the record stays Review.
- **Tests:** `TestRequestBudget*` in `internal/judge/budget_test.go`, including 40 synthetic growth
  shapes across six families in JS and Python.

### Path-group requests over the floor — implemented (XSS)

- **Where:** `planPathGroups`, `packPathGroups`, `groupUse` in `internal/judge/budget.go`;
  `groupAssessment` in `internal/judge/client.go`; `combinePathGroups` in `internal/judge/xss.go`;
  slot costs in `internal/judge/schedule.go`. Contract: [close-findings-gaps](../specifications/close-findings-gaps.md) W4.
- **Behavior:** an XSS record still over the limit after shedding is sent as ordinary requests for
  the same claim, one per path group. A group is the dependencies whose source sits in one file (the
  dispatch alternative), split by storage key only when that file alone is over the limit; whole
  groups are packed into one request while it still fits (first fit, key order). Each request is
  lossless for the paths it carries and names the withheld paths in a `path_group_omitted` coverage
  gap. At most 5 group requests are sent per record, raw groups first; each counts against
  `--judge-limit`, has its own digest and replays alone. Confirmed when any group is Confirmed (scoped
  to that path); Protected only when every group was judged and is Protected; otherwise Review. A
  group still over the limit keeps `evidence_too_large`; groups past the cap are reported
  `path_group_cap`. Records under the limit are unchanged.
- **Measured (DVWA `a1978a2`):** 8 records over the limit (67,703–83,340 bytes) become 24 group
  requests of 54–65 KB, none past the cap. The page-shell excerpts
  (~18–20 KB) and fixed sections are repeated in every group, which meets S2's re-open condition.
  Measured offline, only 3.0–5.0 KB per group request is off the dependency chains (12.6–18.6 KB
  are on them), so S2 could save at most about 7% and is not adopted.
- **Tests:** `TestPathGroup*` in `internal/judge/path_groups_test.go`; `TestDVWARequestSizes` with
  `ZAZZLES_DVWA`.

### W1–W5: Wire Bundle v7 representation — implemented

Owned by the E3 contract; summarized here so the size design is in one place. See the
[proposal §4.3](../project/analyzer-hardening-and-wire-efficiency-proposal.md#43-wire-bundle-v7-t2-2--all-analyzers).

- **W1.** Always apply the lossless compact form (`compactBundle`, `internal/judge/compact_bundle.go`).
  It now applies before the budget on every assessed request.
- **W2.** Drop `evidence_roles`; keep `evidence_coverage`, with the union of adapter and selected catalog obligations.
- **W3.** Send component IDs in model-facing `analysis_components`; keep versions and digests on
  `CandidateUse.Components` and in traces for replay verification.
- **W4.** Project Command, Path and outbound fact context indices to `eN` wire ids. The hard-tier
  budget must keep operating on `CandidateUse` indices and project afterwards.
- **W5.** Keep static fields before `use`, for provider prefix caching.
- **Expected:** 25–35% fewer input bytes per request (proposal estimate; to be measured).

### W6: Move fixed explanatory sentences out of each request — implemented

The implemented scope removes Command/Path/SSRF interpretation already carried by structured
platform/operand fields and selected guidance, with shared index/path interpretation in the static
instruction. Candidate-specific transformation facts remain. The E3 continuation moved the query/middleware
sentences to 14 fact codes owned by `internal/guidelines/facts.md`. A request carries the code with
its exact expression and file, plus only the notes for the codes it names; an unknown code fails the
request. Measured byte effect is neutral (about +90 to +340 bytes on affected requests, −127 on Juice
Shop SQL), because each sentence appeared once per request before. Its value is one owner per
interpretation.

- **What:** `Completeness.ModelFacts` repeats fixed sentences per family (3,753 bytes on
  `order.ts:164`, much of it constant text such as the Express middleware scope explanation). Move
  sentences that do not depend on the candidate into the family's component prose (static, and cached
  through the provider prefix); keep only candidate-specific facts per request.
- **Where:** fact producers in `internal/parse` (for example `claim_assembly.go` and the family
  completeness builders); prose in `internal/analysispacks` and `internal/guidelines`.
- **Risk:** prose drift between component text and the facts the gates assume. Keep one owner per
  sentence and test that each moved sentence still appears in the selected material.
- **Measure:** `model_facts` bytes per family, before and after.

### W7: Condense masked comments and whitespace — implemented

- **Today:** `modelSource` (`internal/parse/model_source.go`) replaces every comment character with a
  space, keeping newlines and tabs. That hides comment text from the model but saves no bytes; a license
  header or JSDoc block is still sent as spaces.
- **What:** in model-facing excerpt text only, collapse only runs of spaces proven by comparison with original source to come from comment/docstring masking. Keep every newline and all unchanged whitespace, including multiline literal content. General blank-line/indentation trimming was rejected because it can change literal values.
- **Constraints:** the request instruction currently says masked source keeps byte positions, and
  `sharedSourceExcerpts` (`internal/judge/source_excerpts.go`) merges excerpts by requiring text length
  to equal span length. Both must change together; excerpt merging must then work on original
  coordinates and condense afterwards. This moves bytes for every request: protocol bump.
- **Measure first:** extend the digest tool to report the masked-whitespace share per section and sample.

### S1: Data-path slicing — deferred (separate contract)

- **What:** send only the statements that carry the request value to the sink, plus every control that
  dominates the sink or a transfer on that path, instead of the whole handler body.
- **Why:** this is the largest general saving. Handlers are the biggest single excerpt in large
  requests, and every family benefits.
- **Risk:** a missed statement can hide a guard or a reassignment, which can turn a protected answer
  into vulnerable or the reverse. The slice must be provably complete for the supported statement kinds,
  and fall back to the whole handler when any statement on the path is unsupported, which the existing
  gaps already identify.
- **Prerequisites:** precise JavaScript `if` modeling (S4) and the shared guard engine
  (`internal/parse/guard_climb.go`), so that dominating controls are known.
- **Acceptance shape:** saved-answer stability on calibration pairs, guarded and unguarded variants per
  family, and a digest delta list.
- **Status:** deferred after measurement; see the [S1 contract](../specifications/data-path-slicing.md).

### S2: Relevance filter for helpers and models — not adopted (soft tier)

- **What:** include a helper or model definition only when a value on the dependency path, or a control
  on that path, passes through it. Today `includeHelpers` (`internal/parse/check_context.go`) includes
  helpers for any pre-use call that may validate or mutate the request, and storage-model bindings are
  attached for every model the handler touches.
- **Why:** on `order.ts:164` this is exactly the set the hard-tier budget shed.
- **Risk:** a helper that mutates the request in place without returning a value (the reason the current
  rule is broad). Keep any helper that receives the request object or a request-derived value as an
  argument; drop only helpers whose arguments carry no dependency.
- **Measure:** bytes and the count of omitted helpers per family; answer stability on saved traces near
  the soft threshold.

### S3: One-line summary for middleware that cannot change the claim — implemented (bounded grammar)

Only stable inline/local/imported middleware with literal response-header calls followed by one
`next()` is summarized. Exact header names and values remain visible, so the model can still weigh
response behavior. Unknown factories, mutations, helpers, authorization and error forwarding retain
source and gaps; serving files is not summarized by this implementation.

- **What:** replace the bodies of registrations that cannot write `req.body` or `req.query` and do not
  authorize with one summary line listing them, for example "12 registrations that only set headers or
  serve files: …".
- **Where:** `middlewareContext` (`internal/parse/middleware_context.go`). The existing
  `transportMiddleware` list and `commandTransportMiddleware` (`internal/parse/command_claims.go`) are
  name-based.
- **Constraint (principle 4):** deciding that middleware is harmless must come from its source (it never
  writes the request fields the claim depends on and never terminates the request), or from a verified
  library contract. A bare package name is not enough.
- **Measure:** middleware bytes per request on Juice Shop and nodejs-goof.

### S4: Remove repeated gaps at the source — implemented

- **What:** model JavaScript `if` statements precisely, as the Python `conditional` does
  (`internal/parse/python_control.go`), instead of falling to `branches` in `internal/parse/flow.go`,
  which records `unsupported_control_flow`, `branch_exit` and `unknown_control_effect` at every `if`.
- **Why:** this is both noise (it repeats in coverage and entry gaps) and an accuracy problem (see
  "Why size matters").
- **Risk:** changes flow evidence for every JavaScript analyzer; the owner sequenced it after core E3 validation in the same worktree and branch.
- **Delivered:** [JavaScript conditional flow](../specifications/javascript-if-flow.md). Modeled `if`
  statements record arm preconditions instead of these gaps. Loops, `switch`, `try`/`finally` and
  request rebinding keep the fallback.

### Rejected

- **Per-framework drop lists** (for example "always drop `helmet` and `morgan`"). Name-based and not
  generic; it violates principle 4.
- **Truncating excerpts at a byte boundary.** It can cut a guard in half and produce evidence the model
  cannot interpret.
- **Raising `requestLimit` without evidence.** The limit should follow confirmed provider limits and
  measured token cost. See open questions.

## Content audit: what the model needs

The request carries several representations of the same facts, plus fields that only Go replay uses.
Each row says what the field is for and proposes an action. "Trace only" means it is kept in the
`CandidateUse` and the decision trace for replay and reports, but not sent to the model. Sizes are the
compacted bytes on `routes/order.ts:164`.

| Field | Bytes | Needed by the model? | Proposal | Strategy |
|---|---:|---|---|---|
| `source_excerpts` | 19,225 | Yes: the source is the evidence | Relevance (S1–S3) and condensing (W7) | S1–S3, W7 |
| `compact_wire` tables (sources, gap rows, detail strings) | 7,178 | Partly: file names and gap text, yes; SHA-256 per source and byte offsets, no | Drop SHA-256 and byte offsets from model-facing rows; keep line ranges | W8 |
| `evidence` rows | 5,582 | Kind, file and lines, yes; byte offsets and hashes, no | Same as above | W8 |
| `model_facts` | 3,753 | Candidate-specific facts, yes; fixed family sentences, no (move to prose) | W6 | W6 |
| `trace_graph` | 3,615 | Yes, but it is derived from `dependencies` and `control_edges`, which are also sent | Send one representation: keep the graph, drop the separate `dependencies` and `control_edges` lists, or the reverse; prove they carry the same facts (`storage_key` exists only on dependencies) | W9 |
| `analysis_guidelines` | 3,256 | The sections relevant to the claim | Select sections by claim and contract, as the component catalog already does for families | W10 |
| `evidence_coverage` and `evidence_roles` | 2,967 + 1,450 | One of them | W2 | W2 |
| `instruction` | 1,728 | Yes; static per family | Keep static and early for prefix caching (W5); move family text into component prose | W5, W6 |
| `invocation` | 1,673 | Entry identity, yes; `entry_gaps` duplicate coverage gaps; the registration evidence duplicates context | Drop gaps already in coverage; reference registration evidence by `eN` | W11 |
| `analysis_components` | 1,666 | Which pack and contract were selected, yes; versions, digests, owner paths, no | Send ids only (extends W3) | W3 |
| `input_facts` | 1,286 | Source and transfer per value, yes; it repeats dependency sources and transfers | Reference dependencies by index instead of repeating evidence | W11 |
| `coverage_gaps` | 367 (61 gaps before deduplication) | Only gaps that touch a dependency, the sink or a control on the path | Send those; summarize the rest as counts by kind | S5 |
| `resolved_gaps` | small | Rarely | One summary line naming the resolving evidence | S5 |
| Provider question and choice text (outside `input`) | about 2–4 KB | Yes; static per family | Order the static parts before the evidence, if the provider API allows it | W12 |

### W8: Model-facing spans without byte offsets or hashes — implemented

Evidence rows, excerpts and gap rows carry `start_byte`, `end_byte` and a SHA-256 per source. The model
reasons over text and line numbers; offsets and hashes exist for replay and excerpt identity. Send file and line ranges plus character columns locating each node in its condensed excerpt (one-based, exclusive end; first-line columns are excerpt-relative). Same-line nodes must remain distinguishable. Keep offsets and hashes in the trace, so replay still verifies exact source. Excerpt
merging (`sharedSourceExcerpts`) keeps using byte offsets internally.

### W9: One representation of the dependency path — implemented

`trace_graph` is built from `dependencies` and `control_edges` (`buildTraceGraph`,
`internal/judge/evidence_trace.go`), and all three are sent. Keep `dependencies` and `control_edges`, removing their derived `trace_graph`. Unit tests across family fixtures prove that the retained form preserves every fact: sink slot, storage key, transfer order
and edge kinds.

### W10: Guideline sections by claim — implemented

Send only the guideline sections the selected claim and contract use. The catalog already selects
components per family; extend the selection to sections for the language documents that are still sent
whole (logging). Gate on the section-validation tests in `internal/guidelines`.

### W11: Reference instead of repeat — implemented for exact duplicates

`invocation.entry_gaps` repeats coverage gaps, `invocation` repeats registration evidence, and
`input_facts` repeats dependency sources and transfers. Replace the copies with `eN` and dependency
indices. This is lossless, and it also removes the entry-gap channel through which unrelated JavaScript
`if` gaps reached the model.

### W12: Static-first request envelope — rejected as outer-key reordering

Provider requests are built from Go maps (`payloadForm`, `internal/judge/client.go`), so keys are sorted
and the envelope is `input`, `model`, `questions`. The static question and choice text therefore follows
the per-candidate evidence, and provider prompt caching, which matches on a prefix, may not reuse it.
The verified [Decisions caching contract](https://developers.openai.com/api/docs/guides/decisions#reuse-shared-input-with-prompt-caching)
states that shared `input` is the reusable prefix and question content lies outside it.
Reordering outer JSON keys cannot move questions into that prefix. Keep the already
static-first input envelope and its ordering regression test; do not duplicate questions
or claim cache savings from JSON key order. Record actual cached-token usage from live responses.

### S5: Claim-relevant coverage gaps — not adopted (accuracy-affecting)

Coverage gaps are by definition not blockers, yet they reach the model in full. Send only those that
touch a dependency, the sink, or a control on the path, and summarize the rest as counts by kind
("12 unrelated control-flow gaps elsewhere in the handler"). The judge gates still read the full,
unreduced use, so outcomes cannot be weakened by the reduction. This is the change most likely to
improve accuracy (see "Why size matters"). It needs the ablation protocol before adoption.

## Ablation protocol for lossy changes

A lossy change is adopted only with evidence that answers stay correct.

1. **Fixed calibration set.** Use the existing calibration pairs
   ([calibration](../../docs/analysis/calibration.md#regression-pairs)): for each family and language, at
   least one guarded or protected case and one vulnerable case, plus the largest real records per sample
   (for example `routes/order.ts:164`, the VulnPy path routes and `updateProductReviews.ts:17`).
2. **Arms.** The current request, then the request with one change. Same model, provider and question
   version, and no fallback.
3. **Budget.** The owner sets an explicit request cap for each run; record it.
4. **Compare.** Choices and probabilities per question, the final finding status, and input tokens.
   A change passes when no case moves toward a wrong verdict and the confidence of correct answers does
   not drop materially. The threshold is set in the contract before running.
5. **Record** each arm in the evidence ledger. Keep the traces, so the comparison can be replayed offline.

Lossless changes (W1–W3, W8, W9, W11) need only the offline digest and unit evidence, not an ablation run.

## Measuring

The differential digest tool (local, never committed; kept in the worktree's ignored
`.zazz/ephemeral/assessment-tools/`) builds every request without sending it and prints, per candidate:
bytes, digest, per-section bytes, uncompacted bytes and sink location. Run it on the base commit and on
the working tree and diff the outputs. Every strategy reports:

- bytes and estimated tokens per app and family: maximum, p95, median;
- the list of candidates whose bytes changed (it must match the contract's delta list);
- for lossy strategies, the omissions per record and answer stability on saved traces.

## Evidence ledger

Append one row per implemented or measured strategy. Do not rewrite earlier rows.

| Date | Strategy | Change | Evidence |
|---|---|---|---|
| 2026-11-15 | Hard-tier shedding and floor | Implemented | Only `order.ts:164` over the limit across 4,404 candidates; 72,580 → 65,235 bytes, 29 context items omitted; judged live (`gpt-6-luna`, 17,087 input tokens; Review with middleware blockers). Requests under the limit byte-identical to base. 40 synthetic growth shapes fit with an omission gap or reach the floor. |

| 2026-11-15 | W1–W5 | Implemented | Always compact; single unioned role ledger; prompt component IDs; post-budget eN projection; static-first input order. Wire, budget and provenance tests pass. |
| 2026-11-15 | W6 | Implemented for Command/Path/SSRF fixed index/platform interpretation | Removed facts duplicated by structured operands/platform fields and selected guidance; independent-path interpretation lives in static instruction. Candidate-specific transformations and per-path facts remain. |
| 2026-11-15 | W7 | Implemented bounded mask compaction | Merge on snapshot coordinates before condensing; preserve all line separators and literal whitespace. Same-line locator and multiline literal regression tests pass. General whitespace trimming rejected. |
| 2026-11-15 | W8 | Implemented with excerpt columns | Snapshot hashes and byte offsets stay local; file/line/character columns identify model nodes, including same-line calls after masked-space compaction. |
| 2026-11-15 | W9 | Implemented | Retain dependencies and control edges, omit derived trace graph. Fixture checks preserve source, transfer order, sink slots, storage keys and explicit control kinds. |
| 2026-11-15 | W10 / logging migration | Implemented | Logging catalog owns four existing facets and selects Logging/Do not claim guidance. Missing/stale selection fails explicitly; local provenance and gates remain. |
| 2026-11-15 | W11 | Implemented for proven duplicates | Input values reference a dependency only on exact source/transfer equality. Invocation gaps are removed only when identical to a claim-ledger gap; unresolved registration spans remain protected in equivalence normalization. |
| 2026-11-15 | W12 | Rejected outer-key reorder | Decisions caches shared input, excluding question content. Retained static-first input ordering; inspect actual cache-read/write usage instead. |
| 2026-11-15 | S3 | Implemented bounded grammar | Only stable inline/local/imported middleware with literal header calls then exactly one next() can summarize. Exact header names/values survive; writes, helpers, authorization, error forwarding, factory calls and reassignment do not summarize. |
| 2026-11-15 | Transparent wrappers / catalog prose | Implemented | Source-proven arrow/function/typed wrappers and error forwarding; async factories, recursion, mutations, reordered/repeated calls and unstable inner bindings retain gaps. sql.js owner fixed; Node fs/archive operand prose synchronized. |

| 2026-11-15 | Final offline and paid verification | Measured | Standard-app reductions 24.6–43.1%; largest request 61,735 bytes, no sample shedding. 434/440 charged requests, 406 final decisions replayed exactly. Raw final usage reports zero cache-read tokens; no cache saving claimed. |

| 2026-11-15 | Relevance pressure before S4 | Measured | Only one of 3,551 assessed-family sample previews exceeds the proposed 90% soft threshold: order.ts:164 at 61,735 bytes. Zero hard-limit exceedances. Re-measure after S4 before adopting broad lossy filtering. |

| 2026-11-15 | S4 | Implemented and independently reviewed | Precise JS `if` modeling removed 161 `unsupported_control_flow` and 111 `branch_exit` gaps from Juice Shop requests; 4,405 candidates unchanged; no Python request changed. Juice Shop bytes −1.1%; `order.ts:164` 61,735 → about 59,100. Paid calibration recorded in the verification record. |
| 2026-11-15 | W6 (query/middleware) | Implemented as guidance-owned fact codes | Byte-neutral on affected JS SQL/NoSQL/command/SSRF requests; single interpretation owner; unknown codes fail. |
| 2026-11-15 | S1, S2, S5 after S4 | Measured; not adopted | 1 of 3,934 assessed sample requests over 55,000 bytes, 0 over the limit. Decisions: [relevance tier](../specifications/evidence-relevance-tier.md), [data-path slicing](../specifications/data-path-slicing.md). |

Measured distributions and validation limits are in the [v7 verification record](../evaluation/wire-bundle-v7-results.md).

## Open questions

- **The right unit for the limit and the soft tier.** Bytes, estimated tokens, or per-section caps. The
  65,235-byte request was 17,087 tokens, so a token limit would admit far more source than the byte
  limit does. Confirm the provider's actual request limits before changing `requestLimit`.
- **The final soft threshold.** About 90% of the limit is proposed; confirm it from the distribution
  measured after the always-on strategies land.
- **Citations.** Structured answers carry no evidence citations (`analysis.AnswerDetail` holds choice,
  confidence and probabilities only), so "a shed item was never relied on" cannot be checked directly.
  Decide whether to add a citation field to the question protocol in the bump.
