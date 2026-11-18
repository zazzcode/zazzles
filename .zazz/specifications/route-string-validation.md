# Route string validation — implementation contract

Historical contract/evidence below retains its original names. Current package, CLI and report
names are documented in the [implemented architecture](../architecture/README.md#naming-and-compatibility).

**Authorization:** explicit user request, 2026-10-31, to implement in the isolated
`route-string-validation` worktree. No further greenlight ceremony is required. The user also
requested provider-neutral judging and a graph design covering outbound service exchanges.

## Outcome

Add a bounded JS/TS route-to-string-use evidence mode alongside the unchanged route-v1 inventory.
Resolve direct named relative imports and handler factories for the selected Juice Shop login/search
cases. Track request-field dependencies through supported local expressions/assignments to candidate
SQL and outbound HTTP calls. Report source-backed evidence, transfer limits and uncertainty; never
label missing evidence protected. Make OpenAI judge access explicit and optional; retain Jev and
future adapters in the design without claiming unimplemented transports exist.

## Implementation boundary

- Tree-sitter identifies syntax; no regex security verdicts. A separate evidence schema preserves
  route, source, operation and candidate-use relationships and source hashes.
- The first slice supports local named ESM imports, direct/factory handlers and local expression
  dependencies. Supported same-file functions and relative-imported named exports are entered at call
  sites, with identifier parameter bindings and direct return witnesses. Closures, wrappers, rest or
  destructured parameters, recursion, heap writes and external response continuations stay explicit gaps.
- SQL `.query` shapes are candidate sink models, not proven library identity or confirmed vulnerabilities.
  Outbound calls record request argument evidence; opaque response behavior stays unknown.
- `--strings [--json] [--entry <relative-file>] [--route <path-pattern>] <target-root>` runs offline by default. Optional
  `--judge openai` uses `OPENAI_API_KEY`; `--judge jev` uses `TYPESAFE_API_KEY`; each assessment preserves provider/model and failure state.
  No automatic provider fallback. Jev uses its verified provider-specific choice contract and requires an explicit model name.
- Models judge protection adequacy from bounded evidence. Offline output has `not_run` assessment;
  no protection or exploitability claim is inferred from missing validation alone.
- No live requests during tests or this session without credentials and a bounded evaluation scope.
  No target application execution or HTTP probing.

## Acceptance evidence

- Existing list/route tests remain unchanged and pass.
- Fixture routes connect named imported factories to request sources and candidate use spans.
- Supported assignment/concatenation/interpolation preserves dependencies; reassignment removes
  stale dependencies; unknown calls retain possible dependence with explicit uncertainty.
- HTTP-client route-shaped calls are not promoted to verified Express entry points in the new mode.
- Outbound argument evidence and response-flow limitations remain distinct.
- Offline runs are deterministic; parse/resolution/flow gaps and judge `not_run` are visible.
- Stubbed judge tests reject missing/duplicate/refused/invalid answers and non-success responses.
- CLI tests cover new mode, incompatible flags, bad entry paths and missing target roots.
- Manual Juice Shop verification records login/search candidates and remaining limitations.
- Same-file and relative-imported helper calls discover SQL candidates when an argument reaches a
  `.query` sink or a returned query operand. Case09 and case10 produce those candidates. Case12
  reaches Sequelize binding evidence. A declared SQL check with no candidate records `sql_sink_missing`.

## Design and operating references

[Graph design](../architecture/repository-graph.md), [architecture](../architecture/README.md),
[plan](../project/implementation-plan.md), [AGENTS.md](../../AGENTS.md),
[testing](../standards/testing.md), [code structure](../standards/code-structure.md).
Execution history belongs in `.zazz/ephemeral/route-string-validation-run-log.md`.

## Implemented evidence and known boundaries

The report is a route-linked collection of source-to-use dependency paths, not the complete canonical
IR/CFG described by the long-term graph design. Supported expressions yield local syntactic
relationships. Unknown transformations and branch merges retain possible dependencies with gaps;
those are not proven execution paths. Source size is capped at 2 MiB per loaded module, expression
work at 10,000 per handler, and dependency/transfer paths at 64 with explicit limit reasons.

Both OpenAI and Jev adapters share normalized validation/protection choice answers, model/provider,
question version and common usage counters. No model probability is used for policy. Legacy static gaps
force uncertainty; checked candidates use required roles and claim-relevant blockers. Independent review
and a vulnerability CI gate remain future work. The original connection test and the subsequent [two-case evaluation](../evaluation/juice-shop/results.md)
completed; no runtime target confirmation or held-out accuracy measurement was performed.

## Two-case implementation increment

Authorized user steering adds explicit method/path/field requirements via `--checks <json-file>`.
The tracked [phase cases](../evaluation/juice-shop/validation-checks.json) cover login email/SQL and
registration nonempty credentials. These are policy requirements, not expected judge answers.

- Attach applicable earlier middleware, same-route handlers, relevant input helper bodies and
  model/setter/hook context. Support the declared namespace/concise-factory and finale resource subset.
- Emit supported local branch/successor edges for registration middleware; preserve return/throw
  termination and source spans. Do not claim a complete interprocedural CFG.
- Deduplicate wire evidence and refer to it from dependencies, control edges and required fact roles.
- For checked candidates, require declared evidence roles and block on claim-relevant unknowns.
  Preserve unrelated coverage gaps. Legacy candidates remain conservative.
- Report supported_potential/protected_for_claim/needs_evidence separately from raw judge answers;
  no status implies runtime confirmation or independent review.
- Verify vulnerable, protected and unknown fixtures, missing bindings/guards, shadowed helpers,
  method-specific grouping, bounded relevant context and stable checked-evidence goldens.

The final two Luna calls returned insufficient validation/protection and supported_potential for both
cases. See [evidence design](../architecture/evidence-and-claims.md),
[login case](../project/08-login-validation-case.md), [registration case](../project/07-registration-validation-case.md)
and [results](../evaluation/juice-shop/results.md). No target code was modified. SARIF 2.1.0 export and illustrative remediation templates are implemented;
model-generated code, independent review and SCA remain planned work.

## Reporting and comparison increment

- `--sarif` exports strings output; `--export-sarif <saved-json>` converts offline without another API call.
- Preserve route identity, source locations, supported dependency paths, raw validation/protection
  facets, claim status, blockers, coverage and review/runtime state. Do not fabricate registration
  value flow or export unverified code examples as fixes.
- Verify official schema conformance and original vulnerable/protected/unknown controls with expected
  labels excluded from the submitted bundle. Preserve mismatches and evidence corrections in the
  [comparison results](../evaluation/corpus/README.md).
- Keep automatic novel-repository discovery as the next bounded Phase 3/5–8 extension in the
  [evidence design](../architecture/evidence-and-claims.md#discovery-on-novel-target-repositories).
- Run a pinned Bearer CLI/rules comparison on original controls, added helper/mutation/outbound
  controls and matching source scopes of both sample repositories. Preserve incomplete runs and
  source-inspect disagreements; do not treat absent findings as safety or challenge labels as runtime truth.
- Maintain the complete pinned Juice Shop challenge registry and per-finding review status. Evaluate
  the product goal of equal-or-better detection with fewer false positives; current development
  evidence does not establish held-out quality or whole-graph analysis.

## Helper SQL sink discovery

A call to a same-file function or a relative-imported named export is analyzed with the callee body.
Positional identifier parameters receive the evaluated argument, including its existing dependency
witnesses, as `parameter_binding` evidence spanned in the callee module. A direct `return` is
`return_value` evidence. That return replaces the conservative argument may-dependency only when the
body has at least one modeled return and the callee did not record unsupported control flow, binding,
recursion, work limit, or helper-call limit. Otherwise the call result keeps the prior may-dependency
and any sinks already found inside the body remain.

Expansion allows three nested helper levels and 24 call expansions per handler. A further call records
`helper_call_limit` and is not treated as a resolved body. A recursive re-entry records
`recursive_helper` and stops. This slice does not complete cross-function analysis: closures, rest
and destructured parameters, defaults that are actually used, property calls, and mutation of caller
locals are unresolved.

Checked `sql_query` requirements still select routes. When the route resolves and no
`sql_query_candidate` was discovered, the report includes one `sql_sink_missing` use. That use is
incomplete discovery, not a protected assessment and not evidence that the route has no query.

## Query structure and input validation

Defensive posture: restrict each field as far as the business requirement allows, and construct
the sink so the value cannot change query, update, or insert structure. A type or length check is
not that construction. A field the business must accept as free text, such as a comment, message,
description, review, or feedback, may contain any character. An allow-list would reject valid
input. For those fields the injection control is a bound query, update, or insert.

Every supported request field read (`req.body`, `req.query`, `req.params`, `req.headers`,
`req.cookies`, and the next property) is a validation subject. Applicable `app.use` middleware and
middleware arguments on the route registration are included. A field with no check in either place
carries `input_validation_absent`. A type or length check while the value is still built into query
structure carries `validation_insufficient_for_sink`. The same weak check on a bound sink carries
`validation_type_only`. A free-text field built into a statement carries `sink_must_bind_free_text`.
A free-text field that is already bound carries `validation_free_text_bound`. A custom call or a
middleware read whose predicate is not a recognized type or length check stays unresolved. Fields
that never reach a query sink are separate `input_validation_candidate` uses.

Query, update, and insert structure is a separate fact:

- Sequelize `.query`, and `Op.like` templates, record `query_text_interpolated` when the text is built
  from a value. A bound parameter in a later argument does not get that gap.
- Mongo collection calls (`Collection.find`, `update`, `insert`, and the listed siblings) record
  `query_text_interpolated` for `$where` strings and `query_document_unvalidated` when a request
  value enters the document. `users.find(callback)` is not a query sink.
- A logged SQL string is not a query sink.

Nested functions are entered only when their text contains `$where`, `Op.like`, or `.query(`.
That is how the chat tool's query strings are reached. Other callbacks stay unknown.

The language practice pack lives in `internal/rules/` and is embedded in the binary. It is a scan
rule set, not an SDLC document. A decision request sends the pack for the sink file's language.
JavaScript and TypeScript share one pack. Python and Go packs are loaded when those files are
assessed. Offline reports name the pack id and version and do not copy the full text onto every use.

## Implementation And Review Change Log

### 2026-10-31 — Helper-call SQL sink discovery

**Source:** resume instruction after the pinned Bearer comparison. Case09/10 produced no scan uses
and case12 disappeared before binding could be assessed.
**Changed sections:** implementation boundary, acceptance evidence, helper SQL sink discovery.
**Rationale:** a judge cannot recover a sink the structural slice never found. Argument, parameter
and return witnesses have to be source-backed before another model call.
**Summary:** enter supported same-file and relative-imported helpers, record parameter and direct
return evidence, and emit `sql_sink_missing` when a declared SQL check has no candidate.
**Verification impact:** parse tests cover case09/10/12, returned operands, missing sinks, recursion
and the fourth-level limit. `go test ./...`, vet and build passed. No new live model calls.

### 2026-10-31 — Query structure and input validation

**Source:** branch exit is every lacking input validation result and every string-built SQL or NoSQL
query, update, or insert on the documented Juice Shop and vulnerable-app sinks.
**Changed sections:** query structure and input validation.
**Rationale:** a route can validate a field and still concatenate it into a query, or bind a query
and still leave the field unvalidated. Those are separate findings.
**Summary:** record absent and unresolved validation, interpolated SQL and `$where` text, and
unvalidated values in collection documents. Do not treat `console.log` of SQL or `Array.find` as a
query sink.
**Verification impact:** shape tests, Juice Shop route comparison, vulnerable-app comparison, and
`go test ./...`. No new live model calls.

### 2026-10-31 — Pinned comparator evaluation and false-positive objective

**Source:** continuation request and user steering for lower false positives, Juice Shop expected
findings and the second TypeScript sample.
**Changed sections:** reporting/comparison increment; product objective and evidence-design references.
**Rationale:** measure custom protection recognition and actual coverage rather than raw finding totals.
**Summary:** pinned CLI/rules runner, thirteen controls, both samples, capability inventory and complete
challenge/per-finding review index; no scanner implementation change or new live model calls.
**Verification impact:** offline runner failure regressions, source/hash inventory checks, matched
snapshot scans and existing Go tests/vet. Independent human review and broad parity remain pending.

### 2026-10-31 — Route-focused reporting and original comparison controls

**Source:** user requests for iterative accuracy work, SARIF, remediation examples and novel targets.
**Changed sections:** reporting/comparison increment and implemented boundaries.
**Rationale:** distinguish actual graph evidence quality from judge confidence and known target labels.
**Summary:** add offline SARIF export/templates, original controls and verified import provenance in bundles.
**Verification impact:** schema checks, live capped Luna comparisons and offline export/status regressions.
