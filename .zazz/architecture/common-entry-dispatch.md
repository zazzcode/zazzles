# Common entry, dispatch, and entry-specific reporting

Implemented bounded architecture, updated 2026-11-05. The shared model, existing consumers,
selectors/presenters, explicit browser events, finite dynamic HTTP, Apollo GraphQL and unary Node.js
gRPC subsets are implemented. [Acceptance evidence and remaining visual review](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05)
distinguish implementation from final milestone completion.
The [delivery brief](../project/common-entry-dispatch.md#outcome) owns scope;
the [deliverable contracts](../specifications/scan/common-entry-dispatch.md) own execution.

## 1. Original problem and migration boundaries

The scanner already separates source evidence, semantic judgment, policy, and reporting.
The pre-migration boundary coupled analysis starts and invocation identity to HTTP:

- `scan/internal/analysis/analysis.go`: `Entry.Route`, `CandidateUse.RouteID` / `ClientID`,
  `Check.Method` / `Path`, and separate `AnalysisReport.ClientEntries`.
- `scan/internal/parse/analysis.go` and `route_analysis.go`: registration discovery selects
  HTTP handlers and initializes request/response-specific flow.
- `scan/internal/parse/flow.go` and `python_flow.go`: flow state and parameter initialization
  carry route assumptions. Renaming records cannot supply resolver/message inputs.
- `scan/internal/judge/evidence_coverage.go`: required roles include `route_handler` and
  request-specific sources. Evidence presence is distinct from semantic completeness.
- `scan/internal/report`: HTML grouping, finding associations, and SARIF labels depend on
  route/browser identity. Saved-report export accepts schemas 1/2.

The implementation MUST preserve existing bounded flow, sink models, raw assessments,
claim policy, and snapshot evidence. It MUST NOT require a full repository IR rewrite.
Existing [package boundaries](README.md#11-implemented-package-boundaries) remain.

## 2. Semantic records and cardinality

| Record | Responsibility | Relationships |
| --- | --- | --- |
| Entry point | Logical exposed operation within a service/application instance. A Symfony route also carries `access` (authentication and roles) and `state_changes` (storage key, operation, span) for the writes that action performs | Has zero or more registrations |
| Registration | Source/configuration wiring and generation provenance | Exposes an entry; has dispatch bindings |
| Dispatch binding | Target alternative, condition, ordering, invocation mapping, resolution | Belongs to entry/registration; zero or one known callable target |
| Callable | Lexically resolved function/method/body identity | Shared by any number of bindings |
| Invocation context | Receiver, parameter/closure bindings, input roles, applicable controls | Belongs to one binding and analysis context |
| Input origin | Role, projection, source evidence, and supported trust assumptions | Supplies actual parameter/value bindings |
| Gap | Unknown fact, affected records, reason, bound, completeness impact | Can exist without a candidate use |
| Transport association | Optional supported delivery relationship | Connects an entry to transport evidence or another entry |

An entry can have several registrations and target alternatives. An unresolved alternative
has no fabricated callable. Ordered middleware is a chain; conditional alternatives are
branches. They MUST NOT be represented as interchangeable lists of possible callees.

Logical identity includes application/server/schema instance. Two servers exposing the
same method/path or schema coordinate are not automatically the same entry. Grouping
multiple registrations into one entry requires supported common ownership; uncertain
ownership stays separate with a gap. A callable's identity includes its lexical scope,
source snapshot and span, independent of registration count.

Entry kind, dispatch mechanism, source language, and transport are independent dimensions.
Initial kinds are `http`, `browser`, `graphql`, and `grpc`; mechanism vocabulary covers
direct registration, factory/table expansion, schema-field binding, service-method binding,
and browser bindings. Unknown serialized kinds remain inspectable with a generic presenter.

## 3. Identity and candidate association

IDs MUST be deterministic for identical source snapshots, namespaced by record kind,
and independent of judgments, output ordering, or wall-clock time. Persistent IDs cite
repository-relative paths, source hashes, lexical/span discriminators and derived inputs.
They are snapshot identities, not edit-stable vulnerability fingerprints.

A candidate's primary association is an `entry_id` and `invocation_context_id`.
The context resolves registration, dispatch, and callable references. Candidate identity
also distinguishes sink/operand, claim/check, and supported context alternatives.
Related entries, such as a stored-value producer, are secondary relationships and cannot
replace the primary association. Completed milestone output MUST NOT maintain parallel `route_id`
and `client_id` authorities. A report validator checks references and context ownership.

A shared callable can reuse source records and context-independent parsing/binding facts.
Guard sufficiency and value bindings MUST remain scoped to their invocation context.
No global protected bit or entry-agnostic security summary is introduced.

Desired: two registrations of one function have one callable and separate input/control
contexts, yielding separate use records when applicable.
Existing shape to replace: `Entry{Route: r, Handler: ...}` plus `RouteID` / `ClientID`
associations in `scan/internal/analysis/analysis.go`.

### Implemented schema-3 shape

This section records the common-entry milestone baseline. The later component refactor emits
schema4 with additive selection/request provenance for migrated families; see the
[current component compatibility contract](analysis-packs.md#bounds-and-compatibility). Existing
entry/context identities below remain authoritative. Saved schema3 answers keep their original versions.

The report has `entries`, `registrations`, `dispatch_bindings`, `callables`,
`invocation_contexts`, `uses`, `gaps`, `files`, `analysis_guidelines` and existing shared
finding/assessment metadata. Record collections have deterministic ordering. The model
contract defines their Go types; the migration contract owns the serializer cutover.

A binding has `id`, `entry_id`, `registration_id`, `mechanism`, `resolution`, optional
`callable_id`, invocation mapping, stage/condition evidence and gaps. Resolution is
`resolved`, `partial` or `unresolved`; a missing callable stays absent. Known alternatives
have separate binding records; an unknown remainder has its own unresolved record.
Contexts have `id`, `entry_id`, `dispatch_binding_id`, actual input/receiver/closure
bindings, applicable control references and gaps. Each input binding has a role, target
parameter/projection, source evidence and supported origin/trust facts; unknown facts
remain unknown. Shared records refer to evidence by snapshot-bound identity.

Entry metadata is discriminated by `kind`: HTTP method/path/mount details; browser
entry category/event/target details; GraphQL schema instance/type/field/operation details;
gRPC server instance/package/service/method/streaming details. Unknown kinds retain
available metadata for generic presentation. This is a typed schema, not an arbitrary
map used by adapters to bypass validation.

For example, a new check can select a resolver without HTTP metadata:

```json
{
  "id": "search-query",
  "selector": {"kind": "graphql", "type": "Query", "field": "search"},
  "kind": "sql_query",
  "fields": ["args.term"],
  "validation": "No additional business constraint supplied",
  "protection": "Input must remain separate from executable SQL structure"
}
```

The absence of a business constraint in this example MUST remain unknown/not established
for validation; that text is not an application policy. HTTP selectors carry method/path;
gRPC selectors carry service/method; browser selectors carry category/name/event where
known. Validate kind-specific fields and reject incompatible combinations. The tagged selector is accepted input; its policy text alone does not establish an application requirement.

## 4. Adapter-to-flow boundary

Framework adapters establish exposure, dispatch, callable resolution, input bindings,
ordered controls and gaps. Language flow engines consume resolved callable/context facts,
seed their environments from input bindings, and retain language-specific transfer rules.
The scanner remains implemented in Go; adding a gRPC adapter does not add Go target analysis.

HTTP-specific request/response projection stays in the HTTP adapter and operation models.
Browser input/event initialization becomes another consumer of the same entry association.
Existing browser source and inline-template snapshot provenance MUST survive migration.
JS/TS and Python do not need to share an evaluator implementation to share the contract.

| Entry | Initial input distinctions |
| --- | --- |
| HTTP | Path/query/body/header/session projections and response object roles |
| GraphQL | Arguments, parent object, request context, execution info, resolver return |
| gRPC | Request message, metadata, call context, response callback |
| Browser | Event input, DOM/location/storage origin, response field, component context |

An entry kind never proves attacker control. GraphQL arguments are externally supplied
under verified execution binding; parent/context need their own origin evidence.
gRPC request fields and metadata remain distinct; callback/context objects are not request
strings. Schema types, directives, authentication names and message types do not establish
sink protection or business validation. Reachability does not establish value transfer.

## 5. Claim completeness and dispatch alternatives

Replace HTTP-specific required roles with explicit entry registration, dispatch binding,
invoked callable, input origin/binding, sink binding, and relevant control/value witnesses.
Adapters supply additional obligations where needed. This change MUST preserve the strength
of existing HTTP requirements rather than merely renaming `route_handler`.

Completeness has three scopes: entry discovery, dispatch resolution, and candidate trace.
Discovery/dispatch gaps remain visible for zero-use entries and at scan scope when the
unknown exposure cannot be assigned an entry. Coverage absence cannot become protection.

An unsafe supported witness can substantiate its scoped defect despite an unrelated unknown
alternative. An unknown applicable guard on that witness still blocks its affected claim.
A claim of protection across an entry requires all relevant dispatch alternatives and
paths to be covered. A protected candidate is not a green badge for an entire entry.
Report counts remain counts of contextual uses/claims, not unique vulnerabilities.

The judge receives the relevant entry/context facts and explicit evidence roles.
Changed request envelopes MUST increment evidence/protocol versions and invalidate replay;
claim protocols change only where their question semantics change. Exact requests and
raw historical answers remain auditable. Policy does not let the model invent bindings.

## 6. Entry-specific reporting

`scan/internal/report` owns one shared finding interpretation and entry-specific presentation.
Use a small switch/presenter function over typed metadata; no runtime plugin system or
speculative interface is required. Presenters supply labels and details, never detection,
claim completeness, trust, or status decisions.

| Kind | Primary label | Details and locations |
| --- | --- | --- |
| HTTP | `POST /accounts` | Mount/receiver, middleware chain, registration and handler |
| GraphQL | `Mutation.createAccount` | Schema coordinate, resolver, arguments, parent/context, optional transport |
| gRPC | `accounts.AccountService/CreateAccount` | Service/method, unary/streaming declaration, handler, message/metadata binding |
| Browser | Event/component/module label | Binding, source category, component and rendering context |
| Unknown | Kind/name or stable ID | Available source locations and explicit unresolved metadata |

HTML MUST group by actual entry identity and expose registration/dispatch alternatives.
Use neutral shared headings such as Entry and Declaration location, with kind-specific
labels inside details. Keep findings, Review, Protected, categories, sorting, disclosure,
keyboard access, narrow layouts and zero-use entries. A GraphQL transport `/graphql`
MUST NOT collapse field entries into one HTTP row or duplicate resolver candidates.

SARIF MUST use the operation/sink as a finding's primary source location where available,
with registration, schema/proto and callable locations as related locations. Add
`scan.entryId`, `scan.entryKind`, `scan.invocationContextId` and typed entry metadata;
logical locations use the entry-specific identity. Entry/scan gaps without a use belong
in invocation notifications/properties, not fabricated security findings.

JSON is canonical typed evidence. Text, HTML and SARIF consume the same interpretation.
Missing metadata gets an explicit fallback; no format drops an unknown kind or orphaned
legacy use. Only final claim-level protection receives green styling.

## 7. Selectors and public compatibility

Keep `--entry` as registration-file scope and `--route` as an HTTP-only filter.
Add `--entry-kind` (one known kind) and `--entry-id` (exact snapshot ID) for common selection.
Filters intersect; an empty selection reports an error as current route selection does.
ID filters are suitable for inspecting a saved inventory, not portable policy definitions.

Checks continue to accept the existing top-level JSON array. Each check uses either
legacy method/path or a tagged `selector`, never both. Normalize legacy HTTP selectors
at the boundary. Typed selectors support HTTP method/path, GraphQL type/field, gRPC
fully qualified service/method, and browser stable kind/name; optional registration file
narrows ownership. A selector can intentionally match multiple entries: evaluate each
context separately and report match identities/counts. Zero matches produce a visible gap.
Check fields retain source roles (`args.email`, `request.email`, etc.); missing application
requirements remain unknown. Retain current size/count/unknown-field validation limits.

The common-entry migration introduced analysis schema3; the component refactor now emits schema4.
Route inventory schema1 remains an HTTP view. Read saved schemas1–4 at one input boundary; preserve
original schema provenance, source/hash facts, uses, raw assessments and guideline metadata.
Legacy `practice` metadata is decoded only there. Ambiguous legacy associations become
explicit unresolved entries/contexts; conversion cannot claim dispatch facts never saved.
A converted report can export the current schema but cannot silently reuse its answers for changed
model requests. Export never overwrites the input or reads fresh target source.

Legacy wire types remain private to compatibility decoding. Remove superseded internal
route/browser identity aliases and duplicate canonical state before milestone completion.
Intermediate migration checkpoints are not final schema/compatibility acceptance.

## 8. Implemented bounded framework subsets

The user prioritized Node.js GraphQL first and asked for browser event support; exact
framework targets are flexible. Apollo and grpc-js are the concrete initial subsets chosen
for bounded implementation. They reuse existing JS/TS analysis and do not claim universal
framework coverage. A future user-built GraphQL application is not a prerequisite: small
source-reviewed fixtures supply initial acceptance, with application evaluation deferred.

- Browser events: verified DOM/window `addEventListener` registrations with literal
  `click`, `input`, `change`, `submit`, or `message` names and inline/local named callbacks.
  Preserve event target/data provenance separately from other DOM reads; a message origin
  check is relevant control evidence, not universal sanitization. Dynamic event names,
  callback mutation, custom event buses and unsupported receiver aliases retain gaps.
  Existing framework/browser analysis remains available without claiming event bindings
  that were never established.
- Dynamic HTTP: verified Express registration through literal finite tables/for-of loops
  and direct local factories with literal arguments and directly returned handlers.
  Retain expansion site, row and factory call/closure bindings. Runtime data, mutation,
  recursion and unresolved wrappers remain gaps. Preserve existing finale persistence models.
- Python dynamic HTTP: bounded existing Flask/Blueprint `add_url_rule` and generated
  FastAPI/APIRouter decorators, verified local factory arguments and captured values, and
  finite local-source registry/member selection. The mandatory target is the pinned
  [VulnPy trace acceptance](../specifications/scan/common-entry-dispatch-05-dynamic-http.md#vulnpy-acceptance-target-and-required-traces),
  including imported trigger selection and nested callback/cursor propagation to actual SQL
  sinks and generated raw HTML responses. Derive finite alternatives from parsed local
  declarations and evidenced naming/lookup operations; never execute imports/reflection or
  hardcode the sample's endpoint map. Retain unsupported members, mutation, external/runtime
  lookup and reached-limit gaps. Other VulnPy frameworks/families and unrelated template
  hardening are outside this subset. Existing static Python routes/evidence remain intact.
- GraphQL: verified `@apollo/server` `ApolloServer({typeDefs, resolvers})`, literal SDL
  and literal resolver maps, supported local/imported named resolver functions. Include
  Query/Mutation and explicitly bound object-field resolvers. Support a local literal
  `.graphql` source under the selected root; no target code execution. Default resolvers,
  subscriptions, federation, dynamic composition, custom scalar execution, loaders and
  arbitrary wrappers remain outside the first flow subset. Explicit object fields are
  analyzed independently; parent-result transfer across fields requires actual evidence
  and remains a gap when unsupported.
- gRPC: verified Node `@grpc/grpc-js` server construction and `addService`, with
  `@grpc/proto-loader` literal `loadSync` plus `loadPackageDefinition` and literal handler
  maps. Read local proto3 package/service/rpc/message declarations to bind unary methods.
  Streaming methods remain visible unsupported entries. Static generated JS/TS stubs,
  dynamic descriptors, interceptors and arbitrary include paths remain explicit limits.

Schema/proto readers MUST be bounded syntax-aware readers with span/error reporting,
not name/regex guesses. Restrict paths to selected source scope, prevent root escapes,
preserve hashes and never run generators. Readers support the stated subset; unsupported
syntax yields a gap. No new runtime dependencies in target applications are permitted.
Framework major-version evidence must come from fixture manifests/available target metadata;
unknown versions remain explicit assumptions. Validate these APIs against official references
before implementation and pin fixture dependency declarations; source fixtures are never executed.

Initial expansion limits: 128 derived registrations per registration site, 16 target
alternatives per entry, 64 contexts per entry and 10,000 newly derived entry/binding/context
records per scan. These are deterministic adapter limits, additional to existing
flow limits (three helper levels / 24 expansions), file/input and judge limits. At a limit,
retain a located reached-limit gap including unexpanded remainder; do not silently truncate
and claim coverage. Sort work before consuming budgets. Preserve existing direct entries;
a generation limit does not discard unrelated supported registrations.

## 9. Delivery and evidence

Eight deliverables share the assigned worktree/branch and proposed milestone draft PR
into `stage`. Each has its own executable specification and green recovery boundary.
The [delivery index](../specifications/scan/common-entry-dispatch.md#delivery-order)
owns sequencing and usage-window checkpoints; it is not another execution contract.

Capture pre-change source-reviewed HTTP/browser baselines. New adapter fixtures require
raw/protected/unknown controls, same-callable separate-context cases, unresolved dispatch,
shadowed framework negatives, deterministic output and reached-limit evidence. Generate
JSON/HTML/SARIF through the actual pipeline, with local judge stubs for protected outcomes.
Offline reports MUST distinguish not assessed from stub-assessed controls. Do not claim
fresh model accuracy, exploitability, or universal framework coverage from stub results.

## 10. Non-goals and design risks

No new vulnerability families, authorization engine, queue/job/CLI adapters, Go target
language, graph database, whole-program IR, automatic cache, independent Findings Review,
paid calibration, or changes to pinned sample apps are included.

The largest risk is the existing-consumer migration touching flow, evidence roles and
reporting together. Keep a runnable bridge only at explicit compatibility/migration
boundaries and remove it before final acceptance. Other risks are scope creep in schema
parsing, accidental guard sharing, factory closure identity loss, dropped zero-use entries,
and reinterpreting old answers. The phase contracts require direct negative controls.

## 11. Sources and ownership

- [Implemented architecture §3](README.md#3-parsing-and-language-adapters),
  [repository graph: canonical records](repository-graph.md#canonical-records-and-views),
  [trace judgment](trace-judgment.md#separate-judgments-and-gates).
- [Apollo resolver documentation](https://www.apollographql.com/docs/apollo-server/data/resolvers)
  documents resolver maps and distinct parent/argument/context/info parameters.
- [gRPC Node basics](https://grpc.io/docs/languages/node/basics/) documents descriptor loading,
  service registration and separate unary/streaming shapes. The bounded support above
  is a bounded zazzles implementation derived from those APIs, not an upstream completeness guarantee.

The owning architecture/reporting/user guides describe the implemented boundaries. The
[results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05) own measured
regressions, artifact hashes and outstanding acceptance; contracts own the required checks.
