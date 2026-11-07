# Source traces and claim judgments

[Architecture](../architecture.md#7-evidence-bundle-contract) · [Evidence and claims](evidence-and-claims.md)

## Acquisition and semantic reasoning boundary

Node requests can additionally carry versioned transport-neutral input facts. Initial and sink types
are distinct, and transformations, lifecycle stages and control source references share the existing
deduplicated evidence table. The optional `source.node-input-v1` component supplies interpretation
only to Node candidates carrying these facts, preserving unchanged Python request material. Mongoose
operation semantics do not depend on Express, Fastify, Hapi or HTTP parameter syntax.

The judge evaluates supplied application controls; policy still requires complete source/binding/path
evidence and consistent per-path conclusions. An unknown effect with source present can be assessed;
a missing implementation cannot be filled by confidence. Native coercions apply only to their exact
outputs. Scalar operand evidence contradicts an unsupported ObjectId operator-injection answer.

`node-route-discovery-v1` is a separate choice protocol, source inventory and budget, with exact-request
replay and no fallback/retry. It proposes registration/handler relationships and attached middleware
alternatives. Its answers cannot mutate the trusted graph. The engine validates snapshots and known
dispatch independently; unresolved alternatives remain explicit provisional coverage in all reports.
Historical responses remain bound to their exact old request; fresh Node input facts invalidate replay.

## Implemented evidence contract

`internal/judge/bundle.go` emits `evidence_version: 6` for every language adapter. The
wire format contains a deduplicated source-evidence table, candidate/entry identity,
explicit invocation identity, typed entry/dispatch metadata, actual input/control bindings,
ordered dependency witnesses, an explicit trace graph, control edges, evidence-role
coverage, the exact requirement, library contracts and remaining blockers. Source spans
and hashes identify the analyzed snapshot. Source is evidence data, never model instructions.

The graph projects supplied dependencies; it does not discover new calls from nearby
text. Edges distinguish argument-to-parameter binding, helper return, projection, other
value transfers, sink use and path conditions. Branch conditions constrain a path and
are not value transformations. Explicit control edges remain separate. Each dependency
keeps its index, storage key and sink operand role. SQL text and separate value parameters
are distinct roles; JavaScript query options remain options until their binding semantics
are established. An options object alone cannot protect interpolated SQL.

Template adapters also supply a bounded `render_markup_context` source slice containing the
actual surrounding tag/attribute, including multiline attributes. The shared judge indexes it
as rendering context; a bare interpolation expression need not determine the DOM context.

The coverage ledger says which required roles are supplied or missing. Additional role
indexes expose actual helper bodies, path conditions and field policies already present
in adapter evidence. **Supplied means present, not semantically complete or protective.**
Indexing never changes canonical completeness or resolves a blocker. This distinction
prevents richer context from becoming an unsupported claim of proof.

The model envelope supplies language Analysis Guidelines from `internal/guidelines` under
`analysis_guidelines`. This scanner-authored guidance is separate from source data and API contracts.
Guideline versions and full text participate in exact-request identity; historical reports remain
readable without making their old answers reusable for changed inputs. See
[naming and compatibility](../architecture.md#naming-and-compatibility).

Common source/handler roles are `input_source` and `invoked_callable`. Structural entry
registration, dispatch and supported invocation-binding roles supplement claim-specific
requirements; supplied evidence does not establish adequacy. Input witnesses remain distinct
from caller argument bindings. Browser source-scope markers preserve offsets/hashes without
uploading entire modules or claiming verified event exposure. The generic protocol is
`candidate-use-v10`; SQL uses `sql-components-v2`, NoSQL `nosql-components-v1`, standalone
validation `validation-components-v1` and XSS `xss-components-v1`. Logging retains `log-use-v1`;
outbound observations select `pack.outbound` but have no model questionnaire or assessment protocol.
They return `not_run` without a model call, remain Review and leave requested assessment incomplete;
Preview rejects them without a request body. Logging is the remaining unmigrated existing family.
Selected obligations extend the
original source-required roles and mandatory Go gates. Changed request context still rejects replay;
old question versions remain historical on export.

## Route and browser slices

For API entries, the bounded slice follows the request field through assignments,
projections, helper bindings, relevant conditions and operation operands. It includes
actual helper implementations and import/constructor provenance when resolved. API
contracts describe verified patterns such as driver value binding; Luna evaluates the
actual call against the contract, including SQL construction before execution.

For browser entries, the slice starts at a browser input/event or response field and
ends at a DOM/framework sink in its output context. A server producer is linked only
when route/response evidence establishes the relation. JSON output alone is not XSS.
Stored-field correlation remains bounded; table/field matching is not proof of database,
row or deployment identity. Unresolved origin and configuration facts remain explicit.

## Separate judgments and gates

| Claim | Positive evidence | Outcome distinction |
| --- | --- | --- |
| Injection | External source, actual text/selector slot, verified library and supported path | Syntax/operator control versus data separation |
| Validation | Concrete named-field policy plus relevant enforcement implementation | Established unmet policy versus enforced policy versus missing requirements |
| Rendering | Source, renderer/sink, context and relevant transformations/paths | Context-appropriate escaping versus raw output versus unknown behavior |
| Logging | Emitted content, sensitivity and actual log/redaction behavior | Sensitive content exposure versus non-content fact versus unresolved sensitivity |

The selected `validation-components-v1` protocol asks whether a requirement is established, whether enforcement is
sufficient, and whether relevant enforcement coverage is complete. Both canonical evidence
roles and consistent answers are necessary. An established unmet policy becomes
`poor_practice`; enforced policy becomes `protected_for_claim`; missing policy, helper,
path or relevant downstream constraint stays `needs_evidence`. Form attributes can
establish intended policy but never server enforcement. Field names cannot invent policy.
Historical `validation-use-v2` answers remain exportable without being relabeled as fresh
component assessments. This shared protocol can consume any adapter's validation completeness. The Python
adapter currently emits named policy claims from matching Flask forms and HTTP methods; this is not
universal schema/middleware inference across languages.

A construction defect can be definite while exploitability remains unresolved. Parameter
binding and HTML escaping never establish business validation. Protection requires the
relevant paths; a vulnerability may use one supported unsafe path with stated conditions.
An unknown fallback cannot erase a separately supported raw path, and an escaped branch
cannot lend protection to an unresolved sibling. Unsupported parameters, helper expansion
limits, loops and unresolved applicable calls retain uncertainty instead of losing input.

Rules and API models capture recommended protective techniques and their preconditions.
They do not encode app names, challenge answers or arbitrary business restrictions. Luna
judges the supplied implementation; its confidence cannot close static blockers. Complete
source availability alone is not complete dispatch, heap, runtime or library knowledge.

## Reporting and reproducibility

Only a final `protected_for_claim` protection record uses green styling. Canonical
blockers, missing required roles, failed assessments and inconclusive final statuses
prevent a green protection claim even when a saved model answer says protected. Injection
status cannot color a separate validation pill green. Raw answers remain auditable.

Guidance is derived from the record and source location. Protected records describe what
to preserve; Review records name investigation blockers; defects name the operand and
constraint to change. Narrow SQLite, Jinja and jQuery replacements are labeled unverified
candidates with preconditions and regression cases. No generated remediation is applied
or exported as a verified SARIF fix. JSON, HTML and SARIF use the same scoped guidance.

Decision transport remains bounded to 64 KiB/request and 1 MiB/response, explicit per-run
request limits, selected provider/model and no fallback. Oversized evidence remains
unassessed; it is not silently truncated into protection. Exact requests/responses are
retained locally during calibration. Replay requires byte-equivalent compact JSON and
matching protocol; changed source, roles, questions or trace evidence needs a new judgment.
Expected labels stay in independent evaluation files and never enter model bundles.

## Verification and limits

Regression pairs cover raw/bound SQL, real/shadowed drivers, escaped/raw/unknown dictionary
alternatives, request aliases, variadic helper uncertainty and constant Jinja templates
with autoescape on/off/unknown. Shared tests verify evidence references, graph edge roles,
missing-role gates, validation outcomes, green-status consistency and scoped remediation.
HTTP stubs test transport/policy, not model accuracy. Live sample calibration remains a
bounded evaluation, not runtime exploitation, independent review or Semgrep/Bearer parity.
