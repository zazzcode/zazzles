# Source traces and claim judgments

[Architecture](README.md#7-evidence-bundle-contract) · [Evidence and claims](evidence-and-claims.md)

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

`scan/internal/judge/bundle.go` emits `evidence_version: 6` for every language adapter. The
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

The model envelope supplies language Analysis Guidelines from `scan/internal/guidelines` under
`analysis_guidelines`. This scanner-authored guidance is separate from source data and API contracts.
Guideline versions and full text participate in exact-request identity; historical reports remain
readable without making their old answers reusable for changed inputs. See
[naming and compatibility](README.md#naming-and-compatibility).

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
original source-required roles and mandatory evidence validation checks. Changed request context still rejects replay;
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
judges the supplied implementation; its confidence cannot close static blockers. A blocker
closes only through a verified model resolution (below). Complete source availability alone
is not complete dispatch, heap, runtime or library knowledge.

## Model-assisted evidence resolution

The scanner asks the model specific questions about the points it could not resolve, and an
answer counts only when the evidence the model cites verifies against the request it received.
The [contract](../specifications/scan/model-assisted-evidence-resolution.md) owns the detail.

| Question | Asked when | Answer that can change the outcome |
|---|---|---|
| Flow gap (`flow-gap-v2`) | A path or SQL flow blocker (comprehension, unresolved call or dispatch, PHP value or loop, transfer limit, unknown transfer) overlaps a dependency | `value_preserved` with a verified chain through the gap discharges the blocker |
| Stored origin (`stored-origin-v2`) | A `storage_origin_unresolved` XSS or SQL record has a write census with at least one write | A verified cited request write discharges the blocker; `no_request_write_in_evidence` supports Protected only when every key's store is `closed` |
| Witness (`witness-citation-v2`) | A path record whose facts hold no unsafe witness | A vulnerable verdict whose only contradiction is the missing witness stands with a verified chain along a flow with no containing control and no open gap |
| Bypass (`bypass-citation-v2`) | A command record with a guarded path | `bypass_identified` needs a verified chain on a guarded path of the unsafe facet. On a shell path whose characters the scanner lists, those characters must also be able to carry command text ([command bypass support](../specifications/scan/command-bypass-support.md)) |
| Needed evidence (`needed-evidence-v1`) | A path, SQL, command or XSS record whose gaps name an unresolved symbol | One follow-up carrying the symbol's single exact definition from the snapshot |

The rules that bound it:

- **Citations are checked, not trusted.** The decision APIs accept choice questions only, so each
  resolution question has a `_cite` companion whose choices are ordered `eN`/`gN` chains built
  from the request. One verifier (`scan/internal/judge/citation.go`) checks that every cited ID was in
  the request, the chain runs from a dependency source to the sink, and each hop is a scanner
  edge or a bridge through the asked gap within a dependency that gap overlaps. A rejected,
  missing or off-list citation changes nothing and is recorded.
- **Protection needs scanner proof.** A model-resolved fact may move a record from Review to a
  finding with the ordinary status. It moves a record to Protected only when the scanner holds
  the coverage fact itself (for stored origin, every key closed).
- **No request without a question.** A record whose outcome a scanner blocker fixes, and whose
  blocker has no resolution question, is not sent (`blocker_unresolvable`).
- **Bounded requests.** One assessment request and at most one follow-up per record; follow-ups
  stop at 25% of the scan's assessment requests. Transport retries are unchanged.
- **Resolution is visible.** Each answer is an `assessment.resolutions` record (question,
  version, blocker, answer, cited chain and spans, verification, whether policy used it), and a
  record whose status rests on one carries `model_resolved` in JSON, HTML and SARIF.

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

Assessment scheduling (`scan/internal/judge/schedule.go`) has three passes. The plan pass is offline and
sequential. It groups candidates by equivalence signature, runs `Preview` and the size and TPM
preflight, and assigns `--judge-limit` slots to group leaders in priority order. Dispatch sends
leaders through at most `--judge-concurrency` workers, in waves. After a wave, a group whose leader
did not complete promotes its next member into an unassigned slot. Finalization walks priority
order alone: it replays equivalent members and applies cap and halt outcomes, then calls
`SaveTrace` and writes limitations. Output therefore never depends on completion order. With
concurrency 1 this matches the serial scheduler. One edge case differs: a leader fails without
halting while the cap binds. A serial run gave the next member the freed slot; the plan gives
that slot to the next leader in priority order. The limiter reserves a window entry under its lock
and holds no lock across HTTP. Its `complete` reconciles that same entry, and the first failure
halts new acquisitions.

## Verification and limits

Regression pairs cover raw/bound SQL, real/shadowed drivers, escaped/raw/unknown dictionary
alternatives, request aliases, variadic helper uncertainty and constant Jinja templates
with autoescape on/off/unknown. Shared tests verify evidence references, graph edge roles,
missing-role gates, validation outcomes, green-status consistency and scoped remediation.
HTTP stubs test transport/policy, not model accuracy. Live sample calibration remains a
bounded evaluation, not runtime exploitation, independent review or Semgrep/Bearer parity.
