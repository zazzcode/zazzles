# Route evidence bundles and claim assessment

**Design and bounded implementation, 2026-10-31.** This owns how target source becomes judge evidence
and claim-scoped results. [Repository graph design](repository-graph.md) owns the full graph; the
[current contract](../specifications/route-string-validation.md) owns implemented scope and acceptance.

## Transport-neutral input and value evidence

A source binding establishes how an external value enters a callable. It does not establish its type
at a later sink or the safety of that sink. Shared input facts MUST preserve these separate claims:
source origin and initial type; supplied transformations/hooks/schema code and stage ordering; type
at the actual operand; and remaining coverage gaps. Sink contracts consume these facts without
HTTP-path or framework-specific protection flags. A constrained value on one path cannot protect a
sibling operand, branch, registration or invocation.

Node HTTP, GraphQL and unary gRPC acquisitions can populate `InputFacts` version 1. Python migration
is deferred; absence of these optional records does not invent new facts on historical reports.
Source-present validators can be semantically assessed; absent helper implementations remain blockers.
Unknown sink type is distinct from missing code. Only positive scalar evidence or source-present
controls with consistent complete judgments can support the bounded generic ObjectId lookup claim.

Model-proposed acquisition bindings are separate `discovery_proposals`. The engine rechecks selected
manifest paths, source spans/hashes and canonical source projections. Only a match to an independently
established registration/callable binding is verified-existing. Provisional proposals MUST NOT create
entries, input bindings, flow edges or Protected claims. See [Node guidance](../../docs/analysis/node-inputs.md).

## Product objective

Present findings in terms of **inbound route → middleware/handlers → input definitions and
transformations → sensitive use**. A use may be a database query, account creation, an outbound API
request, or a later supported sink. Relevant response continuations form separate value relationships.
The product evaluates sufficient validation and sink-specific protection, then proposes complementary
improvements with source evidence. The long-term direction is selected OWASP Top 10 families plus
[dependency auditing](sca-design.md). No route is certified impervious to every attack.

## Evidence selection

The [product quality goal](../project.md#long-term-objectives) is Bearer-level-or-better effectiveness
with fewer false positives, plus a per-route report of sufficient protection, lacking protection, and
poor code-practice findings. Repository-wide structural analysis should make all relevant protection
and bypass paths available for semantic assessment. Actual guard/helper semantics and sink binding
can prevent a suspicious call shape from becoming a false finding. That benefit remains an
evaluation hypothesis; missing graph edges or incomplete slices can still cause false findings or
false protected claims. The current implementation does not supply or analyze an entire repository
graph. Measure both false positives and missed vulnerabilities/abstentions before claiming improvement.

Supply a bounded source-backed graph slice **and** the actual code of its relevant functions. A graph
alone omits custom-validator semantics; the entire repository forces the judge to rediscover paths
and buries evidence. Go selects and substantiates supported relationships. GPT Decisions or Jev
interprets adequacy for a precise declared requirement. A model MUST NOT invent missing edges.

The current checked mode accepts a JSON requirements file via `--checks`. It declares method/path,
fields, operation kind, validation requirement and protection requirement without an expected answer.
The phase's [two-case file](../evaluation/juice-shop/validation-checks.json) reflects the user's stated
requirements for the pinned target; the scanner does not hard-code those paths, helper names, or an
acceptable validator regex. Domain requirements are explicit policy inputs, not guessed from missing
validators or TypeScript annotations.

A bundle includes:

- Method/path and source-backed registration/receiver/handler references.
- Applicable earlier USE registrations and same-route middleware in registration order.
- Request-field dependencies, supported local transfers, and the actual sensitive operand.
- Relevant local/named/namespace helper definitions, including pre-use calls without return values.
- Conditional tests and supported local successor edges, preserving return/throw termination.
- ORM field definitions, setters and hooks; generated persistence mapping when its adapter applies.
- Library-binding evidence, declared models/assumptions, relevant blockers and remaining coverage gaps.

The wire bundle stores each evidence record once and refers to it by an ID from source/transfer,
control and evidence-role records. Reports retain original spans and source hashes. Context selection
propagates simple input aliases and helper parameters; unrelated challenge bookkeeping is not a
continuation of the original string. This selection is not a full interprocedural solver.

Helper expansion is bounded to three levels and 24 definitions per traversal. A reached limit is
explicit and blocks a checked claim when required context might be missing. Requests remain bounded
by the adapter payload/response/deadline/request-count limits. No recursive autonomous model browsing
or repository upload is implemented. Comments and public challenge labels are untrusted benchmark
context, not expected-answer instructions; held-out original fixtures are required for accuracy work.

## Discovery on novel target repositories

The product must discover checks without prior knowledge of a target's challenge routes. Current
`--analyze` already discovers supported SQL/outbound call shapes and route dependencies without a
requirements file; full claim-scoped automatic assessment is still incomplete. `--checks` files are
explicit business-policy inputs and evaluation selectors, not the intended prerequisite for scanning
a novel repository.

Deliver this next in the existing phases rather than adding target-specific vulnerability rules:

1. Phase 3: catalog source and sink argument roles, library provenance and semantics. Distinguish SQL
   text from bind values, outbound URL from body, and generated creation from an ordinary callback.
2. Phases 5–6: propagate field/value identities through helpers, aliases, mutations, guards, matched
   calls/returns and supported async continuations; preserve bypasses and unresolved behavior.
3. Phase 7: automatically assemble the same claim-scoped bundles used by checked mode. Include
   actual relevant function bodies, import/receiver provenance, schema/model constraints and blockers.
4. Phase 8: derive intrinsic questions from the sink model (for example, can input change SQL
   structure?). Keep explicit business requirements separate from inferred constraints. Label inferred
   requirements and their provenance; unknown business intent is not a demonstrated violation.
5. Phases 1/8/9: evaluate unseen vulnerable/protected/unknown repositories, independently review
   findings, and retain evidence/coverage in route-oriented JSON and SARIF.

The defensive rule is the tightest validation the business field allows, plus sink construction
that does not let the value change a query, update, or insert. A string or length check is not
injection protection. A comment or other free-text field may contain any character, so an allow-list
is the wrong fix and the statement must bind the value. Applicable middleware is part of the
validation path. A missing validator call is
`input_validation_absent`. A call that merely receives the field is `input_validation_unresolved`.
String-built SQL, `Op.like` templates, and NoSQL `$where` strings are `query_text_interpolated`.
A request value inside a collection query, update, or insert document is
`query_document_unvalidated`. A logged SQL string and `Array.find` are not query sinks. These facts
are candidates for agent fixes. They do not prove exploitability, and they do not turn a bound
query into a structure defect.

The bounded scanner now enters supported same-file functions and relative-imported named exports
while discovering SQL candidates. Positional identifier parameters and direct returns are
source-backed witnesses, limited to three nested calls and 24 expansions per handler. A declared SQL
check that finds no candidate records `sql_sink_missing` rather than an empty use list. Closures,
rest and destructured parameters, recursion, mutation and asynchronous continuations remain
unresolved. This is not repository-wide graph analysis.

Structural source/sink models remain necessary even when the judge recognizes arbitrary custom
validators. They establish what a value controls and what protection the operation requires; they do
not need a hard-coded regex for every adequate validator. The current bounded implementation cannot
yet guarantee detection of arbitrary novel repository flaws. See the
[original comparison corpus](../evaluation/corpus/README.md) for the current evaluation boundary.

## Declared library models

These are bounded semantic assumptions, not evidence that dependencies are trustworthy or runtime
bindings cannot change. Unknown/custom middleware and unmodeled operations remain blockers.

| Model | Current use and limits |
|---|---|
| ESM and Express receiver/registration subset | Direct registrations, named/namespace imports and direct/concise factories; required mount/path cases are explicit |
| Generic parser/header/logging/static middleware | Known imported transport/parser packages supply context without being treated as domain-field validators; custom middleware bodies are supplied separately |
| Sequelize raw query | Constructor/import provenance is supplied as source evidence identifying the modeled API; SQL text and parameter options have distinct roles; mutable/dynamic binding is not universally resolved |
| finale-rest generated resources | Supported direct resource declaration or literal table/for-loop/template expansion associates create endpoints with an imported model; arbitrary route generation is unsupported |

Model declarations are independent of validator adequacy. Exact package version compatibility,
custom extensions, setter effects and runtime behavior still need validation. Upstream references:
[Sequelize raw queries](https://sequelize.org/docs/v6/core-concepts/raw-queries/) and
[finale resource semantics](https://github.com/tommybananas/finale/blob/master/README.md).

## Shared trace contract

The implemented [trace and judgment design](trace-judgment.md) adds explicit dependency/control
relations and a supplied/missing evidence-role ledger without relaxing claim completeness.
Validation has a separate policy-backed protocol; query binding cannot satisfy field requirements.

## Claim-specific completeness and outcomes

Required evidence roles are checked before a candidate becomes eligible for a scoped finding.
Missing route/helper/operation/model facts and unknown applicable guards block their affected claims.
Unrelated metadata, password-only transformations in an email SQL claim, or post-request response
coverage do not automatically block an independent earlier use. Gaps remain visible even when they
do not block a particular claim. Unclassified legacy candidates retain conservative uncertainty.

A missing guard body is not made irrelevant just because the judge says insufficient. An unknown
validator that receives the checked field remains a blocker. An unrelated helper must be excluded
by dependency/context selection, not by a target-specific exception. Tests cover both directions.

| Result | Meaning |
|---|---|
| `supported_potential` | Model finds insufficient protection; required evidence roles exist and no declared claim blocker remains, under the stated models/scope |
| `protected_for_claim` | Model finds sufficient protection for this exact stated constraint and supplied scope |
| `needs_evidence` | A relevant fact/role is missing, a limit was hit, or the model is uncertain |
| `not_applicable` | The declared protection question does not apply; not a general safety conclusion |
| Assessment failed / not_run | No completed semantic judgment; never a safe or confirmed finding |

These statuses are advisory source-analysis findings, not runtime-confirmed exploitability, formal
proof, or completed independent Findings Review. Positive findings need a supported violating case;
adequate-protection claims need the relevant paths/invariant. Future precision work must verify
coverage of mutation, aliases, middleware applicability, asynchronous effects and library extensions.

## Two phase acceptance cases

**Login email and SQL:** keep email type/format separate from SQL query semantics. The email
operand's parameter separation is the primary injection question; hashing a different operand or
accepting a syntactically valid email cannot establish it. The desired remediation set includes
parameterized SQL, server-side field constraints and negative/safe regression cases. Current SQL
call-shape checks are not universal SQL parsing or a complete driver/library resolver.

**Registration:** evaluate required email/password checks when passwordRepeat is absent, validation
before/after trimming, next()/return behavior, model validators, setters and hooks, and generated
creation. A challenge observer is not a rejecting validator or proof that a row was created. Detailed
source observations and test caveats live in the [registration case](../project/07-registration-validation-case.md).

Controlled fixtures must include vulnerable, protected and unknown variants. Test that model-irrelevant
gaps do not force uncertainty and that unknown guards still do. The source-path/role/golden tests
verify evidence assembly; fixed HTTP answers verify policy/transport, not model accuracy. Small
Luna-only calls on the pinned target are integration checks. Runtime confirmation additionally needs
an isolated application test and a persisted-row assertion; it has not been performed in this phase.

## Reporting and remediation

The [report design](reporting-and-sarif.md) keeps one route-oriented internal model and a SARIF export.
Report observed facts, model assessments, blockers, assumptions, reviewer status and runtime evidence
separately. Provide multiple complementary remediation options, with their required preconditions and
regression cases. Do not turn a generated suggestion into an applied fix or claim the route is immune.
