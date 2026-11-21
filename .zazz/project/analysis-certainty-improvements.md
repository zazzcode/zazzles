# Making scan results more definitive

**Planning update, 2026-11-01.** User feedback asks how to resolve the HTML report's uncertainty and
reduce **Review** as analysis improves. These are proposed increments, not implemented capabilities
or authorization for additional paid calls. Select an analysis increment deliberately rather than
expanding that detector into a general engine rewrite.

## Target behavior

A result should explain the specific question, available evidence, remaining blocker, and how that
blocker could be resolved. Keep **Findings**, **Review**, and **Protected** as the UI headers, and use
**Categories** for overlapping family labels. Findings count distinct supported issues, not source
operations or category pills. A single operation can have separate validation and query-protection
claims, but uncertainty about a field requirement is not a second established validation finding.

The [root philosophy](../../docs/philosophy.md) owns the remediation-first policy: established poor
practice is a finding worth fixing without proof of exploitation; Review is for uncertainty about
the problem or protection. A true positive means the evidence supports the named weakness or
practice violation within the declared scope. A static
finding need not claim a demonstrated exploit. Conversely, model agreement, a matched method name,
or an observed string construction does not establish every precondition of injection. Define the
required facts for each weakness/practice rule, preserve independent-review status, and reserve
runtime confirmation for separately authorized controlled testing.

## Acceptance target: automatic login SQL-injection judgment

The user reports successfully exercising Juice Shop's login SQL injection. Treat this as a known
positive acceptance target at the pinned revision, not a manual verdict to overlay on reports.
The scanner must independently establish the actual SQL API, request-controlled email operand,
interpolation into executable statement structure, reaching definitions, and relevant guard/parameter
separation facts. Add protected and unknown paired cases to ensure the rule does not merely recognize
the route name, known target, or a user's annotation. Define the supported proof boundary explicitly.

A definitive vulnerability result should upgrade the same named SQL issue, preserving its evidence
and separate validation concerns; it must not double-count practice and vulnerability for that same
issue. The soft-red UI treatment is reserved for the resulting scanner-supported verdict. Until the
analysis supports it, retain truthful practice/Review output. Larger models, test labels in prompts,
and manual confirmation overrides are not substitutes for the required evidence.

## What the current message actually means

The generic paragraph in [report interpretation](../../scan/internal/report/findings.go) is appended to
all records. Its mention of missing library behavior, control flow, and middleware is not a
claim-specific blocker analysis. The additional messages do correspond to current report state:

| Message | Current cause | Evidence needed to resolve it |
|---|---|---|
| Missing library behavior | Calls are classified partly by shape; [flow extraction](../../scan/internal/langjs/flow.go) adds `sink_binding_unverified` | Resolve actual import/receiver, package/API semantics, argument role, and binding behavior |
| Control flow unresolved | Branches and helper returns can merge possible values without proving path feasibility | Supported successor/termination edges, reaching definitions, and guard/value relationships |
| Middleware unresolved | Extraction adds a conservative gap; some [middleware context](../../scan/internal/langjs/middleware_context.go) is available, but effective enforcement is incomplete | Applicable order, mount/path/method matching, rejection versus continuation, and relevant mutations |
| No direct request-field dependency | The use has no resolved dependency; this does not prove its value is constant or trusted | Source origin and transfers, or positive evidence of a trusted constant; callback/tool inputs need explicit modeling |
| Semantic assessment was not run | The saved run was offline | Use the decision model to assess the source-backed claim. Deterministic practice evidence remains available offline. |

The current [checked-mode implementation](../../scan/internal/langjs/checks.go) already separates some
claim blockers from coverage gaps and resolves selected SQL bindings. Extend and validate that
mechanism for automatic claims and additional operations instead of discarding the existing work.

## Prioritized increments

| Priority | Improvement | First concrete acceptance example | Exit evidence |
|---|---|---|---|
| 1 | Atomic claims and claim-specific completeness | Separate order-ID field policy from NoSQL expression protection on `/rest/track-order/:id` | Independent claim IDs, required evidence, status, and remediation; unrelated gaps cannot block or establish a claim |
| 2 | Proven library/API identity and operation slots | Distinguish raw Sequelize SQL text, bound parameters, ORM `Op.like` values, and NoSQL `$where`/selector/update slots | Aliases, shadowed methods, look-alike APIs, pinned model versions, and safe/unsafe/unknown controls; no promotion from names alone |
| 3 | Source and value tracking across callbacks/wrappers | Follow chat-tool arguments through destructuring and `execute`, and through supported imported helper parameters/returns | Actual source provenance and argument-to-parameter witnesses; unsupported invocation contracts stay Review |
| 4 | Guard and effective-middleware enforcement | Trace the configured filter/conversion/truncation branches in `trackOrder`, plus registration rejection/`next()` paths | Enforcing checks dominate the named use; rejected paths terminate; reassignment/bypass paths tested; unknown configuration yields scoped conditional results |
| 5 | Relevant helper summaries and bounded slicing | Avoid re-expanding unrelated challenge/webhook helpers for every validation or query claim | Dependency-scoped summaries with complete cache keys, fewer distinct blockers, preserved detection coverage, and explicit limit exhaustion |
| 6 | Evidence-ready semantic assessment and independent verification | Assess custom validators whose bodies and enforcing paths are actually available | Capped explicit provider/model runs, validated typed answers, preserved disagreements/failures, and held-out labels; no invented missing edges |

### 1. Claims and useful uncertainty explanations

Create one finding/review record per distinct rule or constraint and operation slot. Link related
records through a shared operation ID and existing route/use provenance. Keep validation requirements
explicit: a comment can allow punctuation, while an order identifier may have a specific domain.
Absent business policy cannot establish a format violation. SQL binding and domain validation can
produce different statuses at the same location.

Replace the universal paragraph with per-claim blockers, each carrying source location, reason,
affected fact, and suggested next evidence. Show coverage gaps separately. Model availability and
execution status are separate from missing source facts. Do not require semantic assessment for a
fully specified deterministic rule, or remove a relevant blocker merely because a model answered.

### 2. Library models with proven provenance

Reuse binding resolution and add small versioned models for the APIs actually used by the corpus.
Inspect imports, aliases, constructors, dependency metadata, and receiver identity before applying a
model. Record verified argument roles: executable text, bound data, selector keys, update values,
URL destination, and log payload are different slots. Unsupported versions or wrappers remain explicit.

An ORM `Op.like` value can contain interpolation without becoming executable SQL. NoSQL documents
can safely carry constrained values. Tests must recognize valid protection as well as unsafe shapes;
matching `.query`, `.find`, or `.update` is insufficient to decide either outcome.

### 3. External sources beyond direct request reads

Handle supported destructured parameters, imported wrappers, closure captures, and callback argument
bindings incrementally. For the chat case, the tool schema and an `execute({query})` body do not alone
prove the HTTP request-to-tool invocation path. Model that invocation boundary explicitly and retain
its trust assumptions. A tool argument can be externally influenced without being a direct `req.*`
field; record the actual origin rather than fabricating that direct dependency.

Distinguish known constants, known external sources, derived/indirect sources, and unresolved values.
“No dependency resolved” means unknown unless the scanner has positive evidence of independence.
Apply the same discipline to eventual logger payloads and asynchronous outbound-response values.

### 4. Path and guard semantics

Track the exact value reaching each use through assignments, conversions, branches, and returns.
Model both guard outcomes and whether rejection really stops execution. Link middleware to the
actual route, order, and mount scope; middleware reading a field is not evidence of enforcement.

For `trackOrder`, evaluate filtering and truncation paths separately. For review lookup, inspect
`Number(id)` and the possible resulting values before claiming expression injection. A conversion
might prevent syntax control without meeting the identifier's domain/range requirement. Unknown
configuration must not silently select the vulnerable or protected path for the entire route.

### 5. Relevant summaries and limits

Measure distinct gap locations and affected claims, not only repeated gap occurrences. In the saved
Juice Shop UI run `run-3847474605`, 695 use-attached `helper_call_limit` occurrences reduce to 11
unique kind/file/start-byte locations. This measures duplication, not proof that only 11 semantic
problems exist. Shared helper expansion and gap propagation deserve targeted investigation.

Build function summaries for supported input/return/mutation/sink effects. Cache by source snapshot,
binding and call context, relevant value facts, model version, and analysis configuration. Slice from
the claim's source and operation, while preserving facts that may influence reachability or guards.
Increasing traversal limits can be a measured experiment; it is not a substitute for relevant slicing.

### 6. Assessment and verification

Assemble a compact source-backed claim for the decision model to assess custom check adequacy
or operation semantics. A semantic answer cannot prove an absent control-flow edge,
identify an unresolved library by guessing, or turn missing source provenance into a trusted source.
Keep the existing provider/model restrictions and small explicit request caps. This planning change
makes no live calls and authorizes no target execution.

Build paired vulnerable/protected/unknown cases and independent held-out labels for each increment.
If runtime confirmation is useful, design a separately authorized isolated harness; preserve its
revision, inputs, observations, and scope. Static Findings, independently reviewed Findings, and
runtime-confirmed behavior must remain distinguishable.

## Measure progress without hiding uncertainty

Track distinct claims moving from Review to Findings or Protected, with the supporting evidence and
rule/model version. Also record unresolved claims by reason, missed known weaknesses, false positives,
false protected results, coverage, cost, and runtime. An explicit not-applicable outcome is different
from a protected claim. Retain unresolved cases in the denominator and preserve deferred/skipped work.

Choose accuracy thresholds and scope before held-out evaluation. Fewer Review records are useful
only when their questions are resolved correctly, rather than filtered out or relabeled. Regression
fixtures should include same-name non-database methods, real binding, free text, ineffective guards,
configuration-dependent branches, sanitizer aliases, async callbacks, and shared-helper repetition.

The [reporting design](../architecture/reporting-and-sarif.md),
[evidence design](../architecture/evidence-and-claims.md), and
[finding-type glossary design](../architecture/finding-types.md) own implementation semantics;
this document owns the proposed improvement sequence and first acceptance targets.
