# 01 — Proposed functionality

**Concept-stage proposal, 2026-10-19.** These are desired capabilities, not built or accepted behavior.
Technical context: [architecture](../architecture.md). Delivery boundaries:
[scope](02-project-scope.md) and [implementation plan](implementation-plan.md).

**Provider decision (2026-10-31):** the [architecture](../architecture.md#current-provider-decision)
owns the current provider decision; this document defers to it.

## Purpose and users

Zazzles aims to help developers and coding agents assess security, quality and dependencies,
then repair established issues with verification. Current bounded Scan behavior is described in the
[README](../../README.md#scan-current-implementation). This catalog also records planned functions.

## Four product capabilities

**2026-11-05 direction:** keep Scan, Inspect, Audit and Fix distinct as product responsibilities.

| Capability | Functional goal | Status |
| --- | --- | --- |
| Scan | Assess source-backed security vulnerabilities and controls | Bounded current implementation |
| Inspect | Assess correctness, maintainability, hygiene and defined coding/architecture standards | Planned distinct capability, building on existing validation and construction-practice checks |
| Audit | Assess dependency/advisory evidence independently of source reachability | Planned |
| Fix | Help an agent remediate supported issues from all assessment capabilities, test and reassess | Planned |

Inspect and Scan share supported extraction, models, semantic judgment and evidence policy. Inspect
checks may use a function/module scope rather than a security input-to-sink trace. Each claim needs
its own applicable requirement, evidence and completeness obligations. No missing standard may be
invented from a model's preference.

Future presentation SHOULD separate security findings and quality assessments with linked evidence
for overlapping concerns. A validation defect MUST NOT become an injection vulnerability by label
alone, and policy compliance MUST NOT become a security certificate. Prioritize by impact within
clear assessment domains. Linked claims must avoid duplicate issue counts.

Review remains the unresolved-evidence report category. Independent Findings Review remains a
planned verification stage, not the name of the quality capability. This documentation changes no
current command, output schema, classification or detector. Broader Inspect and Fix need separate
contracts. The [analyzer and pack architecture](../architecture/analysis-packs.md) organizes knowledge
for the SQL Injection Analyzer, NoSQL Injection Analyzer, Input Validation Analyzer and XSS Analyzer,
plus outbound observations. The Sensitive Data Logging Analyzer remains a separate catalog migration;
this internal organization does not implement general Inspect or Fix capabilities.

### Independent use and optional composition

Scan, Inspect, Audit and Fix MUST support independent use in any order as they are implemented.
Users can select one capability or compose an agent feedback loop. Fix may start from an existing
report or a user-specified issue with the required source context. It MUST NOT require fresh runs
of all assessment capabilities merely to begin a repair.

Each capability still needs its own valid inputs, supported evidence and verification. Independent
use does not waive tests or scoped reassessment of a repair. Current commands remain unchanged.
Future command/API details require their own contracts.

## Analyzer vocabulary

Use the [canonical terminology](../architecture.md#analyzer-terminology): an **Analyzer** is an
assessment capability; an **analysis pack** supplies its versioned interpretation knowledge;
**analysis components** are reusable knowledge items; the **shared analysis engine** supplies common
infrastructure. The XSS Analyzer includes reflected, stored and client-side/DOM/framework capabilities.
The Command Injection Analyzer is implemented for Node `child_process` and Python `os`/`subprocess` under a declared POSIX assumption. Names do not imply complete language/framework coverage.
The [capability checklist](implementation-plan.md#supported-capability-checklist) owns delivered status.

## Detection modes

| Mode | Proposed behavior | Evidence and limits |
|---|---|---|
| Track A: deterministic rules | Match explicit known-risk conditions without a semantic judge | Rule ID, supported constructs, source spans; reproducible does not mean certainly exploitable |
| Track B: flow plus semantic judge | Trace supported string dependencies to a sink; assess validation/sanitization adequacy | Witnesses, guard facts, separate validation/sanitization facets, typed assessments |
| Findings Review | LLM reviews every identified rule/judge issue and uncertain candidate against source evidence | Supported, disputed, or needs more evidence; separate review status and cited evidence IDs |
| Structural-only operation | Run local analysis without credentials or external calls | Pattern findings and path candidates; semantic evaluation explicitly `not_run` |
| Track C: future bounded scope checks | Assess explicitly enumerated authorization/logic questions | Deferred; separate evidence contract, corpus, and specs required |

The configured judge (GPT Decisions or Jev) is the primary semantic assessor; the LLM Findings Reviewer is the planned review stage for
identified issues. No mode claims complete OWASP Top 10 coverage. Reports preserve source evidence,
Decision Assessments, and reviewer conclusions separately. A skipped/failed review stays explicit.

## Functional domains

| Domain | Proposed capability |
|---|---|
| FD-1: input selection | Deterministic manifest, language/path selection, ignore policy, skipped-file accounting |
| FD-2: extraction | Tree-sitter CSTs and versioned query captures with exact source locations |
| FD-3: normalization | Language adapters emit operations, symbols, blocks, values, and provenance |
| FD-4: resolution | Resolve supported imports, call targets, handlers, parameters, returns, and framework registrations |
| FD-5: classification | Identify sources, sinks, and candidate guards through rules/library models |
| FD-6: local flow | Track declared assignments, expression dependencies, branch joins, and bounded loops |
| FD-7: cross-function flow | Propagate supported argument/parameter and return dependencies through bounded summaries |
| FD-8: deterministic rules | Detect tested patterns and rule-specific mitigation facts without inference calls |
| FD-9: path candidates | Produce bounded source-to-sink witnesses; deduplicate and account for unexamined candidates |
| FD-10: evidence preparation | Bundle snippets, spans, bindings, guards, sink semantics, and completeness markers |
| FD-11: Decision Assessment | Use provider-specific typed questions about validation/protection; normalize responses and preserve uncertainty |
| FD-12: findings review and policy | LLM reviews identified issues and uncertain candidates; Go reconciles separate assessments, exposes disputes/incomplete review, and applies policy |
| FD-13: reporting | Route-oriented canonical JSON and human reports; bounded SARIF findings/code-flow export; stable baselines remain planned |
| FD-14: finding identity | Stable identity independent of model predictions; group related source traces |
| FD-15: comparison and baseline | New/persisting/changed assessments, reviewable suppressions, explicit incomplete-scan semantics |
| FD-16: incremental rescan | Reuse unchanged artifacts with dependency- and version-aware invalidation |

Optional name/pattern-based sensitive-data tags may inform prioritization later. They are heuristic
signals and are not proof of sensitive runtime data.

<a id="initial-rule-families-and-coverage"></a>

## Initial analyzer capabilities and coverage

The first feasibility slice focuses on a few JS/TS source-to-sink families. Expand only after measuring
safe/vulnerable pairs and unsupported constructs.

| Analyzer / capability | Candidate evidence | Mitigation distinctions to test |
|---|---|---|
| SQL Injection Analyzer | Source-derived query fragments, query API, parameter positions | Bound values versus dynamic identifiers or SQL fragments |
| NoSQL Injection Analyzer | Initially MongoDB/Mongoose and MarsDB-compatible filters; other engines need separate API models/rules/guidelines | Scalar coercion, schema enforcement, operator/object allow-lists; findings name the actual database/driver |
| Command Injection Analyzer | Shell command construction and execution mode | Shell interpolation versus argument-vector execution; executable/option control |
| Path Traversal Analyzer | Untrusted path parts reaching filesystem operations | Normalization versus enforced base-directory containment |
| SSRF Analyzer | Untrusted input affecting an outbound request target | Host/scheme restrictions, redirects, unresolved runtime/network behavior |
| Unsafe deserialization / HTML injection | Input reaching a relevant API or output context | Type- and context-specific protection |
| Pattern-only configuration / crypto | Explicit risky API/configuration use | Precisely documented rule preconditions and counterexamples |

Not every occurrence of `exec.Command`, SQL construction, a regex, or a validation API is a
vulnerability or a mitigation. Rules declare what they establish and when the case needs more evidence.
Missing authorization, insecure design, and deployment-dependent configuration cannot be inferred
reliably from an arbitrary code pattern alone; broad coverage of those remains future work.

OWASP mappings include an explicitly selected edition in the future catalog. CWE mappings and severity
come from reviewed rule metadata. The old unversioned A01–A10 list is retired rather than carried
forward as a release commitment. Dependency vulnerability scanning is outside this initial Scan slice and belongs to the planned Audit capability.

## Language sequence

The committed language sequence is JavaScript, TypeScript, Python, and Go. JavaScript and
TypeScript and a bounded Python adapter are implemented; Go remains future work. Each adapter
includes extraction, resolution, lowering/flow semantics, library models, and a coverage matrix.
Recognizing a file extension is not analysis support. A new language may expose core IR changes
that need a contract revision before that adapter claims the same query and validation findings.

## Trace-backed judgments and remediation

The shared [trace judgment pipeline](../architecture/trace-judgment.md) supplies Luna with
source references, dependency/control relations, actual helper implementations, field policy,
operation slots, API contracts and explicit missing evidence. Adapters supply language facts;
the shared judge assesses exploitability and recommended protective patterns for that exact use.
It does not infer arbitrary validation rules from field names or benchmark labels.

Policy-backed validation claims distinguish unmet server requirements, enforced constraints and
missing evidence. Flask form constraints currently supply named policy for Python claims; this
mechanism does not establish general framework schema coverage. Injection, construction practice,
validation, output escaping and log-content sensitivity remain separate judgments.

Reports reserve green for protected claims, retain raw model answers and show precise blockers
for inconclusive results. Defect guidance names source operands and requirements, with narrow
source-derived candidate replacements where supported. Protected guidance preserves demonstrated
patterns. Model requests are bounded and saved decisions require exact matching evidence.

## Interfaces and report semantics

The source-level CLI foundation currently present is `scan --list [--json] <path>`, `scan --routes [--json]`,
and `scan --analyze [--json]` with entry/route selectors, checked-mode requirement files, and bounded
JSON/HTML/SARIF export. All further analysis interfaces are future spec work. Inspection of graph,
classifications, witnesses, and explanation bundles is desirable, but exact flags/subcommands beyond
these are not decided by this document.

Security reports should include detection mode, source/sink evidence, rule/CWE/OWASP metadata,
severity policy, assessment status, model/question versions when used, and coverage gaps. Evaluation
states distinguish `not_run`, `completed`, and `failed`; a completed semantic assessment can be
`uncertain`. Neither a request failure nor absent credentials produces a safe verdict.

Stable candidate identity is distinct from current risk assessment. A changed assessment remains
visible even when the fingerprint is unchanged. A missing result from an incomplete scan cannot be
reported as resolved. CI policy and future security exit codes need their own spec.

## Decisions before specs

The [proposal register](03-jev-design-proposal.md#open-decision-register) tracks first-slice selection,
semantic-policy requirements, CI behavior, and allowed source transmission. The
[evaluation protocol](04-jev-validation-research.md#proposed-corpus-and-evaluation-protocol) defines
how to assess the resulting capability choices.

## Follow-on dependency auditing

After the code-path foundation, add SCA through ecosystem audit adapters: npm/pnpm audit and
pip-audit initially. Preserve package/version/advisory evidence independently of route reachability.
The [SCA design](../architecture/sca-design.md) owns milestones and adapter boundaries. Source and
SCA findings share route/context-aware reporting without equating their evidence or coverage.
