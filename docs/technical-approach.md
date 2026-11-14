# Technical approach and design strengths

[Documentation](README.md) · [Philosophy](philosophy.md) · [Implemented architecture](../.zazz/architecture.md)

## Source-backed analysis with constrained semantic judgment

Zazzles establishes supported code relationships through static analysis, then uses a decision model
to evaluate whether the demonstrated controls satisfy a specific security requirement. Evidence
validation checks completeness and consistency before classification. The intended output helps a
developer or coding agent decide what to repair, what protection to preserve and what uncertainty to investigate.

The Go scanner reads application source, resolves supported language/framework bindings and follows
values into security-sensitive operations. Each candidate carries source spans and hashes, relevant
helpers, branch conditions, operation operand roles, library contracts and unresolved facts. The
semantic judge receives this evidence together with versioned language **Analysis Guidelines**.
The [architecture](../.zazz/architecture.md#evidence-validation) defines the deterministic evidence
checks applied to the model answers; the predictions themselves are not assumed deterministic.

The model is part of security judgment, rather than only a prose explanation of a preexisting alert.
It does not generate the source relationships or fill missing code with assumptions. Source text is
evidence data; scanner-supplied guidelines define the interpretation instructions. JSON preserves
both evidence and raw answers, while HTML and SARIF present the validated result.

A custom validation function illustrates the intended benefit. When its implementation, actual value
transfers and relevant conditions are supplied within supported paths, the judge can assess whether
the control is adequate for the operation without requiring a named sanitizer rule for that particular
function. This is bounded interpretation of supplied evidence, not an ability to discover arbitrary
missing code or prove every custom validator correct.

**Semantic judgment reduces the need to enumerate every acceptable implementation pattern; it does
not eliminate the need for analysis models.** Input discovery, handler resolution, supported
transfers and library argument roles still need explicit engineering. Discovery misses never reach
the judge; unresolved claim-relevant facts remain blockers. Reduced false findings and improved
coverage remain hypotheses to measure alongside false protection, abstention, latency and cost.

## Shared analysis across distinct product goals

The product goals are **Scan** (source security), **Inspect** (correctness and engineering standards),
**Audit** (dependency/advisory assessment) and **Fix** (verified agent remediation).
Scan is implemented with bounded coverage. A distinct Inspect capability, Audit and automated Fix
remain planned. Existing validation and construction-practice findings provide a quality foundation
inside today's scanner.

The separation is in assessment purpose, claim semantics and future report organization. It does
not require duplicate engines. Analysis components can support security claims, quality claims or
both, with the required evidence for each. Fix can consume supported issues from all three assessment
capabilities while preserving intended behavior and existing controls.

Future reporting should keep security and quality views distinct, link overlapping evidence and
avoid duplicate issue counts. Priority depends on impact rather than assuming quality defects are
always minor. Review remains the outcome for unresolved evidence. It is not another capability name.
These goals do not change the current CLI or report schema.

The intended capabilities are independent and can run in any order once implemented. A user can
select an assessment or give Fix an existing report or a specific issue. Each operation still needs
its own evidence and verification. The proposed agent feedback loop is optional composition rather
than a requirement to run all four capabilities.

## Code quality and engineering hygiene

Zazzles's objectives also include code quality and best practices. Current input-validation and
selected construction-practice checks already identify defects worth repairing independently of
exploitability. For example, a missing enforcement step for an established field requirement can
remain a defect while a separate SQL-binding claim is protected.

The same evidence discipline can support broader standards in future: name the applicable
requirement, supply the implementation and relevant context, then assess compliance with explicit
limits. Deterministic checks suit mechanical properties. Semantic judgment is useful for contextual
questions, but cannot invent an engineering standard or supply missing evidence.

Broader reliability and maintainability coverage remains planned. The
[analysis pack proposal](../.zazz/project/analysis-pack-mvp.md#security-code-quality-and-engineering-hygiene)
includes quality claims as future consumers of the modular structure. Inspect compliance and
security protection must remain distinct. The implemented component migrations organize existing
Scan analyses without implementing a general quality platform.

The longer-term agent workflow uses team-approved coding and architecture standards as explicit
assessment requirements. Agents create code, consume security/quality evidence, make repairs, then
run tests and reassessment before review. Users need not adopt the project's Zazz methodology.
Zazzles's internal development standards are not automatically loaded as policy for target code.

A model's learned coding knowledge helps interpretation but does not define a team's policy.
Zazzles already supplies versioned language guidance, claim questions and applicable API contracts.
Broader quality baselines and optional team standards are planned so users need not author every
rule. Standard-based findings need an identifiable requirement and evidence. Exploratory suggestions
must remain distinguishable from established defects and compliance claims.

This complete loop, general standards selection and broader architecture-quality checks remain
planned. The [pack proposal](../.zazz/project/analysis-pack-mvp.md#standards-driven-agent-workflow)
defines the intended boundaries. A passing scoped assessment cannot certify all standards or replace
functional tests and review.

## The distinctive design choices

The useful distinction is the combination and enforcement of these boundaries. It is not a claim that
syntax parsing, dataflow, taint analysis, model-assisted security review or SARIF originated here.

| Design choice | Practical strength | Current boundary |
|---|---|---|
| Separate claims for validation, construction and use protection | A fix can address the exact defect while preserving an existing control | Reports still group several concerns within one operation record |
| Source-backed evidence roles and claim blockers | A confident model answer cannot turn absent bindings, helpers or policies into protection | Incorrect extraction or an incorrect answer can still produce a bad result |
| Analysis Guidelines plus actual helper/guard evidence | Semantic questions can consider an implementation rather than only a validator's name | Custom behavior is judged only within resolved, bounded paths |
| Findings, Review and Protected outcomes | Agents receive both repair work and scoped controls to preserve, plus explicit investigation gaps | Protected applies to the named claim, not the route or whole application |
| Entry/dispatch invocation context and bounded stored/cross-tier links | Shared handlers keep separate input/control facts for each exposure; review can connect supported producer and rendering contexts | Framework discovery, dynamic dispatch, storage identity and cross-tier coverage remain bounded |
| Versioned evidence, guideline documents and exact-request replay | A historical decision remains auditable and cannot silently move onto changed input | Replay is explicit; an automatic persistent decision cache is not implemented |
| Shared language-neutral analysis records and reporting | JS/TS and Python use the same claim gates and output semantics | Each language still needs its own correct framework and flow models |

For example, a signup handler can bind an email safely into SQL while enforcing only presence, even
though the matching form establishes an email-format requirement. Zazzles can preserve the SQL-binding
claim and separately report the unmet validation policy. Conversely, a missing business requirement
stays Review: the model cannot invent a restriction merely because the field has a familiar name.
A construction defect can also merit repair without establishing an injection exploit.

## Relationship to established SAST

The common-entry design follows established static-analysis principles: represent program structure,
resolve possible call targets, bind inputs to particular invocations and track values separately from
control reachability. Other tools need not use Zazzles's record names or identical boundaries to
implement related analysis. This comparison concerns architectural ideas, not equivalent coverage.

### Research references and inspiration

We studied the following SAST approaches for design ideas and evaluation. Conventional SAST includes
structured program models, framework semantics and dataflow analysis, not only textual matching.
These references inform Zazzles's engineering; they do not establish equivalent coverage or quality.

| Tool/reference | Approach and ideas studied | Role in Zazzles research |
|---|---|---|
| [CodeQL](https://codeql.github.com/docs/writing-codeql-queries/about-data-flow-analysis/) | Local/global dataflow, source/sink models, taint steps and path queries | Architecture and semantic-model reference; not a measured CodeQL benchmark or a Zazzles runtime dependency |
| [Joern / Joern Scan](https://docs.joern.io/scan/) and [Code Property Graph](https://docs.joern.io/code-property-graph/) | Shared program representation across language frontends; graph relationships, traversals and predefined security queries | Architecture reference reviewed for common representations and query-driven scanning; no Joern comparison run or integration is claimed |
| [Bearer](https://docs.bearer.com/guides/dataflow/) | Go/Tree-sitter language adapters and flow/reporting patterns studied in its pinned source; reports exposing classifications, source locations and components | Read-only implementation study plus pinned local comparison scans; see the [research record](../.zazz/project/05-prior-art-and-feasibility.md#bearer-inspection-provenance) and [baseline runbook](samples/nodejs-goof/bearer-runbook.md) |
| [Semgrep](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview) | Pattern rules and taint models for sources, propagation, sanitization and sinks | Rule/model reference plus pinned Community Edition comparison scans; CE evidence does not establish the capabilities or performance of every edition |

Bearer and Semgrep CE baselines are scope-specific observations on selected applications, not
rankings of whole products. CodeQL and Joern are architectural research references here, not executed
benchmarks. Studying these approaches does not imply their engines, source or rule sets are embedded
in Zazzles. The [prior-art record](../.zazz/project/05-prior-art-and-feasibility.md) retains research
provenance and the boundaries of implementation reuse.

### Relationship to Joern Scan

There is a broad similarity: extract program structure, preserve relationships and source locations,
evaluate security properties, and report findings. In the
[documented Joern Scan workflow](https://docs.joern.io/scan/), Joern generates a Code Property Graph,
runs a selected bundle of predefined queries against it and reports matches. Its queries can express
structural and flow-related analysis; the approach is more than a text-pattern scanner.

Zazzles is not Joern Scan with a model added. Its current static engine uses Tree-sitter, typed Go
entry/dispatch records and bounded language-specific flow/evidence assembly, rather than Joern's CPG
backend or a full repository IR. Go records deterministic findings where the construction is
established. The decision model assesses claim-specific security questions about supplied code,
including controls and operation roles; Go then applies evidence-completeness and consistency gates.
It is part of judgment, not just an explanation appended to an alert.

The model cannot create a missing call/argument binding, assume a generated route exists, or turn an
unresolved trace into protection. Thus the distinction involves both the representation and the
judgment contract, not merely adding AI to an otherwise equivalent scanner. Neither architecture
implies equal language coverage, trace depth, accuracy or runtime cost. This comparison concerns the
documented Joern Scan pipeline, not every possible extension built on Joern.

Model assistance also has prior art. IRIS combines static analysis with LLM-assisted specification
inference and contextual path review. Semgrep describes AI-assisted triage and remediation on top of
its deterministic engine. Zazzles's hybrid structure therefore does not establish research novelty
or exclusive use of semantic reasoning. [IRIS authors' repository](https://github.com/iris-sast/iris),
[Semgrep's technical description](https://semgrep.dev/blog/2024/the-tech-behind-semgrep-assistant/)

Zazzles's intended advantage is a precise workflow around source-backed, separately named security
claims: explicit evidence gaps, semantic interpretation of supplied code, preservation of sufficient
protection and targeted repair guidance for agents. These are implemented design strengths; the size
of any advantage over another scanner must be measured on matched cases. Mature tools may have
broader framework coverage, deeper flow models and production workflows that Zazzles does not yet have.

<a id="analysis-knowledge-and-proposed-packs"></a>

## Analysis knowledge and components

An **Analyzer** is a named assessment capability, such as the **SQL Injection Analyzer** or **XSS
Analyzer**. Its **analysis pack** supplies applicable versioned knowledge, composed from reusable
**analysis components**. The **shared analysis engine** supplies parsing, flow/evidence, judgment and
reporting infrastructure. Reflected, stored and client-side/DOM XSS are capabilities within the XSS
Analyzer. These terms describe responsibilities, not separate engines or Go packages. See the
[architecture vocabulary](../.zazz/architecture.md#analyzer-terminology) for the canonical definitions.

Analysis knowledge ships in the binary: compiled language/framework and flow adapters, verified API
contracts, embedded Analysis Guidelines, claim questions and Go evidence policy. Application `--checks`
files supply requirements and selection; they do not add a parser or vulnerability detector. Editing
a public analysis guide alone does not change the running judge's instructions.

The SQL Injection Analyzer, JS/TS NoSQL Injection Analyzer, Input Validation Analyzer and XSS
Analyzer now consume the internal component catalog. Language
guidance, entry/flow capability references, applicable operation/rendering contracts, family questions
and evidence obligations have
explicit identities, versions, digests, applicability and test references. Static assembly selects
components from supported source facts; the judge uses that selection and receives only applicable
interpretation material alongside the candidate trace. Executable adapters remain compiled, and Go
checks mandatory evidence and consistency gates. A component cannot invent a binding, clear a gap or
certify a custom validator by name.

Fresh reports use schema 4 to preserve per-candidate selection provenance. SQL requests use protocol
`sql-components-v2`, NoSQL `nosql-components-v1`, standalone validation `validation-components-v1`
and XSS `xss-components-v1`. Logging keeps `log-use-v1` pending its separate component migration;
outbound observations have no model protocol. Exact effective requests bind selected
content and provenance, source evidence, questions and model. Changing any of them rejects historical
answers for fresh replay. Saved reports remain exportable with their original evidence and answers.
XSS composes one primary rendering contract with context/protection interpretation and source-backed
stored/browser/response capabilities. Its five questions and mandatory origin/context/path gates remain
independent of database judgments; data-only observations are unassessed. Browser fetch attribution
uses direct literal methods, defaults to GET for absent/literal method-free options, and leaves
unsupported methods unresolved. This bounded correction is recorded separately in the migration ledger.
Explicit component/material bounds complement the existing 64 KiB final request bound; excess material
remains unresolved rather than being truncated.

The [implementation architecture and migration ledger](../.zazz/architecture/analysis-packs.md)
records inventory, limits, compatibility, offline verification and fresh paid-model acceptance.
SQL detection scope is preserved;
this reorganization is not evidence of improved live-model accuracy. NoSQL, standalone validation
and XSS are migrated; outbound observations now select `pack.outbound` with static limits and no
security questionnaire. JS/TS shape observations keep combined argument dependencies and unverified
binding/response gaps; names or package declarations cannot establish a URL operand or trusted API.
Python's existing bound requests/httpx functions and urllib.request.urlopen retain their separate
URL/body/response roles. Browser HTTP remains distinct from server request evidence. Observation
assessments return `not_run` without model requests; Preview rejects them without a body/digest.
Schema4 remains unchanged, with catalog compatibility `outbound-observation-v1` and no outbound
model protocol. Historical generic answers remain unchanged on export. Logging remains a follow-on
migration. Command injection is the first new family delivered on this structure. Public pack loaders, registries, executable plugins and broad
standards ingestion remain outside the MVP.

## Evidence for the approach

The [Python evaluation](../.zazz/evaluation/python-support-results.md) records 29 passing scoped case
checks across the original three pinned applications, including nine source-reviewed SQL/XSS positive
cases. It also records model overclaims that evidence validation blocked and the validation calibration needed
to avoid stronger requirements being invented. These examples support the value of explicit evidence validation
and claim boundaries; they do not establish general accuracy.

The original VulnPy baseline recorded six positive coverage misses and four warning controls.
Later dynamic-route work recovered generated Flask/FastAPI SQL and raw-HTML traces; the
[fresh component verification](../.zazz/architecture/analysis-packs.md#fresh-paid-component-e2e-2026-11-06)
retains their 28 contextual confirmations. The separate Jinja path remains unresolved. Historical
reports and the original 29-case success claim remain distinct. The [XSS evaluation](../.zazz/evaluation/xss-implementation-results.md)
and sample answer guides record additional implemented behavior and gaps. Local Semgrep CE/Bearer
baselines are pinned, scope-specific observations, not full-product rankings. CodeQL and Joern documentation
here are architecture references, not measured CodeQL/Joern benchmarks.

## What remains to establish

Broader or novel-repository coverage, lower false-positive rates at equal recall, safe handling of
custom validators and lower end-to-end cost/latency are evaluation goals. A novel combination may
have product value without being a new static-analysis algorithm; no exhaustive originality study
or general superiority claim has been completed.

Comparisons need pinned source/rules/models, matched vulnerability and framework scope, independently
reviewed vulnerable/protected/unknown controls and held-out cases. Measure precision, recall, false
protection, abstention/coverage, evidence usefulness and remediation correctness alongside time,
resources and model cost. Fewer alerts alone does not establish improvement. The same agent's source
review, implementation and calibration are not independent findings review.

Independent LLM Findings Review, a full repository IR/graph, automatic incremental caches, severity
CI gates and dependency scanning remain planned. Current analysis is bounded static evidence, not
runtime confirmation or a security certificate. Paid model judgment also introduces source-transmission,
service-availability and cost considerations; offline evidence inspection remains available.

## Common entry and dispatch architecture

The shared model separates these responsibilities:

| Record | Meaning | Why it is separate |
|---|---|---|
| Entry | Logical exposed operation, such as an HTTP endpoint or schema field | The same implementation can serve different operations; transport is optional metadata |
| Registration | Source/configuration wiring and generation provenance | A generated endpoint needs evidence of how it was exposed |
| Dispatch binding | A known or unresolved callable alternative, stage or condition | Discovery of an operation does not establish its implementation or value flow |
| Callable | Lexical implementation identity and source snapshot | Shared code retains one identity without acquiring a global protection flag |
| Invocation context | Actual parameters, captured values, input roles and applicable controls | A guard or binding from one exposure must not leak into another |
| Gap | A located unresolved fact or reached limit | Unknown alternatives and zero-use entries remain inspectable without invented security findings |

For example, one handler exposed twice can have one callable record, two registrations and distinct
invocation contexts. If only one registration runs an enforcing guard, the other retains its own
unprotected or unresolved claim. Separately, a discovered registration with no resolved callable
remains a coverage record; it cannot be interpreted as a safe operation.

Adapters own framework evidence and input roles. Language flow engines own supported transfers,
helper/callback binding and control facts. Shared claim policy and presenters interpret the resulting
evidence without manufacturing a missing edge. This makes reports and selectors reusable across entry
types while leaving each adapter responsible for proving its own source relationships.

The common records, existing HTTP/browser consumer migration and typed reports/selectors are
implemented in the merged common-entry/dispatch foundation. Supported adapters include explicit
DOM/window event callbacks, bounded Express and Python generated registrations with finite lookup
and closure/callback flows, Node.js Apollo resolver maps with literal schemas, and grpc-js unary
handlers with local proto3 declarations and request-field inputs. Dynamic-route acceptance includes
real VulnPy traces/findings and Juice Shop regressions. GraphQL and gRPC acceptance uses source
fixtures; real-application evaluation remains deferred. Dynamic schema composition, subscriptions,
generated gRPC stubs, interceptors and streaming flow remain unsupported.
The [README use-case matrix](../README.md#entry-use-cases-and-delivery-status) summarizes supported
and planned scenarios; the [common-entry design](../.zazz/architecture/common-entry-dispatch.md)
and [delivery contracts](../.zazz/specifications/common-entry-dispatch.md) own the detailed boundaries.

The architectural benefit is a common evidence and invocation contract rather than a separate
security interpretation for every framework. It does not automatically yield deeper analysis,
fewer false positives, complete dynamic-language coverage or proof that all runtime paths were
examined. Source-reviewed real applications and independent raw/protected/unknown controls must
establish those capabilities incrementally. This is a deliberate engineering combination of known
techniques and constrained semantic judgment; research novelty and superiority remain unproven.
