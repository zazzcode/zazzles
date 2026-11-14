# Zazzles — project overview

**Project overview, updated 2026-11-14.** This overview owns product purpose, direction,
and repository state. The [agent orientation](docs/zazzles-agent-orientation.md#documentation-map) routes
to the detailed documents and defines their responsibilities.

## Purpose

Zazzles helps developers and coding agents assess application security, code quality and
dependencies, then use the evidence to make verified repairs. Its four product goals are Scan,
Inspect, Audit and Fix. Scan has bounded implementations today. Inspect as a distinct capability,
Audit and automated Fix remain planned. A completed run is not a security or quality certification.

Each analyzer uses the shared engine for extraction, model assessment, evidence validation and
reporting. The [architecture](architecture.md#evidence-validation) owns these definitions and the
boundary between evidence validation and security policy.

## Shared decision-model support

OpenAI Decisions (`gpt-6-luna`) and Google Gemini Decisions (`gemini-decision-1`) can assess every
implemented analyzer through the same source/evidence gates. [User setup](../docs/decision-models.md#credentials-and-local-environment)
owns configuration; the [provider contract](specifications/gemini-decisions.md#capability-and-boundary)
owns this delivery. A two-request Gemini scan of the pinned TypeScript sample's `/api/ping` confirmed
command injection and preserved Review for unknown field policy. See [verification evidence](evaluation/gemini-decisions-results.md).
This bounded result does not establish equal provider accuracy. No live Jev calls were made.

The [roadmap checklist](project/implementation-plan.md#active-delivery-shared-gemini-then-path-traversal)
separates completed provider setup from the [later Path Traversal Analyzer](specifications/path-traversal.md#1-capability-and-prerequisite),
which has not been implemented or launched. NoSQL remains an extensible analyzer category with
bounded MongoDB/Mongoose and MarsDB-compatible support initially; other engines need distinct rules
and guidance, and findings must identify the actual database/driver.

## Four product capabilities

**2026-11-05 user direction:** the product distinguishes these responsibilities:

| Capability | Responsibility | Current boundary |
| --- | --- | --- |
| Scan | Source-code security vulnerabilities and controls | Bounded JS/TS/Python support, also emitting existing validation and construction-practice findings |
| Inspect | Correctness, maintainability, hygiene and defined engineering standards | Planned capability with existing quality-related checks as its foundation |
| Audit | Dependency vulnerabilities and advisory evidence | Planned ecosystem-tool integration |
| Fix | Evidence-backed repairs from Scan, Inspect and Audit, followed by verification | Planned agent workflow and orchestration |

These are product boundaries, not a commitment to four CLI commands or separate engines. Inspect
will use shared analysis models, evidence, judgment and reporting infrastructure. Current findings
are not reclassified or moved by this documentation update.

The intended capabilities MUST be usable independently and in any order. Users may run one or
combine several. Fix can consume an existing assessment or user-specified supported issue without
requiring a fresh Scan, Inspect or Audit run. Each capability retains its own input, evidence and
verification obligations. An automated loop is an optional composition, not a mandatory pipeline.

Security and quality assessments SHOULD have separate presentation/filtering and claim semantics.
Related claims SHOULD link their evidence without double-counting a single issue. Default security
prioritization MUST NOT imply every quality defect is low impact. A serious correctness defect may
also be urgent. Severity/priority and future reporting changes require their own contract.

Review remains an unresolved-evidence outcome. Planned independent Findings Review is a separate
verification role. Neither is the Inspect capability, and Hygiene is part of Inspect rather than a
fifth product goal. The [functionality catalog](project/01-functionality.md#four-product-capabilities)
records the functional boundary and the [implementation plan](project/implementation-plan.md#product-goals-and-capability-boundaries)
owns delivery scope and ordering.

## Product philosophy and user documentation

The authoritative user-facing [agent-first philosophy](../docs/philosophy.md) lives in root `docs/`.
Established vulnerabilities and poor practice are remediation tasks even without a demonstrated
exploit; Review is reserved for uncertainty about the problem or protection. Preserve established
protection and verify changes. The [user documentation index](../docs/README.md) owns setup, running,
result interpretation, glossary, decision-model use, CI, and contributor guidance.

This internal overview owns planning context, capability state, and product-direction decisions;
engineering designs and SDLC records remain under `.zazz/`. User-facing guidance MUST NOT be
maintained solely in internal project documents.

## Security and code-quality objectives

**2026-11-05 user direction:** Zazzles should identify code-quality, engineering-hygiene and
best-practice defects alongside security vulnerabilities. Input-validation judgments and selected
construction-practice findings already support this broader purpose. A source-backed requirement
can be unmet even when an operation is protected against injection.

The planned Inspect capability provides lightweight contextual quality assessment. Broader reliability,
maintainability and project-standard checks remain planned and need explicit requirements,
source evidence, independent evaluation and bounded contracts. This is not a claim of a complete
quality platform or parity with another product.

The [analysis pack proposal](project/analysis-pack-mvp.md#security-code-quality-and-engineering-hygiene)
covers both security and quality claims under the same modular organization. Each claim retains its
own applicability, evidence requirements and result semantics. Mechanical checks can remain
deterministic. Semantic judgment evaluates contextual standards without turning a quality defect
into a vulnerability or treating policy compliance as general safety. The initial MVP still migrates
SQL behavior first and does not add broad quality detection.

### Standards-driven agent feedback loop

One optional workflow is agent-authored code, selected Scan/Inspect/Audit assessments,
evidence-backed Fix proposals, tests and reassessment, followed by review. Users should be able to select their
own code-structure and architecture standards without adopting Zazz methodology. Explicitly approved
standards define assessment requirements, while source evidence establishes compliance within scope.

Broader standards selection/ingestion, architecture-quality analysis and automatic repair orchestration
are planned. The scanner does not currently implement this complete loop or treat arbitrary Markdown
as trusted policy. The [pack proposal](project/analysis-pack-mvp.md#standards-driven-agent-workflow)
records the future trust, provenance, evidence and remediation boundaries. The implemented
component migrations organize existing Scan knowledge; they do not implement that broader workflow.

## Long-term objectives

**Objective update, 2026-10-31:** build a source-code security scanner that is **as good as or better
than Bearer at SAST detection and code analysis, with fewer false positives**, with the long-term goal of supporting all equivalent
analysis and developer-workflow capabilities. This includes capabilities available across Bearer CLI
and Pro; the free CLI is the first local comparison baseline, not the ceiling for zazzles's ambition.

Track parity through a versioned capability inventory: supported languages/frameworks and weakness
families; source-to-sink taint and control/dataflow analysis; interprocedural and cross-file analysis;
sensitive-data classification and security/privacy impact; finding evidence and remediation guidance;
and reporting, configuration, incremental/baseline and CI workflows. Verify each comparator capability
and edition rather than assuming a marketing description establishes behavior. The detailed inventory
is recorded in the [versioned capability inventory](evaluation/bearer-capabilities.md); phased
delivery contracts remain to be developed for unsupported capabilities.

Measure equal-or-better detection on matched, pinned source scopes and independently labeled,
held-out vulnerable/protected/unknown cases. Require lower false-positive rates at equal-or-better
vulnerability recall on comparable scope; fewer findings alone is not success. Select numeric
thresholds and denominators before held-out evaluation. Compare recall, precision, false safe claims, abstentions,
coverage and evidence quality; record latency, resource use and model cost alongside accuracy. More
findings alone do not establish superiority. Demonstrated parity applies only to the capabilities and
corpus actually evaluated; broad parity has not been achieved by the current implementation.

The [technical approach](../docs/technical-approach.md) distinguishes implemented design strengths,
comparison evidence and unproven novelty/performance claims. The full repository graph remains
planned; today the judge consumes bounded source slices.

The intended advantage is a decision model that considers the relevant paths in a repository-wide
code graph, including actual custom-validator bodies, enforced guards, value changes, bypasses and
sink semantics, so valid protection is recognized and false positives are reduced. This is a quality
hypothesis to test, not an established benefit. Build the repository graph structurally and supply
complete claim-relevant slices within model limits; the current implementation supplies only bounded
slices and does not analyze the entire code graph. Missing paths or unknown effects must remain
explicit, rather than become protected claims. Provide route-oriented explanations and complementary
remediation. Test that advantage against traditional
SAST rather than assume that using AI improves detection. The
[pinned CLI comparison](evaluation/bearer-results.md) starts this evaluation; the
[phased plan](project/implementation-plan.md) owns delivery order. SCA remains a complementary objective
after the source-code analysis foundation.

**Languages, updated 2026-11-14.** JavaScript, TypeScript and Python have implemented bounded
adapters. Go remains planned; later language expansion has no fixed delivery position. A file
extension is not analysis support.

**Route report, 2026-10-31.** For each route, identify and report both where protection is sufficient
and where it is lacking. A sufficient result names the claim, the value, and the sink slot it covers.
It stays in the report so silence is not read as safety and an agent does not redo a protection that
already holds. A lacking result names the value that can still affect that use. Also report poor
code-practice findings on the route: hard-coded secrets, insecure cookie and session defaults,
missing baseline headers, weak randomness, and similar deterministic issues. Agentic coding can fix
those alongside dataflow fixes, so a route review that drops them is incomplete. Keep practice
findings distinct from a claim that request input can change a sink. A practice finding is not
exploitability, and a protected dataflow claim does not make the route's configuration sound.

## Product direction

The chosen direction combines **Tree-sitter extraction, Go control-flow/dataflow analysis, provider-neutral Decision
assessment of string validation/sanitization, then an LLM Findings Reviewer for identified issues**.
All scanner and code-analysis implementation is Go, including model clients and orchestration.
The decision model's role is bounded semantic assessment; the reviewer provides deeper findings review.
Experiments must measure accuracy, latency, and total cost, including whether the model recognizes
adequate protection and whether the reviewer corroborates or challenges its identified issues. Local-only operation
remains useful, with omitted assessment/review stages explicitly marked.

**Direction update, 2026-10-24.** The first slice is greenlit and implemented:
[route identification](specifications/tree-sitter-route-identification-mvp.md). `scan --routes`
writes a JSON route index of Express-style JS/TS registrations and the handler names at the call.
It does not follow imports or decide whether a string is validated. The OpenAI Decisions API
(`gpt-6-luna`) is the later assessor of validation and sanitization. It is not called in this slice.
The [architecture provider decision](architecture.md#current-provider-decision) keeps explicit
OpenAI, Gemini and Jev adapters behind a shared judge. `JUDGE_DECISION_MODEL` selects one model
for every analyzer; `--judge` enables calls and must match the model. Gemini accepts only
`gemini-decision-1` through v1beta Decisions. Jev remains stub-tested, without live validation here.
The [graph design](architecture/repository-graph.md) covers the target repository: API entry points,
internal paths, outbound service calls and their strings, responses, and subsequent value flow.
The 2026-10-31 [assessment](project/06-route-validation-assessment.md) records route verification
and the next branch scope. The implementation update below supersedes its initial pre-code status;
later [two-case Luna results](evaluation/juice-shop/results.md) supersede that initial no-live-test status.

Start with a small JS/TS slice, then expand from measured results. The
[capability catalog](project/01-functionality.md) defines detection modes, rule families, language
sequence, and interfaces. The [scope](project/02-project-scope.md) defines boundaries, quality
hypotheses, and risks. First-release coverage remains undecided.

Technical responsibilities live in the [architecture](architecture.md). The
[design proposal](project/03-jev-design-proposal.md) owns the change from generative call-path review
to supported Go dataflow plus bounded semantic classification, along with the rationale, retained
concepts, and open decisions. The [Jev research](project/04-jev-validation-research.md) records published
evidence and the evaluation needed to measure the chosen assessment-and-review pipeline.

## Concept-stage repository state

The module is `github.com/zazzcode/zazzles`, declaring Go `1.27.2`. `scan --list` walks a tree.
`scan --routes` parses JS/TS with Tree-sitter and emits the route index from the
[route-identification spec](specifications/tree-sitter-route-identification-mvp.md). There is no
complete CFG/interprocedural analysis, independent Findings Reviewer, or reviewed findings report yet.

**Implemented 2026-10-31:** `--analyze` adds bounded route/handler resolution and request-value
use witnesses with source hashes, candidate SQL/outbound HTTP call models, and explicit gaps.
Optional `--judge openai|gemini|jev` sends bounded evidence through provider-specific typed adapters;
bounded Luna integration/control evaluations are recorded in [results](evaluation/juice-shop/results.md). See the [current contract](specifications/route-string-validation.md)
and [API setup](docs/openai-decisions-setup.md).

Phase 0's walker, language registry, and CI remain. Their historical record is the
[Phase 0 specification](specifications/phase0-skeleton/README.md). Recognizing a language extension
does not establish security-analysis support for that language.

Workspace conventions and the `stage` rules live in the
[orientation](docs/zazzles-agent-orientation.md).

## Route reporting and dependency direction

The product should explain findings by inbound route and source-to-use graph, separating field
validation from sink/API semantics and proposing multiple complementary improvements. A valid email
format does not establish SQL parameter separation. Keep the canonical internal evidence model and
provide the bounded SARIF 2.1.0 export; see [report design](architecture/reporting-and-sarif.md).
After the code-path foundation, add [SCA dependency auditing](architecture/sca-design.md) using
language/package-manager tools, with advisory evidence separate from reachability.

## Delivery and evidence

The [implementation plan](project/implementation-plan.md) owns phase decomposition, future spec slices,
dependencies, acceptance targets, and phase-specific evidence. Those phases are proposals, not approved
contracts or scheduled milestones. Specifications will be authored in separate sessions and greenlit
through the [Zazz delivery lifecycle](docs/zazz-methodology.md#specification-driven-delivery-cycle).

The plan includes the cloned OWASP Juice Shop reference and small paired fixtures. Its
[acceptance-target section](project/implementation-plan.md#acceptance-targets) owns their role and setup
work. Source handling, accuracy, latency, cost, and packaging remain hypotheses to measure rather than
established product promises.

## Analysis pack initiative

The **SQL Injection Analyzer**, **NoSQL Injection Analyzer** (JS/TS), **Input Validation Analyzer**,
**XSS Analyzer** and **Command Injection Analyzer** use embedded analysis packs and reusable components. **Sensitive Data Logging
Analyzer** is implemented on its existing path; its catalog migration remains pending. The **Command
Injection Analyzer** is delivered ([results](evaluation/command-injection-results.md)); **Harden XSS
analyzers** is the next analyzer task. XSS includes reflected, stored and client-side/DOM
capabilities rather than separate engines. The
[architecture terminology](architecture.md#analyzer-terminology) distinguishes analyzer capabilities,
analysis-pack knowledge and the shared analysis engine.

The catalog also supports [outbound observations](specifications/components-03-outbound.md), without
implementing the planned SSRF Analyzer's security assessment. This implements the
SQL-first MVP and migration sessions 01–03 from the [analysis-pack design](project/analysis-pack-mvp.md).

Static source/report comparisons and fresh paid OpenAI Decisions scans of Juice Shop and VulnPy
verify this organization. All 944 eligible paid judgments passed exact replay against freshly parsed
source; all 35 historical confirmed source contexts remain confirmed. The
[verification record](architecture/analysis-packs.md#fresh-paid-component-e2e-2026-11-06) distinguishes
these results from coverage limits and broader accuracy goals.

The delivered consumers organize existing language/framework models, embedded guidance, verified API contracts,
claim questions and evidence obligations under explicit versions and applicability. The
[architecture ledger](architecture/analysis-packs.md#current-implementation-status)
records acceptance evidence, limits and remaining work. Outbound components describe observations,
not SSRF protection: requested assessments return `not_run` with zero model calls and leave the scan
incomplete. The judge receives
only relevant interpretation material alongside the source trace; executable adapters and mandatory
Go evidence gates remain in the scanner. The goal is reusable, auditable analysis knowledge as new
analyzers are added. Downloadable packs, executable plugins and a new rule language remain
deferred. The [implementation plan](project/implementation-plan.md#analysis-pack-mvp-initiative)
owns sequencing; the [technical approach](../docs/technical-approach.md#analysis-knowledge-and-components)
owns the public explanation and evaluation limits.
