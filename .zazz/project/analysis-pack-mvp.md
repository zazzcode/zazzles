# Analysis pack MVP proposal

**Implemented foundation; broader proposal retained, updated 2026-11-06.** The SQL-first MVP and
NoSQL, standalone-validation, XSS and outbound-observation migrations implement this design's
internal component boundary. The [component architecture](../architecture/analysis-packs.md#current-implementation-status)
owns current runtime organization and verification; the [implementation plan](implementation-plan.md#analysis-pack-mvp-initiative)
owns remaining delivery order. Logging remains a separate migration. Broader Inspect, external pack
loading and standards ingestion remain proposed capabilities.

The original 2026-11-05 decision separated this initiative from common-entry/dispatch. That
foundation and the subsequent component contracts are complete implementations, not instructions
to create another worktree or repeat the migrations. The remaining proposal sections explain design
principles and future goals; they do not independently authorize implementation.

## Analyzer terminology

Use the [current architecture vocabulary](../architecture.md#analyzer-terminology): **Analyzer** names
the assessment capability (for example, SQL Injection Analyzer or XSS Analyzer), **analysis pack**
names its supporting versioned knowledge, and **analysis component** names a reusable catalog item.
The **shared analysis engine** supplies common infrastructure. This proposal retains the historical
initiative name “analysis pack MVP”; its completed specifications and recorded results are unchanged.

## Purpose and architectural distinction

> Zazzles establishes supported code relationships through static analysis, then uses a decision
> model to evaluate whether the demonstrated controls satisfy a specific security requirement.
> Explicit evidence gates constrain the resulting judgment.

The decision model evaluates the supplied implementation, operand roles and relevant paths. Within
supported analysis boundaries, that can avoid needing a named sanitizer rule for every custom
validation function. A supplied function body and actual transfers/conditions let the judge assess
whether the control is adequate for this operation. A function name alone cannot establish protection.

Semantic judgment reduces the need to enumerate every acceptable implementation pattern; it does
not eliminate the need for analysis models. Sources, handler bindings, transfers, sink argument roles
and library behavior still need correct static support. Missing discovery means the judge never sees
the candidate. Missing helper bodies, unresolved effects and reached limits remain explicit gaps.

Established SAST includes structured program models, framework knowledge and dataflow, not just
text matching. For example, [Semgrep taint rules](https://docs.semgrep.dev/writing-rules/data-flow/taint-mode/overview)
define sources, propagation, sanitizers and sinks and can produce traces. Zazzles's design places a
decision model within claim judgment, constrained by static evidence and Go policy. This is an
architectural distinction, not proof of uniqueness, broader coverage or superior accuracy.

<a id="current-foundation-and-proposed-change"></a>

## Implemented foundation

The current scanner already contains the components below. They ship in the binary and are not
user-downloadable analysis packs.

| Component | Current owner | Responsibility |
| --- | --- | --- |
| Language/framework discovery and bounded flow | `internal/parse/` | Reference implemented capabilities and their supported subsets; executable adapters stay compiled |
| Verified library/API contracts | `internal/analysispacks/`; bindings proved in parse | Select versioned contract content for demonstrated operations |
| Versioned language Analysis Guidelines | `internal/guidelines/`; family projections selected by the catalog | Embed canonical guidance and select validated applicable sections |
| Claim questions and answer protocols | Migrated families in `internal/analysispacks/`; transport and gates in judge | Supply questions and interpretation for the named claim; logging remains in judge |
| Required evidence and consistency gates | Parse completeness and Go judge policy | Declare obligations while retaining mandatory core gates |
| Positive/protected/unknown controls | Existing fixtures and tests | Identify regression coverage for each declared capability |

The MVP organizes and versions existing knowledge. It does not implement new languages, frameworks
or vulnerability families merely by declaring them in a manifest. A `--checks` file remains an
application-requirement/selection input; it is not a language adapter or general rule-pack loader.
Product analysis documentation remains distinct from embedded model guidance: editing a public guide
alone does not change detection or the running judge's instructions.

## Two consumers, one explicit selection

| Consumer | Material it uses | Boundary |
| --- | --- | --- |
| Static engine | Applicability metadata, references to compiled source/sink/binding/flow models and evidence obligations | Establish source relationships before security judgment; pack declarations cannot invent edges |
| Decision Model Judge | Selected guidelines, applicable API contracts, claim questions and interpretation guidance alongside the trace | Assess the supplied implementation for a named requirement; no missing evidence filled by confidence |
| Reporter and replay validation | Selected component IDs, versions/digests, supported scope and judgment provenance | Keep results auditable and prevent changed requests from inheriting historical answers |

A pack is not itself the trace. The trace contains application evidence; the selected pack material
supplies scanner-authored interpretation context. Target code, comments, manifests and repository
text MUST remain untrusted evidence, not instructions that select or redefine security policy.

For example, a JS/TS gRPC SQL candidate could compose language guidance, the verified unary gRPC
input capability, a Sequelize operation contract and the SQL-injection claim definition. Only the
applicable judgment material accompanies that candidate's source/transfer/control evidence.
The scanner does not send executable adapters, test labels, unrelated vulnerability guidance or an
entire pack catalog to the judge.

Language, entry framework, library and claim family SHOULD remain independently composable.
The design SHOULD avoid requiring a separate monolithic pack for every combination. Actual
selection MUST depend on supported source facts or explicit scanner configuration, not framework
names or installed-package declarations alone. Unknown versions/applicability MUST retain limits.

## Product capabilities and shared components

**2026-11-05 user direction:** Scan, Inspect, Audit and Fix are the four product goals. Scan assesses
source security, Inspect assesses correctness/maintainability and engineering standards, Audit
assesses dependencies, and Fix supports repairs and verification across those assessment domains.
A distinct Inspect capability, Audit and automated Fix remain planned. Current Scan output retains
its existing validation and construction-practice findings.

Components SHOULD declare their supported claim domains and applicability without requiring a
separate engine for Inspect. A security API model, quality standard or shared validation capability
may participate in different claims with different evidence obligations. Do not force a quality
claim into a security source/sink shape. Fix can consume the resulting supported issues without
owning the detection or weakening either domain's gates.

Future reports SHOULD separate security and quality assessments, preserve domain-specific status
semantics, link overlapping evidence and avoid duplicate issue counts. Security concerns should be
prominent, with priority still based on impact. A quality defect may be urgent but does not become
a vulnerability by being severe. Compliance with a coding standard cannot establish general safety.

Review remains an unresolved-evidence outcome, and independent Findings Review remains a planned
verification stage. Neither names the Inspect capability. Hygiene is part of Inspect. Capability
names do not prescribe four CLI commands, change today's schema or authorize report migration.

The intended capabilities MUST be independently usable in any order. They are not mandatory stages
of one pipeline. A user may choose Scan, Inspect or Audit alone, and Fix can start from an existing
report or an explicitly supplied issue with the required source context. Evidence and verification
obligations still apply. Components SHOULD support optional composition without imposing fresh runs
of all four capabilities. Their public command/API shape remains undecided.

Independent usage order does not change initiative delivery prerequisites. The pack MVP still
follows common-entry/dispatch merge and precedes command injection. Broader Inspect and Fix remain
separately scoped work, and the agent feedback loop is optional rather than a usage dependency.

The MVP records these boundaries while migrating existing SQL behavior first. Broader Inspect
coverage, distinct domain presentation, Audit and automated Fix remain separately scoped work.
This product split does not create new implementation work inside the current milestone or pack MVP.

## Security, code quality and engineering hygiene

**2026-11-05 user direction:** Zazzles's objectives include code quality, engineering hygiene and
best practices as well as security vulnerabilities. Modular analysis components SHOULD support both
security and quality claims. Their value does not depend on external downloads or a paid edition.
Distribution and monetization remain separate product decisions.

Input validation already illustrates this distinction. A required field format can be unenforced
while SQL value binding prevents injection. The validation defect merits repair independently of
whether an exploit is established. Selected construction-practice checks also identify work worth
correcting without proving exploitability. These existing capabilities do not establish a general
maintainability, reliability or code-quality platform.

The pack structure SHOULD make the following responsibilities explicit without fixing a public
schema in this proposal:

- **Requirement and applicability.** Name the security property, engineering standard or application
  requirement being assessed, its source/version and where it applies. Project-specific standards
  need explicit scanner configuration or source-backed requirements. Arbitrary repository prose
  MUST NOT become trusted judge instructions or override core policy.
- **Evidence and scope.** Define the actual source facts needed for that claim. A future quality
  check may concern a function or module and may not need an external input or sensitive sink.
  It MUST NOT invent those roles merely to fit a security trace. Any new analysis-root/evidence
  capability needs its own implementation contract and tests.
- **Assessment method.** Use deterministic checks for mechanical properties where suitable.
  Reserve semantic judgment for contextual questions about the supplied implementation and the
  applicable standard. A model is not required for every formatting or hygiene check.
- **Result and limits.** Keep quality-policy compliance, construction practice and security
  protection distinct. A quality defect MUST NOT automatically become a vulnerability, and
  compliance with one standard MUST NOT certify security. Missing requirements, effects or context
  remain Review. New quality-specific report behavior needs its own contract.
- **Evaluation.** Include conforming, nonconforming, unknown and not-applicable cases. Expected
  labels remain outside model requests. Judgment must follow the explicit standard and evidence,
  not an assumed universal style preference or invented business restriction.

Semantic assessment can reduce the need to enumerate acceptable custom implementations for these
standards. It still depends on supported extraction, adequate context and measured judgment quality.
Broader error-handling, reliability or maintainability checks are possible future consumers, not
features delivered by this proposal.

The MVP inventories security and existing quality-related components and migrates SQL injection
first as already proposed. It MUST preserve the independent validation and construction-practice
behavior on those SQL cases. General quality coverage, new claim families and new reporting statuses
are outside that migration. They require separate scope and acceptance evidence after the internal
structure is validated. The staged migration of existing XSS, validation and logging remains intact.

## Standards-driven agent workflow

One optional product workflow is a feedback loop in which agents create code, Zazzles assesses
security and defined engineering standards, agents remediate supported issues, and tests plus
reassessment verify the revision before review. Code-structure and architecture guidelines are
potential quality requirements. Users MUST NOT need to adopt Zazz methodology to use this workflow.

The modular structure SHOULD separate reusable analysis capabilities from team-selected standards.
A capability defines what relationships/evidence the scanner can establish and assess. An approved
standard supplies the applicable requirement. Standard content alone cannot add language support,
prove an architecture relationship or establish enforcement without the required implementation.

Future standards integration and remediation contracts MUST address these boundaries:

- **Explicit policy selection.** The user or trusted configuration selects/version-pins the team's
  standards and their scope. The project's own `.zazz/` development standards are not automatic
  target policy. Arbitrary target comments or documents MUST NOT become trusted instructions.
  Supported standards formats and selection mechanisms remain to be designed.
- **Claim-specific evidence.** Architecture or quality claims need their own source-backed structural,
  dependency or control facts. Missing relationships remain explicit. Do not equate readable guidance
  with an implemented detector or assume every quality claim is an input-to-sink security trace.
- **Scoped remediation.** Assessment output names the issue, requirement, evidence, remaining gaps
  and behavior/protection to preserve. The agent proposes targeted changes. A quality concern MUST
  NOT silently authorize a broad rewrite or change an application's intended requirements.
- **Reassessment and provenance.** Tests and required checks run against the changed revision.
  Reassessment uses that revision and the same effective standards, or explicitly records a policy
  change. Preserve prior evidence/answers and reject stale decision replay. Remediation success MUST
  NOT be inferred merely from fewer findings or removed/unexamined code.
- **Bounded orchestration and review.** Future automation needs iteration/call budgets and explicit
  handling of unresolved findings, unsupported standards, regressions and failure to converge.
  Incomplete assessments cannot become compliance claims. Tests and human approval remain distinct
  from semantic judgment and automatic proposal generation.

The current scanner supplies bounded assessments and reports. Broad standards-document ingestion,
architecture-quality coverage and the complete automated remediation loop are future capabilities.
They are not hidden additions to the SQL-first pack MVP. No public standard format, external pack
registry, paid-edition boundary or remediation API is fixed by this proposal.

### Learned knowledge, baseline guidance and team standards

A decision model brings learned coding knowledge that can help interpret code and suggest issues.
That knowledge alone is not a stable or authoritative project standard. It may vary with the model,
request and available context, and cannot establish a team's architectural choices or business rules.

Users SHOULD be able to start with a versioned Zazzles baseline rather than write a standards manual.
Current language Analysis Guidelines, claim questions and API contracts already provide explicit
security interpretation context. Broader quality baselines and optional project profiles remain
planned. Standards can be concise principles, structured checks or selected documents; no single
standards-document format is prescribed here.

The intended layers are learned model knowledge for interpretation, versioned baseline guidance for
default expectations, and explicitly selected team requirements for project-specific decisions.
Each standard-based finding MUST identify the applicable requirement and supporting source evidence.
Absent policy cannot be replaced by a model's preference. Mechanical properties SHOULD use reliable
deterministic checks where available.

Exploratory model review may suggest maintainability concerns without a configured team standard.
Such suggestions MUST remain distinguishable from established standard violations, security findings
or compliance claims. Any new advisory presentation needs a separate implementation contract.
Effective baseline/team content and model/question versions MUST remain auditable in judgment
provenance, with changed requests rejecting stale replay. Explicit guidance improves accountability
but does not itself prove judgment accuracy or complete coverage.

## Bounded MVP scope

- Define an internal embedded manifest with stable pack/component IDs, versions, compatibility
  references, applicability and test-coverage references. Keep scope and known limits discoverable.
- Inventory existing language guidance, verified API contracts, security and quality-related claim
  questions and required evidence. Give each an explicit owner and reference without rewriting the
  analysis engine or adding new quality detectors.
- Migrate the existing SQL-injection family into that structure as the first working consumer,
  preserving its behavior across supported JS/TS/Python cases. Include this migration in the MVP
  contract rather than stopping at an inventory or a manifest used only by future features.
- Select the relevant components deterministically for a candidate. Missing or conflicting required
  components MUST remain explicit configuration/coverage failures; no permissive silent fallback.
- Assemble a bounded judge request containing the trace plus only the applicable interpretation
  material. Mandatory evidence and consistency gates MUST remain in Go and cannot be weakened by
  pack content. A pack MUST NOT mark a custom helper safe merely by its name.
- Record selected versions/digests in report/judgment provenance. Exact effective request content
  MUST participate in replay validation. Changed guidance, contracts, questions, evidence or request
  protocols MUST NOT reuse old answers. A representation change that alters an envelope needs an
  explicit version/compatibility decision, even if intended security behavior is unchanged.
- Reuse existing fixtures and offline stubs to demonstrate preserved findings, scoped protection,
  unknowns, evidence and output semantics. Use command injection as the next consumer of the new
  organization after the MVP is accepted, not as hidden work inside this initiative.

The implementation contract will determine the minimal file/schema changes after a current-code
inventory. This proposal does not fix a public pack format, CLI flag, package API or new runtime
plugin interface in advance of that evidence.

## Staged migration of existing analysis

Existing SQL injection, XSS, input validation and logging should ultimately use the same component
structure as new vulnerability families. The goal is one coherent architecture reached through
small, verified migrations. A separate architecture used only by new features would leave duplicated
ownership and policy paths to maintain.

The delivered sequence is SQL first, then NoSQL/standalone validation, XSS and outbound observations.
Logging remains separately scoped. The migration principles are:

- **Inventory first.** Identify API contracts, embedded guidance, claim questions, required evidence
  and reporting policy across existing families. Separate shared responsibilities from language-
  and family-specific semantics. Record each family's migration scope and remaining work explicitly.
- **Migrate SQL injection in the MVP.** Its query-text, bound-value, validation and injection-protection
  distinctions provide a concrete first boundary. Existing JS/TS/Python vulnerable, protected and
  unknown controls can verify that the new organization preserves actual pipeline behavior.
- **Implement command injection separately.** Use the accepted component structure to add process
  API contracts, command-specific questions and regression controls. This tests reuse across another
  vulnerability family without hiding new detection work inside the packaging initiative.
- **Migrate logging separately.** Preserve sensitive-content, emission and redaction semantics with
  explicit acceptance evidence. The completed family migrations provide the shared structure; logging
  is an active consumer to migrate, rather than dead code to remove.

Family-specific semantics MUST remain explicit. XSS needs output-context and rendering behavior
that does not belong in a generic injection abstraction. Shared components SHOULD emerge from
working consumers rather than forcing every analyzer into the same shape.

The first migration changes ownership, composition and versioning while preserving detection
behavior. Existing findings, protected controls, unknowns and coverage gaps MUST remain equivalent.
Source availability alone MUST NOT resolve an existing blocker or broaden a protection claim.
Intentional judgment-envelope changes MUST be versioned and reject stale-answer replay.

Detection improvements, broader SQL/XSS coverage and unrelated cleanup MUST remain separate from
the migration. This makes regressions attributable and allows evaluation to distinguish better
analysis from a change in organization. No full analyzer rewrite is a prerequisite to the next
vulnerability family, and no downloadable-pack mechanism is needed for internal modularity to help.

## Deferred scope

Downloadable registries, third-party or target-supplied policy packs, executable plugins, arbitrary
runtime imports, a new rule language, Semgrep YAML compatibility, automatic remote updates and
unrestricted user-authored safety contracts are outside the MVP. External distribution needs its own
trust, compatibility, update and validation design once real consumers establish the extension points.

A whole-program IR, broader helper/heap/async coverage, independent Findings Review, automatic
judgment caching and new vulnerability/language support remain separate initiatives. No paid
calibration, target execution or sample-application changes are required for this packaging MVP.

## Proposed acceptance and evaluation goals

- Existing JS/TS/Python cases retain their source bindings, claim outcomes, blockers and coverage
  through actual adapter-to-judge-to-report pipelines; zero-use entries and unsupported paths remain
  visible. Allow only explicitly reviewed provenance/envelope changes in baseline comparisons.
- SQL injection is a working migrated family, not only a manifest entry. Actual supported JS/TS/Python
  SQL pipelines preserve source/sink bindings, validation-versus-injection distinctions, model/policy
  outcomes and reporting behavior. Unmigrated families retain regression coverage and explicit
  follow-on migration tasks without acquiring a competing permanent architecture.
- Applicability controls cover supported and unsupported combinations, verified versus fake APIs,
  missing/conflicting components and shared-callable contexts without borrowed protection.
- Raw, protected and unknown controls demonstrate that the judge receives the right guidance and
  contracts and that optimistic answers cannot override missing evidence. Expected labels remain
  outside model requests.
- Deterministic selection and exact-request replay controls reject changed pack/guidance/contract
  content. Saved reports and raw historical responses remain intact; version changes cannot relabel
  those responses as fresh decisions.
- JSON/HTML/SARIF retain result parity and distinguish offline discovery, stub assessment and live
  model assessment. Request-size/selection limits remain explicit instead of truncating obligations.
- Measure selection/payload size and local overhead. Broader precision/recall, reduced false findings
  or false protection, custom-validator generalization and live model cost remain separate evaluated
  hypotheses requiring independently labeled held-out cases and explicit call authorization.

The first recovery boundary should be an inventory/manifest with unchanged behavior. A working SQL
migration follows, including component selection and request/report provenance. Full regression and
compatibility evidence closes the MVP before command injection starts as a separate initiative.
No broad engine rewrite or unrelated cleanup is part of those checkpoints.

## Delivery boundary and next step

The common-entry/dispatch prerequisite and the SQL-first component MVP plus sessions 01–03 are
implemented. Their contracts and the [migration ledger](../architecture/analysis-packs.md#migration-ledger)
record acceptance and remaining limits. Subsequent vulnerability families should use the shared
component structure. Logging migration and new families need separate bounded assignments; neither
is implicit cleanup or authorization to create another worktree. External pack distribution can be
reconsidered after the internal boundaries have further real consumers.
