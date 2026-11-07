# Proposed phased implementation plan

**Long-term planning, 2026-10-19; capability checklist updated 2026-11-02; component status updated 2026-11-06.** Phases 0–13 below are
not approved for execution. This is a decomposition for later spec sessions, not a specification,
calendar schedule, or blanket claim of completed functionality. The [capability checklist](#supported-capability-checklist)
and delivery list below own current status and ordering; older phase/increment sections are references,
not instructions to repeat delivered work.

## Product goals and capability boundaries

**2026-11-05 user direction:** organize Zazzles around four goals: **Scan** for source-code security,
**Inspect** for correctness/maintainability and engineering standards, **Audit** for dependencies,
and **Fix** for agent remediation and verification across the assessment capabilities.

Scan has bounded implementations, including validation and construction-practice findings that form
part of Inspect's foundation. A distinct Inspect command/view, broad standards support, Audit and
automated Fix remain planned. The goals do not establish a public CLI shape or duplicate engines.
Review remains an unresolved-evidence outcome, not the Inspect capability.

The [project overview](../project.md#four-product-capabilities) owns product responsibilities.
The [analysis pack proposal](analysis-pack-mvp.md#product-capabilities-and-shared-components)
records shared component ownership and future domain separation. Inspect claims need separate
applicability/evidence and should not be mixed into vulnerability counts or automatically treated as
security defects. Prioritization remains impact-based, with security concerns clearly visible.

**Usage order is independent of delivery order.** Once implemented, Scan, Inspect, Audit and Fix
can run independently in any order. Fix may begin with an existing report or a user-specified issue.
The agent feedback loop is optional composition. Each capability retains its required inputs and
verification. This product requirement does not reorder implementation milestones or make the
planned capabilities available now.

No new Inspect delivery milestone is inserted into the existing ordered list. Broader quality
checks, separate presentation, standards selection and automated Fix require bounded contracts and
an explicit priority decision. The established sequence stays common-entry/dispatch acceptance and
merge, then the separate SQL-first pack MVP, then command injection. Additional family migrations
remain incremental. These documentation updates do not authorize implementation.

## First build

The [route-identification spec](../specifications/tree-sitter-route-identification-mvp.md) is greenlit
and implemented. `scan --routes` emits a JSON route index of Express-style registrations and same-file
handler names. It is not a resolved execution trace. The OpenAI Decisions API (`gpt-6-luna` on
`POST /v1/decisions`) remains the later assessor and is not part of this slice. Juice Shop manual
checks use tag `v20.3.0`. Phases 0–13 stay proposed. The next objective is evidence-backed assessment
of external string uses on selected routes.
Validation, transformation, sink-specific protection, and uncertainty are separate facets; see the
near-term sequence below. A four-label string verdict is not an approved contract.
Context: [architecture](../architecture.md), [scope](02-project-scope.md),
[design proposal](03-jev-design-proposal.md), [Jev research](04-jev-validation-research.md), and
[Zazz methodology](../docs/zazz-methodology.md).

## Route-string-validation delivery sequence

**2026-10-31 sequence; the bounded current contract is explicitly authorized.** The assigned branch is
`route-string-validation`. First verification is complete for the existing syntactic route contract:
see [evidence and limitations](06-route-validation-assessment.md#route-verification). The current route
inventory is already present here; do not reimplement the MVP from the older backlog.

The immediate objective is a small reviewable path from route to external string to sink-specific
protection assessment. Start with Juice Shop login/search SQL cases and controlled pairs, then expand.
GPT Decisions and Jev are alternative judge providers, with OpenAI first; [architecture](../architecture.md#current-provider-decision)
owns that decision and [API setup](../docs/openai-decisions-setup.md) owns key instructions.

| Sequence | Proposed contract | Dependency and exit evidence |
|---|---|---|
| R1 | Route trust and selected corpus | Reuse MVP; distinguish Express receivers from clients; pin selected files/revision, expected registrations, exclusions, safe/vulnerable/unknown labels |
| R2 | Selected handler and input resolution | R1; resolve login/search imports, returned handler factories and wrapper; locate request sources and SQL sinks; lexical shadowing/unknown tests |
| R3 | Local SQL-use evidence and offline report | R2; minimal normalized operations for assignments, interpolation, guards and parameter binding; witnesses, explicit gaps and coverage; separate validation/protection facets |
| R4 | Decisions adapter and feasibility experiment | Hand-reviewed bundles from R1 can support an early independent experiment; production integration uses R3 evidence. Validate transport with HTTP stubs first; then bounded live labeled evaluation |
| R5 | Independent review and reconciled output | R3–R4; reviewer assesses evidence independently; preserve disagreements, refusals, missing context and incomplete stages; compare against held-out human labels |

Each row is a reviewable outcome to refine. The current contract implements a bounded subset
in this assigned worktree; related design and implementation remain together. Independent future
deliverables may use separate worktrees after accepted prerequisites.
The user explicitly authorized implementation in this worktree on 2026-10-31. Follow the updated
[authorization rules](../../AGENTS.md#authorization-and-delivery) and the
[current implementation contract](../specifications/route-string-validation.md); no separate greenlight is needed.

R4's early experiment uses hand-prepared evidence and cannot be presented as end-to-end scanner
capability. API credentials are not required for R1–R3 or HTTP-stub tests. A key is not permission to
upload source or spend without the live experiment's declared scope/budget.

The first slice MUST retain unknowns and MUST NOT report missing sanitization as a vulnerability
when sink-specific protection is established, such as SQL parameter binding. Proposed candidate
facets are validation, transformations, sink-specific protection, and evidence completeness; exact
fields/verdicts belong to the next spec. Desired evidence: the guarded value reaches the SQL binding.
A real rejected inference is treating the search handler's length limit as SQL protection (see
[assessment](06-route-validation-assessment.md#suggested-first-security-slice)).

Long-term phases below remain a roadmap. R1 overlaps foundation/corpus/parser audit, R2 overlaps
resolution, R3 overlaps local flow/evidence/minimal output, and R4–R5 overlap semantic feasibility and
review. Future specs MUST reconcile these overlaps rather than repeating completed extraction or
claiming all of a phase complete. Broad interprocedural flow, all OWASP families, caching, baseline CI,
and other languages remain outside this first slice. The older S01–S34 identifiers and Jev adapter
names are historical planning references until their individual contracts are refined.

## Current two-case increment

The [requirements file](../evaluation/juice-shop/validation-checks.json) declares login email/SQL
protection and registration required-credential checks. Implemented checked mode assembles route-chain,
relevant helper, model/generated-persistence and local branch evidence. Claim-specific required roles
and blockers replace the blanket any-gap downgrade for checked candidates. Unchecked candidates
remain conservative. See [design](../architecture/evidence-and-claims.md) and the current contract
for tests and remaining limits. Source/field requirements and SQL parameterization are separate
questions; route remediation should present complementary improvements. SARIF export and illustrative remediation templates are implemented; runtime confirmation remains
future work. [Original comparisons](../evaluation/corpus/README.md) exercise protected and unknown
controls. Next extend automatic claim assembly to novel targets through the
[Phase 3/5–8 sequence](../architecture/evidence-and-claims.md#discovery-on-novel-target-repositories);
explicit check files are evaluation/business-policy inputs, not the final discovery strategy.

## Reducing Review through stronger analysis

The [analysis-certainty improvement plan](analysis-certainty-improvements.md) proposes atomic claims,
claim-specific blockers, verified library/API models, callback/source provenance, enforcing guards and
middleware, relevant helper summaries, and evidence-ready semantic assessment. It maps the HTML
uncertainty text to concrete missing facts and gives acceptance targets and evaluation measures.

Keep the AppSec headers **Findings**, **Review**, and **Protected**, with overlapping **Categories**.
Count distinct supported issues independently of operation records; a type pill is not an additional
finding. Preserve Review for unresolved requirements or evidence. Extend the existing checked-mode
completeness machinery instead of promoting every observed pattern to a true-positive finding.

These are follow-on analysis increments to scope deliberately. They do not authorize a broad engine
rewrite during other assigned work, paid evaluations, or target execution. Reduce Review by resolving
its questions correctly, measuring false findings and false protection alongside coverage.

## Human report UI and packaged demonstration

The current [human-report contract](../specifications/human-readable-reports.md) adds clearer JSON
finding explanations, standard SARIF output, and the [standalone HTML UI](../architecture/html-reporting.md).
The UI was reviewed against the input-validation and SQL/NoSQL cases before logger-leak detection began.
Local scan artifacts live outside worktrees under the configured
`_test-findings/<repo-name>/run-<id>/` root; they are not committed as routine test output.

### Curated public sample outputs

**Implemented at the user's request:** root [docs/samples](../../docs/samples/README.md) contains
Juice Shop and vulnerable TypeScript JSON/HTML/SARIF, with README links near the project introduction.
This supersedes the earlier proposed demo/juice-shop directory. Samples are updated as reporting
and analysis improve; they remain deliberate curated outputs rather than routine test artifacts.

Each sample records the pinned upstream source revision, source attribution, actual scope and
model-assessment coverage, scanner baseline/question versions, and limitations. Public project labels
replace developer-specific absolute roots. HTML and SARIF are generated from matching canonical JSON;
no model call is needed to view them or refresh their presentation. The offline refresh script is
owned by the [sample guide](../../docs/samples/README.md#refresh-as-zazzles-improves).

Keep examples honest: preserve incomplete/failed/unassessed states, source hashes and IDs. Do not
invent a protected finding or vulnerability for visual effect. Input-validation and DB-protection
claims remain distinct, and third-party comparisons never appear in product report content.
Routine scans continue using the external _test-findings root; changes to bundled examples require
an intentional refresh and review. Independent UI acceptance and broader held-out accuracy checks
remain separate from publishing these illustrative samples.

## User-agent workflow skills

Planned: [user-agent scan and remediation skills](user-agent-skills.md) for running scan on a user's
repository, interpreting canonical findings/evidence, and implementing tested remediation. These
product skills are separate from zazzles's own development-agent orientation and SDLC skills. Publish
consumer guidance through root docs and future skill packages; keep internal process out of the
primary user introduction. No consumer skills are implemented by this planning update.

## Future capability branches

### Supported capability checklist

This is the implemented-analyzer checklist. Table rows use short names under the Analyzer header. **Analyzer** names a capability; **analysis pack** names
its supporting knowledge. The [architecture terminology](../architecture.md#analyzer-terminology)
owns definitions. XSS rows are subcapabilities of one XSS Analyzer; adapters and linkage are supporting
coverage. The [delivery punch list](#future-capability-branches) includes planned analyzers and
infrastructure with stable branch IDs. Naming changes do not change completion or coverage claims.

**Status update, 2026-11-02 (user).** Keep the complete list, including delivered work. A checked
cell means a bounded implementation exists with regression/evaluation evidence; it does not promise
all frameworks, paths or vulnerability instances are covered. An unchecked cell remains explicit work.
JavaScript, TypeScript and Python are the supported source languages. Every future capability must
include extraction/models, evidence/judgment, reporting and positive/protected/unknown tests for all
three; Python is no longer an additional-language milestone.

| Analyzer / supporting capability | JavaScript | TypeScript | Python | Evidence and remaining limits |
|---|---|---|---|---|
| Input Validation | [x] | [x] | [x] | Source-backed field-policy and enforcing-guard claims; missing business requirements remain Review |
| SQL Injection | [x] | [x] | [x] | Verified operation/operand models and source traces; Python DB-API support is bounded |
| NoSQL Injection | [x] | [x] | [ ] | Bounded JS/TS selector/expression analysis; Python driver/model coverage remains pending |
| Sensitive Data Logging | [x] | [x] | [x] | Sensitive-content emission and redaction judgments; whole containers/unknown sensitivity remain Review |
| XSS — Reflected/server output | [x] | [x] | [x] | Verified response/template context and encoding; unsupported engines/configuration remain gaps |
| XSS — Stored | [x] | [x] | [x] | Bounded source/write/read/render links; exact origin/row identity is not universally resolved |
| XSS — Client-side/DOM/framework | [x] | [x] | [x] | JS/TS browser analysis also handles selected inline scripts in Python templates; not every browser framework |
| XSS — API-to-browser linkage (supporting coverage) | [x] | [x] | [ ] | Bounded JS/TS cross-tier evidence; general Python linkage remains pending |
| Python language adapter | — | — | [x] | Delivered bounded adapter; dynamic registration/dispatch and framework parity remain explicit gaps |

References: [query/validation results](../evaluation/query-validation-comparison.md),
[logging contract](../specifications/sensitive-data-logging.md),
[XSS scope](xss-detection-scope.md), [XSS results](../evaluation/xss-implementation-results.md), and
[Python contract/results](../evaluation/python-support-results.md). The original three Python apps
have 29 passing case checks. VulnPy adds six known SQL/XSS positive misses and four passing coverage
warning controls; those misses are not passed findings or a claim of complete Python coverage.

### Common entry/dispatch foundation

The [common entry/dispatch model](common-entry-dispatch.md) completed its eight-deliverable
milestone and merged through PR #8 on 2026-11-05. It supplies common entry, registration, dispatch,
callable and invocation identities, with bounded browser-event, dynamic HTTP, Node.js GraphQL and
unary gRPC support. Its [acceptance evidence](../evaluation/common-entry-dispatch-results.md)
retains unsupported subsets and explicit gaps. The merged foundation is the baseline for the
separate analysis pack MVP; the Command Injection Analyzer remains the next new analyzer.

### Analysis pack MVP initiative

**Implemented foundation, updated 2026-11-06:** the [SQL-first contract](../specifications/analysis-pack-mvp.md)
and migration sessions 01–03 below deliver the shared component architecture. The
[design rationale](analysis-pack-mvp.md) explains the boundary; the
[component architecture and verification ledger](../architecture/analysis-packs.md) owns runtime
responsibilities, compatibility, static baseline comparisons and fresh paid E2E evidence.

SQL, JS/TS NoSQL, standalone validation, XSS and outbound observations use explicit selection and
versioned provenance. Static adapters and mandatory Go gates remain authoritative. Fresh reports
use schema 4; historical reports preserve original answers, and changed requests reject stale replay.
Offline regression checks and all 944 eligible fresh paid Juice Shop/VulnPy judgments passed,
including exact replay against newly parsed source. Outbound remains observation-only; logging
remains the next existing-family migration rather than a completed catalog consumer.

Public pack loading, executable plugins, new rule languages, standards ingestion, general
Inspect/Audit/Fix and expanded detection remain separate work.

The planned Command Injection Analyzer MUST use the accepted components under its
[bounded contract](../specifications/command-injection.md).
The follow-on migrations have separate contracts; sessions 01–03 are now complete, while logging
remains unassigned. None is hidden cleanup in the SQL MVP:

| Implementation order / session | Boundary | Required acceptance |
| --- | --- | --- |
| 1. [NoSQL + standalone input validation](../specifications/components-01-nosql-validation.md) — implemented 2026-11-05, offline verification passed | Generalized family registrations/material/provenance, then migrated JS/TS NoSQL and JS/TS/Python standalone policy/enforcement together (`nosql-components-v1`, `validation-components-v1`; SQL provenance bytes changed, recorded as `sql-components-v2`) | Independent injection/validation outcomes, no API requirement for standalone validation, selected guidance completeness, source/report/replay parity; Python NoSQL stays unsupported; see the [ledger evidence](../architecture/analysis-packs.md#nosql-and-standalone-validation-migration-verification-2026-11-05) |
| 2. [All XSS types, including browser](../specifications/components-02-xss.md) — implemented 2026-11-05, offline verification passed | Staged server/template, stored, DOM/framework/event/inline-script and cross-tier migration | All current XSS regressions; no borrowed encoding/origin/path protection; explicit bounded browser fetch-method correction and separate before/after evidence |
| 3. [Outbound observations](../specifications/components-03-outbound.md) — implemented / offline verified 2026-11-06 | Current destination/response observation components, trusted only to actual supported binding/operand evidence | Browser/server and URL/body/response isolation; no SQL-question fallback or invented SSRF verdict; historical answers and explicit unassessed/incomplete semantics |
| Later, separately assigned: logging migration | Sensitive-content, emission, redaction and verified logger contracts/questions | Secret/personal data, constant/metadata, redacted and unresolved controls; independent logging gates |

The session grouping and accepted predecessor revisions are recorded in the linked contracts and
verification ledger. NoSQL/validation, XSS and outbound are delivered migrations; their implementation
prompts are historical execution contracts, not next-step assignments.

The order is based on dependency and risk: validate reuse with two real non-SQL claim types first;
then handle rendering and browser provenance; finally migrate outbound observations while preserving
those browser boundaries. The XSS spec includes only an explicitly bounded fetch-method attribution
correction. The outbound spec explicitly separates observation eligibility from future SSRF judgment.
These small behavior corrections require their own before/after evidence, separate from parity.

SQL query validation facets already use the SQL selection. The first follow-on also handles
standalone field requirements without adding a general quality/standards engine. The second covers
all currently implemented XSS types; it does not promise all browser vulnerability families. General
CSRF, CORS, browser storage leakage, clickjacking and new code-injection capabilities need their own
contracts. Complete outbound SSRF, redirects/DNS/network policy, Python NoSQL and general Python
API-to-browser linkage remain separately scoped coverage work.

The three numbered migrations are implemented and verified; live model evidence and remaining
coverage limits are recorded in the component ledger.
Later migrations require assignment and MUST converge on the shared architecture without a permanent
alternate policy path. This ordering governs these migration
sessions; the Command Injection Analyzer remains the next new analyzer and other roadmap scope is
unchanged. Completed verification does not authorize additional paid calls or sample changes.

### Complete delivery list

This punch list uses short analyzer names in the table. **Command Injection** is the next analyzer
to implement, followed by **Harden XSS analyzers** for the existing reflected, stored and client-side
capabilities. Shared infrastructure and coverage-completion work are identified separately; their
rows do not represent additional vulnerability analyzers.

**Sequence decision, 2026-11-02; pack initiative added by the user on 2026-11-05:** common
entry/dispatch with bounded dynamic-route, GraphQL and gRPC support follows Python support. Both
that foundation and the component MVP/migration sessions are implemented. Command injection and
separately scoped XSS hardening remain subsequent work.
Keep the other planned classes. Complete Python NoSQL and API-to-browser XSS
linkage coverage immediately before dependency vulnerability scanning (SCA), after the other planned
vulnerability-type work. Secret scanning follows SCA. Language expansion has no fixed position
in this sequence; gRPC entry support is independent of source-language support.
This order supersedes earlier sequence notes and the historical language-phase dependencies below.

The analysis pack MVP is explicitly assigned above. Other unchecked rows require their own bounded
contract and implementation assignment; this plan does not authorize them. Preserve current capabilities and their unresolved coverage while implementing new ones.

| Status | Analyzer / supporting capability | Branch / capability ID | Acceptance target or delivered reference |
|---|---|---|---|
| [x] | Input Validation | `input-validation` | Bounded source-backed policy/enforcement judgments; retain separate destination protection |
| [x] | SQL Injection | `sql-injection` | Bounded SQL construction, binding and injection judgments on verified APIs |
| Partial | NoSQL Injection | `nosql-injection` | JS/TS delivered subset; Python support remains unchecked in the language matrix |
| [x] | Sensitive Data Logging | `logger-leak` | Explicit sensitive logger calls, access-log URL credentials and logging-specific judgment; see the contract |
| [x] | XSS | `xss-response` | Delivered bounded reflected, stored, browser and cross-tier analysis; retain hardening gaps rather than claiming universal coverage |
| [x] | Python adapter (shared infrastructure) | `python-support` | Delivered adapter and shared trace/report guardrails; same claim architecture as JS/TS |
| [x] | Common entry/dispatch (shared infrastructure) | `common-entry-dispatch` | Shared entry/registration/dispatch/callable model; migrate HTTP/browser consumers and add bounded dynamic-route, GraphQL resolver and gRPC handler adapters with explicit unknown controls |
| [x] | Analysis-pack catalog (shared knowledge infrastructure) | `analysis-pack-mvp` | SQL-first embedded selection, bounded judge composition, report provenance and exact-request replay; [contract](../specifications/analysis-pack-mvp.md), [architecture/ledger](../architecture/analysis-packs.md) |
| [ ] | Command Injection | `command-injection` | Request-to-process execution and protective patterns in JS/TS and Python; start with TypeScript `/api/ping` and source-reviewed Python sinks |
| [ ] | Harden XSS analyzers | `xss-hardening` | General renderer/configuration, factory/helper and cross-tier coverage; retain raw/escaped/unknown controls, including VulnPy's Jinja Environment/template case |
| [ ] | Path Traversal | `path-traversal` | Request-influenced file paths, starting with `/api/files`; include JS/TS/Python containment controls |
| [ ] | Code Injection | `code-injection` | Request-to-eval/code-generation paths, starting with `/api/calculate`, across supported languages |
| [ ] | XXE | `xxe` | Request-to-XML parsing and verified parser configuration across supported languages |
| [ ] | Open Redirect | `open-redirect` | Request-influenced redirect targets and actual destination policy |
| [ ] | Weak Randomness | `weak-randomness` | Randomness used for security-sensitive tokens; ordinary non-security randomness stays a negative |
| [ ] | Cookie/Session/Header Configuration | `cookie-session-headers` | httpOnly, secure, session configuration and source-backed baseline header requirements |
| [ ] | SSRF | `ssrf-destination` | Complete judgment of existing outbound candidates, including axios.default.get; verify URL slots and restrictions |
| [ ] | Prototype Pollution | `prototype-pollution` | JS/TS object/prototype operations such as _.merge; test Python's non-applicability rather than inventing equivalent prototype semantics |
| [ ] | Python analyzer coverage completion | `python-coverage-completion` | Complete Python NoSQL and API-to-browser XSS linkage coverage immediately before SCA; retain separate binding, origin and rendering claims with paired controls |
| [ ] | Dependency Audit (planned Audit capability) | `sca-library-audit` | Resolved dependency/advisory auditing for JS/TS npm/pnpm and Python pip-audit, with failures and reachability separate |
| [ ] | Secret Scanning | `hardcoded-secrets` / secret scanning | Private material in source; public verification keys and placeholders remain controls |

Dynamic-route reporting must not turn an unresolved factory into a fabricated concrete endpoint.
Static/dynamic describes registration origin, not vulnerability status; both kinds can be resolved,
unresolved, protected or vulnerable. Broader corpus expansion and the living
[ThreatByte](../evaluation/threatbyte-detection-guide.md),
[FastAPI](../evaluation/python-insecure-app-detection-guide.md), and
[VulnPy](../evaluation/vulnpy-detection-guide.md) answer guides accompany each future capability.

<a id="next-concrete-case-registration-validation"></a>

## Registration validation acceptance reference

The earlier user-selected acceptance case was account registration. The
[registration case design](07-registration-validation-case.md) records pinned Juice Shop source,
actual conditional checks, bypass shapes, generated persistence endpoints, test-label limitations,
and exact structural/prompt improvements. The original offline scan emitted no registration candidate; checked mode now
assembles this candidate and the [login case](08-login-validation-case.md).
[Two-case results](../evaluation/juice-shop/results.md) record the live integration outcome.

Prioritize effective middleware chains and generated ORM create operations (Phase 3), local
next()/return/guard control flow (Phase 5), model/helper transfers (Phase 6), claim-specific completeness
(Phase 7), and atomic judge questions plus finding eligibility (Phase 8). Keep these as one bounded
registration-focused increment where possible. Do not equate OWASP's repeat-password/DRY challenge
with Empty User Registration or treat challenge flags as proof of persisted invalid accounts.
This case refines R2–R5; only the bounded subset in the current contract is implemented.

## Structural analysis and semantic judgment

The objective is a target-repository framework for API routes, internal code paths, outbound service
request strings, remote response values and subsequent use. Go establishes supported dependencies;
GPT Decisions or Jev judges sufficient validation/protection and potential vulnerabilities from that
evidence. This avoids hard-coding every acceptable custom validator while retaining precise source/sink
and library semantics. See the [graph design](../architecture/repository-graph.md).

| Phase | Required structural work | What stays a judge question |
|---|---|---|
| 2 | Parse routes, calls, assignments, returns, branches into source-backed operations and values | None; syntax is evidence |
| 3 | Resolve handlers/imports; model request-field sources, SQL operands, outbound URL/header/body slots and response sources | Whether a shown custom constraint is adequate for the specified use |
| 5 | Local value/control flow, reassignment, joins, guard outcomes and bypass facts | Whether those guards/transformations meet the sink's security requirements |
| 6 | Matched argument/parameter and return flow, supported await/promise/callback continuations | Interpretation of a complete cross-function protection case |
| 7 | Bounded evidence with helpers, witness, sink semantics, snapshots and gaps | No invented evidence or missing paths |
| 8 | Explicit provider selection, independent calibration and failure handling, Findings Review | Typed protection/vulnerability assessment over the supplied evidence |

Start with the authorized [current contract](../specifications/route-string-validation.md) spanning a
small subset of these phases, validate on Juice Shop and controlled pairs, then grow the structural
subset. Full phase completion is not a prerequisite to a bounded provider experiment. Outbound
request detection does not by itself implement remote response propagation. Each new sink family or
async pattern needs its own evidence and capability tests. General OWASP coverage remains long-term.

## Starting point and definition gate

Use the [repository-state record](../project.md#concept-stage-repository-state) for existing artifacts.
Phase 0 below audits their fitness; their presence does not establish an accepted implementation.

Every phase uses Go for zazzles-authored scanner, code-analysis, integration, and evaluation-harness code,
following the [implementation boundary](../architecture.md#1-architecture-premise). Target-language
fixtures and maintained JavaScript/TypeScript/Python adapters refer to languages being analyzed;
Go/Java remain later language work. Reference tools such
as IRIS inform the design without introducing their runtimes into zazzles.

Before the next implementation spec, select its JS/TS/framework slice, OWASP edition, analysis limits,
source-transmission policy, and evaluation criteria from the
[open decision register](03-jev-design-proposal.md#open-decision-register). Resolve only what the next
contract needs. Credential-dependent work is identified per phase; pending key status and setup
references live in the [research note](04-jev-validation-research.md#what-can-happen-before-a-key-exists).
Library candidates and selection ownership live in the
[proposal's library register](03-jev-design-proposal.md#library-choices). Owning specs record exact
versions, compatibility/build constraints, licensing, and verification before adding dependencies;
the pasted library examples do not constitute approved dependency selections.

## How a phase becomes agent-manageable work

Use the assigned isolated feature worktree for related specification, design, implementation and tests.
Independent future deliverables may use separate worktrees/PRs into `stage`. Explicit user requests
authorize implementation under [AGENTS.md](../../AGENTS.md#authorization-and-delivery). See the
[orientation](../docs/zazzles-agent-orientation.md#branches-and-worktrees).

- Suggested spec names below describe future contracts; they are not files created or greenlit now.
- Each spec has one reviewable outcome and its own scope, non-goals, inputs/outputs, dependencies,
  acceptance criteria, mapped tests/evidence, standards, and halt conditions.
- A phase containing multiple specs is implemented one contract at a time. Further split any contract
  that mixes independent outcomes or cannot produce a compact, verifiable handoff.
- Long-running execution resumes from a gitignored run log with current branch/spec, completed
  acceptance evidence, changed artifacts, failed checks, unresolved decisions, and next bounded step.
  Persist checkpoints before context loss; no chat-only progress state.
- Downstream work starts from accepted dependency contracts. Shared IR/schema changes require owner
  steering and updates to dependents, not silent drift.
- Ownership, greenlight, review, and storage follow the
  [methodology](../docs/zazz-methodology.md#specification-driven-delivery-cycle); branch/worktree policy
  lives in [AGENTS.md](../../AGENTS.md#branch-model).

## Acceptance targets

| Target | Role | Setup/limits |
|---|---|---|
| Small paired JS/TS corpus | Exact expected flows, guards, findings, and classification labels | Human-reviewed safe/vulnerable pairs; tuning and held-out partitions |
| OWASP Juice Shop | Realistic JS/TS repository and selected documented challenges | Clone supplied; pin the accepted revision and map selected challenges |
| SQL and MongoDB microfixtures | Compare sink/API-specific mitigation behavior | Isolated examples, not assumptions that SQL is safe or NoSQL unsafe |
| Hand-built IR/graph fixtures | Verify analysis independently of parsing/model output | Joins, cycles, guard bypass, unknown calls, call/return transfer, resource bounds |

Juice Shop is a [deliberately insecure Node.js/Express/Angular application](https://owasp.org/projects/juice-shop?tab=overview).
Map selected challenges to reachable code and expected findings at a pinned revision. Not every
challenge is statically detectable, and dependency/deployment/client/runtime-only issues may be outside
the chosen slice. Do not call total challenge count a scanner recall denominator. Keep expected labels
and challenge explanations out of model input. Paired cases live in our separate corpus rather
than modifying the reference checkout; selected built-in coding-challenge fixes can seed that corpus. Fixture access, licensing, inclusion/exclusion, and versioning
belong in a future spec. Local clone lookup and handling follow the
[orientation workspace conventions](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root).

### Juice Shop case selection and paired fixes

Observed checkout revision: `399fba76194305a312693eee44f4df64bdf0c3ce`; the future corpus spec must explicitly
select its accepted revision and map each case to the documented challenge, root cause, source/value,
sink, relevant helpers, and expected result. Use the documented vulnerable case as the positive test,
then a reviewed protected counterpart and inadequate-fix variants as separate tests. Judge safety per
vulnerability/use; a SQL-safe fix is not proof of correct authentication or the absence of other flaws.

The clone includes coding-challenge snippets and explanation metadata under `data/static/codefixes/`.
For example, the [ignored replacement variant](https://github.com/juice-shop/juice-shop/blob/399fba76194305a312693eee44f4df64bdf0c3ce/data/static/codefixes/unionSqlInjectionChallenge_1.ts)
calls string replacement without using its returned value; the
[parameter-bound login fix](https://github.com/juice-shop/juice-shop/blob/399fba76194305a312693eee44f4df64bdf0c3ce/data/static/codefixes/loginAdminChallenge_4_correct.ts)
binds query values. Treat these as candidate cases, not automatically accepted labels. Verify code,
helper behavior, intended functionality, and sink-library semantics against their metadata.

Hide label-bearing filenames such as `_correct`, challenge IDs, vulnerability-marker comments,
solution explanations, and expected outcomes from model input while retaining a provenance mapping
outside the payload. Preserve real executable semantics and separately test misleading ordinary
comments. Partition by root cause/helper family, not challenge ID: several challenges may share one
underlying flaw. Include held-out original variants because public examples can be familiar to models.

The [prior-art study](05-prior-art-and-feasibility.md) informs parser/adapter/flow/rule/report specs:
Bearer for Go implementation patterns and CodeQL's open queries/libraries for semantic models and
regression cases. Keep these studies scoped to the next contract. Phase 1 may compare prepared
evidence with pinned Bearer results; treat human labels as the
reference, not Bearer output. This study does not change the chosen Decision Assessment → Findings Review roles.

## Dependency overview

| Phase | Depends on | Proposed outcome |
|---|---|---|
| 0 | Definition gate | Audit/retain bootstrap foundation |
| 1 | Definition gate | Corpus, question design, optional live feasibility evidence |
| 2 | 0; corpus shape from 1 | Parser choice, normalized IR, deterministic extraction |
| 3 | 2 | Resolution and security-role/library models |
| 4 | 3; labels from 1 | Useful deterministic rules and minimal finding output |
| 5 | 2–3; flow fixtures from 1 | Local CFG/dataflow and mitigation-use facts |
| 6 | 5 + resolution from 3 | Bounded cross-function flow and witnesses |
| 7 | 6; evidence needs from 1 | Complete, minimized evidence bundles |
| 8 | 7 + live feasibility from 1 | Decision Assessment, LLM Findings Reviewer, and reconciliation policy |
| 9 | 4, 6–8 | Unified reporting, identity, baseline, CI behavior |
| 10 | 9 | Correct incremental caches and resource/performance evidence |
| 11 | Delivered under the Python contract | Existing bounded Python adapter; retained historical phase reference, not a future language |
| 12 | Selected language-adapter scope and framework/flow prerequisites; unscheduled | Go adapter in a separate future contract |
| 13 | Separate proposal + relevant foundation | Optional scope checks, coverage expansion, and additional languages such as Java |

Phases 4 and 5 are independent after their prerequisites. Offline phases 0–7 can progress after their
own authorization without a judge key. Phase 1 live feasibility and Phase 8 need credentials; absence of a
key does not justify inventing benchmark results or an automatic provider substitution.

## Ordered specification backlog

**These are historical planning IDs, not proof of authored/accepted specs.** The current capability
checklist above owns delivery status and order; S29–S30 are superseded by the delivered Python contract.
Follow this recommended sequence, but start a spec only after its listed prerequisites are accepted.
Rows describe independently reviewable outcomes; related rows may be delivered in the assigned
worktree when explicitly requested by the user.
A successor branches from `stage` after its prerequisites merge; independent rows can proceed in
separate worktrees when authorized. An explicit user implementation request is sufficient authorization; record its scoped contract.

| Order | Phase | Future spec | Prerequisites | Reviewable outcome |
|---|---|---|---|---|
| S01 | 0 | `foundation-audit` | Definition gate | Verified current behavior and gaps |
| S02 | 0 | `foundation-adjustments` | S01; only if needed | Bounded fixes to accepted foundation/toolchain |
| S03 | 1 | `corpus-and-juice-shop-map` | Definition gate | Pinned fixture scope and human labels |
| S04 | 1 | `semantic-question-design` | S03 | judge validation/sanitization questions and reviewer rubric |
| S05 | 1 | `semantic-feasibility-eval` | S04; credentials/budgets | Measured Decision Assessment and Findings Review on prepared evidence |
| S06 | 2 | `parser-binding-evaluation` | S01, S03; S02 if needed | Binding/grammar/build decision |
| S07 | 2 | `analysis-ir-contract` | S06 | Normalized operations, typed adjacency contract, identity, provenance, capability limits |
| S08 | 2 | `jsts-cst-extraction` | S07 | Deterministic syntax extraction |
| S09 | 3 | `jsts-module-call-resolution` | S08 | Supported import/call/parameter/return resolution |
| S10 | 3 | `security-model-catalog` | S09 | Source/sink/guard and library models |
| S11 | 4 | `pattern-rule-contract` | S10, S03 | Rule metadata and evidence schema |
| S12 | 4 | `initial-pattern-rules-and-output` | S11 | Offline rule findings, marked not yet reviewed |
| S13 | 5 | `local-cfg` | S08, S10 | Control-flow blocks and branch/loop behavior |
| S14 | 5 | `local-value-flow` | S13 | Value transfer, reassignment, joins, and unknowns |
| S15 | 5 | `guard-use-and-mitigation-facts` | S14 | Guard/value/sink relationship and bypass evidence |
| S16 | 6 | `function-dependency-summaries` | S09, S15 | Bounded argument/return dependency summaries |
| S17 | 6 | `cross-function-witnesses` | S16 | Multi-file traces, recursion limits, gaps |
| S18 | 7 | `candidate-evidence-contract` | S17, S04 | Versioned assessment/review evidence contract |
| S19 | 7 | `bounded-bundle-builder` | S18 | Complete bounded bundles and inspector output |
| S20 | 8 | `decision-judge-adapters` | S19, S05 | Production Decision Assessment adapter and failure states |
| S21 | 8 | `llm-findings-reviewer` | S20 | Independent Findings Review and bounded reconciliation |
| S22 | 8 | `assessment-review-policy-and-evaluation` | S21, S12 | Integrated pipeline, human-label evaluation, audit/completeness policy |
| S23 | 9 | `finding-identity-and-grouping` | S22 | Stable identity across detector/reviewer assessments |
| S24 | 9 | `report-and-scan-comparison` | S23 | Unified findings/review/coverage and compatible-scan comparison |
| S25 | 9 | `baseline-and-ci-policy` | S24 | Reviewed baseline rules and incomplete-review CI behavior |
| S26 | 10 | `dependency-aware-cache` | S25 | Cache correctness across source/model/policy changes |
| S27 | 10 | `resource-and-performance-validation` | S26 | Measured latency, resource, spend, and cancellation limits |
| S28 | 10 | `release-packaging-and-readiness` | S27; release-scope decision | Reproducible selected-platform release evidence |
| S29 | 11 | `python-extraction-and-resolution` (historical) | Superseded by [Python contract](../specifications/python-support.md) | Bounded Python extraction/resolution delivered |
| S30 | 11 | `python-flow-and-rules` (historical) | Superseded by the delivered Python contract | Bounded Python flow/rules/judgment delivered; coverage gaps retained |
| S31 | 12 | `go-resolution-and-lowering` | Selected language-adapter scope and framework/flow prerequisites; unscheduled | Go receiver/interface/lowering subset |
| S32 | 12 | `go-flow-and-rules` | S31 | Go flow, rules, and assessment/review evaluation |
| S33 | 13 | `java-resolution-and-lowering` | Java-scope decision and relevant shared foundation; unscheduled | Java types, annotations, overloads, lowering |
| S34 | 13 | `java-flow-and-rules` | S33 | Java flow, rules, and assessment/review evaluation |

S05's live experiment can remain pending while S06–S19 progress after their own authorization. S12 and
S13 start independent rule/flow lanes after shared prerequisites. The initial release is evaluated at
S28; later language rows are a proposed expansion sequence, not initial-release requirements. SARIF
and Phase 13 capabilities need separately scoped backlog entries when approved.

## Phase 0 — Foundation audit and tooling decision

**Future specs:** `foundation-audit`; `foundation-adjustments` only if the audit identifies needed work.
Inspect the existing CLI/walker/registry, module/toolchain declaration, and CI against the refined scope.
Verify behavior and keep useful source. Decide any missing ignore/selection behavior explicitly.

**Evidence/exit:** reproducible manifest and code-check results, gap list, retained behavior, and
owner-approved toolchain/platform assumptions. Existing manifest exit codes are documented.
**Exclude:** parser, analysis, model integration, and speculative package scaffolding.
**Halt/replan:** toolchain unavailable or current behavior conflicts with a necessary contract.

## Phase 1 — Ground truth and semantic feasibility

**Future specs:** `corpus-and-juice-shop-map`; `semantic-question-design`; `semantic-feasibility-eval`.
These are separate offline and live deliverables. Start with a few named SQL/command/path cases; expand
NoSQL/SSRF and other families only as agreed. Include safe, vulnerable, and intentionally unknown cases,
ignored validator results, bypass branches, custom helpers, and misleading comments. Label validation,
context-specific protection, and actual guard use separately.

**Evidence/exit:** human-reviewed expectations, pinned reference revision and scope, held-out partition,
hand-prepared evidence bundles, versioned questions, and a declared evaluation protocol. Live spec sets
error/uncertainty/cost budgets before execution; report false-safe and false-alarm rates by family.
Experiment with Decision Assessment of validation/sanitization, then Findings Review of identified issues.
Use diagnostic deterministic/judge-only/reviewer-only baselines on the same evidence to measure contribution.
Audit judge-protected cases for missed issues; reviewer agreement is not a human label.
**Exclude:** production scanner implementation and API requests in the offline specs.
**Halt/replan:** missing key for live work, contested labels, poor mitigation discrimination, or unclear
question semantics. Preserve offline artifacts; narrow the proposal rather than forcing a model result.

## Phase 2 — Parser decision, IR contract, and extraction

**Future specs:** `parser-binding-evaluation`; `analysis-ir-contract`; `jsts-cst-extraction`.
Evaluate selected grammars/bindings on real syntax and the intended build matrix. Define normalized
operations, values, blocks, source spans, provenance, identities, and serialized artifact versions.
Define zazzles-owned typed adjacency and forward/reverse relation indexes using the
[graph decision](../architecture.md#graph-storage-decision). Then extract declarations, imports, calls,
assignments, branches, and anonymous handlers. Verify the chosen parser's compatibility rather than
reopening library choices without a concrete blocker.

**Evidence/exit:** decision record, extraction goldens, malformed/partial-source diagnostics, native
resource lifecycle evidence, stable serial/parallel artifacts, and identity collision/edit cases.
Graph fixtures preserve parallel relation kinds, self-edges/cycles, and source provenance; initial
resource measurements establish a baseline for the later performance phase.
**Exclude:** resolved execution claims, taint propagation, and model calls.
**Halt/replan:** binding portability is incompatible with release needs or the IR cannot represent the
agreed local-flow subset; revise the contract before more adapters depend on it.

## Phase 3 — Resolution and source/sink/guard models

**Future specs:** `jsts-module-call-resolution`; `security-model-catalog`.
Resolve the declared aliases/re-exports/call patterns, registration-by-reference, parameters, and
returns. Classify source/sink/guard candidates with versioned query/rule/library data. Unknown targets
remain visible; imported package names alone do not prove API identity.

**Evidence/exit:** fixture source→call→sink relationships with exact binding evidence, unknown-edge
accounting, shadowing/alias negatives, and reviewed library-model preconditions. Map the selected
Juice Shop slice without claiming all application paths are resolved.
**Exclude:** a universal dynamic-language resolver and automatic sanitizer acceptance.
**Halt/replan:** false target resolution or framework assumptions invalidating the selected corpus.

## Phase 4 — Deterministic rules and minimal reports

**Future specs:** `pattern-rule-contract`; `initial-pattern-rules-and-output`.
Define reviewed rule metadata, versioned OWASP/CWE mapping, severity, and evidence requirements.
Implement a small rule set with safe/vulnerable pairs and minimal stable JSON findings. Rules needing
flow wait for the relevant supported-flow phase; do not fake it with string matching.

**Evidence/exit:** useful no-key/offline results, per-rule precision/recall on the declared corpus,
repeated-run equality, and evidence-backed positive/negative rule cases.
**Exclude:** broad OWASP completion claims, final baseline lifecycle, and semantic inference.
**Halt/replan:** a “pattern” verdict requires missing flow or runtime facts; narrow or defer that rule.

## Phase 5 — Local control flow and dataflow

**Future specs:** `local-cfg`; `local-value-flow`; `guard-use-and-mitigation-facts`.
Lower the agreed JS/TS subset into blocks and transfers. Define assignment/reassignment, expression
uses, branch joins, bounded loop handling, and unknown-operation behavior. Determine whether the
relevant validated/transformed value actually reaches a sink under the required guard outcome.

**Evidence/exit:** hand-built IR and parsed-source cases agree; guard-after-sink, bypass branch,
ignored return, changed value, cycles, and bounds are covered. Emit source-to-sink witnesses and gaps.
**Exclude:** broad alias/heap analysis and unsupported asynchronous semantics.
**Halt/replan:** proposed mitigation clears taint without value/control justification or loops fail to
converge/terminate under the declared bound.

## Phase 6 — Bounded interprocedural flow

**Future specs:** `function-dependency-summaries`; `cross-function-witnesses`.
Connect supported argument/parameter and return transfers. Define summary context, recursion/call
bounds, unknown/external calls, cancellation, and representative witness extraction/deduplication.
Report approximations and limits instead of enumerating every possible execution path.

**Evidence/exit:** multi-file vulnerable/safe fixtures, recursive/cyclic cases, helper sanitizer use,
unknown dispatch, and bounded runtime/memory. Every witness edge identifies its justification.
**Exclude:** exhaustive interprocedural alias solving and unstated framework behavior.
**Halt/replan:** limits silently lose expected findings or summaries conflate incompatible contexts.

## Phase 7 — Evidence bundles

**Future specs:** `candidate-evidence-contract`; `bounded-bundle-builder`.
Build minimal candidate bundles with snapshot/hash-bound spans, witness operations, branch/guard
facts, off-path helper definitions, sink semantics, library versions, and explicit missing evidence.
Add payload budgets and inspector output before any production semantic calls.

**Evidence/exit:** human review can reconstruct the case using only the bundle; missing/oversize
context is explicit; stable bundle hashes and allowed-source/redaction behavior are verified.
**Exclude:** classifier transport, free-form repository uploads, and generated citations.
**Halt/replan:** necessary evidence cannot fit or the source-transmission policy is unresolved.

## Phase 8 — Decision Assessment and Findings Review

**Future specs:** `decision-judge-adapters`; `llm-findings-reviewer`; `assessment-review-policy-and-evaluation`.
Choose the configured judge transport/model and validate typed IDs/options/ranges with bounded requests, deadlines,
retries, cancellation, budgets, and no-key/failure states. Add the LLM Findings Reviewer as a required
stage in the full pipeline. It independently inspects source evidence for every identified issue and
uncertain candidate before comparison with the judge/rule assessment. Go retains separate results,
validates evidence IDs, and handles disagreement or missing context explicitly.

**Evidence/exit:** local HTTP stubs cover both adapters and partial failures; held-out human-labeled
evaluation measures validation/sanitization recognition, reviewer corrections and incorrect agreement,
false-safe risk, uncertainty, citation validity, review completeness, latency, and spend. Audit a sample
of judge-protected candidates. Diagnostic baselines measure the roles; they do not turn the reviewer into
an optional production tier. No issue is labeled reviewed unless its review completed.
**Exclude:** autonomous graph exploration, generated fixes, and automatic safety acceptance/suppression.
**Halt/replan:** credentials unavailable, model changes, budget exceeded, evidence missing, or the quality
bar is not met. Keep incomplete stages and unresolved cases visible; reopen scope with the owner.

## Phase 9 — Unified reporting, identity, baseline, and CI

**Future specs:** `finding-identity-and-grouping`; `report-and-scan-comparison`;
`baseline-and-ci-policy`. Extend the bounded SARIF export using the
[report design](../architecture/reporting-and-sarif.md); preserve canonical finding identity/evidence.
Unify rule findings, flow candidates, semantic assessments, and coverage. Specify collision/move
behavior, grouping, compatible-scan comparisons, model/policy changes, and incomplete-scan exit policy.
Keep baseline ownership/reason review separate from model assessment.

**Evidence/exit:** repeat scan has no structural identity churn; assessment changes remain visible;
new sink/rule is reported correctly; incomplete scans never silently resolve missing findings;
no-key and mixed-failure reports expose incomplete Findings Review; CI behavior matches reviewed policy.
**Exclude:** a vulnerability lifecycle service and model-driven suppression.
**Halt/replan:** fingerprints collide or unchanged identity hides a material changed assessment.

## Phase 10 — Incremental correctness, performance, release readiness

**Future specs:** `dependency-aware-cache`; `resource-and-performance-validation`;
`release-packaging-and-readiness` for the explicitly selected release scope.
Cache parses/IR/summaries/bundles/raw model responses with complete dependency/version keys. Reapply
policy independently. Benchmark cold/warm runs and limits on pinned fixtures; choose supported builds.

**Evidence/exit:** cached/uncached equivalence after changed validators, imports, callers/callees,
model/question/rule/config versions; no live requests for unchanged eligible bundles; measured CPU,
RSS, latency and spend; documented rule/language coverage and limitations; reproducible packaging.
**Exclude:** graph databases and promises of complete Top 10 coverage.
**Halt/replan:** stale caches alter findings, resource bounds fail, or the chosen release scope lacks
acceptance evidence. Humans alone promote `stage` to `main` and tag a release.

## Phase 11 — Python adapter (delivered reference)

The bounded adapter was delivered under the [Python contract](../specifications/python-support.md),
with [evaluation evidence and limits](../evaluation/python-support-results.md). The old S29/S30
split is retained only for historical navigation. Python is a supported source language, not a future
language-addition task. Future functionality must include JS, TS and Python acceptance evidence.

Dynamic routes, callbacks, custom frameworks and remaining per-family gaps are ongoing hardening,
not a reason to mark the entire adapter as unimplemented or to claim universal parity.

## Phase 12 — Go adapter

JavaScript, TypeScript and Python are currently supported. This section is a technical design
reference, not a scheduled roadmap commitment. Language-adapter work uses a separate scoped contract;
phase numbering does not impose a language delivery order.

**Future specs:** `go-resolution-and-lowering`; `go-flow-and-rules`.
Go stresses receivers and interfaces.

**Evidence/exit:** language-specific resolution/flow fixtures, signature identity tests, explicit
unknowns, rules and semantic-question evaluation. Release support is declared per proven capability.
**Exclude:** complete interface/reflection resolution and blanket cross-language parity.
**Halt/replan:** ambiguous target selection, unsupported semantics, or language-specific evaluation gaps.

## Phase 13 — Optional scope checks and broader coverage

**Future specs:** one proposal and corpus contract per capability, followed by bounded implementation
specs. Revisit authorization/ownership, middleware ordering, logic constraints, additional framework
rules, or other languages based on measured user value.

**Evidence/exit:** enumerated questions, explicit required business/framework facts, stable anchors,
positive/negative corpus, uncertainty routing, and evidence of benefit beyond path detection.
**Exclude:** open-ended “review the application for security” as an unbounded model task.
**Halt/replan:** an expected answer requires business requirements or runtime facts absent from input.

## Follow-on phase — SCA ecosystem auditing

After the accepted route/source-to-use milestone, add ecosystem audit adapters and dependency
findings. Per the 2026-11-02 sequence decision, SCA for JS/TS and Python follows the remaining
vulnerability types and the remaining Python coverage item; secret scanning follows SCA. The
[SCA design](../architecture/sca-design.md) owns SCA-1 schema/tool selection, SCA-2 bounded audit
execution/reporting, and SCA-3 optional route-reachability correlation. Start with npm/pnpm audit for
JS/TS targets and add pip-audit for Python inputs under its own verified adapter contract. Preserve
resolved versions, advisory identity, dependency paths, failures and unknown reachability. Do not
silently dismiss dependency findings because a route path was not resolved.

## Progress and decision records

The capability checklist records bounded delivered work; unchecked items and partial language
coverage remain visible. Update completion only from accepted contract outcomes and evidence. Durable conclusions go into the proposal/architecture/scope docs; run logs and
resumption notes stay in `.zazz/ephemeral/`. Measure filtered/unexamined candidates alongside findings,
so cost reduction cannot conceal lost coverage. Revisit scope after each accepted capability instead
of treating this long-term plan as fixed.
