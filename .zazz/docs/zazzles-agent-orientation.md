# zazzles — agent orientation

Compact session context and document routing. Read [AGENTS.md](../../AGENTS.md) for binding rules and
when to load supporting guides. Keep this document under 400 lines; link to details rather than copy them.

## Table of contents

- [Current work](#current-work)
- [Portable workspace and DEV_ROOT](#portable-workspace-and-dev_root)
- [Branches and worktrees](#branches-and-worktrees)
- [Task reading paths](#task-reading-paths)
- [Documentation map](#documentation-map)
- [Working protocol](#working-protocol)
- [Methodology refinement](#methodology-refinement)
- [Commands and credentials](#commands-and-credentials)

## Current work

**XSS hardening, 2026-11-07:** implemented in the `xss-hardening` worktree under the
[contract](../specifications/xss-hardening.md). All 28 required cases across five apps are confirmed and all controls
hold; read the [results](../evaluation/xss-hardening-results.md) and [matrix](../evaluation/xss-hardening/matrix.json).
sql.js SQL candidates are verified offline only; 10 Juice Shop SQL/NoSQL records need a fresh judgment after `try`
control modeling. The paid-scan authorization covered the XSS loop only. Human review is pending; no merge or integration push is authorized.

**Node input refactor, 2026-11-07:** bounded Express/Fastify/Hapi acquisitions now feed transport-neutral
origin/type/transfer facts and a generic Mongoose lookup contract. Existing GraphQL/gRPC can carry the
same records. Optional model-assisted discovery remains outside trusted flow until independently
verified. Read the [contract](../specifications/node-http-input-refactor.md) and
[guide](../../docs/analysis/node-inputs.md). Python runtime behavior is unchanged; the root
[Python proposal](../../PYTHON-INPUT-REFACTOR-PROPOSAL.md) is deferred. This slice uses offline/stub
validation; saved real-app reports retain their prior scan provenance. No new paid calls are authorized.

**Command Injection Analyzer delivered, 2026-11-07:** implemented in the `command-injection` worktree under the
[implementation contract](../specifications/command-injection.md); read the
[acceptance results](../evaluation/command-injection-results.md), the independent
[matrix](../evaluation/command-injection/matrix.json) and the [public guide](../../docs/analysis/command-injection.md).
Four full judged scans (OpenAI Decisions `gpt-6-luna`) confirmed every required positive: the TypeScript `/api/ping`,
Goof `POST /create`, both VulnPy core sinks in all 11 framework adapters and the five app witnesses; Juice Shop's
source-reviewed zero-positive controls were clean. VulnPy ran with `--skip-family input-validation` (a standard option;
the report states the analyzer was not used). Human review is pending; no merge or integration push is authorized.
The earlier paid-scan restrictions
below apply to later work again: no new paid calls without explicit authorization.

**Component refactor, 2026-11-06:** SQL, NoSQL, standalone validation, XSS and outbound observations
are implemented and offline-verified in the assigned `analysis-pack-mvp` worktree/branch. Outbound
was committed at `c169a79` from clean `dc309cd`, preserving runtime `4e0be3e` and XSS migration `30fada9`. Read the
[component ledger](../architecture/analysis-packs.md#outbound-observation-verification-2026-11-06)
for ownership, protocols, source/report parity and remaining limits. Fresh reports use schema4;
schemas1–4 remain readable with historical answers intact.

[Outbound session03](../specifications/components-03-outbound.md) selects scoped observations.
JS/TS shapes remain unverified; Python retains its demonstrated URL-operand contract. Requested
outbound assessments return explicit `not_run` with zero model calls, stay Review and leave a
requested scan incomplete. Preview rejects them without a request body. Browser requests do not
establish server SSRF. Logging migration and complete SSRF/exfiltration/browser-security assessment
remain future work.

Full offline Juice Shop E2E validation and feature commit/push completed at `c169a79`.
The [full E2E ledger](../architecture/analysis-packs.md#juice-shop-full-e2e-follow-up-2026-11-06)
records actual all-registration scope, unchanged non-outbound requests and conservative incomplete
assessment behavior. Resume the existing feature worktree and preserve unrelated changes.
The assigned migrations are complete; logging remains unmigrated, so do not claim every existing
family uses the catalog. The [current status](../architecture/analysis-packs.md#current-implementation-status)
distinguishes delivered consumers from future coverage and migration work.
The user subsequently authorized fresh paid scans of Juice Shop and VulnPy. All 944 eligible
OpenAI Decisions `gpt-6-luna` judgments completed and passed fresh-source exact replay; all 35
historical confirmed source contexts remain confirmed. Read the
[paid component E2E evidence](../architecture/analysis-packs.md#fresh-paid-component-e2e-2026-11-06)
for actual results and preserved observation/binding limits. No further paid calls, target execution,
sample edits, new agents/worktrees, PR creation or integration merge are authorized by this
checkpoint. Human review remains pending.

**Completed foundation:** the [common entry/dispatch brief](../project/common-entry-dispatch.md)
records the implemented shared model with bounded dynamic-route, GraphQL resolver and gRPC
handler support, accepted and merged through PR #8. The shared model and existing HTTP/browser
consumers are migrated through
[deliverable2](../specifications/common-entry-dispatch-02-consumers-compatibility.md). Fresh
reports now use schema4 with canonical entry/context associations and component provenance; saved
schemas1–4 still export.
Typed selectors/presenters and bounded DOM/window events are implemented. Additional framework
adapters remain separately scoped work.
Use the current reviewed Python/terminology revision as the prerequisite, not the old pre-rename API.

**Architecture/terminology closeout:** embedded documents are **Analysis Guidelines**
(`internal/guidelines`); shared records live in `internal/analysis` as `CandidateUse`,
`AnalysisReport` and `RouteInventory`. `--analyze` is canonical; `--strings` remains an external
alias. Fresh analysis JSON is schema4 with `analysis_guidelines`; schema1–4 saved reports still
export. See the [implemented architecture](../architecture.md) and the
[closeout contract](../specifications/python-support.md#architecture-and-terminology-closeout).
Historical reports retain their original versions/answers; changed guideline inputs need fresh judgments.


**Prior Python activity, 2026-11-01: `python-support-base`.** The bounded Python adapter is implemented
and tested on three pinned apps. Read the [Python contract](../specifications/python-support.md),
[results and limits](../evaluation/python-support-results.md), and [user guide](../../docs/python-support.md)
for resumption. Raw results remain under `_test-findings/<app>/run-<id>/`; source keys, hashes and curated
reports are in root `docs/samples/`. 184 Luna calls were completed; saved answers require exact
request matching and changed evidence cannot inherit them. The user authorized pushing `python-support-base` and continued general hardening;
The user subsequently authorized committing/pushing this closeout and creating a draft PR into
`stage`. Integration pushes and merge remain unauthorized. Python NoSQL is out of corpus/unimplemented. Shared trace/report hardening and policy-backed
validation are documented in [trace judgment](../architecture/trace-judgment.md); all 29 independent
Python case checks pass. Only final Protected records are green.
Living answer guides for ThreatByte, the FastAPI app and the added VulnPy corpus are linked from
[Python results](../evaluation/python-support-results.md). VulnPy has six known positive coverage misses
and four warning controls; its offline baseline is not part of the original 29-case pass claim.

**Previous XSS worktree: `xss-response`.** The first XSS discovery/reporting pass was
committed and pushed as `26f50d0`. Verify the actual path, branch and changes with `pwd` and
`git status --short --branch`; later work may have advanced the branch.

For a later JS/TS XSS hardening session, read in this order:

1. [Implementation results](../evaluation/xss-implementation-results.md) for delivered behavior,
   current sample counts, actual model observations and verification limits.
2. The local, gitignored XSS handoff (`.zazz/ephemeral/xss-analysis-handoff.md`), if present, for prioritized
   investigations, code entry points and the suggested first bounded task. Handoffs MUST stay under
   `.zazz/ephemeral/` and MUST NOT be committed. A fresh clone will not contain them; resume from
   the tracked results, contract and reference documents instead.
3. [XSS contract](../specifications/xss-response.md), [scope](../project/xss-detection-scope.md),
   [product analysis guide](../../docs/analysis/xss.md) and the target's independent source-reviewed
   answer key linked from [sample reference policy](../../docs/samples/reference-policy.md).

**Current capability:** bounded JS/TS/CommonJS route and browser-source analysis, server/template/stored
and DOM/framework XSS facts, existing validation/database/outbound/logging analyzers, optional
versioned model judgments, and shared JSON/HTML/SARIF classification. Browser entries have a separate
report section. HTML can hide Protected records. This is not whole-program soundness or proven
scanner parity. Cross-tier origin, helper/control-flow and protection completeness remain hardening
work; unsupported paths stay Review. The [results](../evaluation/xss-implementation-results.md) own
current details; historical reports may contain superseded protection labels.

**Historical XSS hardening boundaries:** the earlier `xss-response` work supplied the accepted
source semantics. Current component work uses the assigned feature tree above; new detector
hardening still needs its own bounded contract. Preserve all implemented analyzers and compare
against independent source references.
Baseline vulnerable apps MUST remain unchanged; remediation uses copies. Five approved Luna calls
are complete and saved for offline inspection/replay. They authorize no additional paid requests.
Changed evidence MUST NOT reuse old model answers. The bounded Python adapter is now documented above; remaining vulnerability types follow, then SCA
for JS/TS and Python; language expansion has no fixed position in the roadmap;
shared graph/judgment/report facts remain language-neutral. No merge or integration push is authorized.

**Sample applications are read-only scan targets.** Zazzles detects vulnerabilities; agents do not
fix them in the sample apps. Agents MUST NOT edit, fix, reformat, install dependencies into, check out
another revision of, or write any file inside the pinned sample checkouts under `<DEV_ROOT>` (for
example `<DEV_ROOT>/nodejs-goof`, `<DEV_ROOT>/juice-shop`, `<DEV_ROOT>/vulnerable-typescript-app`).
Hardening changes belong in the scanner, never in a target to make a result appear. Code changes to an
application are allowed only in an independent copy created to test whether a scan detects the
remediation, following [remediation copies](../../docs/samples/reference-policy.md#remediate-a-copy).
Scan output goes to `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<app>/run-<id>/` via `--output-dir`,
never into the target. Before and after a session, `git -C <target> status --porcelain --ignored` MUST
be empty and `HEAD` MUST match the pinned revision. If a checkout was changed, stop and re-clone it
from upstream at the pinned revision before trusting any further result.

The long-term objective is source-backed vulnerability and protection analysis across languages,
with accuracy evaluated independently of model confidence or scanner agreement. Independent Findings
Review remains distinct from the semantic judge. See the [project objectives](../project.md#long-term-objectives)
and [graph design](../architecture/repository-graph.md).

Earlier logger-leak, route-string and SQL/NoSQL session notes describe historical work. Their old
“next slice” instructions are not the active assignment. Consult the tracked
[route/string contract](../specifications/route-string-validation.md),
[original Bearer evaluation](../evaluation/bearer-results.md), and
[Juice Shop evaluation index](../evaluation/juice-shop/README.md) only when the current case needs them.

## Portable workspace and DEV_ROOT

**`<DEV_ROOT>` means this computer's development directory**, usually `Dev/` under the user's home.
It is documentation notation, not an implemented environment variable. Usual locations:

- Repositories: `<DEV_ROOT>/<account>/<project>`; zazzles's container is `<DEV_ROOT>/zazzcode/zazzles`.
- Reference clones: `<DEV_ROOT>/juice-shop` (application), `<DEV_ROOT>/bearer`, and `<DEV_ROOT>/codeql`
  (SAST design references).

Resolve/verify roots each session; durable docs/configuration MUST NOT hardcode usernames or absolute
checkout prefixes. Other documents should link here for workspace conventions.

## Branches and worktrees

Scan uses a shared bare Git directory with sibling worktrees. `stage` integrates work and `main` is
release-only. Use the assigned feature worktree for related design, implementation, and tests.
Independent future deliverables may use separate feature worktrees and PRs into `stage`.
Load [worktree setup](worktree-setup.md) for the layout, reference-clone handling, naming, creation,
and recovery details; [AGENTS.md](../../AGENTS.md#branch-model) declares the current `stage/` exception.

## Task reading paths

After `AGENTS.md` and this orientation, choose the smallest applicable row. Load linked sections first;
load whole design documents only when the task crosses their boundaries. A link is not an include.

| Task / question | Read next | Load more when |
|---|---|---|
| Run scan or confirm route extraction | [README](../../README.md#run), [verification and limits](../project/06-route-validation-assessment.md#route-verification) | Read the [route spec](../specifications/tree-sitter-route-identification-mvp.md) and `internal/parse` when changing the route contract |
| Plan this branch's input-validation work | [near-term sequence](../project/implementation-plan.md#route-string-validation-delivery-sequence), [assessment](../project/06-route-validation-assessment.md#architecture-and-plan-assessment) | Read architecture §§3–7 for resolution, value/guard semantics, or evidence schema changes |
| Design graph or outbound service analysis | [Repository graph design](../architecture/repository-graph.md) | Load architecture §§4–7 for shared IR, flow and evidence policy |
| Design model assessment / review | [current provider decision](../architecture.md#current-provider-decision), architecture §8, [API setup](openai-decisions-setup.md) | Read historical [Jev research](../project/04-jev-validation-research.md) only for evaluation ideas or a provider comparison |
| Set up a key or diagnose access | [API setup](openai-decisions-setup.md) | Follow its official API links for current schema/access; never load or print secrets |
| Author the next specification | Near-term plan, [spec index](../specifications/README.md), `spec-builder`, [spec hygiene](../standards/spec-hygiene.md) | Resolve only decisions required by that contract; the old route spec does not authorize this branch's implementation |
| Implement or resume | Current authorized spec, its local run log, [execution discipline](agent-execution-discipline.md), `spec-driven` | Select relevant standards from the standards index; explicit user implementation requests are sufficient authorization under AGENTS.md |
| Reassess scope or long-term architecture | Project overview, architecture, scope, then proposal | Load functionality for capability details; prior-art/research docs for evidence behind a disputed choice |

## Product documentation versus SDLC documentation

Root `docs/` owns public philosophy, user/contributor setup, CLI operation, result interpretation,
and [scan analysis rules and guidelines](../../docs/analysis/README.md). These are product documents
used by people running scans and agents refining detection. They MUST NOT be placed under `.zazz/`.
Load the [database injection](../../docs/analysis/database-injection.md),
[input validation](../../docs/analysis/input-validation.md), and
[calibration](../../docs/analysis/calibration.md) guides when changing those analyses.

`.zazz/` owns SDLC/process standards, project plans, implementation contracts, internal architecture,
and evaluation history. `.zazz/ephemeral/` is ignored execution scratch and session handoff only.
Public rules describe the implemented analysis; current Markdown files are not dynamically loaded
by the binary. Changes MUST keep those rules, Go evidence/judgment code, and tests aligned.

## Documentation map

Select the document that owns the topic; do not load every row. Research/design context is preserved
in these files independently of chat attachments.

| Document | Primary content |
|---|---|
| [User documentation](../../docs/README.md) | Product introduction, agent-first philosophy, setup, use, result interpretation and contributor guides |
| [Project overview](../project.md) | Purpose, [public philosophy](../../docs/philosophy.md), current state, direction |
| [Architecture](../architecture.md) | Flow diagrams, judge/provider contracts, analysis semantics, package boundaries |
| [Analysis components](../architecture/analysis-packs.md#current-implementation-status) | Embedded catalog ownership, implemented family selection, provenance, verification and remaining migrations |
| [Repository graph design](../architecture/repository-graph.md) | Target-repository nodes/edges, inbound/outbound API boundaries, response flow, identity and provenance |
| [SQL/NoSQL judgment design](../architecture/query-judgment.md) | Automatic query claims, model contracts, conditional output facts and policy gates |
| [Evidence and claims](../architecture/evidence-and-claims.md) | Source-backed route slices, relevant functions, checked requirements and finding eligibility |
| [Reporting and SARIF](../architecture/reporting-and-sarif.md) | Route-oriented output, remediation options, internal model and implemented bounded SARIF export |
| [Standalone HTML](../architecture/html-reporting.md) | Core human-facing CLI report, native disclosure rows and JSON/SARIF relationship |
| [SCA design](../architecture/sca-design.md) | Follow-on ecosystem audit adapters and reachability correlation |
| [Functionality](../project/01-functionality.md) | Capabilities, detection modes, rule families, language sequence, interfaces |
| [Scope](../project/02-project-scope.md) | Boundaries, quality hypotheses, risks |
| [Design proposal](../project/03-jev-design-proposal.md) | Rationale, supplied concepts, graph/library choices, decision register |
| [Jev research](../project/04-jev-validation-research.md) | Capability evidence, limitations, evaluation protocol |
| [Prior art and feasibility](../project/05-prior-art-and-feasibility.md) | Novelty assessment, pinned Bearer study, engineering risks |
| [Vulnerable sample applications](../project/vulnerable-sample-apps.md) | Sample app sources, pins, expected findings and current scanner results |
| [Implementation plan](../project/implementation-plan.md) | Near-term route/string sequence, then long-term phases and backlog |
| [Route validation assessment](../project/06-route-validation-assessment.md) | Verified Juice Shop evidence, gaps, architecture review, bounded next scope |
| [Registration validation case](../project/07-registration-validation-case.md) | Next field-constraint case: middleware/guard bypass, generated persistence, evidence and judge questions |
| [Login SQL/validation case](../project/08-login-validation-case.md) | Separate email constraints and query semantics; phase regression expectations |
| [Two-case results](../evaluation/juice-shop/results.md) | Known-target Luna outcomes, usage, offline checks and remaining limits |
| [Bearer comparison plan](../evaluation/bearer-comparison.md) | Repeat/extension protocol; links to pinned results and capability inventory |
| [Semgrep CE results](../evaluation/semgrep-results.md) | Semgrep CE baseline and three-tool XSS answer-key comparison |
| [Semgrep CE cheat sheet](../../docs/semgrep-ce-cheat-sheet.md) | Second local comparison scanner: privacy flags, rule snapshots, output layout, CE limits |
| [Original comparison controls](../evaluation/corpus/README.md) | Label-isolated corpus, Luna outcomes, provenance correction and limitations |
| [Decision-model user guide](../../docs/decision-models.md) | Provider credentials, environment loading, capped scanner assessment |
| [Integration evidence](openai-decisions-setup.md) | Historical provider setup, transport and access smoke-check evidence |
| [Zazz methodology](zazz-methodology.md) | SDLC, ownership, greenlight and review lifecycle |
| [Specifications](../specifications/README.md) | Execution contracts and index |
| [Standards index](../standards/index.yaml) | Task-specific engineering standards routing |

## Working protocol

Load [Agent Execution Discipline](agent-execution-discipline.md) for execution, testing, verification,
resumption, or handoff; [AGENTS.md](../../AGENTS.md) supplies repo-specific overrides. For planning,
use the [phase-slicing guide](../project/implementation-plan.md#how-a-phase-becomes-agent-manageable-work).

## Methodology refinement

The Project Owner may assign Zazz refinements during definition. Load the
[methodology](zazz-methodology.md) for that work; record whether a change is local or proposed upstream
and preserve human authority. Assigned process changes do not authorize scanner implementation.

## Commands and credentials

Commands and contributor checks: [README](../../README.md#contributing). Current live-model setup:
[OpenAI Decisions setup](openai-decisions-setup.md). Offline extraction and fixture work need no key.
The decision-model key is already configured in the local ignored `.env`; agents MUST NOT print it.
The scanner does not auto-load that file; see the [README](../../README.md#required-decision-model-setup).
API setup is separate from permission to transmit target source or execute a paid evaluation.
Live requests remain restricted to OpenAI Decisions with `gpt-6-luna`, small explicit request caps,
and no provider/model fallback. The previously reported $10 funding is context, not a spending authorization.
