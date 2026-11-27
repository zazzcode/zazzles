# Analysis components 03 — outbound request observations

## 0. Capability and implementation order

Third follow-on session, after [NoSQL/validation](components-01-nosql-validation.md) and
[XSS/browser](components-02-xss.md): organize existing outbound destination observations and their
known library contracts as selected components. Preserve source evidence and explicit uncertainty.
Clearly distinguish server requests, browser request/response origins and rendered browser output.
Do not turn this packaging migration into complete SSRF, exfiltration, CORS or CSRF assessment.

The user requested ordered specifications on 2026-11-05 and assigned this implementation after the
completed session02 checkpoint. Outbound observation components are implemented and offline-verified
on 2026-11-06; see the [verification ledger](../architecture/analysis-packs.md#outbound-observation-verification-2026-11-06).
Command injection and complete SSRF judgment remain separately scoped features. Sensitive-data
logging remains a separate migration.

## 1. Required reading

- [AGENTS](../../AGENTS.md#start-here), [orientation](../docs/zazzles-agent-orientation.md#task-reading-paths),
  [plan](../project/implementation-plan.md#analysis-pack-mvp-initiative).
- [Component architecture](../architecture/analysis-packs.md#boundary-and-ownership),
  [session 01](components-01-nosql-validation.md#4-decisions-and-extension-risks-to-resolve),
  [session 02](components-02-xss.md#4-decisions-and-explicit-parity-exception).
- [Repository graph boundary](../architecture/repository-graph.md#objective-and-analysis-boundary),
  [technical approach](../../docs/technical-approach.md#analysis-knowledge-and-components),
  [result interpretation](../../docs/scan/interpreting-results.md) and [Python scope](../../docs/scan/python-support.md).
- [spec-driven](../../.agents/skills/spec-driven/SKILL.md), [execution discipline](../docs/agent-execution-discipline.md),
  [standards index](../standards/index.yaml), [structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [spec hygiene](../standards/spec-hygiene.md),
  [docs hygiene](../standards/docs-hygiene.md), [doc-check](../../.agents/skills/doc-check/SKILL.md).
- `internal/parse/{flow,python_frameworks,xss_client_calls,xss_client_http,xss_cross_tier}.go`,
  `internal/report/findings.go`, `internal/judge/{client,components}.go`, `cmd/scan/analysis.go`,
  family registrations from session 01; inspect actual code before choosing companion filenames.

## 2. Invariants

- Source trust, mandatory Go gates, caller isolation, immutable historical answers and explicit
  unsupported scope from preceding component contracts remain binding.
- Destination, request body/headers and response data are different operands. Taint in a POST body
  does not prove control of its URL; a response is not an alias of a request argument.
- A browser `fetch`/Angular HttpClient call does not establish that an application's server makes a
  request. A same-path/method/field link needs the actual supported producer relation, not a name.
- Client/server scope derives from supported entry/binding evidence, not `.js` versus `.ts` or file
  names. Mixed/unknown runtime context remains explicit; do not invent server-side behavior.
- Same-name fake or shadowed fetch/axios objects are unverified observations, not trusted library
  contracts. No new model confidence can close missing receiver, operand or response-flow facts.
- No target request is executed. DNS, network reachability, redirects, remote service implementation
  and deployment policy are not established by this bounded static refactor.

## 3. Scope and review shape

One deliverable/specification, one assigned feature worktree/branch and one intended draft PR to
`stage`. Use the accepted predecessor tree and record its commit or full source/diff manifest.
Preserve uncommitted earlier work; do not reset to a `HEAD` missing component implementation.
No additional worktree or integration merge is requested by this checkpoint.

**Session03 starting point:** runtime checkpoint `4e0be3e` on `analysis-pack-mvp` contains session01,
XSS migration `30fada9` and its cleanup. Use the latest committed documentation closeout on that
same feature branch; record actual starting HEAD/status before implementation. The
[checkpoint ledger](../architecture/analysis-packs.md#session-02-closeout-and-session-03-starting-point)
records current protocols, source-backed Juice Shop parity and remaining scope. Do not substitute
an older checkout missing the component consumers. Current outbound still uses generic legacy
assessment; observation-only zero-call handling below is work for this session, not accepted baseline
behavior. Preserve SQL/NoSQL/validation/XSS effective request bytes while adding observation mode.

| Repository-relative path | Change | Purpose |
| --- | --- | --- |
| `internal/analysispacks/` | Add outbound registration/contracts/tests | Explicit observation-mode selection, supported limits and known API content |
| `internal/parse/{analysis,flow,python_frameworks}.go` and tests | Narrow modify | Attach components to current observations; retain original dependency/gap facts |
| `internal/parse/xss_client*.go`, `xss_cross_tier.go` | Regression tests; narrow shared wiring only | Keep browser response sources and XSS origin linkage separate from server requests |
| `internal/analysis/{components,analysis,json}.go` and tests | Narrow modify if necessary | Reuse static selection provenance without fabricated assessed provenance |
| `internal/judge/{client,components,trace}.go` and tests | Narrow modify | Explicit observation-only assessment eligibility; prevent generic SQL-question fallback |
| `internal/report/`, `cmd/scan/` | Narrow wiring/tests | Preserve destination Review presentation, historical export and incomplete-assessment semantics |
| `internal/parse/testdata/` | Narrow add | Minimal destination/body/response/context controls |
| This spec; specification index; component architecture/plan; orientation; `README.md`; technical/model/running guides | Narrow modify | Explain observation-only scope and evidence |

The diff MUST stay within those paths. No new supported client library, axios.default binding
expansion, Request-object resolution, arbitrary alias/async analysis, server-to-server service graph,
DNS/redirect/IP-policy engine, SSRF verdict, sensitive-data exfiltration detector, browser CORS/CSRF
assessment, application edits, paid calls or report redesign. Unrelated cleanup remains separate.

## 4. Decisions and explicit behavior boundary

**Observation is a real supported mode.** Family registration must support a discovered observation
without a security questionnaire or mandatory verified API contract. Register existing
`outbound_http_candidate` as observation-only. This uses component selection and discoverable limits
without fabricating the evidence required for a future destination-security claim.

**Do not upgrade shape matches.** At authoring, JS/TS `flow.go` recognizes fetch/axios names, combines
argument dependencies and adds `sink_binding_unverified` and `external_response_unresolved` gaps.
It is not a verified JS/TS destination-operand model. Retain those original records and gaps.
Components describing them MUST say observation/unverified, not certify a trusted network API or URL
slot. Fake, shadowed and same-name local calls may remain current uncertain observations; removing
such discovery is separate detector work. Package presence alone cannot upgrade them.

Python's existing `outboundCall` distinguishes method-first `.request`, positional/keyword URL,
request data and independent response values after existing module binding checks. Move its
`python-http-destination-v1` contract to one catalog owner, selected only for those demonstrated facts.
Preserve the existing supported requests/httpx subsets; do not label all HTTP libraries supported.
A fixed Python URL with request data only must remain the existing negative destination-control case.

**No SQL questionnaire as an outbound security claim.** Current generic client fallback can send
SQL-oriented validation/construction questions for an outbound candidate; those are not a destination
security protocol. New observation-only assessments MUST make zero HTTP calls and return explicit
`not_run` with a reason that outbound security assessment is not implemented. No request digest or
claim of completed model assessment is invented. Preview returns an explicit non-assessable error
and no request body for observation-only candidates, rather than constructing a generic payload. Preserve existing destination Review records/counts.

This is an intentional assessment-eligibility correction, not hidden detection expansion. Record
before/after assessment status/reason separately from source/report parity. Saved generic historical
responses keep their original status, question versions and answers on export. Do not overwrite them
with the new observation result. An incomplete requested assessment remains explicitly incomplete;
no skipped observation makes a report into a security certificate. The existing incomplete-requested-
assessment failure rule stays active; replacing a generic completed answer with explicit not-run may
therefore change that run's exit result, and the before/after evidence MUST identify it. Preserve current conservative
request-limit scheduling/exit behavior rather than redesigning budgets in this migration; no real
HTTP request count may exceed the configured limit. Future SSRF work owns an actual destination
question protocol, evidence gates, budgets and accuracy controls.

**Browser cooperation without conflation.** Preserve session-02 literal fetch-method correction and
its unknown-method gaps. Browser request metadata/response origins can support a later XSS rendering
claim with a resolved field; they do not produce server SSRF findings. Do not duplicate those existing
XSS records as new outbound vulnerabilities or create a server URL control claim from client sources.
Missing browser response paths stay gaps. No browser HTTP adapter expansion is included here.

**Provenance and compatibility.** Reuse schema-4 `analysis_components` for selected observation
capabilities/contracts and limits, without a new model protocol for this unassessed mode. Claim
material/request digests for SQL, NoSQL, validation and XSS remain unchanged. Retain schema1–4
export compatibility and raw historical answers. If shared serialized representation must change,
record a schema/protocol decision and compatibility tests before integration, never silently relabel.
Retain existing component/material/request size bounds; no model request is built for outbound observations.

## 5. Implementation rules and halt conditions

One Contributor Agent implements the session with local toolchain/offline modules and no delegation
or external tracker. Use ignored `.zazz/ephemeral/components-outbound-run-log.md` under its storage
policy for accepted baseline, standards, source inventory, eligibility exception and test evidence.
Run commands from the assigned root. Preserve unrelated work and sample apps. The user subsequently
assigned full offline Juice Shop E2E validation, fixes if needed, then a feature commit/push to
`analysis-pack-mvp`. No PR creation or integration merge is assigned.

Halt for a needed stronger network/receiver/operand claim, changed browser producer attribution,
unexplained discovery/count/status drift, new protocols pretending to assess SSRF, changed required
assessment success/failure rules beyond the explicit observation boundary, or out-of-scope files.
Inspect accepted-base, working and untracked diffs together. Clearly report remaining unsupported
network behavior rather than making a generic protective conclusion.

## 6. Acceptance criteria

| ID | Observable acceptance | Verification |
| --- | --- | --- |
| O1 | Existing JS/TS shape observations and verified Python destination observations select correctly scoped components; unverified JS/TS APIs never acquire a verified contract | `TestOutboundComponentSelection`, `TestOutboundBindingScope` |
| O2 | JS/TS original candidates/dependencies/gaps remain byte-equivalent apart from selection metadata; Python positional/keyword URL, method-first request and fixed-URL/body-only controls retain actual operand facts | `TestOutboundComponentEvidenceParity`, existing `TestPythonOutboundOperandRoles` |
| O3 | Observation-mode candidates require neither a security questionnaire nor a fake API; direct Assess/AssessTrace/Preview and CLI make zero model HTTP calls for them; explicit not-run reason retained | `TestOutboundObservationNotAssessed` with both local provider stubs |
| O4 | A mixed requested assessment still assesses supported SQL/NoSQL/validation/XSS claims under its cap, reports outbound incompleteness explicitly, retains request-limit scheduling and the incomplete-assessment failure rule, documents the intentional eligibility/exit-result delta, and never calls a target URL | `TestMixedAssessmentWithOutboundObservations` in CLI |
| O5 | Browser fetch/Angular response sources and API-to-browser XSS remain separate; same browser/server call spellings cannot lend server provenance; POST/dynamic-method controls keep session-02 guarantees | `TestBrowserServerRequestIsolation`, `TestBrowserFetchMethodIsolation`, `TestCrossTierResponseFieldLinks` |
| O6 | JSON/HTML/SARIF retain source, gaps, entry coverage, destination Review counts and historical answers/provenance; no new SSRF, exfiltration or browser-security finding is emitted | `TestOutboundComponentReportParity`, extended saved-report compatibility tests |
| O7 | Other families' requests/replay remain unchanged, malformed/missing catalog config fails explicitly and full offline checks pass | Existing family request/replay frozen controls; catalog tests; contributor checks |

## 7. Test strategy

Capture accepted current outbound source/report projections before changing ownership; separately
capture legacy generic assessment status so the explicit eligibility correction cannot hide drift.
Use synthetic source with request-controlled URL, body-only value, response consumption, fake/shadowed
calls, unsupported binding and browser/server calls at the same URL. Python controls reuse
`TestPythonOutboundOperandRoles`, `TestPythonBindingControls` and `TestPythonEvidence`.
JS/TS tests characterize actual current limitations instead of assuming Python precision.

Exercise real parse → component selection → explicit unassessed mode → JSON/HTML/SARIF. Stub
servers count model calls and fail if any outbound observation reaches them; target URLs are inert
fixture literals and never executed. Mixed local-stub scans verify supported families still receive
correct requests and unassessed uses remain visible. Browser/XSS regressions prove that a request
source and rendering context are not collapsed. No expected label enters a model request. No paid
measurement or browser runtime is required; measure static component/material selection overhead only.

## 8. TDD entry point and execution sequence

1. Verify accepted session-02 tree; freeze source/report and generic-assessment baseline distinctions.
2. First failing test: an unverified JS/TS fetch-shaped observation must not obtain a trusted API or
   receive SQL construction questions; model HTTP call count must remain zero.
3. Register observation-mode material/eligibility in the existing component registry, avoiding a new engine.
4. Move Python's demonstrated contract to its single owner; attach scoped selections to current observations.
5. Retain browser request/response/XSS paths and method isolation; verify evidence and report parity.
6. Implement explicit observation not-run handling, historical export, mixed-request cap/exit regressions.
7. Remove duplicate owners, document known JS/TS/Python limits, update ledger/README and run full checks.

```text
analysispacks/outbound.go: observation-mode capability descriptors + existing Python contract
parse: existing discovered operations/evidence -> scoped observation selection
judge: registered observation -> explicit not_run, no payload/request/protection judgment
report/CLI: existing Review/incomplete semantics, no invented SSRF finding
```

## 9. Definition of done

- [x] O1–O7 have evidence; no stronger binding/operand/protection claim than the existing source supports.
- [x] Eligibility correction is explicit; original source/report parity and historical raw answers survive.
- [x] Browser/server/request-body/response distinctions and earlier-family requests remain intact.
- [x] No outbound model/target HTTP calls; bounds and mixed-request regressions pass.
- [x] Full race suite, vet, build, changed-file formatting, docs and ledger updates pass.

## 10. Open questions

No drafting question blocks the bounded observation migration. Complete SSRF and broader browser
network-security semantics remain future contracts. If product direction instead requires new outbound
security verdicts now, resolve that scope and update the evidence/question/accuracy contract first;
do not infer it from the word outbound or reuse SQL questions.

## 11. Run log protocol

Append standards/baseline, owner transfers, explicit eligibility differences, phases, deviations,
failures/recoveries and evidence paths to the named ignored log. Artifacts follow repository output
policy; durable summaries belong in component architecture. Resume from this spec, local log if
present, actual Git state and relevant diffs. No external tracker or separate execution doc is needed.

## 12. Implementation prompt

> Implement `.zazz/specifications/components-03-outbound.md` in the assigned feature worktree after
> sessions 01 and 02. Read AGENTS and its orientation, this contract, component architecture,
> repository graph boundary, spec-driven and matched standards. Preserve accepted predecessor code
> and record a source/commit baseline. Migrate existing outbound observations into explicitly scoped
> observation components; retain unverified JS/TS shape gaps and Python's demonstrated URL-operand
> contract. Do not upgrade names/package declarations to trusted APIs or mix destination/body/response
> operands. Preserve browser request sources, POST/dynamic-method isolation and XSS producer links;
> browser HTTP is not server SSRF. Observation-only outbound uses must not receive generic SQL
> security questions or make model calls: return explicit not_run, preserve Review and requested-scan
> incompleteness, and document this bounded eligibility correction separately from source/report
> parity. Historical raw answers remain intact. Use local stubs to verify zero outbound calls and mixed
> claim/cap/exit behavior, plus saved JSON/HTML/SARIF parity and all earlier-family replay controls.
> Run scoped/full contributor and doc checks, update README/plan/ledger, and report unmet criteria.
> No new SSRF/exfiltration/browser-security detector, paid calls, target requests, sample edits, extra
> agents/worktrees or integration merges. Follow the user's assignment for commits/pushes/draft PRs.

## 13. Implementation and review change log

Implementation completed against this contract on 2026-11-06 from clean `dc309cd`, with no scope
or acceptance changes. The user assigned the existing feature worktree and prohibited delegation,
extra worktrees, live calls and integration merges. The [verification ledger](../architecture/analysis-packs.md#outbound-observation-verification-2026-11-06)
records O1–O7 evidence and the authorized eligibility/exit delta separately from source/report parity.
Execution attempts and recoveries remain in the ignored run log. New security assessment remains a
separate capability with its own evidence contract. Initial implementation did not assign commits,
pushes or PRs; the follow-up delivery assignment is recorded below.


### 2026-11-05 — Predecessor checkpoint documented

**Source.** User requested architecture/project closeout before the planned outbound session.

**Changed sections.** §0 and §3 identify outbound as the next unimplemented session and record
runtime predecessor `4e0be3e` plus the latest documentation closeout on the same feature branch.

**Summary.** Link the accepted component protocols, actual Juice Shop preservation checks and
cleanup evidence. Explicitly distinguish current generic outbound assessment from the planned
observation-only eligibility correction. O1–O7, scope, limits and review shape remain unchanged.

**Verification impact.** Documentation/link checks only for this closeout. Implementation must still
freeze its actual starting source/report and legacy-assessment baseline before executing §8.


### 2026-11-06 — Full Juice Shop E2E and feature delivery assigned

**Source.** User requested full Juice Shop E2E validation, fixes if needed, then commit and push.

**Changed sections.** §3 includes the orientation status pointer; §5 authorizes the feature commit/push.

**Rationale and summary.** Extend validation to the unchanged pinned application's complete static
entry scope and deliver the reviewed feature diff. Keep localhost model stubs, no paid/target calls,
no sample edits, no new agents/worktrees, no PR creation and no integration merge.

**Verification impact.** Compare accepted `dc309cd` and current full CLI reports, all 208 candidate
assessments under both local providers, exact earlier-family requests/replay, source-reviewed XSS
controls, saved JSON/HTML/SARIF parity and required incomplete exits. Record results and supported
limits in the [ledger](../architecture/analysis-packs.md#juice-shop-full-e2e-follow-up-2026-11-06).

### 2026-11-06 — Documentation consistency and merge-readiness recheck

**Source.** User requested consistent README/project/architecture documentation, verification of
component-design completion, another complete Juice Shop baseline comparison and obsolete-code cleanup.

**Scope.** Reconcile current capability and migration status across the README, user documentation
index/analysis overview/technical approach, project overview/functionality/proposal/plan, architecture
index/component ledger/trace contract and agent orientation. Preserve historical planning and raw
reports. Remove only the unused `Client.decode` wrapper and exercise the current decoder directly in
its duplicate-answer regression. Logging remains a separate migration, not implicit work in this
closeout. No public behavior, protocol, detection scope or O1–O7 acceptance requirement changes.

**Verification impact.** Repeat full unchanged Juice Shop source/report comparison with accepted
`dc309cd` and original pre-componentization `f8b7dbd`, both localhost provider probes, exact earlier-family request/replay checks, full CLI and
saved-export parity, target revision/hash/cleanliness checks, full race/vet/build and scoped docs checks.
Continue to use the existing feature branch; no paid calls, target execution, sample edits, new
worktrees/agents, PR creation or integration merge.

### 2026-11-06 — User-authorized paid component verification

**Source.** User explicitly requested paid Decision LLM scans for both Juice Shop and VulnPy,
clarifying that offline/stub verification did not satisfy the requested live judgment check. The
central acceptance goal remains working component selection/composition and obsolete-code cleanup.

**Scope.** This one-time authorization supersedes earlier no-paid-call wording for these two full
pinned checkouts only: OpenAI Decisions `gpt-6-luna`, capped at 117 eligible Juice Shop requests
and 827 VulnPy requests. Preserve observations, unsupported bindings, historical reports, raw
responses and source evidence. No new detector, family migration, target execution, sample edits,
extra agents/worktrees, provider/model fallback or integration action is authorized.

**Verification.** All 944 fresh paid requests completed without retries or provider failures.
Source/request selections, versions/digests and language guidance match; all 944 independently
fresh-source exact replays and saved exports pass. Historical confirmed contexts remain, with
source-reviewed additional Juice Shop login SQL/DOM-search judgments. The
[paid verification ledger](../architecture/analysis-packs.md#fresh-paid-component-e2e-2026-11-06)
records results, artifact provenance and remaining limits. No further paid run is needed for this
acceptance; no product semantics or O1–O7 requirements changed.
