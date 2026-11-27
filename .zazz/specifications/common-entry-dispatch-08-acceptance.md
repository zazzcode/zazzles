# Cross-entry regression and behavior reports — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 8 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user authorized unattended implementation on 2026-11-05, as one agent in this worktree.
The user subsequently authorized fresh paid full-judge E2E for all seven example apps, Juice Shop
first, and commit/push/draft PR after expected full-run outcomes. The user explicitly approved
publishing a draft with AC4 rendered review retained as a pre-merge blocker. This exception changes
draft publication timing only; no visual pass or merge is implied. Publication remains limited to
`common-entry-and-dispatch`, with one draft PR into `stage`.

Original D8 acceptance remains offline; the added real-judge requirement uses only OpenAI Decisions
`gpt-6-luna`:1146 eligible assessments and ceiling1149 paid attempts including the three explicitly
bounded transient recoveries. Completed answers are retained only after exact fresh request matching.
No target execution, new worktrees, provider fallback, merge or another initiative.

## 0. Capability

Verify the completed shared model against existing HTTP/browser samples and new event/dynamic/GraphQL/gRPC fixtures; produce reviewable before/after evidence and JSON/HTML/SARIF reports without paid calls.

## 1. Required reading

- [AGENTS](../../AGENTS.md#authorization-and-delivery) and
  [orientation](../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §9](../architecture/common-entry-dispatch.md#9-delivery-and-evidence), [Python results](../evaluation/python-support-results.md#verification-and-provenance), [contributor checks](../../docs/contributing.md#contributing).
- Dependency: All seven implementation deliverables. [Previous deliverable](common-entry-dispatch-07-grpc.md)
- [Execution discipline](../docs/agent-execution-discipline.md#verification-discipline)
  and repository `.agents/skills/spec-driven/SKILL.md` for implementation.
- [Code structure §§1–6](../standards/code-structure.md#1-package-layout),
  [testing §§2–9](../standards/testing.md#2-test-kinds),
  [docs hygiene](../standards/docs-hygiene.md#cross-document-linking),
  [spec hygiene](../standards/spec-hygiene.md#acceptance-criteria-are-testable-from-the-criterion-alone),
  [PR process](../standards/pr-process.md) at publication.
  Recheck [standards index](../standards/index.yaml) against actual changed paths.
- Read the source files in §3 and adjacent existing tests before editing.
  Preserve current [analysis semantics](../../docs/scan/analysis/README.md).

## 2. Invariants

- Existing supported HTTP and browser analyses MUST retain evidence, claim status and coverage semantics.
- Entry kind, dispatch mechanism, transport and implementation language MUST remain independent.
- Controls and input bindings MUST NOT cross invocation contexts; calls alone MUST NOT establish value flow.
- Unknown bindings and reached limits MUST remain explicit; a missing candidate MUST NOT imply protection.
- Source snapshots and historical raw answers MUST remain intact; changed requests MUST NOT reuse old answers.
- Only final scoped protection receives green styling. No entry-wide safety or runtime exploit claim is implied.

## 3. Scope and review shape

All edits MUST remain inside the assigned feature worktree. Allowed implementation paths
for this slice are listed below; focused adjacent consumers in the same named packages
may be updated where necessary for the same contract, with exact paths recorded in the
run log. New packages, framework subsets or public behavior beyond this contract require
an in-place contract revision. Unrelated cleanup is outside scope.

| Path | New / modified | Purpose |
| --- | --- | --- |
| `cmd/scan/entry_pipeline_test.go; internal/report/entries_test.go; internal/judge/*_test.go` | new/modified | Mixed-entry integration, replay and policy regression |
| `internal/parse/express_contracts.go; express_query_controls_test.go; mongoose_query_context.go; mongoose_query_context_test.go; middleware_context.go; helper_resolution.go; relevant_context.go; query_evidence.go; checks.go; modules.go` | new/modified | User-authorized accuracy hardening: verified immutable Express transport/predicate contracts and complete contextual branch evidence; preserve unknown/custom blockers |
| `internal/judge/injection.go; validation.go; policy.go; express_controls_test.go` | modified | Versioned injection-specific conversion/selector questions, independent of construction practice |
| `internal/parse/flow.go; crypto_transfer.go; crypto_transfer_test.go; query_constraint_review.go` | modified/new | Bounded immutable Node crypto hex-output transfer for SQL evidence; raw sibling alternatives and unsupported encodings stay distinct |
| `internal/report/scoped_guidance.go; rendering_guidance_test.go` | modified/new | Correct renderer-specific EJS/Markdown/Handlebars/server versus Python repair guidance found during rendered review |
| `docs/analysis/database-injection.md` | modified | Document actual bounded contracts, claim-specific input/guard semantics and remaining limits |

| `docs/samples/evaluate-python.py` | modified only if required | Canonical report input compatibility without changing expected cases |
| `.zazz/evaluation/common-entry-dispatch-results.md` | new | Durable source-reviewed outcomes, commands and limitations |
| `.zazz/architecture/README.md; .zazz/architecture/common-entry-dispatch.md; .zazz/architecture/reporting-and-sarif.md, html-reporting.md` | modified | Actual implemented package/report contracts |
| `docs/running-scans.md, interpreting-results.md, analysis/README.md; .zazz/project/common-entry-dispatch.md; .zazz/specifications/README.md` | modified | Capability/compatibility status and discoverable results |
| `.zazz/specifications/common-entry-dispatch-08-acceptance.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-08-acceptance-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
unbounded paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Compare contextual source/sink/claim outcomes against pre-change baselines because new snapshot identities and grouping are intentional changes.

**Decision 2.** Separate offline discovery, stub-assessed policy and saved historical model evidence because they prove different properties.

**Decision 3.** Defer the user-built GraphQL application to later evaluation because fixture acceptance should be reproducible now without claiming application-level accuracy.

## 5. Agent implementation rules

Use the current assigned worktree as command cwd; verify path/branch/status before edits.
Explicit later implementation instructions authorize the requested slice under AGENTS;
do not request a separate ownership ceremony. Follow the milestone usage-window policy.
Record exact modified paths and compare the slice diff against its recorded start revision.

Keep coherent green recovery points. Commit/push only when authorized by the active user
request; verify the `zazzcode` identity/authentication before publication. Never merge,
push to `stage`/`main`, or create a release. Draft PRs target `stage` when publication is requested.
Offline acceptance uses no live keys. The subsequently authorized seven-application E2E assessment and bounded SQL/NoSQL accuracy probes
may use the selected OpenAI key; no other provider credentials may enter that child process. Do not
execute/install dependencies in target applications.

Halt dependent work for missing required reference data, a conflicting user edit, unresolved
scope/public-contract choice, destructive recovery, or an invariant violation. Investigate
routine failures autonomously; after three repeated failures without progress record the
blocker and surface it. Do not weaken tests or drop mandatory coverage to fit a window.

## 6. Acceptance criteria

- **AC1 — TestMixedEntryPipeline.** One mixed JS/TS/Python target contains actual HTTP/browser-event/GraphQL/gRPC adapter output and dynamic registration. Entries/candidates/contexts remain correctly associated through canonical JSON, HTML and SARIF; related transports do not double count resolver uses. Verified by `TestMixedEntryPipeline` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC2 — TestEntryProtectionCoverage.** Across entry kinds, guarded/unguarded shared callables, multiple targets plus unresolved alternatives, unknown applicable guards and zero-use gaps preserve claim-specific outcomes and cannot produce an entry-wide safe label. Verified by `TestEntryProtectionCoverage` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC3 — RegressionCommands.** Run all Go race/vet/build checks, focused local stubs for both provider transports, original 29 Python saved-report case checks, supported saved-schema exports and offline existing HTTP/browser plus new-adapter CLI reports. Explain every normalized behavioral difference; no unexplained HTTP regressions. Verified by the exact race/vet/build, Python case-check and CLI/export commands in the milestone index, with command output and artifact hashes recorded in the results.
- **AC4 — ReportReview.** Visually inspect HTTP-only, event-only, GraphQL-only, gRPC-only and mixed HTML. Confirm entry-specific labels, metadata, location, sorting, disclosures, zero-use coverage, source excerpts and status parity; record paths/hashes and source-reviewed expected/observed matrix. Verified by the manual HTML inspection and cross-format status matrix in the milestone index, with reviewed artifact paths recorded in the results.
- **AC5 — FullJudgeE2E (user-added before merge).** Fresh full FE/BE source snapshots of Juice Shop,
  Node.js Goof, vulnerable TypeScript app, ThreatByte, python-insecure-app, vulnerable-flask-app and
  VulnPy run through the current real OpenAI Decisions `gpt-6-luna` judge. Preflight all1146 eligible
  requests; retain exact request/raw response/usage and failures, one request per candidate, no
  automatic retries/fallback and maximum4 in flight. Three explicitly bounded transient recoveries
  increase the corpus ceiling to1149 paid attempts while retaining original failures. Twenty-four
  API-data observations remain explicitly
  unassessable. The SQL/NoSQL-only accuracy follow-up refreshes75 changed requests while retaining1071
  exact-request answers, plus19 bounded one-call probes with all iterations preserved. Verify source pins/clean state before/after, source-reviewed positive/protected/unknown
  case outcomes and JSON/HTML/SARIF parity. Explain misses and changes against historical evidence;
  model completion alone does not establish accuracy. All seven runs and unresolved results must be
  reviewed before merge; transport/funding failures are blockers, never passing evidence.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestMixedEntryPipeline`: One mixed JS/TS/Python target contains actual HTTP/browser-event/GraphQL/gRPC adapter output and dynamic registration. Entries/candidates/contexts remain correctly associated through canonical JSON, HTML and SARIF; related transports do not double count resolver uses.
- `TestEntryProtectionCoverage`: Across entry kinds, guarded/unguarded shared callables, multiple targets plus unresolved alternatives, unknown applicable guards and zero-use gaps preserve claim-specific outcomes and cannot produce an entry-wide safe label.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./...
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

## 8. TDD entry point and execution sequence

First failing test: `TestMixedEntryPipeline` with the observable contract in §6.

1. Start with TestMixedEntryPipeline and a source-reviewed expected entry/use matrix authored independently from scanner output.
2. Build current scanner once. Generate offline JSON/HTML/SARIF for existing HTTP/browser targets and new source fixtures; add local-stub assessed fixture runs for protection policy without live keys.
3. Run full validation once after final code changes. Re-run only affected checks if fixes are needed, followed by the final required integration gate. Inspect every golden diff.
4. Verify original saved-report hashes unchanged, replay rejection, removed legacy internal aliases and no fabricated HTTP non-HTTP fields. Record improved discovery/context/report behavior and remaining gaps in the evaluation document.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// cmd/scan/entry_pipeline_test.go
// Build source-only mixed fixture; run real scanner with local judge stubs;
// compare canonical associations/statuses against reviewed expectations and export all views.
```

Recovery checkpoints: Mixed fixture integration; then full suite; then visual report review and durable evidence.
A checkpoint MUST leave a coherent runnable state before being called green; otherwise
record exact partial changes and failing checks, without claiming this deliverable complete.

## 9. Definition of done

- [x] Required source/standards read and current scope verified.
- [x] All acceptance criteria have passing, cited evidence; affected regressions explained.
- [x] Scoped tests/race checks and diff checks pass; only changed Go files formatted.
- [x] Required offline reports/manual review performed where this slice changes output.
- [x] Remaining gaps, exact artifact locations and next checkpoint recorded.
- [x] No out-of-scope change, fabricated protection or stale-response replay.
- [x] User receives the completed slice and any remaining unchecked acceptance items.

## 10. Open questions

No deliverable-specific blocker remains beyond user review of the proposed design/scope.
Node.js GraphQL is first new server support; Apollo and grpc-js are concrete bounded
implementation choices, adjustable by user steering. The user's future GraphQL test app
is deferred evaluation, not a dependency. Resolve any materially new choice before its
dependent code; do not block unrelated earlier deliverables on later evaluation data.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-08-acceptance-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement only the user-authorized deliverable in the existing common-entry-and-dispatch
worktree. Read AGENTS.md, .zazz/specifications/common-entry-dispatch-08-acceptance.md,
its linked design/dependencies, and the deliverable-specific ignored run log. Load spec-driven and
matched analysis/engineering standards. Work as one agent. Start with the first failing
acceptance test, keep HTTP/browser regressions green, and verify actual pipeline behavior.
Record context/coverage and exact evidence; use recovery checkpoints to fit the available
usage window. Do not begin another deliverable automatically when only this one is assigned.
Preserve sample apps, raw historical answers and user edits. No paid calls, target execution,
new worktrees, merge or integration push. Report acceptance results and next checkpoint.
```

## 13. Implementation and review change log

2026-11-03 — Initial contract from the user's design/spec request, Node.js GraphQL
priority, explicit browser-event/reporting requirement, retained HTTP sample compatibility,
and later application evaluation. Product implementation has not started.

2026-11-03 — User requested one ignored run log per deliverable; updated log paths
and resume prompts. This changes execution tracking only, with no product/test change.

### 2026-11-05 — Authorized acceptance execution and blocked rendered review

**Source.** User requested unattended D8 execution, preservation of user/history evidence and
conditional verified commit/push to the assigned feature branch only.

**Changed sections.** Authorization header and definition-of-done evidence. Contract semantics,
acceptance criteria and mandatory visual coverage are unchanged. The focused report test uses
`internal/report/entry_coverage_test.go` in the already allowed package.

**Implementation and verification.** `TestMixedEntryPipeline` uses actual parsed JS/TS/Python source
(68 entries/53 uses), JSON/HTML/SARIF and immutable exports. `TestEntryProtectionCoverage` in judge
checks six parsed source sets through loopback stubs and exact/cross-context replay. The report test
adds explicitly synthetic multiple target/unresolved/transport catalog metadata to parsed uses;
it proves presentation/cardinality only, while the other tests exercise actual adapter flow.
Full race/vet/build, both provider stub transports, ten exact predecessor fixture comparisons,
seven unchanged real-sample evidence scans, original Python29/29 and immutable schema1/2/3 exports
pass. No production behavior, historical answer, source fixture or expected label changed.

**Outstanding mandatory acceptance.** AC4 rendered visual/interaction/keyboard/narrow review is
blocked: browser URL policy rejected the local HTML protocol and prohibited workarounds or alternate
surfaces. No screenshots or visual pass are claimed; AC4 and the all-acceptance checkbox remain open.
No commit/push was performed because the user's condition is unsatisfied. Remaining review and
artifact integrity are recorded in the [results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05),
the append-only ignored run log, `d8-report-manifest.json` and `d8-final-report-index.md` under
`.zazz/ephemeral/`. Resume with rendered review; do not start another initiative.

### 2026-11-05 — User-authorized full Juice Shop model assessment

**Source.** User asked to run the full decision LLM after reviewing the offline report.

**Changed sections.** Authorization header and implementation credential restriction. Mandatory
D8 offline checks and outstanding rendered review are unchanged. This bounded follow-up uses the
same source/claim/report pipeline and existing worktree, not another initiative.

**Scope and verification (initial authorization, expanded below).** Fresh full source snapshot of the pinned Juice Shop FE/BE, current
OpenAI Decisions `gpt-6-luna`, maximum188 eligible candidate requests, no retries/fallback. Twenty
API-data observations have no rendering claim and remain explicitly unassessable. Save exact
requests/raw responses, usage, failures and source-integrity checks separately from historical
runs and synthetic stubs. Review resulting SQL/NoSQL/other classifications and cross-format parity;
report actual completion and remaining evidence gaps. Stop on funding/rate response or repeated
failure. This paid follow-up does not satisfy blocked rendered acceptance or permit early publication.

### 2026-11-05 — User expanded live E2E acceptance to all example apps

**Source.** User explicitly required full-judge E2E for every example vulnerable app before merge
and asked whether offline tests alone establish the new design's behavior.

**Changed sections.** Authorization header, credential exception and new AC5. Original AC1–AC4
remain; deterministic tests establish migration/policy invariants while real judge E2E establishes
actual provider/claim/report operation. Neither substitutes for source-reviewed outcome accuracy.

**Verification impact.** Seven apps, exact total1146 eligible fresh requests (Juice Shop188,
Goof33, TypeScript16, ThreatByte56, Python insecure2, Vulnerable Flask24, VulnPy827), no retries or
fallback, max4 in flight. Fresh artifacts remain ignored and separate from historical/synthetic
runs. Source-reference outcomes, misses, controls, usage and completion are required evidence before
merge, alongside still-outstanding rendered review. No target execution or separate initiative.

### 2026-11-05 — Juice Shop first, then the other paid full-judge runs

**Source.** User explicitly reaffirmed paid calls and required Juice Shop's full report first,
followed by the other vulnerable sample apps.

**Changed sections.** AC5 execution order: complete and review the fresh Juice Shop report before
launching another app's paid calls. Preserve all seven per-app caps and no-retry/fallback boundaries.
No paid API call had started at the point of this steering; an initial preflight guard rejected
request changes caused by saved-report rehydration. The evaluation runner now uses fresh parsing
and exact preflight request hashes consistently; this is an ignored orchestration correction,
not a production detector change or a weakening of exact-request matching.

### 2026-11-05 — Single transient provider recovery for the full Juice Shop report

**Source and rationale.** User reaffirmed paid calls and a full Juice Shop report first. Its initial
188-request run completed187; the remaining outbound candidate received HTTP504. Routine recovery
is limited to that one candidate, preserving the failed attempt and all original answers.

**Current bound.** One extra manual request, total189 Juice Shop attempts and corpus ceiling1147;
no automatic retries, no full-run repeat, no provider/model fallback. All188 original fresh request
hashes must match independently freshly parsed source before retaining any successful answer in
the recovered report. A second failure remains blocked without another request. Other apps still
wait for completion/audit of the Juice Shop report.

### 2026-11-05 — Token-rate continuation and conditional draft PR

**Source.** User requires all sample apps fully judged, Juice Shop report first, then commit/push
and a milestone draft PR if the runs deliver expected source-reviewed results. Merge remains human.

**Recovery bound.** Six apps completed. VulnPy stopped after284/827 completed assessments on one
HTTP503 and one token-rate HTTP429 (2,000,000 TPM, not a funding error). Resume only543 incomplete
assessments after the rate window, at one dispatch/second and max4 in flight. Verify all827 original
request hashes against fresh source before retaining284 completed answers. No whole-run repeat or
model/provider fallback. Preserve all partial traces. Total paid ceiling1149 =1146 distinct eligible
assessments + one Juice Shop504 recovery + two VulnPy503/429 recoveries;24 API-data observations
remain unassessable. Another rate/funding/repeated failure stops the continuation for investigation.

**Publication.** User authorized a single large milestone draft PR into `stage` after verified
full-run expected outcomes. Do not claim missing checks passed or merge. Outstanding rendered
review and any residual source-positive limits must remain explicit in the PR/evaluation evidence.

### 2026-11-05 — Fresh paid E2E completion and expected outcome verification

**Evidence.** All seven apps completed1146/1146 eligible real OpenAI Decisions `gpt-6-luna`
assessments in1149 paid attempts, including the three explicitly bounded transient recoveries.
Juice Shop's full report/audit completed before another app started. Retained successful answers
matched independent fresh source/request hashes. All original failures and historical raw answers
remain preserved. Twenty-four API-data observations remain explicitly unassessable.

**Results.**15 source-reference checks pass, including fresh Python29/29, required VulnPy12-context
matrix and28 full-checkout confirmed positives, Juice Shop product-search SQL/three order-review
NoSQL/linked raw HTML, Goof raw/stored/escaped controls, and TypeScript raw output with no false SQL.
Final JSON/HTML/SARIF/source/export audits pass for all seven reports; pins/clean status and source
reference hashes hold before/after. Paid usage, exact commands, hashes, expected outcomes and known
limits are recorded in the [evaluation](../evaluation/common-entry-dispatch-results.md#fresh-paid-full-judge-e2e-2026-11-05)
and ignored `d8-paid-e2e-manifest.json` / final report index. AC5 passes for this bounded contract;
known source-positive coverage limits are not relabeled negative or claimed resolved.

**Publication boundary.** AC4 rendered review remains open. The user explicitly approved publishing
a draft with AC4 retained as a pre-merge blocker. Draft body, identity checks and report index are
prepared. Publish verified work only to the feature branch, create one draft PR into `stage`, and
retain all unchecked manual acceptance. No merge is authorized.

### 2026-11-05 — Explicit draft publication exception

**Source.** In response to the publication-condition clarification, the user selected:
“Publish draft; keep AC4 as a pre-merge blocker”.

**Changed sections.** Current authorization header and publication boundary. AC4 itself and the
all-acceptance definition-of-done checkbox stay open. Expected paid E2E/source checks pass;
commit/push and one draft PR into `stage` are authorized. User review/merge remain separate.

### 2026-11-05 — User requested accuracy repairs and iterative judgment in this PR

**Source.** User requested fixing the Goof login NoSQL false negative now, then remediating report
issues and closing source-evidence gaps iteratively in this session/PR. User explicitly authorized
using paid Decisions judgment to troubleshoot; publication waits for the affected repair checks.

**Changed sections.** Scope table expanded to exact adjacent parse/claim/report consumers above.
The existing vulnerability families and target languages are unchanged. No sample source changes,
new worktree, merge or additional initiative. Test the known positive beside scalar-constrained,
unknown-helper, fake/mutated import and custom middleware controls; never remove a blocker merely
to obtain a desired verdict. Include actual source/API-contract witnesses and preserve original gaps.

**Iteration evidence.** Fresh live accuracy probes use only OpenAI Decisions `gpt-6-luna`, selected
key only, exact saved request/raw response/usage, no provider fallback, bounded per-iteration caps
(recorded before calls). Start with at most4 new calls for the actual login and paired fixture
controls; increase only to the explicitly reviewed changed-request set. Reuse prior successful
answers only after exact fresh request match; changed requests get fresh answers or explicit not_run.
All historical full-run artifacts remain intact and become checkpoint evidence, not automatically
current acceptance after a production change. Re-run affected scoped/race/provider/report/source
checks and final integration gate; refresh current source snapshots and request identity matrix.

**Rendered review.** User opened localhost preview and explicitly handed it back for inspection;
the permitted existing HTTP tab is accessible. Initial Goof review verified two confirmed rows
(stored under GET / and reflected under GET /login) and found Python/Jinja-specific repair text on
an EJS Markdown sink. Correct that guidance with renderer controls. Remaining5-set interaction,
keyboard and narrow-layout checks still need actual observations; don't claim them passed yet.

### 2026-11-05 — Mongoose schema/version evidence after the first live probe

The first one-call repaired Goof probe had no static blockers and all source/library/guard/path
coverage answers yes, but injection remained unknown. No answer was overridden. Inspection found
that only `mongoose.model('User')` retrieval, not the reachable actual schema declaration/version,
was supplied. Added bounded direct registration-module import/require wiring to the actual literal
schema registration, with default-model ownership and ambiguity/constructor/reassignment controls.
Unrelated same-name schemas must not be borrowed. `model_schema` is required for Mongoose query
claims; the exact manifest pin and publisher4.2.4 query-casting source establish the operator contract
without suggesting a target verdict. Unknown/custom schema behavior remains a review concern.

Iteration2 is bounded to4 new paid calls: actual repaired Goof login and three raw/scalar-constrained/
unknown-helper controls. Retain the first inconclusive probe; no repeated same-request guessing,
provider fallback, target changes or automatic copying of changed answers.

- 2026-11-05 user steering: remaining accuracy iteration is SQL/NoSQL only; broader hardening is deferred until after analysis-pack-mvp. No next-deliverable work is authorized here. Native hex-output transfers and selector control calibration require fresh changed-request judgments and affected checks.

### 2026-11-05 — SQL/NoSQL accuracy closeout and observed rendered acceptance

**Source and scope.** User narrowed remaining accuracy iteration to SQL/NoSQL; broader hardening
waits until after analysis-pack-mvp. No next initiative started. This slice includes immutable
Express transport/predicate contracts, selected Mongoose schema/version context, native crypto
hex-output transfers and independent conservative constraint-review gates. Existing renderer advice
correction stays included. Unsupported/custom evidence remains blocked; no model answer is forced.

**Current acceptance.** AC1–AC3 pass the full race/vet/build and source/report checks; AC4 now passes
bounded actual inspection of HTTP/event/GraphQL/gRPC/mixed localhost HTML, including sorting,
filtering, source/identity disclosures, zero-use gaps, keyboard focus and390px layout. The user-opened
HTTP tab was permitted. The initial local-file rejection is preserved as history, not a current blocker.
Exact reviewed HTML hashes and screenshot are in ignored `d8-html-review.json`.

AC5's current seven full-source reports complete1146 eligible assessments:75 changed requests fresh,
1071 exact-request answers retained;24 API-data observations remain unassessable. Source/reference
checks18/18 and original Python29/29 pass. Only two final statuses changed: Goof login NoSQL and
Juice Shop login SQL are now confirmed. Total confirmed contextual records rises48→50; other app
statuses stay unchanged. Independent source cases, not count agreement, establish supported outcomes.

**Calibration limits.** Nineteen scoped paid probes retained both errors and recoveries. Earlier
judge calls overcalled hex-only SQL and scalar-guarded selectors. Current final hex-only SQL is
Protected; scalar NoSQL stays Review under an explicit contradiction gate; unknown helper stays
Review. Raw sibling SQL and actual login positives remain confirmed. These gates do not fabricate
protection and can conservatively leave real guarded cases inconclusive. General guard/type proof,
whole-program schema/plugin support and broader XSS hardening remain outside this iteration.

**Evidence and publication.** The ignored `d8-final-report-index.md` is the review entry point;
`d8-db-final-manifest.json`, `d8-db-source-review.json`, `d8-db-paid-ledger.json` and final accuracy
race/vet/build logs own exact artifacts/commands. Original reports, failed attempts and run log remain
intact. Commit/push only this verified feature branch, create one draft into `stage`, and leave human
code/design review and merge pending. No automatic readiness conversion or merge is authorized.
