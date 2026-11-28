# Explicit browser event entries and callback dispatch — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 4 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user invoked §12 on 2026-11-04, authorizing deliverable 4 implementation, verification,
commit and feature-branch push. Paid calls, later deliverables, PR creation and merging remain outside scope.

## 0. Capability

Recognize bounded DOM/window event registration and callback binding as browser entries, seed event inputs explicitly and report findings under the actual event context while retaining existing script/component analysis.

## 1. Required reading

- [AGENTS](../../../AGENTS.md#authorization-and-delivery) and
  [orientation](../../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §4](../../architecture/common-entry-dispatch.md#4-adapter-to-flow-boundary), [§8](../../architecture/common-entry-dispatch.md#8-implemented-bounded-framework-subsets), [XSS guide](../../../docs/scan/analysis/xss.md).
- Dependency: 03-reporting-selectors. [Previous deliverable](common-entry-dispatch-03-reporting-selectors.md)
- [Execution discipline](../../docs/agent-execution-discipline.md#verification-discipline)
  and repository `.agents/skills/spec-driven/SKILL.md` for implementation.
- [Code structure §§1–6](../../standards/code-structure.md#1-package-layout),
  [testing §§2–9](../../standards/testing.md#2-test-kinds),
  [docs hygiene](../../standards/docs-hygiene.md#cross-document-linking),
  [spec hygiene](../../standards/spec-hygiene.md#acceptance-criteria-are-testable-from-the-criterion-alone),
  [PR process](../../standards/pr-process.md) at publication.
  Recheck [standards index](../../standards/index.yaml) against actual changed paths.
- Read the source files in §3 and adjacent existing tests before editing.
  Preserve current [analysis semantics](../../../docs/scan/analysis/README.md).

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
| `internal/parse/browser_events.go, browser_events_test.go` | new | Event registration and context binding |
| `internal/parse/xss_client.go, xss_client_calls.go, xss_client_values.go` | modified | Event seeds, callback traversal and contextual candidate identity |
| `internal/parse/python_browser.go` | modified if required | Shared inline-script integration without snapshot rebasing errors |
| `internal/parse/testdata/javascript/browser-events/; internal/parse/testdata/typescript/browser-events/` | new | Source-only event controls |
| `internal/report/entries.go, xss_client_test.go; cmd/scan/analysis_test.go` | modified | Event details and real pipeline exports |
| `docs/analysis/xss.md` | modified | Implemented event coverage and limitations |
| `.zazz/specifications/scan/common-entry-dispatch-04-browser-events.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-04-browser-events-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Use literal addEventListener on verified DOM/window bindings because arbitrary methods with that name do not prove event dispatch.

**Decision 2.** Keep event inputs distinct from DOM/location reads because a click callback can read location data without the click event itself supplying that string.

**Decision 3.** Retain existing unsupported/unbound script/component observations with explicit provenance because registration discovery must not silently erase existing findings or invent event exposure.

## 5. Agent implementation rules

Use the current assigned worktree as command cwd; verify path/branch/status before edits.
Explicit later implementation instructions authorize the requested slice under AGENTS;
do not request a separate ownership ceremony. Follow the milestone usage-window policy.
Record exact modified paths and compare the slice diff against its recorded start revision.

Keep coherent green recovery points. Commit/push only when authorized by the active user
request; verify the `zazzcode` identity/authentication before publication. Never merge,
push to `stage`/`main`, or create a release. Draft PRs target `stage` when publication is requested.
Do not use live keys or execute/install dependencies in target applications.

Halt dependent work for missing required reference data, a conflicting user edit, unresolved
scope/public-contract choice, destructive recovery, or an invariant violation. Investigate
routine failures autonomously; after three repeated failures without progress record the
blocker and surface it. Do not weaken tests or drop mandatory coverage to fit a window.

## 6. Acceptance criteria

- **AC1 — TestBrowserEventDispatch.** click/input/change/submit/message registrations with inline or local named callbacks yield explicit entries, binding evidence and event-specific contexts; one callback registered twice keeps shared callable identity and separate contexts. Verified by `TestBrowserEventDispatch` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC2 — TestBrowserEventProvenance.** Supported event.target value and message.data projections reach real DOM sinks with correct origin roles; escaped/raw/unknown controls retain claim outcomes. An origin check does not establish universal output encoding. Verified by `TestBrowserEventProvenance` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC3 — TestBrowserEventUnknownAndLimits.** Dynamic names/targets/callback mutation and fake/custom addEventListener receivers remain gaps/negative controls without fabricated targets; zero-use registrations and reached limits stay visible. Verified by `TestBrowserEventUnknownAndLimits` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC4 — TestBrowserEventPipeline.** Actual parsed events exercise candidate/completeness/JSON/HTML/SARIF without HTTP/legacy IDs; existing JS/TS frameworks and Python inline-script fixtures retain supported evidence and avoid duplicate same-context uses. Verified by `TestBrowserEventPipeline` in the packages named in §7; new test names are planned contracts, not existing results.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestBrowserEventDispatch`: click/input/change/submit/message registrations with inline or local named callbacks yield explicit entries, binding evidence and event-specific contexts; one callback registered twice keeps shared callable identity and separate contexts.
- `TestBrowserEventProvenance`: Supported event.target value and message.data projections reach real DOM sinks with correct origin roles; escaped/raw/unknown controls retain claim outcomes. An origin check does not establish universal output encoding.
- `TestBrowserEventUnknownAndLimits`: Dynamic names/targets/callback mutation and fake/custom addEventListener receivers remain gaps/negative controls without fabricated targets; zero-use registrations and reached limits stay visible.
- `TestBrowserEventPipeline`: Actual parsed events exercise candidate/completeness/JSON/HTML/SARIF without HTTP/legacy IDs; existing JS/TS frameworks and Python inline-script fixtures retain supported evidence and avoid duplicate same-context uses.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/parse ./internal/report ./cmd/scan
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

## 8. TDD entry point and execution sequence

First failing test: `TestBrowserEventDispatch` with the observable contract in §6.

1. Start with TestBrowserEventDispatch: one named callback registered for two literal events, one with an applicable checked input and one without.
2. Verify receiver binding, registration evidence, callback resolution and environment seeding. Preserve separate event and DOM-read source roles.
3. Route actual candidates into shared report views; ensure current module/function exploratory traversal cannot merge away distinct event contexts.
4. Run raw/encoded/unresolved paired controls, inline-script provenance regression and real pipeline export tests.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// internal/parse/browser_events.go
// discoverBrowserEvents records registrations, callback alternatives and invocation seeds.
// Existing browser flow consumes those seeds; it does not infer protection from event names.
```

Recovery checkpoints: Registration/callback identity; then input propagation and report controls.
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

No deliverable-specific blocker or unresolved scope decision remains.
Node.js GraphQL is first new server support; Apollo and grpc-js are concrete bounded
implementation choices, adjustable by user steering. The user's future GraphQL test app
is deferred evaluation, not a dependency. Resolve any materially new choice before its
dependent code; do not block unrelated earlier deliverables on later evaluation data.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-04-browser-events-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement deliverable 4 only, unattended, in the existing common-entry-and-dispatch
worktree and branch. This instruction authorizes implementing its specification,
completing verification, then committing and pushing the completed checkpoint to
origin/common-entry-and-dispatch. Do not create another worktree or begin deliverable 5.

Deliverable 3 is completed and pushed at db6a796cd374d8179a7aadc4c8a9758f92a50138.
Read AGENTS.md and orientation, then
.zazz/specifications/scan/common-entry-dispatch-04-browser-events.md,
its linked design/dependencies and matching source/tests. Read the latest deliverable 3
run-log entries at
.zazz/ephemeral/common-entry-dispatch-03-reporting-selectors-run-log.md,
and the successful fresh FastAPI follow-up in
.zazz/ephemeral/common-entry-dispatch-02-consumers-compatibility-run-log.md. Maintain
deliverable 4's separate append-only ignored log at
.zazz/ephemeral/common-entry-dispatch-04-browser-events-run-log.md; create it if absent
and reconstruct predecessor state from Git/contracts if local evidence is unavailable.
Do not infer passing verification from missing notes.

Verify actual cwd, branch, HEAD, predecessor checkpoint and existing changes before edits.
Preserve user edits, including any prompt-only preparation in this contract. Record the
actual start revision and bounded D4 scope. Load spec-driven and matched engineering,
testing and XSS analysis standards. Work as one agent; do not delegate.

Start with the failing TestBrowserEventDispatch described in §8. Implement only the
specified bounded DOM/window event registrations, callback bindings and event-source
propagation. Keep invocation inputs/controls isolated, retain zero-use/unknown/limit gaps,
and preserve existing script/component, inline-script and HTTP behavior. Verify real
parsed adapter-to-candidate-to-completeness-to-report behavior; hand-built records alone
are insufficient. Keep deliverable 3 reporting/selector and existing HTTP/browser
regressions green. Use source-only fixtures and local model stubs, never target execution.

Continue autonomously through routine implementation choices, failures and rework.
Stop for a genuine blocker or material scope/public-contract decision; explain the exact
condition and record a resumable checkpoint. Do not request routine progress approval.
Use the specification's recovery checkpoints and milestone usage-window policy. Keep
context, partial state, next action, exact commands/results and coverage current in the
run log so compaction or an enforced usage interruption does not lose the handoff.
Do not invent remaining quota, claim partial work complete, or weaken required tests.

Complete all D4 acceptance criteria, scoped tests and affected-package race checks using
the declared Go toolchain. Run applicable local provider/replay regressions if evidence
or judgment inputs change. Generate and visually inspect required offline browser-event
reports, including raw/protected/unknown and zero-use controls; verify JSON/HTML/SARIF
status and provenance parity. Format only changed Go files. Check git diff --check,
status and the full D4 slice diff against the recorded start revision. Record exact
artifact paths/hashes, context/coverage, limitations and acceptance evidence in the D4 log;
update the owning tracked contract/docs with implemented behavior.

Before publication verify the common-entry-and-dispatch path/branch and zazzcode
Git/GitHub authentication. Commit and push the verified D4 checkpoint only to
origin/common-entry-and-dispatch, then verify a clean worktree and remote synchronization.
Report the commit, acceptance results, remaining limitations and next checkpoint, then stop.

No paid model calls, live-key use, target execution/dependency installation, sample-app
changes, historical raw-answer edits or stale-answer replay. No new worktrees, PR creation,
merges, integration pushes or later-deliverable implementation. Local loopback stubs are
allowed; resolve sandbox socket restrictions through permitted access, never a paid API.
```

## 13. Implementation and review change log

2026-11-03 — Initial contract from the user's design/spec request, Node.js GraphQL
priority, explicit browser-event/reporting requirement, retained HTTP sample compatibility,
and later application evaluation. Product implementation has not started.

2026-11-03 — User requested one ignored run log per deliverable; updated log paths
and resume prompts. This changes execution tracking only, with no product/test change.

2026-11-04 — Prepared §12 as a self-contained unattended implementation prompt for a
new chat. It names the completed D3 checkpoint, predecessor logs, single-agent scope,
recovery/verification duties and explicit future D4 commit/push authorization when invoked.
This edit changes execution instructions only; D4 implementation has not started.

2026-11-04 — Implemented deliverable 4 after the user invoked §12. Verified literal
DOM/window event registrations now supply explicit entries, local/inline callback bindings,
separate invocation contexts and event-input projections. Shared callbacks retain one callable
identity. DOM/location reads remain distinct; message-origin conditions do not encode output.
Zero-use and unresolved registrations, conservative mutation gaps and reached traversal/expansion
limits remain visible. Existing script/component and inline-template provenance are retained.
Focused adjacent changes support single-parameter arrow callbacks and DOM-specific event report
guidance. No new adapter family or later deliverable is included.

Acceptance: `TestBrowserEventDispatch`, `TestBrowserEventProvenance`,
`TestBrowserEventUnknownAndLimits` and `TestBrowserEventPipeline` exercise real parsed JS/TS,
Python inline scripts, typed checks, completeness and JSON/HTML/SARIF exports. Source fixtures
produce six event entries and four contextual uses: two raw, one encoded, one unknown, plus
zero-use and unresolved callbacks. Scoped package/race checks and local provider/replay regressions
pass. Offline discovery and synthetic local-stub reports retain status/provenance parity and were
visually inspected for identity, disclosure, sorting, keyboard focus, gaps and narrow layout.
Exact commands, final artifact paths/hashes and publication identity belong to the separate ignored
D4 run log. Implemented limits are documented in the [XSS guide](../../../docs/scan/analysis/xss.md).
