# HTTP and browser consumer migration with saved-report compatibility — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 2 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one implementation agent; bounded read-only baseline and verification agents.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user explicitly authorized deliverable2 implementation and a success assessment on
2026-11-03, following the proposed bounded baseline/review workflow. Paid calls and merging
remain outside scope. Deliverable3 is not included in this assignment.

## 0. Capability

Make existing JS/TS HTTP, Python HTTP and browser analyses use shared entry/context associations throughout flow, candidates, judgment and baseline reporting. Introduce fresh schema 3 and preserve offline export of historical schemas 1/2.

## 1. Required reading

- [AGENTS](../../AGENTS.md#authorization-and-delivery) and
  [orientation](../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §§3–5](../architecture/common-entry-dispatch.md#3-identity-and-candidate-association) and [§7](../architecture/common-entry-dispatch.md#7-selectors-and-public-compatibility).
- Dependency: 01-model. [Previous deliverable](common-entry-dispatch-01-model.md)
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
| `internal/analysis/analysis.go, json.go, findings.go, xss.go` | modified | Canonical report/use/finding associations and private legacy wire decoding |
| `internal/parse/analysis.go, route_analysis.go, flow.go, python_routes.go, python_flow.go, python_evidence_merge.go` | modified | Entry/context creation and parameter seeding |
| `internal/parse/router_mounts.go, checks.go, check_context.go, automatic_queries.go, python_validation.go` | modified | HTTP chain and completeness context preservation |
| `internal/parse/xss_client.go, xss_client_calls.go, python_browser.go, xss_storage_links.go, xss_cross_tier.go` | modified | Browser identity and related-entry propagation |
| `internal/judge/bundle.go, evidence_coverage.go, trace.go, policy.go` | modified | Generic required roles, context payload and replay versions |
| `internal/report/findings.go, html.go, sarif.go, flows.go, xss_findings.go` | modified | Compile and render existing views using canonical associations |
| `cmd/scan/analysis.go, export.go, checks.go` | modified | Schema/read/filter boundary compatibility |
| `internal/analysis/json_test.go; internal/parse/*_test.go; internal/judge/*_test.go; internal/report/*_test.go; cmd/scan/*_test.go` | modified/new | Focused migration, compatibility and replay regression tests |
| `.zazz/specifications/common-entry-dispatch-02-consumers-compatibility.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-02-consumers-compatibility-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Normalize old saved reports at the input boundary because exporters must consume one canonical current representation. Private legacy wire fields may retain original provenance; current records cannot have competing route/client authorities.

**Decision 2.** Carry invocation context through existing language engines because sharing a record package alone cannot generalize input or guard semantics.

**Decision 3.** Preserve an old answer as historical data without replaying it on changed evidence because report readability and request equivalence are separate guarantees.

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

- **AC1 — TestCommonEntryExistingConsumers.** Real JS/TS HTTP, Python HTTP and browser fixtures reach canonical candidates/completeness with entry/context IDs; preserve source hashes, sinks, claim outcomes and relevant gaps after normalized identity changes. Verified by `TestCommonEntryExistingConsumers` in the packages named in §7; actual acceptance evidence is recorded below.
- **AC2 — TestDispatchContextIsolation.** Guarded and unguarded exposures of one callable never share protection; an unresolved applicable guard blocks its claim, and an unresolved alternative prevents entry-wide protection without erasing an independent unsafe witness. Verified by `TestDispatchContextIsolation` in the packages named in §7; actual acceptance evidence is recorded below.
- **AC3 — TestReportSchemaCompatibility.** Schemas 1/2/3 export offline to HTML/SARIF with raw answers/source/hash/metadata preserved; no target reread or judge call, no input rewrite, explicit unresolved legacy contexts, rejected unsupported versions and conflicting current associations. Verified by `TestReportSchemaCompatibility` in the packages named in §7; actual acceptance evidence is recorded below.
- **AC4 — TestEntryContextReplayMismatch.** Changed context, evidence roles or payload versions reject saved response replay while identical requests still replay. Existing HTTP/browser status and no-green-on-blocker tests remain green. Verified by `TestEntryContextReplayMismatch` in the packages named in §7; actual acceptance evidence is recorded below.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestCommonEntryExistingConsumers`: Real JS/TS HTTP, Python HTTP and browser fixtures reach canonical candidates/completeness with entry/context IDs; preserve source hashes, sinks, claim outcomes and relevant gaps after normalized identity changes.
- `TestDispatchContextIsolation`: Guarded and unguarded exposures of one callable never share protection; an unresolved applicable guard blocks its claim, and an unresolved alternative prevents entry-wide protection without erasing an independent unsafe witness.
- `TestReportSchemaCompatibility`: Schemas 1/2/3 export offline to HTML/SARIF with raw answers/source/hash/metadata preserved; no target reread or judge call, no input rewrite, explicit unresolved legacy contexts, rejected unsupported versions and conflicting current associations.
- `TestEntryContextReplayMismatch`: Changed context, evidence roles or payload versions reject saved response replay while identical requests still replay. Existing HTTP/browser status and no-green-on-blocker tests remain green.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/analysis ./internal/parse ./internal/judge ./internal/report ./cmd/scan
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

## 8. TDD entry point and execution sequence

First failing test: `TestCommonEntryExistingConsumers` with the observable contract in §6.

1. Capture source-reviewed HTTP/browser normalized baselines and old saved-report exports before editing. Start with TestCommonEntryExistingConsumers.
2. Checkpoint A: migrate JS/TS HTTP registration, flow seeding and uses; preserve method/path/mounts as HTTP metadata. Keep any temporary compatibility bridge explicit and isolated.
3. Checkpoint B: migrate Python HTTP and browser consumers including inline-script provenance and stored/cross-tier associations. Run focused existing suites at each checkpoint.
4. Checkpoint C: migrate completeness, judge context/versioning, report associations and saved schema conversion together. Switch fresh schema to 3 only when all existing consumers work; remove temporary duplicate canonical fields/bridges.
5. Run all affected package tests plus offline CLI scans and old/current exports. Compare normalized evidence/statuses, not byte IDs expected to change.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// internal/analysis/json.go: private schema-1/2 wire decoding -> current report.
// internal/parse: resolve registration -> context -> seed language environment -> analyze.
// internal/judge/bundle.go: serialize context and evidence roles with a new evidence version.
```

Recovery checkpoints: A: JS/TS HTTP; B: Python/browser; C: judge/report/schema switch. A/B are recovery checkpoints, not completed migration acceptance.
A checkpoint MUST leave a coherent runnable state before being called green; otherwise
record exact partial changes and failing checks, without claiming this deliverable complete.

## 9. Definition of done

- [ ] Required source/standards read and current scope verified.
- [ ] All acceptance criteria have passing, cited evidence; affected regressions explained.
- [ ] Scoped tests/race checks and diff checks pass; only changed Go files formatted.
- [ ] Required offline reports/manual review performed where this slice changes output.
- [ ] Remaining gaps, exact artifact locations and next checkpoint recorded.
- [ ] No out-of-scope change, fabricated protection or stale-response replay.
- [ ] User receives the completed slice and any remaining unchecked acceptance items.

### Implementation evidence and success assessment, 2026-11-03

The migration is implemented and its automated acceptance gates pass. Actual HTTP and
browser consumers use common entry/registration/dispatch/callable/context records; current
reports are schema3, while private input-boundary conversion reads schemas1/2. There is
one serialized primary entry/context association per use and finding. HTTP-only metadata
and inventory remain available; no GraphQL/gRPC or explicit event adapter is claimed.

| Criterion | Evidence |
| --- | --- |
| Existing consumers | `TestCommonEntryExistingConsumers`; five fresh sample comparisons:244 entries/341 uses, exact normalized entry/witness/context/dependency/gap/assessment/file parity |
| Context/coverage | `TestDispatchContextIsolation`, `TestCheckContextsAndLimitsStayPerRegistration`, `TestOrderedHTTPForwardingContext`, `TestHTTPAllPredecessorApplicability`, `TestMountedHTTPPredecessorUsesSourcePath`, `TestEntryDispatchGapsVisibleWithoutUses` |
| Compatibility | `TestReportSchemaCompatibility`, `TestLegacyEntryNamespacesRemainDistinct`; seven saved schema1 reports, five baseline schema2 reports and current schema3 HTML/SARIF exports; all source input hashes unchanged |
| Replay/policy | `TestEntryContextReplayMismatch`, `TestAccountCreationInvocationBindingPolicy`, `TestBrowserInvocationKeepsRequestBounded`; both-provider local stub suites |
| Identity/determinism | `TestCandidateIdentityDistinguishesHelperWitnesses`; all fresh candidate IDs unique and catalog references valid |
| Regression gates | `go test -race ./...`, `go vet ./...`, `go build ./...`, changed-file formatting and `git diff --check` |
| Historical Python | Original29 case checks pass on original reports and on actual decoder-converted schema3 reports; this is saved-evidence compatibility, not fresh model accuracy |

Both changed goldens preserve original evidence/declarations/snapshots after the documented
role/identity changes. Same-path ordered HTTP stages are included only under supported
source/receiver/forwarding rules, with explicit applicability/expansion gaps otherwise.
Missing-sink and account checks remain independent per registration; an existing API model
can substantiate generated-operation binding without inventing a repository callable.

Implementation additions include `internal/analysis/report_entries.go`,
`internal/parse/entry_context.go`, `http_dispatch_context.go`, and
`internal/judge/entry_context.go`, with corresponding focused tests in the existing packages.
The shared source role names are `input_source` and `invoked_callable`; structural entry/
dispatch and supported invocation-binding roles add evidence obligations without replacing
existing claim-specific source/sink/control/policy obligations. Bundle version3 and generic
question version `candidate-use-v10` reject changed-request replay. Callable and candidate
identities remain independent of model answers.

Recovery evidence is in this deliverable's ignored run log and the ignored
`deliverable-02-baseline/`, `deliverable-02-final/converted-compatibility.json`, and
`deliverable-02-verified/` evidence directories. The final verified scanner artifact hash is
`07cfdccb0b0293723c005fb06b60b5b878e9daa92bfe1eb9a5921e087684583c`.
Bounded read-only review returned PASS for all four acceptance criteria.

Limitations: the native FastAPI checkout has an unrelated untracked `.DS_Store`, so fresh
scanning was skipped; its saved export and converted case checks pass. Browser entries
remain explicitly partial source-slice/component contexts with exposure gaps; event
binding is deliverable4. Local-file browser navigation policy prevented pixel-level HTML
inspection; report structural/escaping/grouping/status tests and static markup review pass,
and report layout/template/CSS/JS are unchanged. No paid calls or target execution occurred.

## 10. Open questions

No deliverable-specific blocker remains beyond user review of the proposed design/scope.
Node.js GraphQL is first new server support; Apollo and grpc-js are concrete bounded
implementation choices, adjustable by user steering. The user's future GraphQL test app
is deferred evaluation, not a dependency. Resolve any materially new choice before its
dependent code; do not block unrelated earlier deliverables on later evaluation data.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-02-consumers-compatibility-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement only the user-authorized deliverable in the existing common-entry-and-dispatch
worktree. Read AGENTS.md, .zazz/specifications/common-entry-dispatch-02-consumers-compatibility.md,
its linked design/dependencies, and the deliverable-specific ignored run log. Load spec-driven and
matched analysis/engineering standards. Keep implementation with one agent; bounded
read-only baseline/verification agents may review evidence without editing sources. Start with the first failing
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

2026-11-03 — User authorized deliverable2. Implemented current-consumer migration, canonical
schema3 and private legacy conversion, generic judgment contexts/roles/replay versions,
per-registration checks and baseline reports. Added targeted context/ordering/compatibility
controls after read-only review. Verification and limitations are recorded in §9; no new
entry-framework adapter or later deliverable was implemented.
