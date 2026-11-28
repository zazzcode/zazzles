# Entry-specific reports and common selectors — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 3 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user authorized deliverable 3 implementation, verification, commit and feature-branch
push on 2026-11-03. Paid calls, later deliverables, integration pushes and merging remain outside scope.

## 0. Capability

Present HTTP routes, browser events/components, GraphQL resolvers and gRPC methods through entry-specific views of one shared finding interpretation. Add typed selectors without breaking existing HTTP selection/check files.

## 1. Required reading

- [AGENTS](../../AGENTS.md#authorization-and-delivery) and
  [orientation](../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §§6–7](../architecture/common-entry-dispatch.md#6-entry-specific-reporting).
- Dependency: 02-consumers-compatibility. [Previous deliverable](common-entry-dispatch-02-consumers-compatibility.md)
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
| `internal/report/entries.go, entries_test.go` | new | Typed entry presentation and fallback |
| `internal/report/html.go, html_types.go, sarif.go, findings.go, bundle.go` | modified | Entry grouping, metadata, location, coverage and counts |
| `internal/analysis/analysis.go, entries.go` | modified | Typed selector and selected-scope metadata |
| `internal/parse/checks.go, check_context.go, python_validation.go` | modified | Context-specific requirement selection |
| `cmd/scan/main.go, analysis.go, checks.go, export.go` | modified | Entry filters and old/new check decoding |
| `internal/report/*_test.go; cmd/scan/*_test.go; internal/parse/checks_test.go` | modified/new | View/selection matrices |
| `docs/running-scans.md, interpreting-results.md; .zazz/architecture/reporting-and-sarif.md, html-reporting.md` | modified | Implemented reporting and selection contracts |
| `.zazz/specifications/common-entry-dispatch-03-reporting-selectors.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-03-reporting-selectors-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Presenters own labels and detail rows because shared classification must remain identical across output formats.

**Decision 2.** Use --entry-kind and --entry-id alongside existing file/HTTP filters because method/path selection remains useful for current applications.

**Decision 3.** Use tagged check selectors with boundary conversion of legacy method/path because old requirement files must remain usable without parallel internal selection models.

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

- **AC1 — TestEntrySpecificReports.** A table of HTTP/browser/GraphQL/gRPC/unknown entries renders proper identity/details, preserves all uses and zero-use gaps, sorts deterministically, and never manufactures HTTP metadata for non-HTTP entries. Verified by `TestEntrySpecificReports` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC2 — TestEntrySARIFLocations.** Use/sink location remains primary; registration/schema/proto/handler locations and entry/context properties remain available; zero-use coverage is represented as invocation metadata without a fake finding. Verified by `TestEntrySARIFLocations` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC3 — TestEntrySelectors.** Existing --entry/--route and legacy check arrays retain behavior; tagged HTTP/GraphQL/gRPC/browser selectors evaluate every matched context separately. Intersecting filters, invalid kinds/conflicting selectors and zero matches have explicit outcomes. Verified by `TestEntrySelectors` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC4 — TestEntryReportStatusParity.** JSON, text, HTML and SARIF share statuses/counts; unknown kind/orphan legacy entry remains inspectable; protected claim never labels an entire incomplete entry safe. Verified by `TestEntryReportStatusParity` in the packages named in §7; new test names are planned contracts, not existing results.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestEntrySpecificReports`: A table of HTTP/browser/GraphQL/gRPC/unknown entries renders proper identity/details, preserves all uses and zero-use gaps, sorts deterministically, and never manufactures HTTP metadata for non-HTTP entries.
- `TestEntrySARIFLocations`: Use/sink location remains primary; registration/schema/proto/handler locations and entry/context properties remain available; zero-use coverage is represented as invocation metadata without a fake finding.
- `TestEntrySelectors`: Existing --entry/--route and legacy check arrays retain behavior; tagged HTTP/GraphQL/gRPC/browser selectors evaluate every matched context separately. Intersecting filters, invalid kinds/conflicting selectors and zero matches have explicit outcomes.
- `TestEntryReportStatusParity`: JSON, text, HTML and SARIF share statuses/counts; unknown kind/orphan legacy entry remains inspectable; protected claim never labels an entire incomplete entry safe.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/report ./internal/analysis ./internal/parse ./cmd/scan
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

## 8. TDD entry point and execution sequence

First failing test: `TestEntrySpecificReports` with the observable contract in §6.

1. Start with TestEntrySpecificReports using canonical records from the model and existing parsed HTTP/browser fixtures.
2. Implement one shared entry projection and kind-specific details. Keep status logic in existing finding interpretation; preserve accessible disclosure/sort behavior.
3. Implement typed check decoding and common selection, retaining old HTTP options and size/count checks.
4. Generate offline HTML/SARIF and visually inspect mixed-entry and HTTP-only reports; update public guides with actual CLI examples.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// internal/report/entries.go
func entryPresentation(entry analysis.EntryPoint) entryView { /* typed metadata -> labels */ }
// cmd/scan/checks.go: decode legacy or tagged selector -> one normalized check.
// Filtering keeps matching entries plus their registration/dispatch/context references.
```

Recovery checkpoints: Report projection and locations; then selectors and HTML visual verification.
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

No deliverable-specific open scope decision remains.
Node.js GraphQL is first new server support; Apollo and grpc-js are concrete bounded
implementation choices, adjustable by user steering. The user's future GraphQL test app
is deferred evaluation, not a dependency. Resolve any materially new choice before its
dependent code; do not block unrelated earlier deliverables on later evaluation data.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-03-reporting-selectors-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement only the user-authorized deliverable in the existing common-entry-and-dispatch
worktree. Read AGENTS.md, .zazz/specifications/common-entry-dispatch-03-reporting-selectors.md,
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

2026-11-03 — Implemented deliverable 3 only after explicit user authorization. Shared
entry projection supplies HTTP/browser/GraphQL/gRPC/unknown identities and details to
HTML/text/SARIF. Canonical sink/related locations and zero-use invocation coverage remain
separate from security findings. Added intersecting entry-kind/ID filters and normalized
tagged checks with per-context requirements, match identities/counts and explicit gaps.
Existing check kinds and HTTP/browser analysis semantics are retained; no new adapter
is implied by selector/presenter support.

Acceptance evidence: `TestEntrySpecificReports` (including parsed JS/TS/Python/browser
pipeline coverage), `TestEntrySARIFLocations`, `TestEntrySelectors` in analysis/parse/CLI,
`TestEntrySelectorsContextIsolation`, and `TestEntryReportStatusParity` pass. Scoped
packages pass race tests; provider stub/replay and Python decision-to-report pipeline
regressions pass in `internal/judge`. Mixed-entry and HTTP-only offline HTML were reviewed
in a browser for labels, disclosure, sorting, keyboard activation and narrow layout.
Exact commands, artifacts/hashes, sample parity and publication checkpoint are retained
in the separate ignored deliverable 3 run log. This closes deliverable 3; deliverable 4
requires a separate assignment.
