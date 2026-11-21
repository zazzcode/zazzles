# Shared entry and dispatch records — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 1 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user authorized implementation of this deliverable on 2026-11-03 and requested a
committed/pushed design checkpoint. Paid calls and merging remain outside scope.

## 0. Capability

Define the shared entry, registration, dispatch, callable, invocation and input records, with deterministic identity, reference validation and explicit uncertainty. This foundation does not claim that runtime HTTP/browser consumers have migrated.

## 1. Required reading

- [AGENTS](../../AGENTS.md#authorization-and-delivery) and
  [orientation](../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §§2–3](../architecture/common-entry-dispatch.md#2-semantic-records-and-cardinality).
- Dependency: None; begin from the current reviewed worktree. No prior deliverable.
- [Execution discipline](../docs/agent-execution-discipline.md#verification-discipline)
  and repository `.agents/skills/spec-driven/SKILL.md` for implementation.
- [Code structure §§1–6](../standards/code-structure.md#1-package-layout),
  [testing §§2–9](../standards/testing.md#2-test-kinds),
  [docs hygiene](../standards/docs-hygiene.md#cross-document-linking),
  [spec hygiene](../standards/spec-hygiene.md#acceptance-criteria-are-testable-from-the-criterion-alone),
  [PR process](../standards/pr-process.md) at publication.
  Recheck [standards index](../standards/index.yaml) against actual changed paths.
- Read the source files in §3 and adjacent existing tests before editing.
  Preserve current [analysis semantics](../../docs/analysis/README.md).

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
| `internal/analysis/entries.go` | new | Typed catalog, metadata and context records |
| `internal/analysis/entry_ids.go` | new | Deterministic snapshot identities |
| `internal/analysis/entry_validation.go` | new | Reference and ownership validation |
| `internal/analysis/entries_test.go` | new | Cardinality, identity and gap controls |
| `.zazz/specifications/common-entry-dispatch-01-model.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-01-model-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Use typed Go records in internal/analysis because parse, judge and report need the same semantics without Tree-sitter dependencies.

**Decision 2.** Keep ordered dispatch stages distinct from conditional target alternatives because middleware chains and alternative handlers have different execution meaning.

**Decision 3.** Leave existing schema-2 runtime consumers unchanged in this foundation; switch them atomically at the next deliverable boundary rather than publishing partly migrated fresh reports.

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

- **AC1 — TestEntryCatalogContexts.** One callable exposed by two entries has separate registrations/contexts and distinct controls; one entry retains two known targets plus an unresolved alternative without a fake callable. Verified by `TestEntryCatalogContexts` in the packages named in §7; implementation evidence is recorded below.
- **AC2 — TestEntryCatalogIdentity.** Identical snapshots and reordered construction yield identical IDs/order; source/service-instance differences remain distinct and judgments never affect identity. Verified by `TestEntryCatalogIdentity` in the packages named in §7; implementation evidence is recorded below.
- **AC3 — TestEntryCatalogValidation.** Reject dangling or cross-entry context references; retain located entry/dispatch gaps with no candidates, and preserve unknown entry kinds for inspection. Verified by `TestEntryCatalogValidation` in the packages named in §7; implementation evidence is recorded below.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestEntryCatalogContexts`: One callable exposed by two entries has separate registrations/contexts and distinct controls; one entry retains two known targets plus an unresolved alternative without a fake callable.
- `TestEntryCatalogIdentity`: Identical snapshots and reordered construction yield identical IDs/order; source/service-instance differences remain distinct and judgments never affect identity.
- `TestEntryCatalogValidation`: Reject dangling or cross-entry context references; retain located entry/dispatch gaps with no candidates, and preserve unknown entry kinds for inspection.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/analysis
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

## 8. TDD entry point and execution sequence

First failing test: `TestEntryCatalogContexts` with the observable contract in §6.

1. Start with TestEntryCatalogContexts using guarded and unguarded registrations of one callable.
2. Add typed HTTP/browser/GraphQL/gRPC metadata and input roles, then deterministic indexes/IDs and ownership validation. Use the architecture record responsibilities; avoid a general graph engine.
3. Verify existing tests still pass without routing current scans through the new catalog. Record this deliberate foundation boundary; do not describe it as non-HTTP analysis support.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
type EntryPoint struct { /* identity, kind, location, typed metadata */ }
type DispatchBinding struct { /* entry/registration refs, stage/alternative, optional target, gaps */ }
type InvocationContext struct { /* binding ref, input/receiver bindings, controls */ }
type EntryCatalog struct { /* canonical record collections and reference validation */ }
```

Recovery checkpoints: Identity/cardinality model; then validation and deterministic ordering.
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

### Verification evidence, 2026-11-03

The foundation is implemented in [entry records](../../scan/internal/analysis/entries.go),
[snapshot identities](../../scan/internal/analysis/entry_ids.go), and
[reference validation](../../scan/internal/analysis/entry_validation.go).
The [model tests](../../scan/internal/analysis/entries_test.go) exercise the three acceptance
criteria plus same-dispatch invocation-control isolation, input provenance/receiver/closure
bindings, partial dispatch, transport associations and invalid identity sources.

Passing commands, using the declared local Go toolchain with `GOPROXY=off` and the ignored
worktree Go cache: `go test -race ./...`, `go vet ./...`, `go build ./...`, changed-file
`gofmt -l`, `git diff --check`, and local documentation links/anchors/text checks.
The full race suite includes existing HTTP/browser and both-provider local stub tests.
An initial sandbox-only loopback denial was resolved by rerunning with local access.

Current analysis report schema remains 2; existing runtime producers and report views
are unchanged. No new-adapter scanner/report support is claimed by this foundation.
No sample checkout was modified, application executed or live model request made.
Detailed recovery history is in this deliverable's ignored run log.

## 10. Open questions

No deliverable-specific blocker remains beyond user review of the proposed design/scope.
Node.js GraphQL is first new server support; Apollo and grpc-js are concrete bounded
implementation choices, adjustable by user steering. The user's future GraphQL test app
is deferred evaluation, not a dependency. Resolve any materially new choice before its
dependent code; do not block unrelated earlier deliverables on later evaluation data.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-01-model-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement only the user-authorized deliverable in the existing common-entry-and-dispatch
worktree. Read AGENTS.md, .zazz/specifications/common-entry-dispatch-01-model.md,
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

2026-11-03 — User authorized deliverable 1. Implemented the shared model, snapshot IDs,
canonical ordering, reference/input/control ownership validation and regression controls.
Existing consumers remain on schema 2 as required; full race/vet/build and documentation
checks passed. No acceptance weakening or adapter scope expansion occurred.
