# Node.js GraphQL resolver adapter — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 6 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user authorized D6 implementation on 2026-11-04, including its verified feature-branch commit/push.
The active user request authorizes this implementation and checkpoint publication; paid calls, PR creation and merging remain excluded.

## 0. Capability

Analyze bounded Apollo Node.js Query/Mutation and explicit object-field resolver bindings through shared input/dispatch, existing sinks, claim policy and resolver-specific reports. Source-only fixtures provide initial acceptance; the user-built GraphQL application is a later evaluation.

## 1. Required reading

- [AGENTS](../../AGENTS.md#authorization-and-delivery) and
  [orientation](../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §§4–8](../architecture/common-entry-dispatch.md#4-adapter-to-flow-boundary), [database analysis](../../docs/scan/analysis/database-injection.md), [validation](../../docs/scan/analysis/input-validation.md).
- Dependency: 01–03 foundations; execute after 05-dynamic-http in this lane. [Previous deliverable](common-entry-dispatch-05-dynamic-http.md)
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
| `internal/parse/graphql_entries.go, graphql_schema.go, graphql_inputs.go, graphql_test.go` | new | Verified Apollo bindings, bounded SDL and resolver input roles |
| `internal/parse/analysis.go, modules.go, flow.go` | modified | Discovery and shared invocation seed integration |
| `internal/parse/testdata/javascript/graphql/; internal/parse/testdata/typescript/graphql/` | new | Pinned manifest/source SDL/resolver control fixtures |
| `internal/report/entries.go; internal/judge/*_test.go; cmd/scan/analysis_test.go` | modified | Real adapter judgment/export integration |
| `docs/analysis/README.md, database-injection.md, input-validation.md; docs/running-scans.md` | modified | Actual supported source and framework boundaries |
| `.zazz/specifications/common-entry-dispatch-06-graphql.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-06-graphql-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
paid calibration, application execution, sample remediation and unrelated formatting.

## 4. Decisions

**Decision 1.** Use @apollo/server ApolloServer literal typeDefs/resolvers as the initial Node subset because exact framework preference is flexible and it has explicit schema-to-resolver wiring.

**Decision 2.** Treat args, parent, context and info independently because only actual provenance and transfer facts justify source-to-sink claims.

**Decision 3.** Analyze explicit object-field resolvers independently while marking unsupported parent-result transitions because a schema edge does not establish a value transfer.

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

- **AC1 — TestGraphQLResolverBindings.** Verified Apollo construction binds literal SDL type/field coordinates to inline/local/imported named resolvers, distinguishes schema instances, exposes explicit object-field resolvers and keeps unresolved/default/runtime composition coverage visible. Verified by `TestGraphQLResolverBindings` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC2 — TestGraphQLInputRoles.** args.email reaches an existing SQL sink through supported transfers; parent/context/info are not relabeled as args or automatically attacker-controlled. Scalar/type/directive names do not satisfy sink or application-policy requirements. Verified by `TestGraphQLInputRoles` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC3 — TestGraphQLProtectionContexts.** Raw/bound/unknown SQL controls and shared-resolver guarded/unguarded registrations traverse real completeness and local-stub policy; unknown applicable wrappers block their claims without lending sibling protection. Verified by `TestGraphQLProtectionContexts` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC4 — TestGraphQLPipelineAndBounds.** Actual Node JS/TS fixtures yield schema-3 JSON, resolver-specific HTML and SARIF with no fake HTTP fields/legacy IDs; include selectors, zero-use gaps, deterministic limits, shadowed Apollo negative and unsupported SDL/root-escape controls. Verified by `TestGraphQLPipelineAndBounds` in the packages named in §7; new test names are planned contracts, not existing results.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestGraphQLResolverBindings`: Verified Apollo construction binds literal SDL type/field coordinates to inline/local/imported named resolvers, distinguishes schema instances, exposes explicit object-field resolvers and keeps unresolved/default/runtime composition coverage visible.
- `TestGraphQLInputRoles`: args.email reaches an existing SQL sink through supported transfers; parent/context/info are not relabeled as args or automatically attacker-controlled. Scalar/type/directive names do not satisfy sink or application-policy requirements.
- `TestGraphQLProtectionContexts`: Raw/bound/unknown SQL controls and shared-resolver guarded/unguarded registrations traverse real completeness and local-stub policy; unknown applicable wrappers block their claims without lending sibling protection.
- `TestGraphQLPipelineAndBounds`: Actual Node JS/TS fixtures yield schema-3 JSON, resolver-specific HTML and SARIF with no fake HTTP fields/legacy IDs; include selectors, zero-use gaps, deterministic limits, shadowed Apollo negative and unsupported SDL/root-escape controls.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/parse ./internal/judge ./internal/report ./cmd/scan
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

### Post-checkpoint sample verification

The user's 2026-11-04 follow-up authorizes fresh source-only scans of all seven pinned sample
applications, investigation/fixes of scanner regressions, and a further verified feature checkpoint
commit/push before their absence. Compare against exact D5 source builds, inspect JSON/HTML/SARIF,
verify source hashes and target integrity before/after, and run existing case evaluations. Source auditing discovered global-console logger evidence whose
text differed from its source span; the follow-up includes the focused correction in
`internal/parse/log_sinks.go` and regression in `internal/parse/log_sinks_test.go`, preserving
logger detection/status behavior and historical answers. The matching logging analysis guide and
implementation results record this evidence correction. Reuse
historical model responses only through complete exact-request replay; no new paid calls, target
execution/modification, new worktree, PR, merge, integration push or D7 is authorized. Retain
historical reports/labels, record real gaps separately, and publish durable verification results.

## 8. TDD entry point and execution sequence

First failing test: `TestGraphQLResolverBindings` with the observable contract in §6.

1. Start with TestGraphQLResolverBindings on literal Query.search SDL and a named resolver bound through a verified Apollo constructor.
2. Implement bounded syntax-aware SDL reader with exact hashes/spans and explicit unsupported syntax. Support literal SDL and local literal .graphql sources inside selected root; never execute target imports/loaders.
3. Bind resolver parameters to distinct source/context roles; reuse existing language transfer and sink semantics. Add raw/bound/unknown SQL pairs and explicit object-field parent uncertainty.
4. Run real adapter -> candidate -> completeness -> stubbed judge/policy -> JSON/HTML/SARIF tests. Record fixture manifest API versions and review official upstream API references.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// graphql_entries.go: verified Apollo instance -> schema field -> resolver dispatch.
// graphql_schema.go: bounded supported SDL syntax -> source-backed coordinates/gaps.
// graphql_inputs.go: parameter slots -> args/parent/context/info value bindings.
```

Recovery checkpoints: Schema/resolver discovery; then input/SQL controls; then end-to-end exports and limits.
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

Use `.zazz/ephemeral/common-entry-dispatch-06-graphql-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement only the user-authorized deliverable in the existing common-entry-and-dispatch
worktree. Read AGENTS.md, .zazz/specifications/common-entry-dispatch-06-graphql.md,
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

2026-11-04 — D6 implemented and verified under the explicit user instruction. Acceptance tests,
source-only JS/typed-TS fixtures, local-stub policy results, exact D5 regression parity and remaining
limits are recorded in [implementation results](../evaluation/common-entry-dispatch-results.md#d6--bounded-apollo-graphql-resolvers-2026-11-04).
The ignored per-deliverable log retains RED/green recovery, issues, commands and artifact hashes.
Browser security policy prevented visual preview; HTML source/export verification passed, without
a browser-QA claim. D7 and the future GraphQL application evaluation remain unstarted.

2026-11-04 — User expanded post-checkpoint verification to real pinned sample apps and authorized
fixing discovered scan regressions now, followed by commit/push. Added the bounded sample-verification
scope in §7; source integrity, D5 parity, real exports and exact historical decision replay are required.
Existing no-paid-call/no-target-execution restrictions and the D7 boundary remain in effect.

2026-11-04 — Real-sample source auditing found inherited synthetic global-console binding text in
Goof and the TypeScript app. Fixed the binding through the standard source-evidence constructor,
with parsed-source TDD, exact expected report-delta validation and full source/report/regression
checks. Current-source D5 decision replay remains exact for all 1,015 responses; no new paid calls.
See [real-sample follow-up results](../evaluation/common-entry-dispatch-results.md#d6-real-sample-follow-up--2026-11-04).
