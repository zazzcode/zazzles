# JavaScript conditional flow

## Assignment and boundaries

Continue in `analyzer-assessment-coverage`, following the owner's core-first sequence
and explicit instruction to defer paid requests until the next session. This is the
next source-modeling slice after [wire v7](wire-bundle-v7.md), not E4. The
[request-size design](../../architecture/request-size-and-evidence-relevance.md#s4-remove-repeated-gaps-at-the-source--implemented)
owns the rationale. Track execution in the shared assessment-coverage run log.

Allowed paths: `internal/parse`, affected `internal/judge` frozen expectations,
related analysis documentation and `.zazz`. No new worktree,
branch, source slicing, helper filtering or new file API contracts.

## Behavior and invariants

- Model supported if/else/else-if statements as two bounded flow branches. Evaluate
  the condition once, preserve its true/false polarity and retain actual branch controls.
- Exclude terminating branches from the continuing environment. Stop following a
  statement when both alternatives return or throw. Preserve returns from both arms.
- Keep branch contexts and environments isolated. Merge data dependencies and nested
  object fields from every continuing arm; never borrow a sibling's protection.
- Preserve unchanged GraphQL/gRPC request markers. Ambiguous binding/response/model
  metadata remains explicitly uncertain instead of silently choosing one arm.
- Keep existing work/dependency/helper limits. Input-observation facts remain monotone
  for the invocation. Unsupported loops, switch, try/finally and unknown operations
  retain gaps. Browser mutable-state and model-setter flows may retain conservative
  fallback until their state joins are modeled.
- Preserve existing known registration-condition behavior. Request/response parameter
  rebinding retains conservative fallback, rather than claiming precise request identity.
- Change only source facts and their request digests; evidence wire schema stays v7.
  Changed exact requests cannot use old model answers. Published E3 sample snapshots
  remain historical; do not relabel or refresh their judgments without new calls.

## Acceptance and verification

| Criterion | Evidence |
|---|---|
| Polarity/fallthrough | True-exit, false-exit, absent else, else-if and both-exit tests |
| Branch isolation | Separate sinks in sibling arms, nested field assignments, helper returns, and ambiguous response state |
| Shared analyzers | Source fixtures covering SQL, NoSQL, command, path, SSRF, logging and XSS |
| Honest limits | Unsupported loop/rebinding/setter/browser cases retain uncertainty |
| Determinism and deltas | Repeat request digest inventory, list changed records by app/family, explain additions/removals and re-record only intentional frozen expectations |
| Offline integration | Scoped tests, full `go test -race ./... -count=1`, vet, format and docs checks |
| Paid calibration | 18-candidate fixture under the 400 cap; 12 of 14 declared expectations met (2 extra file-content XSS records held at needs_evidence), misses analyzed (else-if guard fixed; strict-arm false positive is model judgment); probabilities recorded in the verification record |
| Fresh replay | JavaScript samples re-judged with fresh traces and exact replay; Python samples are byte-unchanged and keep their judgments |

The code can be implemented and verified offline now. Full behavioral calibration
and affected live trace re-recording remain explicit unchecked next-session items.

## Delivered behavior

- `flow.conditional` forks isolated arms; preconditions are `branch_true_precondition` /
  `branch_false_precondition`, which are path evidence and are not promoted invocation-wide.
- Return, throw and unshadowed `process.exit` exit an arm; both exiting arms end discovery.
- Joins tag arm-specific dependencies, join nested fields, keep metadata only on agreement and keep
  path controls only when both arms carry them. Unmodeled heap writes in an arm stay gaps.
- `let`/`const`/`class` are block scoped. The `branches` fallback resets context per body and never
  carries a body's path control to later code. It keeps the request role on any feasible path.
- Helper precision is unchanged: an exiting arm or a possibly content-guarding test keeps a
  helper result a may-dependency.
- GraphQL/gRPC promote only preconditions that every use carries and that hold at the end of the
  walk, as `conditional_test` or `conditional_false_test`.
- The NoSQL `typeof` selector witness requires the excluding polarity.
- The shared guard engine credits each exiting link of an else-if chain.

Recorded limits (pre-E4): `switch` case bodies, labeled non-block statements and brace-less
loop bodies were not traversed; winston/Sequelize `require` destructuring was unbound.
E4 closes those discovery/binding holes under may-path `branches` (see
[shared-node-inputs-and-file-apis](shared-node-inputs-and-file-apis.md) AC6). Remaining:
`break`/`continue` still count as continuing (false-positive direction only); switch/loop
control stays may-path (`unsupported_control_flow`), not precise polarity like `if`.

## Work checklist

- [x] Implement supported conditional forks, polarity and terminating fallthrough.
- [x] Verify branch/value isolation and shared-family regressions offline
  (`conditional_flow_test.go`, JS and TS; SQL, NoSQL, command, path, SSRF, logging, XSS).
- [x] Record final request deltas and intentional expectation changes
  ([verification](../../evaluation/wire-bundle-v7-results.md#s4-and-broader-w6)).
- [x] Complete offline race/vet/format/doc checks and independent review (three confirmed QA
  defects fixed with regressions).
- [x] Run paid calibration (16 answers) and fresh affected-trace re-recording of the JavaScript samples.

## Implementation and review change log

2026-11-15: Owner authorized waiting on paid requests until next session. Implement
this bounded source-flow slice offline; retain live acceptance as pending.

2026-11-15: Owner requested a committed/pushed checkpoint of all work. The prototype is preserved for continuation; none of the unchecked S4 acceptance items is thereby completed.

2026-11-15: Continuation session. Owner set a new 400-request gpt-6-luna cap, accepted the
retention proxy instead of citations, extended W6 in E3, and asked for S1 to be measured, then decided.
The prototype was rewritten and independently reviewed. The calibration miss on else-if guards was
fixed in the shared guard engine; the strict-arm command false positive is model judgment and is
recorded without gate tuning.
