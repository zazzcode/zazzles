# JavaScript conditional flow

## Assignment and boundaries

Continue in `analyzer-assessment-coverage`, following the owner's core-first sequence
and explicit instruction to defer paid requests until the next session. This is the
next source-modeling slice after [wire v7](wire-bundle-v7.md), not E4. The
[request-size design](../architecture/request-size-and-evidence-relevance.md#s4-remove-repeated-gaps-at-the-source--planned-after-e3-validation)
owns the rationale. Track execution in the shared assessment-coverage run log.

Allowed paths: `internal/parse`, affected `internal/judge` frozen expectations,
related analysis documentation and `.zazz`. No live calls this session. No new worktree,
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
| Paid calibration — pending | Next-session owner budget; guarded/unguarded pairs and direct JS allowlist guard, with unchanged gates and recorded probabilities |
| Fresh replay — pending | Only newly judged changed requests; never manufacture responses from historical traces |

The code can be implemented and verified offline now. Full behavioral calibration
and affected live trace re-recording remain explicit unchecked next-session items.

## Work checklist

- [ ] Implement supported conditional forks, polarity and terminating fallthrough.
- [ ] Verify branch/value isolation and shared-family regressions offline.
- [ ] Record final request deltas and intentional expectation changes.
- [ ] Complete offline race/vet/format/doc checks and independent review.
- [ ] Run next-session paid calibration and fresh affected-trace replay.

## Implementation and review change log

2026-11-15: Owner authorized waiting on paid requests until next session. Implement
this bounded source-flow slice offline; retain live acceptance as pending.

2026-11-15: Owner requested a committed/pushed checkpoint of all work. The prototype is preserved for continuation; none of the unchecked S4 acceptance items is thereby completed.
