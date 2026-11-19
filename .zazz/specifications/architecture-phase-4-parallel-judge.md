# Architecture phase 4 — Parallel judge requests

**Worktree / branch:** `parallel-judge`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 4. Objective: performance
**Depends on:** phase 0 merged (independent of phases 1–3; default order runs it after phase 3)
**Delivery topology:** one deliverable, one branch, one draft PR into `stage`
**Coordination:** Lead Agent alone
**Run log:** `.zazz/ephemeral/architecture-phase-4-parallel-judge-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

`AssessScheduled` sends one request at a time, and `limiter.series` also holds a lock across each
HTTP call. This phase makes judging concurrent in two passes:

1. **Plan pass.** A deterministic pass groups candidates by equivalence signature, runs the offline
   preflight, and assigns request slots in today's priority order.
2. **Dispatch.** A capped worker pool sends one leader request per signature group.

The cap is `--judge-concurrency N`, with `JUDGE_CONCURRENCY` as the environment fallback and a
default of 4. Equivalent members are replayed from their leader's answer, as today.

Report order, request bytes, replay, the request cap, RPM/TPM pacing, and halt-on-failure keep
their current meaning. With `N=1` the output is identical to today's. Wall clock falls when model
latency dominates and the run is under its RPM/TPM caps. Token cost does not change.

## 2. Required reading

- Code: `internal/judge/schedule.go` (`AssessScheduled`: priority order, `completed` reuse,
  `calls >= opts.Limit`, slot counting only for HTTP-reaching attempts, `SaveTrace`, limitations
  text); `transport.go` (`exchange`); `limits.go` (`acquire` window reservation, `complete` halts
  on any failure reason); `equivalence.go`; `trace.go` (`Preview`, `AssessTrace`, `Replay`).
- `cmd/scan/judge_limits.go`, `judge_config.go`, `analysis.go`.
- [Testing: concurrency](../standards/testing.md#6-concurrency), [semantic adapter stubbing](../standards/testing.md#7-semantic-adapter-stubbing).
- User docs: [decision models](../../docs/decision-models.md) (judge limits section),
  [running scans](../../docs/running-scans.md).

## 3. Invariants

- Request bytes and digests are unchanged. `TestArchitectureBaseline` passes with no update.
- `report.Uses` order is unchanged. Assessments attach by use index.
- With `N=1`, report JSON and the trace set are byte-identical to the pre-change scheduler for the
  same stub transport. That includes failures, leader fallback, and limit exhaustion.
- At most `opts.Limit` requests reach HTTP. Preflight failures and zero-call size limits still do not consume a slot.
- After any failed request sets the limiter halt, no new request is acquired. Requests already in
  flight finish and are recorded.
- `SaveTrace` calls and every `report.Limitations` line happen in priority order after dispatch,
  never in completion order.
- No retries or fallback models. Unit tests never make live calls.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/judge/schedule.go` | modified | Plan pass, waves, worker pool, ordered finalization |
| `internal/judge/transport.go`, `limits.go` | modified | Remove `series` serialization; acquire reserves, complete reconciles; halt honored by new acquisitions |
| `internal/judge/schedule_parallel_test.go` | new | Stub-transport equivalence, cap, halt, and determinism tests |
| `cmd/scan/judge_limits.go` (or `judge_config.go`), `cmd/scan/main.go`, `cmd/scan/judge_limits_test.go` | modified | `--judge-concurrency` and `JUDGE_CONCURRENCY` (integer ≥ 1) |
| `docs/decision-models.md`, `docs/running-scans.md` | modified | Flag, default, interaction with RPM/TPM and `--judge-limit`, halt behavior |
| `.zazz/architecture/trace-judgment.md` (scheduling note, if present), `.zazz/evaluation/architecture-baseline.md` | modified | Scheduler contract; stub timing table |

Out of scope:

- adaptive concurrency;
- retries;
- per-provider concurrency defaults;
- token-cost changes;
- grouping changes to `EquivalenceSignature`;
- paid calls.

Review shape: one PR.

## 5. Decisions

- **D-1 Run the plan pass offline and in sequence, before dispatch.** It walks priority order;
  applies skipped and only families and non-assessable handling exactly as today; computes the
  signature; runs `Preview` plus the size and TPM preflight; and assigns slots to leaders in
  priority order until `Limit`. Slot assignment is then deterministic, with no refunds.
  Rejected alternative: claiming slots in completion order, which would make which candidates get
  judged depend on timing.
- **D-2 Use waves for leader failure.** Today, when a leader does not complete, the next equivalent
  member makes its own attempt. Each wave dispatches the current leaders. After the wave, a group
  whose leader failed promotes its next member if slots remain and the limiter is not halted. With
  `N=1` this reproduces serial behavior exactly.
- **D-3 Replace `series` with a reserve-and-reconcile limiter.** `acquire` already reserves an
  estimate in the window under `mu`, and `complete` reconciles usage and sets `halted`. Holding
  `series` across HTTP is what forces serial calls, so it is removed. The window accounting stays
  correct under concurrency because every reservation is made under `mu`.
- **D-4 Default `N` to 4, set by flag or environment.** The plan fixed 4, and RPM/TPM still bound
  throughput. `N=1` is the documented serial mode. A CLI-only knob is rejected because unattended
  runs configure the judge through `.env`, as `JUDGE_RPM` already does.
- **D-5 Accept the documented halt difference.** With `N>1`, up to `N−1` requests that were already
  in flight when a failure set the halt are still sent and recorded. A serial run would not have
  sent them. Users are told this in the docs, and the run's `LimitSummary` counts them.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- `N=1` equivalence cannot be made byte-identical for an existing `schedule_test.go` or `schedule_cli_test.go` case.
- `-race` finds shared mutable state on `Client` outside the limiter.
- Any request digest changes.

## 7. Acceptance criteria

1. **AC1 Serial equivalence.** For each existing `schedule_test.go` stub scenario (success,
   equivalent reuse, leader failure with member fallback, limit exhaustion, skipped and only
   families, size-limit preflight), `N=1` produces report JSON and saved traces identical to the
   pre-change scheduler. The pre-change outputs are captured as test data in the first commit.
2. **AC2 Parallel equivalence.** With a deterministic stub (fixed response per signature, random
   per-request delay, 20 seeds), `N=4` produces the same report JSON and trace files as `N=1`.
3. **AC3 Concurrency.** A stub that blocks until 4 requests are in flight shows that 4 distinct
   signatures are dispatched together with `N=4`, never more than `N`, and one request per
   equivalent group.
4. **AC4 Cap.** With 10 distinct signatures and `Limit=3`, exactly 3 requests reach the stub, and
   they are the first 3 leaders in priority order. The rest are `not_run` with today's reason text.
5. **AC5 Halt.** With a stub that fails request #2, no request is acquired after the failure is
   recorded. Every candidate without an answer carries the limiter's "stopped after" reason. The
   number of sent requests is at most `2 + (N−1)`.
6. **AC6 Pacing.** With an injected clock, RPM=2 and `N=4` never has more than 2 requests in any
   rolling minute. The TPM reservation rejection keeps today's message.
7. **AC7 CLI.** `--judge-concurrency 0`, a negative value, or a non-integer is a usage error. The
   environment variable is used when the flag is absent. Tests sit beside the existing limit tests.
8. **AC8 Golden and gate.** `TestArchitectureBaseline` is unchanged and the contributor gate passes
   under `-race`.
9. **AC9 Docs and timing.** The user docs describe the flag, the default, and D-5. The evaluation
   record has a stub timing table: 40 signatures at a fixed 200 ms latency, for N = 1, 2, 4, and 8.

## 8. Test strategy

`schedule_parallel_test.go` holds AC1–AC6 as table-driven stub scenarios. Stubs follow the
semantic-adapter stubbing standard: a local `httptest.Server`. AC7 is in the CLI tests. No paid
calls are made. Live behavior under real provider limits is left to a later owner-capped run and
recorded as unverified in the PR.

## 9. TDD entry point and execution sequence

1. Commit the pre-change `N=1` outputs for the AC1 scenarios as test data. **Red:** AC2 and AC3 fail.
2. Restructure `AssessScheduled`:

```go
type ScheduleOptions struct {
	Limit                         int
	Concurrency                   int // ≥1; 0 means 1 for library callers
	SkippedFamilies, OnlyFamilies []string
	SaveTrace                     func(string, DecisionTrace) error
}

type planned struct {
	index     int    // into report.Uses
	signature string
	preview   DecisionTrace
	spends    bool   // reaches HTTP if dispatched
	slot      bool   // assigned a request slot
}

func (c *Client) plan(report *analysis.AnalysisReport, order []int, opts ScheduleOptions) (groups [][]planned, early map[int]analysis.Assessment)
func (c *Client) dispatch(ctx context.Context, leaders []planned, n int) map[int]result // worker pool; results keyed by use index
// AssessScheduled: plan → waves(dispatch, promote) → replay members in priority order → SaveTrace and limitations in priority order
```

3. Limiter: remove `series`, keep `acquire` and `complete` under `mu`, and make sure `acquire`
   returns the halt error as soon as `halted` is set. Then AC5 and AC6.
4. CLI flag and environment variable (AC7), docs (AC9), timing table, gate, draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC9 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] The PR states D-5 and that live provider behavior is unverified.

## 11. Open questions

None blocking. The owner may set the default to 1 instead of 4 at review. That is a one-line change, and D-4 records it.

## 12. Run log protocol

Use the plan's common rules. Record the captured AC1 baselines and the timing table.

## 13. Agent implementation prompt

> Work in the `parallel-judge` sibling worktree, cut from `origin/stage` after the phase it follows
> in the plan has merged. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md),
> and this spec. Follow the plan's session start and common rules. Execute §9 in order. Do not
> make paid calls; all tests use local stubs. Stop on any §6 halt. Finish with a draft PR into
> `stage` listing AC1–AC9 evidence. Verifier: a fresh-context subagent runs
> `go test -race ./internal/judge ./cmd/scan -count=5`. It reads `schedule.go` to confirm that slot
> assignment happens before any goroutine starts and that `SaveTrace` and limitations run in
> priority order, and it reports PASS or FAIL.

## 14. Implementation and review change log

- 2026-11-18 — Implementation. Changes beyond the §4 table:
  - `internal/judge/limits_test.go` updates its call sites, because `acquire` now returns a
    reservation and `complete` takes it.
  - `cmd/scan/analysis.go` passes the resolved concurrency into `ScheduleOptions`. It was in §2
    reading but missing from §4.
  - `cmd/scan/schedule_cli_test.go` and `cmd/scan/outbound_test.go` make their stub request
    counters atomic. With the default of 4, `-race` flags them. The race is in test-only state,
    not on `Client`, so the §6 halt does not apply.
  - `internal/judge/testdata/schedule_serial/` holds the AC1 goldens.
- D-2 refinement: a promoted member is the group's next member that reaches HTTP. A member that
  fails preflight gets its offline outcome and never takes a slot.
- Known serial difference, outside every AC1 scenario: a leader fails without halting (no
  limiter, or a non-halting answer-detail failure) while `--judge-limit` binds. A serial run gave
  the next equivalent member the freed slot. The plan gives it to the next leader in priority
  order (D-1, no refunds), and the member reports `judge request limit reached`.
- `LimitSummary` says "up to N assessment requests in flight" instead of "requests remain
  sequential" when N > 1. With N = 1 the text is unchanged.
- 2026-11-18 — Owner decision: PR 27 also carries the follow-up
  [judge transient retry and token estimate](judge-transient-retry-and-token-estimate.md) spec. Its
  implementation lands on this branch in a separate session. Two live findings motivated it: transient
  503 halts at N=4, and a byte-based TPM estimate about five times too conservative.
