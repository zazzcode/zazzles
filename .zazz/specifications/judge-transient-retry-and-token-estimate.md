# Judge transient retry and token-based TPM estimate

**Worktree / branch:** `parallel-judge` (the phase 4 worktree; the owner chose to build here)
**Depends on:** architecture phase 4, parallel judge requests, on the same branch
([spec](architecture-phase-4-parallel-judge.md); not yet merged, tracked in PR 27)
**Delivery topology:** extends the phase 4 branch and its draft PR 27 into `stage`; no new PR
**Coordination:** Lead Agent alone; Sonnet subagents allowed for disjoint files
**Run log:** `.zazz/ephemeral/judge-transient-retry-and-token-estimate-run-log.md`
**Drafted:** 2026-11-18

## 1. Capability

This deliverable fixes two problems that phase 4's live runs exposed in the judge transport and
limiter.

1. **Transient retry.** Today one HTTP 502, 503 or 504 from the provider halts the whole scan. Two
   of three concurrent Juice Shop scans stopped this way, at 124 and 148 of 157 requests. After this
   change, `exchange` retries such a request once, after a short bounded wait. Only a second
   consecutive failure halts the scan.
2. **Token-based TPM estimate.** The local TPM reservation today is request bytes plus 4,096. That
   is about 24,000 per Juice Shop request, while the provider reports about 4,900 input tokens. As a
   result, `JUDGE_TPM` throttles about five times harder than its number. After this change, the
   reservation is `ceil(bytes / 3) + 512`, so `JUDGE_TPM` set just under the account limit paces
   close to that limit.

Request bytes, request digests, report order, slot assignment and the phase 4 goldens do not change.

## 2. Required reading

- **Phase 4 spec:** [architecture-phase-4-parallel-judge.md](architecture-phase-4-parallel-judge.md)
  §3 invariants, §5 D-1/D-3/D-5, and the §14 change log.
- **Code:**
  - `internal/judge/transport.go` (`exchange`).
  - `internal/judge/limits.go` (`acquire`, `complete`, `reservationTokens`, `oversized`,
    `LimitSummary`).
  - `internal/judge/schedule.go` (the finalize spend predicate).
  - `internal/judge/trace.go` (`DecisionTrace`, `Replay`).
  - `internal/judge/discovery.go`, which also calls `exchange`.
- **Live evidence:** [architecture baseline](../evaluation/architecture-baseline.md), the phase 4
  sections "Live owner-capped check" and the full judged scans.
- **Standards:** [Testing](../standards/testing.md) §6 concurrency and §7 semantic adapter stubbing.
  [Spec hygiene](../standards/spec-hygiene.md).
- **User docs:** [decision models](../../docs/decision-models.md) (rate and spending configuration);
  [running scans](../../docs/running-scans.md) (scan speed, and judge rate and spending controls);
  `.env.sample`.
- **Rules:** [AGENTS.md](../../AGENTS.md), credentials and live model calls.

## 3. Invariants

- Request bytes and digests are unchanged. `TestArchitectureBaseline` and every golden in
  `internal/judge/testdata/schedule_serial/` pass with no update.
- A request is sent at most twice: the original and one retry. Only 502, 503 and 504 are retried.
  No other status is retried, nor a transport error, a timeout, a 429, a 4xx, a response read
  failure or a decode failure.
- A retry never changes which candidates are judged. Slot assignment (phase 4 D-1) and the
  finalize spend predicate count one slot per candidate.
- A retry is acquired through the limiter like any request: it counts in the RPM/TPM window and in
  `attempts`, and it is refused if the limiter halted meanwhile.
- When both the original and the retry fail, the scan halts with the reason it gives today, for
  example `judge HTTP 503`.
- The TPM reservation never underestimates the reported input tokens of any saved phase 4 trace.
  `complete` still raises a reservation to the reported usage when that is larger.
- The configured RPM and TPM pacing is honored, and nothing falls back to another provider or model.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/judge/transport.go` | modified | One bounded retry for 502/503/504 inside `exchange` |
| `internal/judge/limits.go` | modified | `reservationTokens` is token-based; `abandon` releases a retried attempt without halting; `LimitSummary` reports retries |
| `internal/judge/trace.go` | modified | `DecisionTrace.Retries int` (`json:"retries,omitempty"`) |
| `internal/judge/retry_test.go` | new | Retry stub matrix, halt, limiter accounting, trace field |
| `internal/judge/limits_test.go` | modified | Estimator table and TPM pacing cases |
| `internal/judge/testdata/tpm_ratio.json` | new | Byte and token pairs from the phase 4 Juice Shop traces (numbers only, no request content) |
| `docs/decision-models.md`, `docs/running-scans.md`, `.env.sample` | modified | Retry behaviour; replace the "leave `JUDGE_TPM=0`" guidance with sizing to the account limit |
| `AGENTS.md`, `.zazz/specifications/architecture-update-plan.md` | modified | Narrow the "no retries" rule to "one retry for 502/503/504 only" |
| `.zazz/evaluation/architecture-baseline.md` | modified | Append the estimator table and, if the owner runs one, the capped live check |

Allowed directories: `internal/judge/`, `docs/`, `.zazz/`, plus `AGENTS.md` and `.env.sample`.

Out of scope:

- adaptive or exponential backoff;
- retrying a 429, a timeout or a transport error;
- per-provider retry policy;
- concurrency-default changes;
- request-content or digest changes;
- daily-token (TPD) accounting;
- paid calls without an owner cap.

Review shape: one PR.

## 5. Decisions

- **D-1 Retry only 502, 503 and 504.**
  - **Why:** these statuses mean the provider did not produce an answer and asked to be retried, so
    a resend is not a duplicate billed decision.
  - **Rejected alternative:** retrying transport errors and timeouts. The request may have been
    processed and billed, and a 30 s timeout retried at N=4 can stall a scan for minutes.
- **D-2 Retry once, after a bounded wait.**
  - **What:** wait for `Retry-After`, in whole seconds, when it is present and at most 10 s;
    otherwise 2 s. The wait honors context cancellation.
  - **Why:** one retry recovers the observed single 503 per scan, and a fixed cap keeps the
    worst-case delay predictable.
- **D-3 A retry does not consume a `--judge-limit` slot.**
  - **Why:** phase 4 assigns slots offline before dispatch (D-1, no refunds). Charging retries would
    make which candidates get judged depend on provider timing.
  - **What instead:** the cap's meaning becomes "candidates sent". HTTP requests are at most twice
    the cap, and the docs say so. `LimitSummary` reports `retries N`.
- **D-4 The first failed attempt releases its reservation without halting.**
  - **What:** a new `abandon(id)` keeps the window entry, since the provider saw a request. It
    counts the attempt as unknown usage and leaves `halted` unchanged. Only the retry's `complete`
    can halt.
  - **Why:** halting on the first 503 is exactly the failure being fixed, and keeping the window
    entry stays conservative under RPM.
- **D-5 Estimate tokens as `ceil(bytes / 3) + 512`.**
  - **Evidence:** across the 157 phase 4 Juice Shop traces, bytes per reported token ranged from
    3.69 to 4.39 (median 4.17). Dividing by 3 overestimates every trace by at least 23%, and 512
    covers the framing. The largest overestimate is 1.647×, on the smallest requests (about 12 KB).
  - **Why:** the estimate is simple and deterministic, the same at every concurrency, and the
    existing reconcile in `complete` covers content that tokenizes more densely.
  - **Rejected alternative:** an adaptive ratio learned from reported usage. It would make admission
    depend on completion order and response timing.
- **D-6 Keep the visible TPM message and setting names.**
  - **What:** the oversized-request refusal keeps today's text. Only the arithmetic behind
    `JUDGE_TPM` changes.
  - **Why:** users' `.env` files and the CLI tests stay valid.

## 6. Agent implementation rules

- **Authority and worktree:** follow [AGENTS.md](../../AGENTS.md) authorization and worktree rules.
  Work in the existing `parallel-judge` worktree on branch `parallel-judge`, on top of the phase 4
  commits. Do not create a worktree or a new PR. Verify `pwd`, the branch,
  `git status --short --branch` and `git worktree list` before editing. Never edit in `stage/`.
- **Discipline:** follow [execution discipline](../docs/agent-execution-discipline.md) and the
  `spec-driven` skill. Record a fresh [standards index](../standards/index.yaml) lookup in the run
  log.
- **Commits:** make one green commit per §9 step, with `[AREA]` prefixes. Push to `parallel-judge` at
  completion and update the PR 27 description with an AC1–AC10 section. Never merge.
- **Verification:** run `gofmt -l` on changed Go files, `go vet ./...`, `go build ./...`,
  `go test -race ./... -count=1`, and `go test ./cmd/scan -run TestArchitectureBaseline -count=1`.
- **Paid calls:** none by default. An optional live check needs the owner to state the provider,
  model and a numeric cap in the session.
- **Halts:**
  - any phase 4 golden or `TestArchitectureBaseline` changes;
  - a request digest changes;
  - a retry would be needed for any status outside D-1;
  - the estimator underestimates any row of `testdata/tpm_ratio.json`;
  - an open question in §11 is unresolved;
  - the same test fails three iterations in a row;
  - a file outside §4 needs changing.

## 7. Acceptance criteria

1. **AC1 Retry recovers.**
   - **Behaviour:** a stub that answers 503 to the first request and then 200 completes the
     candidate. The stub sees 2 requests and the limiter records 2 attempts. The trace has
     `http_status: 200`, `retries: 1`, and the successful response. `LimitSummary` includes
     `retries 1`, and the limiter is not halted.
   - **Test:** `TestRetryRecoversOnce` cases 502, 503 and 504.
2. **AC2 Second failure halts.**
   - **Behaviour:** 503 twice gives `failed` with reason `judge HTTP 503`. Later candidates get
     `judge limit: stopped after judge HTTP 503`, and exactly 2 requests reach the stub for that
     candidate.
   - **Test:** `TestRetryTwiceHalts`.
3. **AC3 No retry outside D-1.**
   - **Behaviour:** statuses 400, 401, 429 and 500, a closed connection, and an undecodable 200
     each reach the stub exactly once and halt as today.
   - **Test:** table `TestNoRetryForOtherFailures`.
4. **AC4 Wait honors Retry-After and cancellation.**
   - **Behaviour:** with an injected wait, `Retry-After: 3` waits 3 s, `Retry-After: 60` waits 2 s,
     and a missing header waits 2 s. A context canceled during the wait returns
     `judge limit: pacing canceled` without a second request.
   - **Test:** `TestRetryWait`.
5. **AC5 Retry respects the limiter.**
   - **Behaviour:** with RPM=1 and an injected clock, the retry waits for the window. If another
     request halts the limiter during the wait, the retry is refused with the stop reason and is
     not sent.
   - **Test:** `TestRetryAcquiresThroughLimiter`.
6. **AC6 Scheduling unchanged.**
   - **Behaviour:** the phase 4 goldens pass byte-identically. A new scheduler case, N=4 with one
     503-then-200 on request #2, completes every candidate. `--judge-limit` slots are assigned
     exactly as with no 503, and the report equals an all-200 run except the `LimitSummary`
     retries count.
   - **Tests:** `TestScheduleSerialGolden`, `TestScheduleParallelMatchesSerialGolden`,
     `TestScheduleRetryKeepsSlots`.
7. **AC7 Estimator.**
   - **Behaviour:** `reservationTokens` returns `ceil(bytes/3)+512`, is at least the reported
     tokens for every row of `testdata/tpm_ratio.json`, and is at most 1.65× the reported tokens on
     every row.
   - **Test:** `TestReservationTokensCoversObservedUsage`.
8. **AC8 TPM paces near its setting.**
   - **Behaviour:** with an injected clock, TPM=100,000 and a stream of 20,000-byte requests
     (reservation 7,179), N=4 admits 13 requests in the first rolling minute and never more
     reserved tokens than 100,000 in any minute. `TPM=1` still refuses with today's message.
   - **Test:** `TestTokenEstimatePacing`.
9. **AC9 Docs and rule.**
   - **Docs:** `docs/decision-models.md` and `docs/running-scans.md` describe the single 502/503/504
     retry, D-3's cap meaning, and sizing `JUDGE_TPM` just under the account limit. The "leave
     `JUDGE_TPM=0`" text is removed.
   - **Rules:** `AGENTS.md` and the architecture update plan state the narrowed retry rule.
     `.env.sample` comments match.
   - **Check:** review in the PR, plus `doc-check`.
10. **AC10 Gate:** every §6 verification command passes.

## 8. Test strategy

- **Retry tests in `retry_test.go`:** one `httptest` stub with a per-ordinal status table, which
  drives AC1–AC3 as table rows rather than copied tests. The limiter's `now` and `wait` are
  injected for AC4–AC5, as in `TestSchedulePacingUnderConcurrency`. A closed-connection row
  hijacks and closes the connection.
- **Scheduler case:** `TestScheduleRetryKeepsSlots` reuses the phase 4 `scheduleStub` and
  `prepareScheduleScenario` helpers from `schedule_parallel_test.go`. It compares against an
  all-200 run of the same scenario, normalizing only the `LimitSummary` line.
- **Estimator data:** `TestReservationTokensCoversObservedUsage` reads `testdata/tpm_ratio.json`.
  Generate the file once from the phase 4 live traces as `[{"bytes": n, "tokens": n}]`, numbers
  only, so no transmitted source enters the repository. The generator is a one-line `jq`, recorded
  in the run log.
- **Pacing:** `TestTokenEstimatePacing` follows the observed-window pattern of phase 4 AC6.
- **Omitted:** no new CLI test. The flags and environment names are unchanged, and the existing
  `TestJudgeLimitConfiguration` and `TestJudgeTPMProducesIncompleteThreeFormatBundle` still cover
  them.

## 9. TDD entry point and execution sequence

1. Add `testdata/tpm_ratio.json` and `TestReservationTokensCoversObservedUsage`. **Red:** the
   current estimate fails the 1.65× upper bound.
2. Change the estimator:

   ```go
   // reservationTokens is a conservative input-token estimate: observed request
   // JSON runs 3.7–4.4 bytes per token, so bytes/3 over-reserves; complete()
   // still raises the entry to reported usage when that is larger.
   func reservationTokens(size int) int64 { return int64((size+2)/3) + 512 }
   ```

   Make AC7 and AC8 green and confirm the goldens.
3. Add `retry_test.go` (AC1–AC5, red), then implement:

   ```go
   func (c *Client) exchange(ctx context.Context, payload []byte, trace *DecisionTrace) (data []byte, reason string) {
   	for attempt := 0; ; attempt++ {
   		data, reason, retryAfter := c.send(ctx, payload, trace) // one acquire → HTTP → complete/abandon
   		if attempt == 1 || !retryable(trace) {
   			return data, reason
   		}
   		if err := c.limiter.waitRetry(ctx, retryAfter); err != nil { // nil limiter: plain timer
   			return nil, "judge limit: pacing canceled: " + err.Error()
   		}
   		trace.Retries++
   	}
   }
   // abandon records a retried attempt: window entry kept, usage unknown, no halt.
   func (l *requestLimiter) abandon(id uint64)
   ```

   `retryable` is true only for an HTTP status of 502, 503 or 504. `send` calls `abandon` instead
   of `complete` for a first retryable failure.
4. Add `TestScheduleRetryKeepsSlots` (AC6), then update the docs, rules and `.env.sample` (AC9).
   Append the estimator table to the evaluation record, run the gate (AC10), push, and update PR 27.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC10 verified, with evidence in the run log.
- [ ] The new commits' diff (`git diff <phase-4 head>..HEAD --stat`) matches §4.
- [ ] The PR states D-3 (retries not counted against `--judge-limit`) and the narrowed retry rule.
- [ ] Live behaviour is either verified with an owner-capped run or stated as unverified.

## 11. Open questions

None blocking. The owner requested this deliverable after phase 4's live runs, and that request is
the decision to narrow the "no retries" rule as D-1 describes. The owner may change the status set
or the 2 s/10 s wait bounds at review; each is a one-line change.

## 12. Run log protocol

Append-only, following the plan's
[common rules](architecture-update-plan.md#common-agent-implementation-rules). Record the standards
lookup, the `tpm_ratio.json` generator command, the red and green per step, and gate results.

## 13. Agent implementation prompt

> Work in the existing `parallel-judge` sibling worktree on branch `parallel-judge`, on top of the
> phase 4 commits; do not create a worktree or a new PR. Read AGENTS.md, the orientation contents,
> and this spec. Execute §9 in order. Make no paid calls unless the owner states provider, model and
> a numeric cap. Stop on any §6 halt. Finish by pushing to `parallel-judge` and adding AC1–AC10
> evidence to the description of draft PR 27. Verifier: a fresh-context subagent runs
> `go test -race ./internal/judge ./cmd/scan -count=5` and reads `transport.go` and `limits.go` to
> confirm three things: only 502/503/504 are retried, at most once; the retry goes through
> `acquire`; and the first failure calls `abandon`, not `complete`. It reports PASS or FAIL.

## 14. Implementation and review change log

- **2026-11-18, AC7 upper bound (§7 AC7, §9 step 1, §5 D-5 evidence).**
  - **Source:** implementation finding; the owner chose the resolution in session.
  - **Rationale:** with D-5's `ceil(bytes/3)+512`, 14 of the 157 rows in `testdata/tpm_ratio.json`
    exceed 1.6× the reported tokens, up to 1.647× at 12,040 bytes and 2,748 tokens. The framing
    allowance dominates on the smallest requests.
  - **Summary:** the AC7 upper bound is 1.65×. The estimator and the AC8 numbers do not change.
  - **Verification impact:** `TestReservationTokensCoversObservedUsage` asserts 1.65×.
