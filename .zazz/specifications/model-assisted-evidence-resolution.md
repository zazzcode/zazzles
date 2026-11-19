# Model-assisted evidence resolution (proposal)

- **Worktree and branch** To be assigned by the owner. Suggested: `model-evidence-resolution`.
- **Prerequisite** [False positives and Review noise](accuracy-false-positive-noise.md): its W5
  measures give this contract its baseline, and its W7 proves the cited-answer pattern on one
  family.
- **Delivery** One draft PR into `stage`, with one commit per workstream that ships.
- **Run log** `.zazz/ephemeral/model-assisted-evidence-resolution-run-log.md`
- **Owner decisions** The questions in §11 are answered before implementation starts.

## 1. Capability

Let the decision model resolve evidence the scanner could not, and judge adequacy where rules are
weak, without letting an unsupported answer become a verdict. The scanner asks a specific question
about each unresolved point, the model answers and cites the evidence it relied on, and the
scanner verifies the citation before the answer counts. A resolved fact is marked as
model-resolved wherever it appears. The outcome is fewer Review records caused by analysis limits,
and accuracy that improves with the model instead of with more adapter code.

## 2. Measured baseline

Offline figures come from the eleven pinned samples at `stage` `39c5483`. Judged figures come from
the latest saved runs of Juice Shop, OopsSec, DVWA, ThreatByte and vulnerable-flask-app
(2026-11-15 to 2026-11-18): 241 judged security records. Those runs span scanner versions, so the
judged figures are indicative until the false-positive contract's W5 measures replace them.

| Where the model is under-used | Measurement |
|---|---|
| A scanner blocker fixes the outcome, yet the record is judged | 49 of 241 judged records. All 49 ended Review. On 9 of the 10 blocked path records the model had answered `vulnerable` |
| Code the scanner stops at but a reader can follow | Offline blockers by record: `python_comprehension_unresolved` 65, `python_call_unresolved` 65, `python_dispatch_unresolved` 64 (64 path records at one VulnPy sink), `php_value_unresolved` 31, `php_loop_unresolved` 8, `transfer_limit` 6, `unknown_transfer` 5 |
| Stored-data origin judged without the writes | `storage_origin_unresolved` blocks 41 records offline (25 XSS, 16 SQL) and 20 judged records |
| A disagreement is discarded | `path_answers_inconsistent` on 10 judged records. The model is not asked for the flow it saw |
| The model cannot name what it lacks | Every `unknown` answer. Example: 11 Juice Shop URL-context XSS records where the model agreed on the context and answered `unknown` on encoding |

## 2a. Required reading

- [Judgment gates](../architecture/trace-judgment.md#separate-judgments-and-gates), which state the rule this contract revises: model confidence cannot close a static blocker.
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) and [calibration](../../docs/analysis/calibration.md#evaluation-and-audit).
- [False positives and Review noise](accuracy-false-positive-noise.md) §3 and D-7, the invariant and the pattern this contract generalizes.
- [Decision-model user guide](../../docs/decision-models.md) and [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls) for request and retry limits.
- [Path traversal analysis](../../docs/analysis/path-traversal.md) and [XSS analysis](../../docs/analysis/xss.md).
- [Testing standards](../standards/testing.md) and the plan's [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).

## 3. Invariants

- **The model proposes; the scanner verifies.** A model answer changes a record's evidence only
  when every span it cites exists in the scanned snapshot and the cited items connect the points
  the answer claims to connect. An answer with no verifiable citation changes nothing.
- **Confidence is not evidence.** This contract revises the architecture rule only for verified
  citations. A bare `vulnerable` or `safe` still cannot close a blocker.
- **Resolution is visible.** A blocker resolved this way stays in the record as resolved, with the
  provider, model, question version and cited spans. Reports show it. Nothing is silently dropped.
- **Protection needs scanner proof.** A model-resolved fact may move a record from Review to a
  finding. It may move a record to Protected only when the scanner independently holds the
  coverage fact that makes protection complete. A wrong finding costs a review; a wrong Protected
  hides a defect.
- **Bounded requests.** A record gets its assessment request and at most one follow-up. The
  follow-up is not a retry and adds no stop condition. Transport retry rules are unchanged.
- **Labels stay out of the scanner.** Expected labels, sample names and case IDs never enter
  scanner logic or model input.
- **Changed questions are judged afresh.** A changed question set bumps the protocol version, and
  old answers are never replayed onto it.
- **Recall floor.** The phase 5 checker floor holds, and no keyed positive loses a finding.

## 4. Scope and review shape

| Workstream | Owner | Change |
|---|---|---|
| W1. Resolution protocol and provenance | `internal/analysis`, `internal/judge` | A resolution record on the assessment, a citation verifier, and one policy hook that treats a verified resolution as discharging its blocker |
| W2. Flow-gap questions | `internal/analysispacks`, `internal/judge` (path, injection) | For each flow blocker in §2, send the unresolved span and ask whether the value passes through it. Path traversal and SQL first |
| W3. Stored-origin judgment | `internal/analysispacks`, `internal/judge` (xss, injection) | Send the write set and the read query that the false-positive contract's W3 assembles, and ask whether a request value reaches the stored column |
| W4. Cited witness on disagreement | `internal/judge` (path) | When the model's verdict contradicts the scanner's facts, a verified cited flow stands as a finding; otherwise the existing inconsistency blocker applies |
| W5. One evidence request | `internal/judge` (scheduling), adapters' source index | The model may name one missing item (a helper body, a template, a middleware). When the snapshot resolves it, one follow-up request carries it |
| W6. Measurement | `.zazz/evaluation/` | Per provider and model: blockers resolved, citations rejected, follow-ups sent, outcome moves, and a source review of model-resolved findings |

Files:

| Path | New or modified | Reason |
|---|---|---|
| `internal/analysis/findings.go`, `internal/analysis` assessment types | Modified | W1 resolution record and its JSON fields |
| `internal/judge/resolution.go`, `internal/judge/citation.go` | New | W1 question builder, verifier and policy hook |
| `internal/judge/path.go`, `injection.go`, `xss.go` | Modified | W2 to W4 policy use of verified resolutions |
| `internal/analysispacks/path*.go`, `xss.go`, storage component | Modified | W2 and W3 questions and protocol versions |
| `internal/judge/schedule.go`, `bundle.go` | Modified | W5 follow-up scheduling and evidence item IDs the model can cite |
| `internal/report` (JSON, HTML, SARIF) | Modified | Present model-resolved provenance |
| `.zazz/architecture/trace-judgment.md`, `docs/decision-models.md`, `docs/interpreting-results.md`, `docs/analysis/calibration.md` | Modified | The revised gate rule and how to read a model-resolved record |
| `.zazz/evaluation/model-resolution-results.md` | New | W6 record |

The diff stays inside these paths plus their tests and fixtures.

Out of scope, each a later contract that reuses W1:

- Output context and encoding adequacy from template and sanitizer source.
- Library validator and guard semantics supplied from model knowledge.
- Handler-level validation judgment, one request per entry, which replaces the fixed-outcome
  validation records the false-positive contract stops sending.
- Flow-gap questions for command, code, redirect, SSRF, NoSQL and logging.
- Model-assisted route discovery, which already exists behind `--discover-routes`.
- New adapter analysis. This contract adds no deterministic flow modeling.

## 5. Decisions

- **D-1. One resolution record, one verifier (W1).** Every model-resolved fact is the same shape:
  the blocker it answers, the answer, the cited evidence item IDs and the verification result.
  One function checks citations for every family. **Why.** Per-family resolution code would repeat
  the adapter sprawl this contract exists to avoid, and one verifier is one place to audit.
- **D-2. The model cites items, not line numbers (W1).** Each evidence item in the request has a
  stable ID. A citation names IDs, and for a flow, an ordered chain from source to sink.
  Verification checks that each ID was in the request and that each adjacent pair is either a
  scanner edge or the single gap the question asked about. **Why.** Free-text line references
  cannot be checked, and a chain with two invented hops is a guess.
- **D-3. A flow-gap question is specific (W2).** It names the unresolved span and offers
  `value_preserved`, `value_constrained`, `value_replaced` or `cannot_tell`. Only `value_preserved`
  with a verified chain discharges the blocker toward a finding. `value_constrained` records the
  constraint and stays Review. **Why.** A constrained value is an adequacy judgment that needs the
  guard pattern from the false-positive contract's D-7, not a flow fact.
- **D-4. Stored origin is judged over a stated write set (W3).** The request carries every write
  the scanner found for the storage key, the read query, and whether the store's schema and
  writers are all in scanned source. Answers are `request_write_cited`, `no_request_write_in_evidence`
  and `cannot_tell`. A cited request write that verifies makes the record a stored-flow finding
  candidate. `no_request_write_in_evidence` yields Protected only with the scanner's closed-store
  fact; otherwise it stays Review with that reason. **Why.** The model can reason only over the
  writes it is shown, so absence of a write is meaningful only when the store is closed.
- **D-5. Disagreement asks for the witness (W4).** When the verdict contradicts the facts, the same
  request's cited chain decides it: verified, the finding stands as model-resolved; unverified,
  the existing `path_answers_inconsistent` blocker applies. **Why.** Today the answer is discarded
  without learning whether the model saw a flow the scanner missed.
- **D-6. One follow-up, scanner-resolved (W5).** The model may return one `needed_evidence` item by
  kind and symbol. The scanner fetches it only when the snapshot resolves the symbol exactly, then
  sends one follow-up. An unresolvable request is recorded and the record stays Review.
  **Why.** One round covers the common case of a helper body just outside the expansion limit and
  keeps cost predictable. **Rejected.** An open tool loop, which makes request counts unbounded.
- **D-7. Blocked records are sent only when a question can resolve them (W1).** A record whose
  blockers all have a resolution question is judged with those questions. A record with a blocker
  that has none is not sent. **Why.** This extends the false-positive contract's rule that the
  judge is not asked a fixed question, and it turns the 49 wasted requests into useful ones.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls). Build W1 against a stub judge
before any live call. Paid calls are limited to what the owner authorizes in §11 Q4. Halt if the
recall floor moves, a keyed positive loses its finding, a model-resolved fact yields Protected
without the scanner's coverage fact, or the source review in AC6 finds a false finding.

## 7. Acceptance criteria

1. **AC1 (W1).** With a stub judge, an answer whose citations verify discharges its blocker and
   records provider, model, question version and cited IDs; an answer citing an ID not in the
   request, or a chain with a hop that is neither a scanner edge nor the asked gap, changes
   nothing and records the rejection. Verified by `TestResolutionCitationVerifier` and
   `TestResolutionDischargesBlocker` in `internal/judge`.
2. **AC2 (W2).** For a fixture with a Python comprehension between a request value and a path
   sink, the request names the comprehension span and the four answers. `value_preserved` with a
   verified chain yields a finding marked model-resolved; `cannot_tell` leaves the blocker.
   Verified by `TestFlowGapQuestionPath` in `internal/judge`.
3. **AC3 (W3).** The request for a stored-origin record contains every found write and the read
   query. A verified `request_write_cited` yields a stored-flow finding candidate;
   `no_request_write_in_evidence` yields Protected with the closed-store fact and Review without
   it. Verified by `TestStoredOriginJudgment` in `internal/judge`.
4. **AC4 (W4).** A contradicting verdict with a verified chain stands as a model-resolved finding;
   the same verdict without one gets `path_answers_inconsistent`. Verified by
   `TestDisagreementNeedsWitness` in `internal/judge`.
5. **AC5 (W5).** A `needed_evidence` item that the snapshot resolves produces exactly one
   follow-up containing it; an unresolvable item produces none; no record gets a second
   follow-up. The run reports follow-up counts beside request counts. Verified by
   `TestSingleEvidenceFollowUp` in `internal/judge`.
6. **AC6 (W6).** After the authorized live runs, the results record lists, per sample and model:
   blocked records sent, blockers resolved, citations rejected, follow-ups, and records moved from
   Review to finding or Protected. Every model-resolved finding, up to 40, is source-reviewed, and
   none is a false finding. The phase 5 checker floor holds.
7. **AC7.** JSON, HTML and SARIF each show model-resolved provenance on the record, the
   architecture and user docs state the revised gate, and the contributor gate passes.

## 8. Test strategy

- **Verifier.** One table-driven test: valid chain, unknown ID, extra invented hop, chain that
  skips the asked gap, empty citation.
- **Policy.** One test per workstream pairing the discharged case with the neighbour that must
  not move: `cannot_tell`, an unverified citation, and an open store.
- **Scheduling.** Follow-up count and ordering with a stub judge; no live call.
- **Live.** Bounded runs per §11 Q4, with every model-resolved finding source-reviewed.
- **Omitted.** No new adapter fixtures: this contract changes no flow modeling, and the existing
  adapter goldens prove the offline records are unchanged.

## 9. Execution sequence

1. W1 with a failing verifier test, then the policy hook, all against a stub judge.
2. W4, the smallest use of the verifier.
3. W2 for path traversal, then SQL.
4. W3, once the false-positive contract's write-set evidence is on `stage`.
5. W5.
6. W6 live runs and source review.

Each step is its own commit with its own evidence.

## 10. Definition of done

- [ ] The verifier and policy hook pass their stub tests (AC1).
- [ ] Each shipped workstream meets its AC.
- [ ] Live results and the source review are recorded with no false finding (AC6).
- [ ] The architecture rule, user docs and analysis guides are updated (AC7).
- [ ] The recall floor holds.

## 11. Open questions (owner)

1. **Presentation.** Should a model-resolved finding carry the same status as a scanner-proven one
   with a visible provenance mark (recommended), or a distinct status until calibrated?
2. **Protected.** Is Protected from a model-resolved fact allowed only with the scanner's coverage
   fact (recommended, D-4), or never in this delivery?
3. **Follow-up budget.** Is one follow-up per record right, and should a scan-wide cap apply (for
   example follow-ups no more than 25% of requests)?
4. **Paid budget.** W6 needs judged runs beyond the standing live check: VulnPy limited to the
   path family (about 260 requests), DVWA and OopsSec in full, each on `openai` `gpt-6-luna`. Which
   of these are authorized, and should a second model be measured for comparison?
5. **Scope split.** Should W3 wait in this contract for the write-set evidence, or move to its own
   contract so W1, W2 and W4 can ship first?

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, sample pins, provider, model and question
versions, request and follow-up counts, owner answers to §11 and the source-review outcome per
model-resolved finding.

## 13. Agent implementation prompt

> Work in the owner-assigned worktree based on `origin/stage` with the false-positive contract
> integrated. Read AGENTS.md, the orientation contents and this spec. Confirm the owner's §11
> answers in the run log. Execute §9 in order, building each workstream against a stub judge
> before any live call. Keep samples read-only. Make paid calls only as §11 Q4 authorizes. Deliver
> a draft PR into `stage`, one commit per workstream, with an independent source review of every
> model-resolved finding.

## 14. Implementation and review change log

### 2026-11-19 — Proposal

Drafted from the owner's direction to use the decision model where rule-based analysis is weak,
and from measurements of saved judged runs. No changes recorded since.
