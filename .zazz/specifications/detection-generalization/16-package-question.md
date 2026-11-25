# Detection generalization 16 — the package question

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and are not
  repeated. **Draft, not approved. Nothing is implemented.**
- **Comes from** [15](15-judge-certainty.md), rounds 1 and 2. [03](03-sql-calls.md) and
  [14](14-sql-calls-redesign.md) stopped; contract §5 allowed one redesign, so this one exists only on the owner's word
  (2026-11-25).
- **Depends on** nothing. **Effort** small for phase 0, medium after it. **Review artifact** one draft PR to `stage`.

## Capability

A string built from request data that reads as SQL and reaches a call on a package with no written contract becomes a
record. A **small, separate request** asks the judge what that package operation does with the argument. The scanner
joins that answer with the injection answer of the record. A new driver, ORM or driver version then needs no scanner
change. Only a finding or Review can follow.

## Evidence, and what it does not show

[Results of 15](../../evaluation/detection-generalization-results/15.md). All forms, labels and questions were written
by the implementer.

| Measured | Result |
|---|---|
| Same 18 forms, full request against focused request | 0 of 8 drivers at 0.70 against 7 of 8; input tokens 88,543 against 7,645 |
| Unseen JavaScript drivers and ORM raw calls | 10 of 12 at 0.65 and at 0.70; with the declared version 11 of 12 at 0.65. **Below the 11 of 12 set beforehand without it** |
| Unseen Python drivers (hand-built, no producer) | 9 of 9 at 0.70 |
| Lookalikes and made-up packages | 22 of 22 at 0.09 or below for running SQL |
| Labeled focused answers at 0.65 or above | 101, none wrong; 3 wrong of 14 below it |

Not shown: any real application, held-out application, or scan. No local sample has such a call (03), so **the samples
cannot show a benefit**. Rounds 3 to 5 tested other ideas; none is used here.

## Semantics

**S-1. Candidate.** As 03: the constant text begins a SQL statement, a request value reaches it, and the callee starts
at a package import without a contract. The method name plays no part.

**S-2. Package request.** One per distinct operation in a scan, keyed by import, declared version, callee chain and
argument. It holds the import, how the value is made, the call, the containing function (at most 6 KB) and the declared
version when the manifest gives one. It holds no path, guideline, coverage table or other record. The question is the
`call_effect` question of 15's round 2, with three choices: runs it as SQL, does something else, cannot tell. It says
that a name or the look of the text is not knowledge. The import and binding are scanner facts, so the model cites
nothing.

**S-3. Use of the answer.** `runs_sql` at or above the floor (OQ-2) discharges `sink_binding_unverified` for every record
of that operation. Anything else leaves the record in Review, with the answer visible. A missing, failed or refused
request is no answer.

**S-4. Injection.** On such a record the existing request asks `injection_protection` under the assumption that the
argument runs as SQL text (14 S-2). A finding needs S-3, `vulnerable`, and no other blocker.

**S-5. Limits.** Never Protected, never a dismissal. `not_run_as_sql` removes nothing. A verified contract always wins.

**S-6. Additive and replayable.** The answer, its certainty, the model and the request digest are recorded on the record
and marked model-resolved in every report. The extra request is saved as its own trace and replays exactly. A record of
any other contract, family or language keeps its request byte for byte.

## Scope

| Path | Change |
|---|---|
| `scan/internal/langjs/` (candidate rule) | Restored from `ed257a7`, which passed every offline gate |
| `scan/internal/analysispacks/contracts.go`, `descriptors.go` | The package contract |
| `scan/internal/judge/sql_call.go`, `schedule.go`, `client.go` | Package request, its dispatch beside the follow-up, the S-4 variant |
| `scan/internal/report/` | Provenance text |
| Tests, fixtures, and the documents of [03](03-sql-calls.md) AC6 | |

Out of scope: Python and PHP producers; a constructor as the callee; loops, callbacks and other blockers; validation
libraries; computed facts; trimming any request; other families. Reserved files for both lanes are named in OQ-4.

## Decisions

- **D-1. A second request.** *Why:* 15 measured 0 of 8 against 7 of 8 on the same forms. This reverses 14's D-3.
  *Cost:* one request per distinct operation, not per record; reported in every scan.
- **D-2. Declared version when known.** *Why:* it raised both misses of round 2 and moved no control above 0.35.
- **D-3. Scanner binding, no citation.** *Why:* the binding is already a scanner fact; a citation adds a question.
- **D-4. Full request kept for injection.** *Why:* rounds 3 to 5 gave no safe way to trim it.
- **D-5. Floor for this question only**, if the owner agrees (OQ-2).
- **D-6. No name list.** *Why:* made-up packages with database-like names were answered `cannot_tell`.

## Phases

| Phase | Work | Needs |
|---|---|---|
| 0 | Fresh probe, overlay only, nothing in the repository | Approval of this specification, then the owner's word for the paid run |
| 1 | Code and offline gates | Phase 0 passes |
| 2 | Held-out | Phase 1, and three applications keyed by the key session |

Before phase 1 (free): the key session counts, by script, calls on packages without a contract that carry SQL text in
the candidate applications (OQ-3).

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Phase 0 passes | Results |
| AC2 | Restored 03 candidate tests; each new form records | `go test ./scan/internal/langjs -run TestSQLUnknownCall` |
| AC3 | Stubbed answers: each choice at, above and below the floor, missing, failed and refused; a record with a contract; `vulnerable` without a call answer and a call answer without `vulnerable`. Only a verified answer at the floor with `vulnerable` is a finding; none is Protected | `go test ./scan/internal/judge -run TestPackageQuestion` |
| AC4 | Two records of one operation send one package request, two versions send two; a replay is exact; the limit and the count are in the report | `go test ./scan/internal/judge -run TestPackageQuestionSchedule` |
| AC5 | A request of any other record is byte-identical on the nine samples and, by script, on the reserved control (G2) | Comparison |
| AC6 | G1, G3 to G7 | Commands |
| AC7 | Held-out passes | Results |
| AC8 | Documents of 03 AC6, with the extra request in `trace-judgment.md` | `doc-check` |

## Paid checkpoints

Each asks first, with the exact count (contract §4).

1. **Probe.** 44 requests, hard stop 44, one answer each; identical requests answered identically in 6 of 6 checks, so no
   repeats are planned. 26 package requests on forms unlike any of 03, 14 and 15 (16 drivers and ORM raw calls, 6
   lookalikes, 4 made up), 8 of them again with one neutral sentence, and 10 full requests with the S-4 question on
   5 safe constructions and 5 traps.
   **Pass:** at least 14 of 16 drivers `runs_sql` at 0.65 or above; no lookalike or made-up package above 0.35; the 8
   neutral variants give the same choice; no safe form `vulnerable` at 0.65 or above; no trap `protected`.
2. **Held-out**, after phase 1. Unused applications, cap 60. At least 80% of keyed positives Confirmed, none missed without
   its blocking fact, and no keyed control Confirmed (contract §3, §7).

## Stop rule

Stop and drop the capability when the probe gives fewer than 13 of 16 drivers, any lookalike or made-up package
above 0.35, or a trap answered `protected`. Exactly 13, or a safe form `vulnerable`, goes to the owner. The wording is not
changed after the first request. Stop when OQ-3's count finds no such call in the candidate applications.

## Open questions for the owner

- **OQ-1. Branch.** Recommended: `detgen-16-package-question` from `origin/stage` in lane B, added to the
  [delivery plan](delivery-plan.md) on approval. This document stays on `detgen-14-sql-calls-redesign` until then.
- **OQ-2. Floor.** You named 0.65 as the lowest certainty you would accept. Recommended: 0.65 on the package question
  only, as a stated exception to contract §7 and 14 D-6. The base has no finding here, so a floor cannot lose a true
  finding the base has; it only leaves some in Review. It is not used on any other question.
- **OQ-3. Prevalence.** Nothing shows how often real code makes such a call. Recommended: count first, and do not build if
  none of the candidate applications has one.
- **OQ-4. Shared files.** `judge/client.go` and `judge/schedule.go` are shared with lane A ([plan
  §7](delivery-plan.md#7-what-collides-and-who-waits)). Recommended: lane A does not edit them while phase 1 is open.
- **OQ-5. Held-out applications.** Three, as in 14 OQ-2: a driver in no fixture or form, an ORM raw call, one ordinary
  application. The probe does not wait for them; the merge does.

## First step

The fresh probe forms and their offline check, with nothing sent.

## Implementation and review change log

### 2026-11-25 — Written

The owner asked for it after round 5 of 15. Nothing is approved.
