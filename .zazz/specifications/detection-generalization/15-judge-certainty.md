# Detection generalization 15 — judge certainty, an experiment

- **Series** [Contract](contract.md). **Asked for by the owner 2026-11-25**, after [14](14-sql-calls-redesign.md)
  stopped. The owner's direction to test other approaches is an exception to the one-redesign limit of
  [contract §5](contract.md#5-stop-procedure). **Experiment only: no product code, and no paid request without the
  owner's word.**
- **Goal** (owner) A vulnerability answer has certainty of at least **0.70**. **0.65** is the lowest acceptable. An
  approach that does not reach it is marked and left.
- **Constraint** (owner) Send the judge the right details, well under the 64 KB request limit.
- **Branch** `detgen-14-sql-calls-redesign`, in lane B, kept there by the owner 2026-11-25: an exception to the
  dropped-branch rule of [delivery plan §6](delivery-plan.md#6-moving-a-lane-to-its-next-branch), while 15 is documents
  only. Product code from 15 starts a new branch from `origin/stage`.

## What certainty means here

The probability the model returns for the answer a verdict rests on; the lowest one where a verdict needs several. It
grades an **approach**. It is not a cut-off on scanner records and not evidence for a verdict (contract §7, 14 D-6).

## Free measurement first

From `answer_details` of the four judged reports and the frozen ledger (403 records; 257 true and 20 false Confirmed).

| Bar | True Confirmed at or above | False Confirmed below |
|---:|---:|---:|
| 0.65 | 232 of 257 (90%) | 4 of 20 |
| 0.70 | 213 of 257 (83%) | 6 of 20 |

- The median certainty of a true finding is 0.90, so the goal is realistic.
- **As a cut-off it would be a bad trade:** 0.65 would lose 25 true findings to remove 4 false ones. 11 of the 14 false
  SQL findings are at or above 0.70. Certainty is not correctness.
- Size is not the cause. Median certainty of true findings by request size (fifths, 1.7K to 19K tokens): 0.90, 0.94,
  0.86, 0.83, 0.94.
- Weakest answers on true findings: `all_paths_protected` (NoSQL) median 0.53, `destination_control` (redirect) 0.50,
  `field_impact` (mass assignment) and `weakness` (configuration) 0.74 and 0.84.
- 14's call question, `executes` plus `prepares_then_executes`: 0.29 to 0.64 on eight drivers. None reaches 0.65.

In a 22 KB request of 14 the judged source is about 300 bytes. The rest is general instruction, evidence tables and
guidelines, many of which say to stay unsure.

## Round 1: arms

18 forms of 14, one repeat each. The forms are spent: this screens approaches and proves nothing.

| Arm | Request | Bytes |
|---|---|---:|
| A0 | 14, already sent (repeat 1) | 22 KB |
| A1 | A0 with the two running-SQL answers merged | 22 KB |
| A2 | Focused: import, how the value is made, call, handler; one merged question | 1.6 KB |
| A3 | A2 split into "do you know this package" and "does this call run it as SQL" | 1.8 KB |
| A4 | A3 plus injection under the assumption, verified facts and fact notes | 2.6 to 3.3 KB |

A1 changes one thing. A2 to A4 drop the shared evidence, the guidelines and the practice questions; whether the parts a
production request needs can be put back is a later question. A4's injection text names the three safe constructions
of the forms, so its safe result is optimistic and needs other constructions in round 2.

**Cost** 72 requests, hard stop 72, no retry. About 0.5 MB of requests in all. `criteria-arms.json` holds the marks.

**Mark** GOAL at 0.70 or FLOOR at 0.65 when at least 7 of 8 drivers and all 7 controls meet the bar (a control meets it
when the running-SQL certainty is at most 1 minus the bar), and injection does where asked. Otherwise BELOW, recorded
and not reworded on these forms.

## Round 2: does it hold on what it was not designed on

Packages, made-up names, safe constructions and traps all differ from 03 and 14. JavaScript SQL requests are built from
real scanner records (the 14 overlay), so they hold only what a scan can extract. Five of the 12 drivers sit in a longer
handler. The call question gains "or marks it as raw SQL text", which round 1 lacked. The injection question is
rewritten and names no pattern. The implementer wrote the forms and the questions, so this is not held-out evidence.

| Set | Requests | What |
|---|---:|---|
| H1 | 33 | JavaScript SQL: 8 drivers, 4 ORM raw calls, 7 lookalikes, 4 made up, 5 safe, 5 traps. Call and injection questions |
| H2 | 23 | The drivers, lookalikes and made-up of H1 with the declared package version. Reported, not marked |
| V | 15 | Validation libraries: what can the value be after the call. Hand-built; no producer exists |
| P | 13 | Python: 9 drivers, 3 lookalikes, 1 made up. Hand-built; no producer exists |
| D | 6 | Exact repeats of H1 requests |
| **Total** | **90** | hard stop 90, 0.19 MB of requests |

A trap looks checked and is not: an unanchored pattern, a check without a return, trim and slice, `encodeURIComponent`
in quotes, a `typeof` test. Marks are in `criteria.json`. A set marked BELOW is not reworded on these forms.

**Found offline, free.** The scanner's own blockers hold correct records back whatever the judge answers. In the long
handler a `for` loop that does not touch the value gives `control_flow_unresolved`, `unsupported_control_flow` and
`unknown_control_effect`; a callback can give `unsupported_callback`; `parseInt`, `BigInt` and `Map.get` give
`input_helper_unresolved`. 5 of the 12 drivers have the loop blockers, and 3 the callback blocker (one has both). Generalizing the package question is
not enough alone: the same focused approach has to be tried on those gaps. `look-winston` made no SQL record and
`safe-ternary` made none because no request data is in its text.

## Round 3: whole applications

The owner asked (2026-11-25) to confirm the approach on Juice Shop and the other three README applications with paid
judge runs: the same vulnerabilities, with less data and as good or better results, means it is worth pursuing. This
replaces a round 3 on more invented forms.

- **Records.** All 403 judged records of the four applications in the frozen ledger, every family. Their pins match.
- **F request.** Short instruction, the family's own instruction, api_model, family facts, dependencies, evidence rows
  that something refers to, guards and helpers, the code they point at, and fact notes. Family questions and answers are
  unchanged. Left out: guidelines, components, coverage and invocation tables, unreferenced code, and the SQL and NoSQL
  practice questions (the saved answers stand in). 9.8 MB becomes 5.7 MB; the largest falls from 63 KB.
- **Outcome, not answer.** F answers go through the scanner's own policy by replay (an overlay that only accepts a local
  stub), and the result is compared with the control: the saved answers through the same policy.
- **Control check, free.** The control reproduces 387 of 403 outcomes. Of the other 16, 15 are poor-practice labels
  (2 of them SQL) that the report sets or that rest on answers not replayed; one path finding rests on a citation answer
  that is not replayed. Fed its own
  saved answers, the scorer gives 256 true and 20 false Confirmed with nothing moved.
- **Cost** 403 requests, hard stop 403, no retry. `criteria.json` (round 3) is written first.
- **Measure.** GOOD, BETTER or BELOW as defined there. The contract §7 rule holds: no true finding is lost.
- **Not shown.** The 26 stale records, a multi-question package call, held-out applications, and any production change.

## Round 4: which information does the judge need

The owner (2026-11-25): find what has to be sent to get a signal good enough for the correct result, and the fewer KB the
better. Round 3 cut evidence, so it could not answer that. This round removes **one section at a time**, keeping all
evidence, all code, the api_model and the family questions.

| Arm | Drops | Bytes of the 101 requests |
|---|---|---:|
| G | Guidelines (fact notes kept), component list, generic instruction tail | 2.06 MB |
| C | `evidence_coverage` | 2.25 MB |
| V | `invocation` | 2.29 MB |
| X | Context and required lists, scope, declared requirement, coverage gaps | 2.32 MB |
| L2 | All of them | 1.75 MB |

- **Records.** 101 development records, fixed by seed before any answer: the 44 true Confirmed with a decisive answer
  below 0.70, 20 false Confirmed, 1 not decidable, 15 Protected, 10 other true, 11 others. The fragile ones were chosen
  because they show what is needed. **302 records stay out as a confirmation set.**
- **Safe or needed** is defined in `criteria.json` (round 4), on policy outcomes by replay, plus the change of certainty.
- **Cost** 505 requests, hard stop 505, no retry. Confirmation is a second run of one arm on the 302, asked separately.
- **Later, not here:** adding information. The first candidate is a language-neutral fact, whether the value sits inside
  quotes in the text; the DVWA false positives are values escaped and quoted.

## Round 5: a noise control, and computed facts

The owner asked (2026-11-25) whether the judge should choose what to send, without a recursive loop, or whether Go can
decide it. **Go decides, the judge answers once.** The scanner's one bounded follow-up exists (one per record, 25% cap)
and on the four applications 60 records have one, 0 sent: 49 marked not sent, 11 unresolved. So this round tests facts
the scanner computes.

Round 4 had two flaws: no noise control, and arms C, V and X were re-encoded with the guidelines moved before the
instruction. G and L2 had the guidelines removed, so they kept the order.

| Arm | Requests | What |
|---|---:|---|
| N | 145 | One neutral sentence added: the 101 dev records and the 68 SQL records (24 shared) |
| R | 101 | Dev records re-encoded with nothing dropped: the order change of C, V and X, content equal |
| Fa | 68 | SQL records, full request plus `sql_position_facts` |
| Fb | 68 | Fa plus a short general note on escaping inside and outside quotes |
| **Total** | **382** | hard stop 382, no retry, 9.2 MB |

- **The fact.** For each request value: where it sits in the SQL text (inside a quoted literal or not), and the names of the
  calls on its path. No list of libraries decides anything; the position comes from the text, the call names are reported.
  It is added to the request and nothing is removed.
- **Seen already, before any paid answer.** Of the 14 false SQL findings, 12 have every value inside quotes and an escape
  call on every path; none of the 30 true ones does. The other 2 use a pattern check. So the facts were chosen on these
  records, and a pass needs a Go version and other applications.
- **Criteria** are in round 5's `criteria.json`: facts must lose no true finding, remove at least 8 of 14 false, and clear
  nothing the ledger calls safe; the noise level decides whether any round 4 arm was distinguishable.
- **Not here:** facts for other families, and dropping any section.

## Review change log

### 2026-11-25 — Written, round 1 sent

A2 is marked GOAL; A0, A1, A3 and A4 are BELOW. [Results](../../evaluation/detection-generalization-results/15.md).

### 2026-11-25 — Owner's goal restated

The aim is to generalize, so a new driver version, ORM or validation library needs no scanner change, or as little as
possible, with an easy way to improve. It may differ by language. Consequences for this series: an approach is judged
by how little it needs to know ahead. A focused question built from structural facts fits; a list of packages does not.

### 2026-11-25 — Round 2 designed

Offline only. Nothing of round 2 is sent.

### 2026-11-25 — Round 2 sent

P is GOAL. H1 and V are BELOW and are not reworded on these forms. [Results](../../evaluation/detection-generalization-results/15.md#round-2).

### 2026-11-25 — Round 3 designed

Offline only. Nothing of round 3 is sent.

### 2026-11-25 — Round 3 sent

BELOW: 52 of 256 true Confirmed lost, one false Protected. F withheld evidence XSS and other families need.
[Results](../../evaluation/detection-generalization-results/15.md#round-3-whole-applications).

### 2026-11-25 — Round 4 designed

Offline only. Nothing of round 4 is sent.

### 2026-11-25 — Round 4 sent

No section is safe to drop by the written rules; the stop condition applies. The design lacked a noise control.
[Results](../../evaluation/detection-generalization-results/15.md#round-4-one-section-removed-at-a-time).

### 2026-11-25 — Round 5 designed

Offline only. Nothing of round 5 is sent.
