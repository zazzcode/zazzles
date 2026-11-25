# Detection generalization 15 — judge certainty, an experiment

- **Series** [Contract](contract.md). **Asked for by the owner 2026-11-25**, after [14](14-sql-calls-redesign.md)
  stopped. The owner's direction to test other approaches is an exception to the one-redesign limit of
  [contract §5](contract.md#5-stop-procedure). **Experiment only: no product code, and no paid request without the
  owner's word.**
- **Goal** (owner) A vulnerability answer has certainty of at least **0.70**. **0.65** is the lowest acceptable. An
  approach that does not reach it is marked and left.
- **Constraint** (owner) Send the judge the right details, well under the 64 KB request limit.
- **Branch** `detgen-14-sql-calls-redesign`, in lane B.

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
real scanner records (the 14 overlay), so they hold only what a scan can extract. Half the drivers sit in a longer
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
`unknown_control_effect`; a callback gives `unsupported_callback`; `parseInt`, `BigInt` and `Map.get` give
`input_helper_unresolved`. 5 of the 12 drivers have the loop blockers, and 3 the callback blocker (one has both). Generalizing the package question is
not enough alone: the same focused approach has to be tried on those gaps. `look-winston` made no SQL record and
`safe-ternary` made none because no request data is in its text.

## Review change log

### 2026-11-25 — Written, round 1 sent

A2 is marked GOAL; A0, A1, A3 and A4 are BELOW. [Results](../../evaluation/detection-generalization-results/15.md).

### 2026-11-25 — Owner's goal restated

The aim is to generalize, so a new driver version, ORM or validation library needs no scanner change, or as little as
possible, with an easy way to improve. It may differ by language. Consequences for this series: an approach is judged
by how little it needs to know ahead. A focused question built from structural facts fits; a list of packages does not.

### 2026-11-25 — Round 2 designed

Offline only. Nothing of round 2 is sent.
