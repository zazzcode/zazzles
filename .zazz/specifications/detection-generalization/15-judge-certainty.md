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

**Round 2**, only for an arm marked FLOOR or GOAL: new forms with other drivers, other made-up names and other safe
constructions, two repeats, exact count asked separately.

**Not tested here.** Package facts (a type declaration or documented signature) sent as evidence. They are the strongest
"right details" candidate, but the sample repositories do not hold `node_modules` and getting them needs a download.

## Review change log

### 2026-11-25 — Written

Nothing is sent.
