# Learnings: database package operations

2026-11-25 and 2026-11-26, branch `generalized-nosql-detection`. The verdict on each strategy is in the [index](README.md#where-things-stand-what-was-accepted-2026-11-26). [Specification](../../specifications/scan/detection-generalization/19-database-package-operations.md) ·
[Results](../../evaluation/detection-generalization-results/19.md). Models: openai gpt-6-luna unless Gemini is named; one answer per request.
All numbers are from the `vuln-nextjs` lab at `aeae20a` (57 vulnerable routes, 71 controls) unless NodeGoat is named. The lab has been
read by the sessions that built on it, so nothing here is held-out evidence except the NodeGoat lines that say so.

## Recording: what worked

| Idea | Result | Why it worked |
|---|---|---|
| **Follow definitions backwards from the receiver to the package import**, as a may-path | 0 to 57 of 57 vulnerable routes recorded; 66 of 71 controls | It needs no list of driver methods or client forms. `??=`, a global promise, an async function called in place, `.bind`, destructuring, a class field and a callback parameter are all "a name is defined as an expression" |
| One table entry per package: package to query language | `mongodb` is the only driver-specific line | The scanner states the binding; the judge names no package |
| Record any call on a derived value that receives request data | `count`, `db.command({ mapReduce })`, `db.collection(name)` recorded with no method name | The judge answers what the call is (`operation`); all 135 judged calls were answered, none `cannot_tell` |
| A wrapper rule on structure: the helper passes its own parameter, used once, to a verified forwarding wrapper | 62 of 62 lab route helpers resolved | No helper name; a helper that calls the handler twice is refused |
| Side walks on a copy of the flow, keeping only these records | Class methods, loop iterables, renamed properties and closure arguments reached | Every other family stays byte-identical: 0 records missing, added or changed in nine samples |
| Leave the scanner's own reading limits to the judge for these records, and never answer Protected on them | 31 records that were held (`JSON.parse lacks a definition`, `Object.hasOwn`, a callback) became judgeable | A limit of the scanner is not a limit of a reader. Protected still needs what the scanner read |
| Test on forms another session wrote | 51 of 52 binding forms and look-alikes behaved as designed at the first run; the one miss (`import x = require()`) was a real gap | Forms the implementer writes pass trivially |

## Recording: what did not work, or cost more than expected

- **A list of forms, however long** (specification 18, 683 lines): 0 of 30 on the second lab batch. Each layer hid the next.
- **Improving the flow itself for everyone.** Binding a renamed destructured property in the main flow was correct and changed three
  Juice Shop requests and one XSS test. It is confined to these records. A general flow fix needs its own evidence per family.
- **A new record on an entry changes the identifiers of that entry's other records**, because the invocation key includes the
  controls a query record adds. Saved answers of other families on such an entry no longer match. It is existing behaviour.
- **A join kept one alternative's fields.** `cond ? JSON.parse(x) : { team: 'floor' }` then `.team` lost the request value. Fixed for a
  conditional value and a conditional statement. This is the unsoundness PR 52 names: a join keeps one branch's text.
- **Entries are the first layer everywhere.** NodeGoat (held out): 1 entry and 0 records on `stage` and on this work, before any
  database question. Routes on an app passed to another module, and handlers that are methods of constructed objects, needed
  connector rules. After them: 20 entries, 7 NoSQL records, and records of other families (three `eval` calls) that were never seen.

## Judging: what the experiments showed

| Run | Request | Vulnerable routes called vulnerable (of 57) | Vulnerable routes cleared | Controls flagged (of 66 recorded) |
|---|---|---:|---:|---:|
| Paid check 1 | Existing NoSQL protocol: 30 KB, eight questions | 42 raw; **16 Confirmed** after policy | 3 raw; **2 Protected** | 23 raw; 9 Confirmed |
| Probe 1 | Focused: 7 KB, two questions (what is the call; what does the request control) | **51** | 6 | 14 |
| Probe 2 | Probe 1 plus three part questions (shape, position, limits) | 48 by the verdict question; 36 from the parts | 9; 20 | 15; 3 |
| Probe 3 | Probe 1 plus the scanner's paths and path conditions | 48 | 9 | 16 |
| Paid check 2 | Probe 1 built into the scanner | **47 Confirmed**, 10 Review | **0 Protected** | 18 Confirmed, 10 Protected, 38 Review |
| Paid check 3 | NodeGoat, same protocol, held out for the judge | 4 Confirmed: 3 true, 1 false | 0 | 3 Review |
| Paid check 4 | Check 2 plus four scanner-proven value facts, on the 15 records that have one | Reverted: see below | | 3 of 8 flagged controls cleared, 2 safe records newly Confirmed |
| Paid check 6 | Check 2 plus the module-level definitions the handler uses, on the 39 records that lacked one | 46 Confirmed, 11 Review | 0 Protected | 17 Confirmed: four routes moved, two each way |
| Probe 4 | Check 6's source; the question reworded as "is there an input that changes the operation beyond what the code lists" | 46 | **11** | **11** |
| Paid check 5 | Check 6's request, unchanged, on **Gemini gemini-decision-1** | **50 Confirmed**, 7 Review | **0 Protected** | **7 Confirmed**, 9 Protected, 50 Review |
| Paid check 7 | Probe 4's question on Gemini; **built in as protocol v2** | **52 Confirmed**, 5 Review | **0 Protected** | **4 Confirmed**, 11 Protected, 51 Review |
| Paid check 8 | NodeGoat with protocol v2, both judges (3 true records, 4 safe) | Gemini 3 of 3 Confirmed; gpt-6-luna 2 of 3 | 0 Protected | 1 of 4 safe Confirmed on each, a different record |
| Paid check 10 | Protocol v2 on gpt-6-luna through the committed scanner, in the OpenAI adapter's own choice order | 46 Confirmed, 11 Review | 0 Protected | 15 Confirmed, 6 Protected, 45 Review |
| Paid check 9 | Protocol v2 on gpt-6-luna with the answer choices in the order Gemini receives them: the same bytes for both models | 43 Confirmed, 14 Review | 0 Protected | 10 Confirmed |

- **A small request with the query language next to the question is far better than the general one.** Same records, same model:
  16 Confirmed to 47, with a quarter of the input (870,000 tokens to 223,000). No answer was `cannot_tell`.
- **The general protocol failed for reasons that were not reasoning.** About 50 records had an empty `input_source` role because the
  automatic check's field names do not match `req.body?.id`, a whole body or a header; `guard_coverage` was answered `no` on 27
  records, 15 of them with no limit shown; most answers were under 0.55.
- **More questions made it worse.** The `limits` part was answered "limited" on whole request filters. A verdict derived from parts
  cleared 20 vulnerable routes. Ask one verdict question.
- **Sending the scanner's flow facts did not help this judge.** Paths and path conditions fixed two wrong clears and broke five others.
  The difference between probes 1 and 3 is noise. They are not sent.
- **The remaining errors are reasoning on near twins, with the evidence present.** Missed: a type check with no return, a check of
  another field, a string in `$expr` or an update pipeline, a `catch` that keeps the raw value, an unsigned token. Flagged: `Number`
  into `$where`, `JSON.stringify` as one literal, a schema that drops unknown keys, a helper that removes `$` keys at every depth, a
  constant map, a flat query.
- **Proven facts about a value did not move this judge reliably either** (paid check 4, reverted). Four syntax-only rules on
  `const` declarations (a native number conversion; a membership test of a fixed list with a fixed fallback; a negated
  character-class filter; a closed Zod schema of primitives) gave a fact to 13 lab records, all controls, and to no vulnerable
  route. Of the 8 that were flagged, 3 left Confirmed (`clock-in`, `loads`, `options`) and 5 did not: `Number()` into `$where`
  was still called expression text at 0.29 for data_only with the fact beside it. Two safe records with a fact became
  Confirmed that were not (`stats/amount`; NodeGoat `/contributions`), and one Protected control fell to Review. Net: 18 flagged
  controls to 16 on the lab, 1 to 2 on NodeGoat. That is the size of the noise. The rules were sound and tested against
  near forms; the reader of the facts is the limit. The code is kept outside the repository in
  `_test-findings/vuln-nextjs/gnd-paid-4/reverted/`.
- **The data_only answer is not safe to trust at any confidence seen.** Wrong clears ran from 0.60 to 0.90. The policy asks 0.95 and no
  reading limit; it gave 0 Protected vulnerable routes and 10 Protected controls. The floor was chosen after seeing the answers.
- **About 6 of 128 weak answers move with any wording change.** Voting over three wordings gave 49 found, 0 cleared and 18 controls
  flagged: no better on false positives.
- **One control is disputable.** `findOne(req.query)` in a Next.js route is keyed safe because the query is flat; `?$where=…` is still a
  top-level operator key. The judge flags it at 0.99.

## Strategies: what works, what shows promise, what does not

The owner's position (2026-11-25): the model is not the issue; the issue is whether sufficient and correct information and
the right question reach the judge. The evidence supports the second half strongly and contradicts the first half.

**Works** (measured, kept)

| Strategy | Evidence |
|---|---|
| A request built for one question: query-language notes, the call, the receiver path, request values, source; two closed questions | 16 Confirmed to 47 on the same records and model, a quarter of the tokens. Agrees with [judge requests](judge-requests.md): a small focused request is far more certain |
| The query language stated once, next to the question, and an entry note for what a request value can be | No `cannot_tell` in 900 answers; `req.query` in Next.js stopped being read as nested |
| The binding as a scanner fact (the receiver path), never "do you know this package" | `operation` answered `database_query` on every true database call. Agrees with [package knowledge](package-knowledge.md) |
| Leave out what cannot be computed; never send "unknown" | The general protocol's coverage questions were answered `no` on 27 records with nothing wrong |
| A conservative Protected: a strong answer and no reading limit | 0 vulnerable routes Protected in every scanner run, on both models |
| Per-record text only; resend only requests whose text changed | 89 to 115 of 128 answers reused per experiment. Agrees with [experiment method](experiment-method.md) |
| **A second judge model on the same request** | Gemini: 50 of 57 Confirmed and 7 controls Confirmed (88% of Confirmed are vulnerable) against 46 and 17 (73%) for gpt-6-luna. Same bytes of evidence. The two agree on 106 of 128 routes |
| **Ask whether an attack input exists beyond what the code lists**, not what the request "controls" | On Gemini: 50 to 52 vulnerable Confirmed and 7 to 4 controls Confirmed, none Protected (93% of Confirmed are vulnerable). Built in as protocol v2. On gpt-6-luna the same wording cut flagged controls 17 to 11 but cleared five more vulnerable routes, one at 0.98: a wording is measured per model |

**Shows promise** (one measurement, not adopted yet)

| Strategy | Evidence | What it needs |
|---|---|---|
| Complete source: the definitions of constants and functions the handler uses | 19 of 128 requests lacked one. Sending them was net zero on gpt-6-luna (two better, two worse) | Kept because judging code that is not shown is wrong in principle. Re-measure on Gemini |
| Use both models and treat disagreement as Review | They disagree on 22 routes; where both confirm, 5 controls remain | An owner decision: two providers per record doubles cost |
| Route entries and class methods for every family, not only these records | NodeGoat went from 1 entry to 20 and showed three `eval` calls no family had seen | Its own specification and evidence per family |

**Is it what is sent, or the model?** Both. With the answer choices in the same order the two models still differ by nine
findings and six false positives. See [judge model comparison](judge-model-comparison.md).

**Does not work** (measured, dropped)

| Strategy | Evidence |
|---|---|
| The general NoSQL protocol for these records | 16 of 57 Confirmed, 2 vulnerable routes Protected |
| More questions: shape, position, limits, then a verdict | The verdict got worse; a verdict derived from the parts cleared 20 vulnerable routes |
| Flow facts in the request: paths and path conditions | Two fixed, five broken: noise |
| Proven value facts in the request (number, fixed alternative, filter, closed schema) | 3 of 8 cleared, 2 safe records newly Confirmed: noise. Contrast [judge requests](judge-requests.md), where PHP facts with replaced text cleared 5 of 14: there the fact replaced a sentence that contradicted it |
| A confidence cut-off for findings | No threshold separates the two groups; wrong clears reach 0.98 |
| Voting over wordings on one model | 49 found, 18 controls flagged: no gain |
| A list of driver forms | 0 of 30 on code it was not written against |

**Reading of the owner's hypothesis.** It holds. Information and question took one model from 16 confirmed to 47, and one
more change to the question took the other from 88% to 93% with more found. The model is the second lever: on identical
evidence it moved precision from 73% to 88%, and it decides whether a better question helps or hurts (the same rewording
cost gpt-6-luna five findings and cost Gemini none). The way to work is to fix the request and question first, then compare
models on identical bytes.

## The iteration loop and the agreement check

Four further variants were tested on Gemini and none was kept. The tables and the reading are in
[request wording and agreement](request-wording-and-agreement.md). In short: Gemini repeats its answers exactly, about 13% of
lab routes change with any wording, added facts disturb unrelated answers, and agreement of two wordings gives 93.5%.

## How firm each finding is

Only the lab requests on Gemini were sent twice, and every lab number comes from an application read during development. Read the
findings by how many independent measurements stand behind them.

| Firm: seen in several runs, on both models or on two applications | Evidence |
|---|---|
| Recording by package origin reaches code a list of forms does not | Lab 0 to 57 of 57; NodeGoat 0 to 7; 52 forms another session wrote |
| A request built for the one question beats the general request | 16 to 46 or more Confirmed in every later run |
| Gemini judges these records better than gpt-6-luna | Lab on protocol v1 (50 and 7 against 46 and 17), lab on identical bytes (52 and 4 against 43 and 10), NodeGoat (3 of 3 against 2 of 3) |
| No vulnerable route is Protected under the conservative rule | Every scanner run: five on the lab, three on NodeGoat |
| More questions, flow facts and value facts do not help gpt-6-luna | One run each, all inside the noise of about six routes |

| Single measurement: a direction, not a number to rely on | What would make it firm |
|---|---|
| The reworded question helps Gemini (88% to 93%) | It is repeatable, and it is one draw of the borderline set: four variants range from 85% to 93% |
| Choice order moves gpt-6-luna by about three routes | That is the size of the noise; a repeat |
| The 93% itself | It moves by two points per route. A lab not read during development |
| The 0.95 floor for Protected | It was set after seeing answers; on gpt-6-luna one wrong answer reached 0.98 |
| Complete source is worth sending | Net zero on gpt-6-luna; not measured on Gemini |

Since measured: Gemini answers the same request identically (128 of 128); Mongoose and MarsDB records do better on their
own contracts than on the focused request.

## What this means for the next step

1. Recording by package origin generalizes: it held on forms it was not written against and on NodeGoat's different shapes.
2. The best measured configuration is protocol v2 on Gemini: 52 of 57 vulnerable lab routes Confirmed, none Protected, 4
   controls Confirmed: 93% of Confirmed routes are vulnerable, against a bar of 95%. The lab is built from near twins, so
   ordinary code should be better; not measured.
3. What is left. Controls still Confirmed: `topic` (a complete literal in `$where`), `load` (a reviver that drops `$` keys),
   `export` (a character filter) and `finder` (disputable). Vulnerable routes in Review: `partner` (a check with no return),
   `portal`, `terminal` (a string in `$expr`), `entry` (a `catch` that keeps the raw value), `teams`.
4. Since tested and not kept: value facts on Gemini, paths and stopping tests, Mongoose and MarsDB on the focused request,
   agreement of two wordings. Not run: protocol v2 through the scanner on gpt-6-luna in the written choice order.
   The false positive that both models still make is one form: an update or `$set` whose written keys the code fixes, answered
   `written_fields`. That choice needs the same treatment rule 14 gave `name`: say what is not an input.
5. A second database is one table entry, one query-language note and one set of answer choices.

## What is not shown

No held-out MongoDB application with a key written before scanning. NodeGoat has only three true NoSQL records. NodeGoat's seven records were labelled by the implementing
session after the run. One repeat, on Gemini only. Python and PHP are not covered. Mongoose and MarsDB keep their
contracts and the general protocol.
