# Judge model comparison: Gemini and gpt-6-luna

2026-11-26. What was measured when the same requests were judged by OpenAI `gpt-6-luna` and Gemini `gemini-decision-1`.
[Results](../../evaluation/detection-generalization-results/19.md) own the tables; this page owns the reading.
Applies to native MongoDB driver records only unless a line says otherwise.

## The finding

**On the native-driver lab Gemini was more accurate than gpt-6-luna on identical requests.** This is not shown for other
applications or other families. OpenAI `gpt-6-luna` remains the project's standing judge until the owner decides otherwise.

| Same requests | gpt-6-luna | Gemini |
|---|---|---|
| Lab, protocol v1: found of 57, false of 71 | 46, 17 (73%) | 50, 7 (88%) |
| Lab, protocol v2, each adapter's own choice order: found of 57, false of 71 | 46, 15 (75%) | 52, 4 (93%) |
| Lab, protocol v2, choices in Gemini's order | 43, 10 (81%) | 52, 4 (93%) |
| NodeGoat, protocol v2: true found of 3, safe Confirmed of 4 | 2, 1 | 3, 1 |
| Vulnerable route marked Protected, any scanner run | 0 | 0 |

The percentage is the share of Confirmed routes that are vulnerable.

## Juice Shop, all families (2026-11-27)

On one full Juice Shop scan each, with identical evidence, Gemini found 36 of 41 keyed positives and `gpt-6-luna` 41 ([run record](../../evaluation/gemini-sample-runs-20261127.md#juice-shop-model-or-scanner)). A `gpt-6-luna` rerun on the same scanner reproduced the published report byte for byte, so the gap is the model. Four of the five rows are mass-assignment writes of an owner foreign key (`UserId`) that the request carries only as a name hint; `gpt-6-luna` called them privileged at 0.07 to 0.64, Gemini not sensitive at 0.52 to 0.74. Where the evidence leaves a question open, the two models fall on different sides of it; adding the source fact is the fix, not choosing the model.

## What makes the comparison fair, and what does not

| Point | Detail |
|---|---|
| Same bytes | Evidence and questions were identical. The adapters ordered the answer choices differently; with the order made the same the gap stayed: nine findings and six false positives |
| Protocol v1 was written against gpt-6-luna | Gemini was still better on it, so the v1 gap is not wording fit |
| Protocol v2 was tuned against Gemini | Part of the v2 gap may be wording fit. The same rewording cost gpt-6-luna five findings and cost Gemini none |
| One lab | 128 near-twin routes, read during development. On NodeGoat the two were about equal, each with one different false positive |
| One family | No other family has been judged by Gemini. Mongoose and MarsDB on their own contracts: 7 of 8 found and no false positive on Gemini |

## Other differences that matter for the work

- **Gemini repeats itself.** 128 lab requests sent twice gave 128 identical answers and probabilities. A difference between two
  variants on Gemini is an effect of the text. On gpt-6-luna about 6 of 128 weak answers move with any neutral change.
- **Both are text-sensitive.** See [request wording and agreement](request-wording-and-agreement.md).
- **Both make the same kind of false positive**: an update whose written keys the code fixes, answered `written_fields`.
- **Wrong answers are certain on both.** In a direct probe gpt-6-luna answered one vulnerable route `data_only` at 0.98.
  Through the scanner, in the adapter's own choice order, no vulnerable route was Protected.
- **Where both models confirm, the result is Gemini's.** The two give the same outcome on 100 of 128 lab routes. Both confirm
  45 vulnerable routes and 4 controls, and those four are exactly Gemini's four false positives. Using both adds nothing to
  using Gemini.
- **Choice order matters on gpt-6-luna.** Sorted, 43 found and 10 false; in written order, 46 and 15.

## How to use this

1. Fix the request and the question first. Both models moved more from that than from the swap: one model went from 16
   Confirmed to 47 on a request built for the question.
2. Then compare models on identical bytes, reading the wire request of each adapter.
3. Measure a wording on the model that will run it. A wording is not portable.
4. A scan uses one judge. Changing the project's judge needs every family measured on the new one, not this family alone.

## Not measured

- Any family other than NoSQL on Gemini. One judged Juice Shop scan on Gemini, compared with the saved gpt-6-luna answers,
  would show it.
- Cost and speed side by side. The owner states the cost is equivalent (2026-11-26).
- A third model.
