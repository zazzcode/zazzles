# Request wording, added facts and agreement

2026-11-26. What changing the text of a request does to the answers, and why asking twice does not fix it. Measured on Gemini
`gemini-decision-1` with a cached bench of the lab, NodeGoat, Juice Shop and nodejs-goof: 68 true records or routes, 80 safe.
[Results](../../evaluation/detection-generalization-results/19.md#iteration-loop-on-gemini-307-requests) own the tables.

## The findings

1. **A deterministic judge is still text-sensitive.** Gemini returned identical answers for 128 repeated requests, and about
   13% of lab routes changed outcome with every change of wording.
2. **A fact added to a request as text hits its target and moves unrelated answers**, on both models, even when the fact is
   proven. Three attempts, the same result.
3. **Confirming only when two wordings agree does not reach the 95% bar.** It costs about as many true findings as it
   removes false ones.
4. **The false positives that remain are stable.** The model gives the same wrong answer under every wording, so they are
   not a matter of uncertainty.

## Baseline and the four variants

Baseline, committed scanner: **62 of 68 found, none Protected, 5 of 80 safe Confirmed (92.5%)**. Each variant had its pass
rule written first. None was kept; the scanner is unchanged.

| Variant | Result | Kept |
|---|---|---|
| Mongoose and MarsDB records on the focused request | Juice Shop 6 of 7 found becomes 4 of 7; two nodejs-goof `findById` records fall from Protected to Review | No |
| Proven value facts in the request | Three controls become Protected; two safe records become Confirmed. False 5 becomes 6 | No |
| The scanner's paths and stopping tests in the request | Its two targets (`partner`, `entry`) are found; two other findings are lost; lab false 4 becomes 9 | No |
| A second wording of the question, Confirmed only when both agree | 58 of 68 found, 4 of 80 false (93.5%). Needed 95% and 59 found | No |

## What the borderline set looks like

Across four Gemini wordings of the lab request:

| Group | Count | Routes |
|---|---:|---|
| Vulnerable, Confirmed by all | 48 of 57 | |
| Vulnerable, change with the wording | 7 | `partner`, `entry`, `nickname`, `context`, `shift`, `cancel`, `teams` |
| Controls, Confirmed by none | 59 of 71 | |
| Controls, change with the wording | 10 | `item`, `budget`, `settings`, `options`, `clock-in`, `load`, `start`, `give-back`, `blend`, `export` |
| Controls, Confirmed by all | 2 | `articles/topic`, `people/finder` (disputable) |

One run's 93% is one draw from this set. The stable core is 48 found and 2 false. Report the core, not one run.

## Why agreement failed

The second wording asked for the strongest thing a request can do on the least limited path, dropped the Yes and No prefixes
of the choices and listed the safe choices first. The evidence was byte-identical.

| Whole bench | Found | Safe Confirmed | Share |
|---|---:|---:|---:|
| Committed wording | 62 of 68 | 5 of 80 | 92.5% |
| Second wording | 59 of 68 | 6 of 80 | 90.8% |
| Both agree | 58 of 68 | 4 of 80 | 93.5% |

- It lost four true findings: `members/nickname`, `desk/pass`, `loans/cancel`, NodeGoat `/signup`.
- It removed one false positive net. `articles/topic`, `people/finder`, `desk/load` and NodeGoat `/profile` are Confirmed
  under both wordings.
- It doubles the requests of these records.

## What to do with this

- Do not add facts, paths or notes to a request to fix one route. Measure the whole set, both sides, every time.
- A fact helped once: where it replaced a sentence that contradicted it ([judge requests](judge-requests.md)).
- A library with its own contract and facts does not gain from a generic request. Generalize the record and the
  query-language notes; keep the evidence a specific contract computes.
- Do not spend requests on voting or agreement for these records.
- What is left for the stable false positives is not text: a policy that checks an answer against a fact the scanner proved
  (the series contract forbids it today, an owner decision), or a second reading of whether those four routes are safe.

## Not measured

Agreement on gpt-6-luna. Agreement of two models through the scanner (from saved answers: where both confirm, 5 controls
remain). A renamed copy of the lab.
