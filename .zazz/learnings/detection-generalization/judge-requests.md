# Judge requests

- **Contradicting text costs certainty.** A question that asks for package knowledge was answered by a request that said
  "answer from the supplied source alone". 14 removed the contradictions and calls were still `cannot_tell` on 4 of 8 drivers;
  the rest of the request still argued caution. Read a whole request, every sentence, before testing a question.
  [14](../../evaluation/detection-generalization-results/14.md)
- **A small focused request can be far more certain.** Same 18 forms, same model: 0 of 8 drivers at 0.70 with a 22 KB request and
  7 of 8 with 1.6 KB, with 92% fewer input tokens. Most of what was removed was our own instruction and tables. It answers a narrow
  question, not "is this vulnerable". [15](../../evaluation/detection-generalization-results/15.md)
- **Do not trim whole requests.** Dropping evidence by a list of kinds lost 52 of 256 true findings (arm F). Dropping only general
  text and tables (L2, 25% fewer bytes) lost two strong upload findings that a neutral control kept. Single-section arms are
  indistinguishable from noise. [15, rounds 3, 4 and 6](../../evaluation/detection-generalization-results/15.md)
- **Leave a fact out when it cannot be computed.** "Not established" made the judge doubt a true finding and lost it.
- **Asking the judge what it needs is not a fix.** The bounded follow-up exists (one per record, 25% cap). On the four README
  applications 60 records named one item and none was sent: 49 not sent, 11 unresolved.
- **Two sentences say escaping never protects.** The PHP guideline and the MySQLi contract do, and 12 of 20 known false findings are
  values escaped inside quotes. Correcting the two sentences cleared 2 of 14, below the bar. [Open leads](open-leads.md)
- **A fact the scanner has, the judge is not told.** For PHP, `numeric_conversion` is recorded and no note explains it; JavaScript has notes. Five safe PHP forms and `intval` were all `vulnerable` at 0.79 or more, with old and new text.
- **Facts and the text that explains them work together.** Facts alone cleared 1 of 14, text alone 2, both 5, with no true finding lost. Facts state only what the scanner's flow proves and are withheld when a later step could change the value.

## Certainty

- It is the probability the model returns for the answer a verdict rests on. It is not correctness: 11 of 14 false SQL findings
  are at or above 0.70.
- 90% of true Confirmed findings are at or above 0.65 and 83% at or above 0.70; 44 of 257 are below 0.70.
- **As a cut-off on today's requests it is a bad trade:** 0.65 would drop 25 true findings to remove 4 false.
- In focused questions 101 answers at 0.65 or above had none wrong, on forms the implementer wrote.

## Stability

Adding one neutral sentence changed the outcome of 6 of 54 weak true findings, and of 4 of 202 others. 75 of DVWA's XSS findings
share one cause and move together. Any change is judged against that noise.
