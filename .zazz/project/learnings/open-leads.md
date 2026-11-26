# Open leads and the path to a pull request

Ordered by expected value for accuracy. A lead is not a plan; each needs the owner's word before a paid run.

| # | Lead | Why | What decides it |
|---:|---|---|---|
| 1 | Fact codes for PHP, as JavaScript has. **Tested: 5 of 14 false SQL findings cleared, 0 of 25 true lost, 0 Protected; below the bar set beforehand** | Conversions and escapes are recorded and unexplained; PHP text says casts do not protect. The escaping text alone cleared 2 of 14 (**BELOW**) | New PHP forms first, then the 56 judged records as a check: no true finding lost or Protected, most of the false cleared |
| 2 | Package question (spec 16) | Removes per-driver work | A count of such calls in real applications (none in nine samples), then its 44-request probe |
| 3 | ORM builders and identifiers | Same question, one more answer | A probe with builders and lookalikes |
| 4 | Query languages for MongoDB, MarsDB, then Amazon DocumentDB, Amazon DynamoDB and Elasticsearch | Document, expression and script semantics differ by database; the owner asked for the last three next | A probe across drivers, by query language |
| 5 | Validation libraries with computed facts | 14 of 15 right, under the bar | New forms with the facts the scanner holds |
| 6 | Reporting certainty | 44 of 257 true findings rest on a weak answer | Additive report field; verdicts unchanged |

**A pull request is possible when** a change is on its own branch from `stage`, and:

1. Its replay gate passes: no true finding lost, none Protected that was not, false findings not up, per family.
2. Every request of another family or language is byte-identical.
3. Its gates G1 to G7 pass on the nine samples and, by script, on the reserved control.
4. Held-out evidence exists where the series contract requires it, or the owner accepts its absence in writing.
5. It reverts alone.
6. **Its design is written in `.zazz/architecture/`, with the tested benefit** (owner, 2026-11-25): what changed, why, the measured result per family and the limits, in the document that owns the topic. Write it with the change that passes, not before.

Today **nothing meets this in full**. Lead 1 is the closest: no regressions measured, and it needs the owner's decision on the bar, then a Go change, its text, the gates and held-out PHP. The rest need new evidence first.
