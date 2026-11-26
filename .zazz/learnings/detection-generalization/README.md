# Learnings: generalizing how findings are identified

Topic `detection-generalization` of the [learnings](../README.md).

What this initiative has learned about finding vulnerabilities without a hand-written analyzer for every ORM, driver,
validator and version. These are learnings, not specifications: nothing here approves work. Each statement links its
evidence, and says when the evidence is weak.

**The aim (owner, 2026-11-25).** A new driver version, ORM or validation library should need no scanner change, or as
little as possible, and improving should be easy. Other scanners have rule packs; Code Scan has the decision model as the
judge. It may differ by language.

## Where things stand: what was accepted (2026-11-26)

The verdict on every strategy tried for native MongoDB driver detection
([specification 19](../../specifications/detection-generalization/19-database-package-operations.md),
[PR #54](https://github.com/zazzcode/zazzles/pull/54)). Read this first.

| Strategy | Accept | Why | Detail |
|---|---|---|---|
| Recording by package origin: follow the call's receiver back to the package import | **Yes** | 0 to 57 of 57 vulnerable lab routes recorded; held on NodeGoat; no record changed in nine other samples | [Database package operations](database-package-operations.md#recording-what-worked) |
| Entry connectors: an Express app passed to a module, method handlers, Next.js wrappers | **Yes** | NodeGoat went from 1 entry to 20. This helps every family | [Database package operations](database-package-operations.md#recording-what-did-not-work-or-cost-more-than-expected) |
| A request built for the one question, with the reworded question (protocol v2) | **Yes** | The best judged result on both models against what existed before: 16 Confirmed to 46 on gpt-6-luna, 52 on Gemini | [Database package operations](database-package-operations.md#strategies-what-works-what-shows-promise-what-does-not) |
| Scanner reading limits shown to the model; such a record is never Protected | **Yes** | No true finding was marked Protected in any scanner run | [Database package operations](database-package-operations.md#recording-what-worked) |
| Proven value facts, flow facts, paths or stopping tests added to the request | **No** | Each fixed its target and changed unrelated answers, on both models | [Request wording and agreement](request-wording-and-agreement.md) |
| Mongoose and MarsDB records moved to the generic request | **No** | Juice Shop 6 of 7 found became 4 of 7. Keep the evidence an existing contract computes | [Request wording and agreement](request-wording-and-agreement.md) |
| Confirm only when two wordings agree | **No** | 93.5% against 92.5%, four true findings lost, twice the requests | [Request wording and agreement](request-wording-and-agreement.md#why-agreement-failed) |
| More questions, a confidence cut-off, a list of driver forms | **No** | Each was worse or found nothing on code it was not written against | [Database package operations](database-package-operations.md#strategies-what-works-what-shows-promise-what-does-not) |

**Where the accuracy is.** Gemini `gemini-decision-1`: 52 of 57 vulnerable lab routes Confirmed, 4 of 71 controls (93%).
gpt-6-luna, the standing judge, as the scanner sends it: 46 of 57 and 15 of 71 (75%). The series bar is 95%; for Gemini on
a lab of near twins that is a difference of one route, for gpt-6-luna it is not close.

**The standing judge is safe and noisier** (measured 2026-11-26, 128 requests). On gpt-6-luna no vulnerable route is
Protected, so the earlier concern about a wrong clear at 0.98 is closed. About one Confirmed in four is a safe control there.
The 93% holds only for a scan judged by Gemini. See [judge model comparison](judge-model-comparison.md).

**What is left**, in order, is in [open leads](open-leads.md#native-mongodb-driver-what-is-left).

## Index

When a finding gets its own page is stated in the [learnings root](../README.md#how-to-add-to-this).

| Page | Read it for |
|---|---|
| This page | The verdicts above, the working rules for any judge request, naming and boundaries |
| [Judge requests](judge-requests.md) | What to send, what not to trim, certainty and stability |
| [Package and library knowledge](package-knowledge.md) | Drivers, ORMs, versions, validators, NoSQL: what generalizes and what is specific |
| [Experiment method](experiment-method.md) | How to test a change so that the result can be believed, and the mistakes made |
| [Open leads](open-leads.md) | What could become a change, in order, and what a pull request needs |
| [Judge model comparison](judge-model-comparison.md) | Gemini and gpt-6-luna on identical requests: what differs, what makes the comparison fair, what is not measured (2026-11-26) |
| [Request wording and agreement](request-wording-and-agreement.md) | Why text changes reshuffle answers, why added facts and two-wording agreement were not kept (2026-11-26) |
| [SQL driver independence](sql-driver-independence.md) | Which SQL drivers each language recognizes today; package origin and SQL-text recognition against the contract records; a driver-free judge request against the contract request on Gemini (2026-11-26) |
| [Database package operations](database-package-operations.md) | Recording MongoDB operations by package origin; the judge-request experiments in order; strategies that work, show promise, or do not (2026-11-25) |

## The working rules: what to send the judge, and what to ask

Use this section when designing any request. It is the summary of every experiment in these pages. The owner's reading
(2026-11-25): generalized identification is mostly a matter of sending correctly crafted information and asking the correct
question. The measurements agree: request and question took MongoDB detection from 0 of 57 to 52 of 57 with 4 false positives.
One addition: on identical evidence the model still moved precision from 73% to 88%, so compare models once the request is right
([judge model comparison](judge-model-comparison.md)).

**The division of work**

1. The scanner finds the operation and the request value by structure, and states the binding as a fact. The judge says what the
   operation does and whether the value is controlled. Never ask the judge whether it knows a package.
2. Knowledge is stated once per query language (SQL text, MongoDB documents), not per driver, method or client form.
3. A fact or a rule records; it never gives, removes or suppresses a verdict. Protected needs evidence the scanner read.

**Information: sufficient**

4. Send everything the answer depends on: the handler, every function the value passes through, and the definitions of the
   constants and functions they use. In one run 19 of 128 requests lacked a definition the handler used.
5. Send how the receiver is defined, from the package import to the call, as source. That is what makes "which library is this" a
   reading task.
6. Say what a request value can be when it is read (a JSON body holds any value; a Next.js query value is a string). That is
   connector knowledge, and the judge does not reliably have it.

**Information: correct**

7. Nothing in the request may contradict the question. General text that argues caution, or that says a sanitizer never
   protects, costs certainty and causes false findings.
8. Leave out what cannot be computed. A statement of "unknown" or "not established" makes the judge doubt a true finding, and
   coverage questions get answered `no` with nothing wrong.
9. Facts read from the flow's conclusions were unsound repeatedly. A fact must come from a narrow source pattern that fails closed.
9a. A fact added to a request as text hits its target and moves other answers too, on both models, even when the fact is
    proven. It worked once, where the fact replaced a sentence that contradicted it. Otherwise keep proven facts out of the
    request.
9b. A library with its own contract and facts (Mongoose, MarsDB) does not gain from being moved to a generic request. Use the
    generic request where there is no contract.
10. A scanner limit is not a limit of a reader. Do not withhold a record because the scanner could not follow `JSON.parse`; show
    the code, and bar only the Protected outcome.

**Information: small**

11. One purpose per request. A request built for one question took the same model from 16 confirmed to 47 with a quarter of the
    tokens; 22 KB to 1.6 KB took driver recognition from 0 of 8 to 7 of 8.
12. Do not trim a general request by section or by evidence kind; build the focused one. Trimming lost true findings.

**The question**

13. One closed verdict question. Splitting it into parts (shape, position, limits) made every part and the verdict worse.
14. Ask the thing you mean. "What can the request control" was answered "the name" for a request that picks one of two listed
    names, which is literally true. "Is there an input that changes the operation beyond what the code lists" cleared that whole
    class. Read a wrong answer as a possibly correct answer to a badly put question first.
15. Put the negative conditions in the choice that carries them, and make the safe outcomes first-class choices. A condition
    buried at the end of a "yes" description is not applied.
16. A wording change moves the operating point, and differently per model. Measure both sides every time, on the model that
    will be used: the rewording of rule 14 cost gpt-6-luna five findings and cost Gemini none while finding two more.

**Measuring**

17. Write the pass rule before the first request. Resend only requests whose text changed; replay the rest.
18. A judge can be deterministic and still text-sensitive. Gemini returned identical answers for 128 repeated requests, and
    about 13% of the routes changed outcome with every change of wording. Count the routes every variant agrees on, not one
    run's score. On gpt-6-luna about 6 of 128 weak answers move with any neutral change.
18a. Confirming only when two wordings agree does not reach the bar: 93.5% against 92.5% for one wording, four true findings
    lost, twice the requests. The false positives that remain are the same under every wording
    ([request wording and agreement](request-wording-and-agreement.md)).
19. Certainty is not correctness: wrong answers reach 0.98. No cut-off separates true from false.
20. Test on forms someone else wrote, and on an application nobody tuned for. Forms the implementer writes pass.
21. Compare models on identical bytes before concluding that a request is the limit, or that it is not. Read the wire
    request of each adapter: one sent the answer choices alphabetically, the other in written order. Made identical, the
    models still differed by nine findings and six false positives.

**Open** (what these rules do not yet settle): a wording that keeps rule 14's gain on gpt-6-luna too; whether proven
value facts help a stronger reader; the same method for SQL drivers without a contract.

## Boundary (owner, 2026-11-25)

Each inbound and outbound connector (HTTP, gRPC, GraphQL, message queues and others) keeps specific support. It finds where
data enters or leaves and records one common fact. What an operation *does* with its argument is the part to generalize.
Query languages need their own content.

## Naming rule: always name the NoSQL database

"NoSQL" is never enough. Name the database and the path to it. What the code supports today, from
[`nosql.go`](../../../scan/internal/analysispacks/nosql.go):

| Write | Meaning |
|---|---|
| MongoDB, through Mongoose | Selectors of a Mongoose model. Cast details are stated for Mongoose 4.2.4 |
| MongoDB, native `mongodb` driver | Recorded by package origin and judged by query language in the `generalized-nosql-detection` work; see [database package operations](database-package-operations.md). Not merged |
| MarsDB | MarsDB collections. They match selectors in the MongoDB style, and are **not** MongoDB |
| Not supported | Every other NoSQL database, and Python NoSQL |

Prisma filter objects sit in the same analyzer family but compile to SQL. Call them Prisma filters.

**Next databases (owner, 2026-11-25):** Amazon DocumentDB, Amazon DynamoDB and Elasticsearch. See [package
knowledge](package-knowledge.md#nosql-databases). Name each in full; "AWS NoSQL" is not a name.

## Where these pages come from

The first four pages were written on branch `detgen-14-sql-calls-redesign` (local, never pushed) and were copied on
2026-11-25 to `.zazz/project/learnings/`, which moved here on 2026-11-26, so the learnings are in one place. Their links to
specifications 14, 15 and 16 and to results 14 and 15 point at files that exist only on that branch; read them with `git show detgen-14-sql-calls-redesign:<path>`.

## Sources

[Specification 15](../../specifications/detection-generalization/15-judge-certainty.md) and its
[results](../../evaluation/detection-generalization-results/15.md); [specification
14](../../specifications/detection-generalization/14-sql-calls-redesign.md) and
[results](../../evaluation/detection-generalization-results/14.md); [specification
16](../../specifications/detection-generalization/16-package-question.md), draft.
