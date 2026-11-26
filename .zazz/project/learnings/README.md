# Learnings: generalizing how findings are identified

What this initiative has learned about finding vulnerabilities without a hand-written analyzer for every ORM, driver,
validator and version. These are learnings, not specifications: nothing here approves work. Each statement links its
evidence, and says when the evidence is weak.

**The aim (owner, 2026-11-25).** A new driver version, ORM or validation library should need no scanner change, or as
little as possible, and improving should be easy. Other scanners have rule packs; Code Scan has the decision model as the
judge. It may differ by language.

## The working rules: what to send the judge, and what to ask

Use this section when designing any request. It is the summary of every experiment in these pages. The owner's reading
(2026-11-25): generalized identification is mostly a matter of sending correctly crafted information and asking the correct
question. The measurements agree: request and question took MongoDB detection from 0 of 57 to 52 of 57 with 4 false positives.
One addition: on identical evidence the model still moved precision from 73% to 88%, so compare models once the request is right.

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
18. About 6 of 128 weak answers move with any neutral change. A difference of that size is noise.
19. Certainty is not correctness: wrong answers reach 0.98. No cut-off separates true from false.
20. Test on forms someone else wrote, and on an application nobody tuned for. Forms the implementer writes pass.
21. Compare models on identical bytes before concluding that a request is the limit, or that it is not.

**Open** (what these rules do not yet settle): a wording that keeps rule 14's gain on gpt-6-luna too; whether proven
value facts help a stronger reader; the same method for SQL drivers without a contract.

## Index

| Page | Read it for |
|---|---|
| [Judge requests](judge-requests.md) | What to send, what not to trim, certainty and stability |
| [Package and library knowledge](package-knowledge.md) | Drivers, ORMs, versions, validators, NoSQL: what generalizes and what is specific |
| [Experiment method](experiment-method.md) | How to test a change so that the result can be believed, and the mistakes made |
| [Open leads](open-leads.md) | What could become a change, in order, and what a pull request needs |
| [Database package operations](database-package-operations.md) | Recording MongoDB operations by package origin; nine judge-request experiments; strategies that work, show promise, or do not (2026-11-25) |

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

The first four pages were written on branch `detgen-14-sql-calls-redesign` (local, never pushed) and were copied here on
2026-11-25 so the learnings are in one place. Their links to specifications 14, 15 and 16 and to results 14 and 15 point at
files that exist only on that branch; read them with `git show detgen-14-sql-calls-redesign:<path>`.

## Sources

[Specification 15](../../specifications/detection-generalization/15-judge-certainty.md) and its
[results](../../evaluation/detection-generalization-results/15.md); [specification
14](../../specifications/detection-generalization/14-sql-calls-redesign.md) and
[results](../../evaluation/detection-generalization-results/14.md); [specification
16](../../specifications/detection-generalization/16-package-question.md), draft.
