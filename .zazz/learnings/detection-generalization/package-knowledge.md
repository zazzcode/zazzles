# Package and library knowledge

The idea: the scanner finds the operation and the value by structure. The judge says what the operation does. The scanner
checks, joins and bounds. A package, ORM or version needs no list. Evidence is on forms the implementer wrote; **no real
application has been tested**, and no local sample holds an uncontracted SQL call (nine samples, 0 records).

| Area | What we know | Status |
|---|---|---|
| SQL drivers, raw ORM calls | Unseen JavaScript 10 of 12 at 0.70, Python 9 of 9, no lookalike or made-up package claimed | Draft [16](../../specifications/scan/detection-generalization/16-package-question.md) |
| Version | The declared version raised both misses and moved no control above 0.35 | Include it |
| Constructors as callee, nested calls | Recorded in JavaScript; not asked about | Open |
| ORM builders, identifiers (`orderBy`) | Not tested. Needs a third answer beside value and SQL text: identifier | Open |
| Validation libraries | 14 of 15 right, 11 at 0.65; the wrong one is a text rule called restricted at 0.47 | Below the bar |
| MongoDB (Mongoose), MarsDB, other databases | Not tested | Open: ask by query language, not driver |

Rules that held:

- **The binding is a scanner fact.** The model names no package; the scanner supplies the import.
- **A name is not knowledge.** Made-up packages with database-like names were answered `cannot_tell` because the question says so.
- **Asking "do you know this package" does not work.** It was 0.37 for a driver whose operation was answered at 0.94.
- **A resolved call gives a finding or Review, never Protected.** A verified contract always wins.
- **One request per distinct operation,** keyed by import, version, callee and argument, so cost follows packages and not calls.

What stays specific: connectors; each language's extraction; query languages. A query language is a small set (SQL text,
document operators, script expressions, key-value, graph, search), so a new database means one entry, not one per driver.
This is a proposal. It is not tested.

**Blockers of the scanner's own.** A `for` loop or a callback can hold a correct finding in Review whatever the judge says.
In the four applications 68 of 124 SQL records are unblocked; most of the rest are PHP value and storage gaps.

## NoSQL databases

Each database is named. The owner asked for the last three next (2026-11-25). **Their "query language" column is what a probe
must establish; it is not verified by any test or documentation read for this page.**

| Database | Support | Query language to establish |
|---|---|---|
| MongoDB, through Mongoose | Contracts exist | Document operators (`$ne`, `$in`, `$where`); casting depends on schema and version |
| MarsDB | Contract exists | MongoDB-style operators; `$where` runs JavaScript |
| MongoDB, native driver | Not supported | The same operators, without Mongoose casting |
| Amazon DocumentDB | Next | MongoDB-compatible, so it is reached through MongoDB drivers. Which operators it rejects has to be read from its documentation. It likely needs the native driver first |
| Amazon DynamoDB | Next | Two kinds: expression strings beside placeholder values, and PartiQL text (SQL-like). A request value in the expression text differs from one in the values |
| Elasticsearch | Next | Query DSL objects (a request object can change the query), query-string syntax, and scripts |

So the first questions are per query language, not per driver: document operators, expression text with placeholders, SQL-like
text, query DSL objects, scripts. DynamoDB's placeholders make it the closest to the SQL question already measured. DocumentDB may
come almost free once the native MongoDB driver is recognized.

### Common MongoDB injections to cover (owner, 2026-11-25)

A lab set in `vuln-nextjs` on the native driver is being built in its own session. Not measured by the scanner yet.

| Form | What to find |
|---|---|
| Operator injection | A request object where a value is expected (`$ne`, `$gt`, `$in`, `$regex`), from JSON or bracketed query keys |
| Whole-filter input | A parsed request object used as the filter of a find, update, delete or count |
| `$where`, `$expr`, `$function` | Request text that runs as an expression or script |
| Pipeline input | Aggregation stages from the request |
| Update operators | A request object as the update document, or inside `$set`, including role fields |
| Sort, projection, field name | A request value as a name |
| `$regex` text | Unescaped user text in a pattern |
