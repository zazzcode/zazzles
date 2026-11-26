# NoSQL injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/database-injection.md#database-specific-nosql-scope) · [CWE-943](https://cwe.mitre.org/data/definitions/943.html)

The claim is whether a value changes a verified NoSQL selector, update operand, or executable expression. The database engine and operand role determine the result.
In a judged scan, select this family with `--only-family nosql`.

Current support is JavaScript and TypeScript: Mongoose models, MarsDB collections, and the native MongoDB driver
(npm package `mongodb`).

The native driver is supported without a list of its methods or of the ways an application creates, caches or passes a
client. Code Scan follows the receiver of a call back to the `mongodb` import and records the call when request data
reaches it. The decision model then reads the call, that definition path and the source, and says what the operation is and
whether an input can change it. Any call on a value from the driver is covered this way, including `count`, `distinct`,
`aggregate`, `bulkWrite`, `db.command` and a request-chosen collection name.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Operator-bearing selectors | A request object is used as a value in a supported Mongoose selector | A supported path can be Confirmed when it permits operator interpretation |
| Constrained selector values | An enforced scalar check or verified ObjectId conversion before a selector | May be Protected when the constraint applies to the same value on every path |
| Native driver: operator object or whole filter | `collection.findOne({ name: req.body.name })`, `find(req.body)`, `deleteOne({ owner, ...req.body })` | Confirmed when a request value can arrive as an object, or supplies a key or the whole filter |
| Native driver: server-side JavaScript and expressions | Request text in `$where`, `$function`, a `mapReduce` function, or as a `$`-string in `$expr` or an update pipeline | Confirmed when the text is not a number, one complete literal or a fixed alternative |
| Native driver: patterns, names and written fields | Request text in `$regex`; a request-chosen sort, projection, field or collection name; a request object under `$set` | Confirmed when not escaped or limited to alternatives the code lists |
| Native driver through application code | The client kept in a global promise, a repository class, a helper module, a bound method, a `for await` loop over a cursor | The same record: the definition path from the import to the call is the binding evidence |
| Executable MarsDB selectors | A request string reaches a verified MarsDB `$where` expression | The expression operand is assessed separately from ordinary selector and update data |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `NOSQL-R02` | Native driver, code the scanner did not follow itself | A value passes through a callback or a helper the flow cannot model before a `mongodb` call | The model reads that code and may report a finding. It is never Protected: protection needs evidence the scanner read | Model the construct in the flow |
| `NOSQL-R03` | Native driver, weak "data only" answer | The model finds no way to change the operation, below the strength Protected requires | Review, not Protected | A stronger answer, or scanner evidence of the control |
| `NOSQL-R01` | Unresolved selector constraint | A helper checks a selector object before the query, but its effect is unknown | Review when the relevant value or guard is unresolved | Follow the input through the helper and verify its constraint |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `NOSQL-N01` | Other database engines | A DynamoDB document client receives request-derived filter data | Add the package and its query language: one table entry and one language note |
| `NOSQL-N02` | Python and PHP database adapters | A Python MongoDB driver receives a request selector | Implement and test the language and driver bindings |

## Measured accuracy of the native driver support

Measured 2026-11-25 and 2026-11-26 on the MongoDB module of the `vuln-nextjs` lab at `aeae20a`: 57 vulnerable routes and 71 safe controls
built as near twins. Before this support none of the 57 was reported.

| Decision model | Vulnerable routes Confirmed | Vulnerable routes Protected | Safe controls Confirmed |
| --- | ---: | ---: | ---: |
| Gemini `gemini-decision-1` | 52 of 57 | 0 | 4 of 71 |
| OpenAI `gpt-6-luna` | 46 of 57 | 0 | 15 of 71 |

The lab was used to develop this support, so these are not held-out numbers. Neither model marked a
vulnerable route Protected. With `gpt-6-luna` about one Confirmed route in four was a safe control. Limits: Python and PHP
drivers are not covered, and a safe sanitizer the model misreads can still be reported
(a complete string literal built with `JSON.stringify`, a `JSON.parse` reviver that drops operator keys, a character filter).
