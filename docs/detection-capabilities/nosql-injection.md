# NoSQL injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/database-injection.md#database-specific-nosql-scope) · [CWE-943](https://cwe.mitre.org/data/definitions/943.html)

The claim is whether a value changes a verified NoSQL selector, update operand, or executable expression. The database engine and operand role determine the result.
In a judged scan, select this family with `--only-family nosql`.

Current support is bounded to JavaScript and TypeScript Mongoose/MongoDB and MarsDB operations.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Operator-bearing selectors | A request object is used as a value in a supported Mongoose selector | A supported path can be Confirmed when it permits operator interpretation |
| Constrained selector values | An enforced scalar check or verified ObjectId conversion before a selector | May be Protected when the constraint applies to the same value on every path |
| Executable MarsDB selectors | A request string reaches a verified MarsDB `$where` expression | The expression operand is assessed separately from ordinary selector and update data |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `NOSQL-R01` | Unresolved selector constraint | A helper checks a selector object before the query, but its effect is unknown | Review when the relevant value or guard is unresolved | Follow the input through the helper and verify its constraint |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `NOSQL-N01` | Other database engines | A DynamoDB document client receives request-derived filter data | Register that engine’s operation and operand semantics |
| `NOSQL-N02` | Python and PHP database adapters | A Python MongoDB driver receives a request selector | Implement and test the language and driver bindings |
