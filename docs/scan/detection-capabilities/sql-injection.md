# SQL injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/database-injection.md#sql-rules) · [CWE-89](https://cwe.mitre.org/data/definitions/89.html)

The claim is whether an external value can change executable SQL at a verified database call. Construction practice and field validation have their own outcomes.
In a judged scan, select this family with `--only-family sql`.

Supported bindings include Sequelize, Prisma raw queries, sql.js, better-sqlite3 and other documented JavaScript adapters, Python sqlite3, Psycopg, PyMySQL and MySQL Connector, and PHP mysqli, PDO and SQLite3. The rules guide lists driver-specific contracts.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Interpolated SQL text | An application builds a `SELECT` string with a request field and passes it to a verified query API | Supported raw paths can be Confirmed. Executable-string construction can also produce a practice finding |
| Bound values | A literal statement with placeholders and a separate parameter argument | May be Protected for the bound values. Any interpolated identifier or raw clause is assessed separately |
| Structured Sequelize finders | A verified model finder with values in `where` | Ordinary finder values are bound. Raw SQL literal escapes are evaluated separately |
| Provider-specific literal escaping | Prisma raw SQL with quote doubling inside a single-quoted value | Recognized per operand for SQLite, PostgreSQL and CockroachDB |
| PHP operands escaped inside single quotes, or a hash | `mysqli_real_escape_string` on the query's own connection, then `mysqli_query` in the same run of plain assignments | Stated as facts when every operand fits the pattern. The judge decides, and construction practice stays separate |
| Doctrine DBAL and ORM | A prepared DBAL statement, ORM query, or QueryBuilder chain from a repository or the entity manager executes source-backed query text | Bound data and executable fragments carry separate evidence. Pagination and cache setters keep the chain's text. [Symfony coverage](symfony.md#operations) |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `SQL-R01` | Unresolved query transformation | A custom helper transforms SQL text before execution | Review when the helper’s effect or a route guard is unresolved | Establish the effective SQL text and its source path |
| `SQL-R02` | Unknown external origin | Executed SQL is assembled from a value whose origin is unresolved | Review with `external_origin_not_established` for the construction claim | Link the value to its source |
| `SQL-R03` | Unresolved Doctrine query target | An unknown receiver has a query-shaped method | Dispatch or receiver identity stays unresolved | Trace the receiver to its declared Doctrine type |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `SQL-N01` | Unverified database API | An application passes SQL to a driver with no registered contract | Verify the driver binding and its SQL and parameter slots |

## Outside this claim

SQL text that is only constructed or logged has no database operation to assess.
