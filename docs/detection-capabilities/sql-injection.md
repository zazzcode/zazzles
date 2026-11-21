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

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `SQL-R01` | Unresolved query transformation | A custom helper transforms SQL text before execution | Review when the helper’s effect or a route guard is unresolved | Establish the effective SQL text and its source path |
| `SQL-R02` | Unknown external origin | Executed SQL is assembled from a value whose origin is unresolved | Review with `external_origin_not_established` for the construction claim | Link the value to its source |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `SQL-N01` | Unverified database API | An application passes SQL to a driver with no registered contract | Verify the driver binding and its SQL and parameter slots |

## Outside this claim

SQL text that is only constructed or logged has no database operation to assess.
