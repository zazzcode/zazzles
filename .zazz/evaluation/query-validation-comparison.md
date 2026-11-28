# Database query construction and input-validation comparison

**Baseline: 2026-10-31; explanations revised 2026-11-01.** This comparison records offline observations,
not confirmed exploits. No live judge call was made for this comparison; assessments remain `not_run`.
Input validation and database-operation protection answer different questions and are listed separately.
An observed construction can be a code-practice finding without proving injection. An unresolved call
is an analysis limitation, not evidence that a validator is missing.

Targets: Juice Shop `f189f521266f42c6bd05884468292000cee852ed` with `--entry server.ts`, and
vulnerable-typescript-app `7f8b240a2f02beba099da3632d1ba679ff8bc32f` with `--entry src/server.ts`.
Training snippets and the Juice Shop frontend are outside this comparison. Bearer results refer to the
pinned runs for these revisions, not a fresh benchmark. They are not a denominator for this selected-case table.
“Not reported” describes that tool's output, not a claim that the code is safe.

## Juice Shop: what the code does and what remains unresolved

| Documented item and source | Database-operation observation | Input validation and remaining review | Bearer output |
|---|---|---|---|
| Login SQL; loginAdmin / loginBender / loginJim. `routes/login.ts:34` | Login values are inserted into SQL query text. Review this query-construction finding and replace string-built values with the driver's parameter binding. | No email validator call was identified in the analyzed slice. That does not prove every middleware path lacks validation. Hashing the password does not separate the email value from SQL structure. | SQL injection reported at line 34. |
| Search SQL; unionSqlInjection / dbSchema. `routes/search.ts:23` | Search text is inserted into SQL query text after truncation. Length truncation alone does not keep data separate from SQL structure. | A length restriction is visible; scan has not established sufficient field validation or complete protection. Review the business policy independently of query binding. | SQL injection reported at line 23. |
| NoSQL DoS; noSqlCommandChallenge. `routes/showProductReviews.ts:36` | A product identifier is concatenated into a NoSQL `$where` expression. This is an observed construction finding, not a confirmed denial-of-service exploit. | The code selects numeric conversion or truncation according to configuration. Whether each path adequately constrains the expression remains unresolved; these transformations must not be described as simply absent. | NoSQL: no finding reported. |
| NoSQL exfiltration; noSqlOrdersChallenge. `routes/trackOrder.ts:18` | An order identifier is inserted into a quoted NoSQL `$where` expression. Review the construction and prefer a supported data-only equality filter. | Configuration selects a character filter or truncation. The relevant branch and resulting allowed values must be checked before claiming a bypass. | NoSQL: no finding reported. |
| NoSQL manipulation; noSqlReviewsChallenge. `routes/updateProductReviews.ts:17` | A request-supplied review identifier enters an update selector, with multi-update enabled. Scan has not established a scalar constraint for that slot. This is a document-type review finding, not proof that all structured NoSQL updates are unsafe. | Verify that the identifier cannot contain operators or objects and that update scope matches the authenticated user's permissions. The review message is free text; punctuation alone is not a validation defect. Authorization needs separate review. | NoSQL: no finding reported. |
| Chat catalog search. `routes/chat.ts:117` and `:123` | Chat-tool search text is inserted into ORM search-pattern values. Scan matched the database expression, but has not established whether the library safely separates those values from SQL structure. This is an analysis item requiring library review, not an established SQL-injection finding. | The tool declares a string input schema. Scan did not resolve a direct request-field dependency or establish the complete path from external input through the tool. Check schema enforcement and library behavior. | SQL: no finding reported. |
| Chat review lookup. `routes/chat.ts:149` | A chat-tool product identifier is converted with `Number` and then concatenated into a NoSQL `$where` expression. The string construction is observed; injection is not established. | Review numeric conversion and its actual possible outputs. Scan did not resolve a direct request-field dependency for this nested tool call. | NoSQL: no finding reported. |
| Empty / repetitive / admin registration. `server.ts`, user-create middleware | Registration is a field-validation and account-creation case, not an additional string-built query sink. | Review required fields and enforcing guards before persistence. The separately declared account-creation check covers the passwordRepeat bypass; unmodeled middleware effects remain unresolved. | No dedicated input-validation rule reported. |

The constant search query `models.sequelize.query('SELECT sql FROM sqlite_master')` has no varying
query operand and is excluded from these source-dependent query observations. A library call named
`find` is not automatically a database query; `Array.find` must not be labeled NoSQL.

## Vulnerable TypeScript app

The target README names `main.ts` and `app.controller.ts`, which are absent at this revision.
The scanned source is `src/server.ts`.

| Target claim and source | What zazzles actually observes | Input validation and remaining review | Bearer output |
|---|---|---|---|
| SQL injection. `src/server.ts:73` | The code constructs and logs SQL-looking text but does not send it to a database. Scan therefore reports no database-sink finding here. | Username reaches `users.find`; the call's validation effect is unresolved. That is not proof of missing validation and the array lookup is not a NoSQL operation. | SQL injection: no finding reported. A separate logger finding was reported. |
| Other documented weaknesses in `src/server.ts` | Routes are inventoried; request-field validation is recorded for supported reads. The proxy remains an outbound-operation analysis item at line 125. | Command injection, file access, XSS, eval, XXE, redirect, secrets, cookies, and logger detection are outside this implemented detector increment. No absence-of-weakness claim follows. | Other rule families are present in the earlier 28-finding run; see the pinned results. |

## Fresh offline rerun and presentation records

The following counts describe the earlier observation-based presentation, not version-3 Findings.
Version 3 reclassifies established construction practice versus unresolved checks according to the
[root results guide](../../docs/scan/interpreting-results.md). Raw evidence is unchanged.

The 2026-11-01 rerun used the same target revisions and entry selections. Raw `entries`, `uses`,
`gaps`, `files`, and `limitations` match the pre-presentation baseline exactly. The JS/TS practice
reference advances to version 2 for clarified assessment rules. No new model calls or target execution.

| Target | Inventoried entries | Raw use records | Observed-pattern finding records | Unresolved analysis records |
|---|---:|---:|---:|---:|
| Juice Shop | 152 | 137 | 32 | 105 |
| Vulnerable TypeScript app | 19 | 14 | 2 | 12 |

Juice Shop's 32 observed-pattern records comprise two SQL constructions, thirteen NoSQL constructions
or document-type review cases, and seventeen request-field cases where no validator call was identified.
Two ORM search-value records are analysis items requiring library review, not SQL-injection findings.
The TypeScript app's two observed patterns are request-field validation observations, not database-sink
findings. All counts are per route/use, may repeat a shared helper, and must not be presented as unique
vulnerabilities or proof of superior accuracy. No assessed protection or supported-potential verdict
is fabricated from this offline run.

Artifacts are generated locally under the configured
`_test-findings/<repo-name>/run-<id>/` output root, outside the checkout. Each run contains matching
JSON, standalone HTML, and SARIF. These generated reports are not committed. HTML contains scan results
only; this evaluation document owns comparisons. Browser-tool access to local file URLs was denied,
so interactive visual sign-off remains pending human review; automated escaping, grouping, export,
status, remediation, and artifact-generation checks pass.

## How to read and reproduce these results

The human explanations correspond to internal evidence identifiers, retained for agents and debugging:

| Evidence identifier | Human interpretation |
|---|---|
| `query_text_interpolated` | A value is built into a matched database expression. Verify whether the slot is executable text or a library-managed data value before claiming injection. |
| `query_document_unvalidated` | A request value enters a NoSQL document without a modeled type constraint. Inspect slot, driver, type, keys, and operators. |
| `input_validation_absent` | No validator call was identified in the analyzed slice. This is not a complete proof about all runtime paths. |
| `input_validation_unresolved` / `input_validation_middleware` | A call or middleware may affect validation; its effect has not been established. |
| `validation_insufficient_for_sink` / `validation_type_only` | A basic restriction was observed; business adequacy and operation protection still require separate review. |

This Markdown comparison is maintained by review; no code generator for this file is present.
Detection observations originate in [query-shape analysis](../../scan/internal/langjs/query_shape.go).
The [embedded JS/TS Analysis Guidelines](../../scan/internal/guidelines/javascript.md) constrain model assessment;
the [human report rules](../../scan/internal/report/findings.go) explain raw uses without upgrading their
security verdict, and [remediation rules](../../scan/internal/report/guidance.go) provide reviewable actions.
JSON, HTML, and SARIF share that interpretation; the HTML contains only scan results, without tool comparisons.

Follow [README commands and interpretation](../../README.md#interpret-results) to regenerate a JSON
report and its standalone HTML/SARIF views. Model assessment, independent review, and runtime
confirmation remain separate stages. Shared helper uses may repeat for each calling route; record
counts are not counts of unique vulnerabilities. Logger detection and other rule families remain
[future capabilities](../project/implementation-plan.md#future-capability-branches).
