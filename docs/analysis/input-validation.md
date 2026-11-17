# Input validation analysis

[Analysis index](README.md) · [Database injection](database-injection.md)

A missing validator call is evidence about the analyzed slice, not proof that every execution path
accepts invalid input. Analysis MUST distinguish an absent observed check, an unresolved check, and
an established failure to enforce a declared field requirement.

## Establish the field policy

Use requirements demonstrated by the application or an explicit scan check: required presence,
scalar type, allowed values, format, length, range, or cross-field business constraints. Field names
alone do not define policy. Free-text punctuation is not intrinsically invalid.

A **Poor Input Validation** finding requires both an applicable requirement and evidence that it is
not enforced on a supported path. When business policy is missing, report the precise question as
Review / Inconclusive instead of inventing a restriction.

## Establish enforcement

Analysis MUST inspect what a validator does, whether its result is enforced, and whether execution
can reach the sensitive operation after failure. Include applicable middleware in execution order,
helper bodies, returned/reassigned values, and relevant branch/return facts. A function name or a
call receiving the field does not prove validation. An unresolved check is not a proven bypass.

Native Number conversion can constrain injection syntax without checking range, finiteness, or the
field's business validity. JSON parsing can accept nested objects without validating their schema.
SQL binding does not validate email format; an email-format check does not replace query binding.

For `const parsed = Schema.safeParse(req.body)`, each `parsed.data.<key>` read at exactly one place
keeps its own request-source evidence as a field projection. Reassigned or redeclared results, keys
read more than once and `safeParse` on a non-request object keep plain property reads. The projection
never marks the value safe; whether `success` is enforced remains a separate fact.

## Report for a correct fix

Name the field, requirement, relevant path, and evidence of the enforcement defect. Keep destination
protection separate. Recommend changes that preserve valid application behavior, with normal,
rejected, boundary, protected, and inconclusive cases where relevant.

Validation answers on query records remain facets. Policy-backed standalone field claims use a
separate validation protocol and can establish an unmet requirement independently of SQL protection.
Standalone field uses select embedded validation components: the claim needs an explicit or
source-backed requirement and enforcing path, never a database API contract or a sensitive sink, and
requests carry only selected field-policy guidance and questions. Do not add overlapping category
pills as independent defects. Complete required evidence and consistent policy/enforcement/coverage
answers gate a definite field result.

The [Python adapter](../python-support.md) includes relevant handler/helper code, branch preconditions
and source-backed input constraints from a form posting to the same handler. Client constraints
establish declared policy; they do not prove server enforcement. Standalone fields remain Review
when no business policy is established. Query records retain separate validation and injection facets.

The [PHP adapter](../php-support.md) assembles `source.php-input-v1` facts from superglobal
acquisitions (`$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER` → `http.query`/`http.form`/
`http.cookies`/`http.headers`, `php://input` → `http.body`, `$_FILES` parts) with per-key input
values. Handler guards (isset/empty, type checks, presence tests) are enforcement evidence; HTML
`maxlength` or client script constraints are declared policy only.

The shared trace bundle indexes actual helper/condition evidence and exposes missing roles to the
judge. Presence is not proof of enforcement. A Review recommendation names the missing fact; a
validation-practice finding names the exact source-declared field constraints and direct-request
rejection tests. Protected query guidance does not prescribe a speculative validation repair.

GraphQL argument bindings are separate from parent, context and info provenance. The bounded Apollo
adapter records actual argument reads and supported transfers, but an SDL scalar/type name, non-null
marker or directive name does not establish an application's business requirement or an enforcing
validator. SQL binding remains a destination-specific claim. Default/unresolved resolvers and
unsupported parent-result transitions stay coverage gaps, including when no sensitive operation was
recovered. See [GraphQL scan limits](../running-scans.md#bounded-apollo-graphql-analysis).
