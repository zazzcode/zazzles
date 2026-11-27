# Database injection analysis

[Analysis index](README.md) · [Input validation](input-validation.md) · [Calibration](calibration.md) · [SQL coverage](../detection-capabilities/sql-injection.md) · [NoSQL coverage](../detection-capabilities/nosql-injection.md)

## Three independent questions

Scan separates **business validation**, **construction practice**, and **injection protection**.
An executable query string can deserve refactoring even if a numeric conversion prevents injection.
A parameterized query can prevent injection while accepting values that violate business policy.
A query category label by itself answers neither question.

## Evidence before judgment

Analysis MUST identify the request field, its transfers into the actual operation slot, the bound
library/API, relevant guard and middleware behavior, and a supported source-to-operation path.
Names such as `query` or `find` alone MUST NOT establish a database API. An array's `find` is not a
NoSQL sink. Unresolved applicable checks, dynamic bindings, or missing helper bodies remain blockers.

The bounded automatic adapters currently include verified Sequelize raw-query usage, sql.js statements
and MarsDB collection construction/imports (namespace imports, ES named and aliased imports, export-clause aliases and `export { x } from` re-exports; a name exported more than once or reassigned is not followed), and Sequelize model finders. A sql.js claim needs a verified `sql.js` import and a receiver
assigned from `new <module>.Database(...)`, with request data in the SQL text argument of `run`, `exec` or
`prepare`, directly or through a local helper. Values in a bound array are not a claim. MarsDB has Mongo-style matching semantics; this does not make it
a MongoDB server or establish support for every MongoDB driver. Unsupported bindings remain Review.

## SQL rules

- Values interpolated or concatenated into executable SQL are a construction-practice finding.
- Actual query argument roles matter. Binding parameters or replacements preserve data separately
  from SQL structure; `model` or `plain` options do not protect an already-built SQL string.
- Interpolated ORM search values are not automatically executable SQL. Verify the library slot.
- A Sequelize finder (`findAll`, `findOne`, `findAndCountAll`, `count`, `findOrCreate`) on a class that
  extends the `sequelize` `Model` binds its `where` values, including `Op.like` operands
  (`sequelize-model-finder-v1`). An injection answer is inconsistent unless the same call contains raw SQL
  (`Sequelize.literal`, `sequelize.literal`, `Op.literal`). Unescaped `%` and `_` in a LIKE pattern are a
  wildcard concern (`like_pattern_interpolated`), not SQL syntax control. A call that only contains a
  nested function with a finder, such as a tool or callback registration, is not itself a SQL candidate.
- A `try` body does not guard its query; `catch` is an exceptional successor. `finally` stays unresolved.
- In Prisma raw SQL, an operand passed through single-quote doubling (`.replace(/'/g, "''")`) inside a
  single-quoted literal is recorded per operand (`sql_literal_quote_doubling`) for SQLite, PostgreSQL
  and CockroachDB providers only. MySQL, SQL Server and unknown providers get no fact. The fact marks
  only the escaped operands; a raw sibling operand keeps the record eligible for Confirmed.
- A string merely constructed or logged without a database call is not an executed SQL sink.
- A vulnerability verdict requires request-controlled syntax on a supported path, independently of
  the construction-practice answer. Missing field validation alone does not prove SQL injection.

## Database-specific NoSQL scope

NoSQL names the analyzer category, with intended support for multiple database engines. The initial
implementation covers bounded MongoDB/Mongoose and MarsDB-compatible JavaScript/TypeScript operations,
and calls of the native MongoDB driver (npm `mongodb`) found by
[package origin](#native-mongodb-driver-operations). It does not provide generic NoSQL coverage. DynamoDB and every additional engine require their own
verified API/operand models, rules, guidelines, applicability gates and positive/protected/unknown
controls. Python NoSQL remains unimplemented.

Findings MUST name the actual source-supported database and driver/API in their explanation:
MongoDB through Mongoose, MarsDB for its compatible in-process queries, or an explicitly unknown
engine when identity is unresolved. Preserve the NoSQL category and existing machine IDs; database
identity is additional context. Do not rename MarsDB to MongoDB or infer DynamoDB semantics from
MongoDB selectors. Historical generic report labels remain historical; a generic category alone
does not meet this database-identification requirement for future report improvements.

## NoSQL rules

- Analyze selector keys/values, update data, and executable expressions as different slots.
- An unconstrained request object in a selector value can introduce operators when the verified
  matcher supports them. Do not assume every structured document or update value is unsafe.
- MarsDB `$where` string values are executable JavaScript predicates. Untrusted expression text
  can change behavior; truncating text or stripping newlines does not exclude expression operators.
- A positively constrained scalar selector value can be protected from operator injection.
- JSON/body parsing is transport handling. It does not establish a per-field scalar schema.

## Native MongoDB driver operations

Draft [PR #54](https://github.com/zazzcode/zazzles/pull/54), not merged.
[Specification](../../../.zazz/specifications/detection-generalization/19-database-package-operations.md) and
[results](../../../.zazz/evaluation/detection-generalization-results/19.md) own the detail.

- **Recording.** A call is a NoSQL record when a request value reaches it and its receiver or callee
  derives from the `mongodb` package import. The scanner follows names, members, returned values,
  parameters, callbacks, classes and module exports back to the import. It keeps no list of driver
  methods and no list of ways a client is created, cached or passed. Nothing runs unless a file of the
  target names the package.
- **Origin is a may-fact.** One definition path to the import exists. The record states that path;
  it does not claim every path leads there.
- **Additive.** These records change no other record and mark no request field as consumed.
- **Contract and protocol.** The record carries contract `mongodb-document-query-v1`, and only that
  contract selects protocol `document-operation-v2`. Mongoose and MarsDB records keep their own
  contracts and evidence. Moving them to this request was tested and lost Juice Shop findings.
- **What is sent.** Query-language notes, an entry note, the call, the receiver path, the request
  values, and the source with the definitions the call uses.
- **What is asked.** Two closed questions. `operation`: is the call a database query, a stored
  document, or not a database operation. `request_control`: is there an input an attacker can send
  that changes the operation beyond the choices the code itself lists. The finding answers are
  `operator`, `expression_text`, `pattern`, `name` and `written_fields`; `data_only` is the safe one.
- **Scanner reading limits.** Code the flow could not model is shown to the model and listed in
  `completeness.judged_limits`. A record with such a limit is never Protected.
- **Protected** needs `data_only` at a probability of 0.95 or more and no judged limit. Below that
  the record stays in Review.
- **No scanner rule decides a verdict** for these records. Facts added to the request as text were
  tested three times and each time changed unrelated answers; do not add them without a measured run.
- **Calibration is open.** On the lab, 93% of Confirmed routes were vulnerable with Gemini
  `gemini-decision-1` and 75% with `gpt-6-luna`; neither marked a vulnerable route Protected. The series bar is 95%.
  About 13% of lab routes change answer when the request wording changes.

## SQL calls with no driver contract

[Specification](../../../.zazz/specifications/detection-generalization/21-sql-text-records.md) owns the detail and the
measurements.

- **Recording.** A call that no driver contract records becomes a SQL record when one argument is SQL statement text
  and a request, stored or session value reaches the call. The scanner names no driver, package or method. One shared
  test decides what statement text is: `SELECT … FROM`, `INSERT INTO`, `UPDATE … SET`, `DELETE FROM`, `WITH … AS (`,
  table DDL, `EXEC` and `CALL`, and the clauses `WHERE` with a comparison, `ORDER BY` and `VALUES (`. Ordinary prose
  that begins with such a word does not match.
- **Slots.** A value that reaches the text argument has slot `sql_text`. A value in another argument of the call, or in
  a bind call on a statement prepared from the text, has slot `sql_parameters`. A call with SQL text and no such value
  is not recorded.
- **Contracts keep their records.** A call a contract records is unchanged and gains no second record. In JavaScript a
  record made only because the method is named `query`, with no contract, takes this contract when its argument is SQL
  statement text; otherwise it stays as it was.
- **Contract and protocol.** The record carries contract `sql-text-v1`, and only that contract selects protocol
  `sql-text-operation-v1`.
- **What is sent.** Notes on SQL as a query language, an entry note, the call, the request values, stored values under
  their own name, and source: the handler, the functions the values pass through, and the file of the call (whole up
  to 16 KB, else 60 lines on each side). The judge reads no file; the record carries the excerpts.
- **What is asked.** Two closed questions. `operation`: does the call run SQL, or is it not a database operation (a log
  or print call that takes SQL text is recorded, and answered here). `request_control`: is there an input an attacker
  can send that changes the statement beyond the choices the code lists. The finding answers are `statement_text` and
  `name`; `data_only` is the safe one.
- **Scanner reading limits** are shown as code and bar only Protected, whether they are on the text and its values
  or elsewhere in the entry flow.
- **Protected** needs `data_only` at 0.95 or more, no reading limit and at least one request value.
- **Review by scanner evidence.** A finding answer for a record whose request values are all in slot `sql_parameters`,
  beside a statement text the scanner resolved whole, is Review (`bound_parameters_only`), as for a contract record. A
  record with only stored values is Review.
- **Where the text comes from.** The hook reads the text through concatenation, interpolation and formatting, a
  `join` or `implode` of a list, the returns of one helper defined in the scanned source, and a constant or helper of
  another scanned file. Definitions it read through travel with the record as source.
- **Where a value lands.** When the text has parts that are not literal, the record carries the scanner's reading of
  the literal text: each such part numbered, and whether it sits inside a quoted literal or outside quotes
  (`statement_shape`). The request sends it as `statement`. It states nothing about the value itself. It is not given
  when a backslash sits inside a quoted literal, because databases disagree on what that does.
- **A value bound in another call (JavaScript).** A method call on a name that was assigned from a call whose argument
  is SQL statement text with no request value is one record per statement object, slot `sql_parameters`.
- **Tagged templates (JavaScript).** A tagged template whose literal text is SQL statement text and whose substitution
  carries a request value is recorded with the mark `template_tag`; the scanner does not decide what the tag does and
  the request says it is a tagged template. A finding needs the tag function in the scanned source
  (`template_tag_definition`); without it a finding answer is Review (`template_tag_unresolved`).
- **Not followed.** A helper called by a helper; a list built by a comprehension, `map` or `filter`; a statement
  prepared and run in one chained expression; a variable assigned in an included PHP file; statements outside the
  list above.
- **Calibration is open.** On the lab, 93% of Confirmed routes were vulnerable with Gemini
  `gemini-decision-1` and 75% with `gpt-6-luna`; neither marked a vulnerable route Protected. The series bar is 95%.
  About 13% of lab routes change answer when the request wording changes.

## SQL calls with no driver contract

[Specification](../../../.zazz/specifications/detection-generalization/21-sql-text-records.md) owns the detail and the
measurements.

- **Recording.** A call that no driver contract records becomes a SQL record when one argument is SQL statement text
  and a request, stored or session value reaches the call. The scanner names no driver, package or method. One shared
  test decides what statement text is: `SELECT … FROM`, `INSERT INTO`, `UPDATE … SET`, `DELETE FROM`, `WITH … AS (`,
  table DDL, `EXEC` and `CALL`, and the clauses `WHERE` with a comparison, `ORDER BY` and `VALUES (`. Ordinary prose
  that begins with such a word does not match.
- **Slots.** A value that reaches the text argument has slot `sql_text`. A value in another argument of the call, or in
  a bind call on a statement prepared from the text, has slot `sql_parameters`. A call with SQL text and no such value
  is not recorded.
- **Contracts keep their records.** A call a contract records is unchanged and gains no second record. In JavaScript a
  record made only because the method is named `query`, with no contract, takes this contract when its argument is SQL
  statement text; otherwise it stays as it was.
- **Contract and protocol.** The record carries contract `sql-text-v1`, and only that contract selects protocol
  `sql-text-operation-v1`.
- **What is sent.** Notes on SQL as a query language, an entry note, the call, the request values, stored values under
  their own name, and source: the handler, the functions the values pass through, and the file of the call (whole up
  to 16 KB, else 60 lines on each side). The judge reads no file; the record carries the excerpts.
- **What is asked.** Two closed questions. `operation`: does the call run SQL, or is it not a database operation (a log
  or print call that takes SQL text is recorded, and answered here). `request_control`: is there an input an attacker
  can send that changes the statement beyond the choices the code lists. The finding answers are `statement_text` and
  `name`; `data_only` is the safe one.
- **Scanner reading limits** are shown as code and bar only Protected, whether they are on the text and its values
  or elsewhere in the entry flow.
- **Protected** needs `data_only` at 0.95 or more, no reading limit and at least one request value.
- **Review by scanner evidence.** A finding answer for a record whose request values are all in slot `sql_parameters`,
  beside a statement text the scanner resolved whole, is Review (`bound_parameters_only`), as for a contract record. A
  record with only stored values is Review.
- **Not followed.** Text built by `join`, a helper or another module; a JavaScript value bound in a different call from
  the text; a tagged template; statements outside the list above.
- **Calibration is open.** On 18 injectable driver forms written for the specification, both Gemini
  `gemini-decision-1` and `gpt-6-luna` Confirmed 18. Of 19 bound twins neither Confirmed one; Gemini marked 16
  Protected and `gpt-6-luna` 5. No application the implementers did not write has been measured beyond one file.

<a id="bounded-express-and-mongoose-context"></a>

## Node acquisition and Mongoose context

Immutable direct imports of default method-override/upload adapters and literal-data session options
can supply transport contracts. Custom callbacks/stores, dynamic options, mutation or escaped bindings
remain unresolved. JSON parsing does not impose a scalar schema. A verified `validator.isEmail` call
constrains its argument only; it cannot validate a sibling password selector.

Mongoose query claims require the selected model's actual schema. The adapter follows the sink and
registration modules' direct static imports/requires, with a 24-module bound, and accepts one verified
`mongoose.model` registration with a literal/default schema constructor. It does not borrow unrelated
same-name schemas. Ambiguous/missing schemas, unsupported constructors and custom hooks, callbacks,
mutations or escapes retain blockers or missing required evidence. This is bounded module context,
not complete model/plugin analysis.

An exact root dependency pin matching the lock-derived version can supply the
[Mongoose 4.2.4 casting contract](https://github.com/Automattic/mongoose/blob/4.2.4/lib/cast.js).
Its String paths retain recognized conditional operators such as `$ne`; persistence validation does
not force scalar equality in query filters. `findById` and ObjectId casting remain distinct from
String selector fields. Declared dependency evidence does not verify an installed runtime.

Fresh default-ObjectId lookups use the framework-independent `mongoose-find-by-id-objectid-v1`
contract. It requires the exact 4.2.4 dependency pin and a verified literal schema with default
ObjectId `_id`. `findById` builds `{_id: value}` and casts scalar strings to ObjectId or raises a
cast error; object-valued operands can still carry recognized query operators. Source acquisition,
initial type, transformations, supplied controls and type at the actual sink are separate
[shared Node input facts](node-inputs.md), usable by HTTP, GraphQL and unary gRPC acquisitions.

The judge assesses the complete supplied path; policy requires consistent source/binding/coverage
answers and positive scalar facts or source-present enforcing controls. Plain route/logging options
are not value controls. A schema declaration alone never establishes protection, and unavailable
hook/helper bodies remain blockers. The historical Express-coupled contract remains readable for
saved reports, without being selected for fresh lookups. Protection says nothing about authorization,
valid-ID error handling, business validation or stored-content rendering.

A supplied `typeof` guard is evidence to assess against its enforcing branch and subsequent writes.
The bounded policy conservatively keeps a vulnerable model answer in Review when a relevant selected
field has preceding type-guard evidence that needs independent bypass review. It does not turn the
witness into a Protected result. This can leave real vulnerabilities inconclusive when another field
or path is unsafe; current controls expose that limit explicitly.

## Conditional values and conversions

Analysis MUST evaluate each output alternative separately. A conversion's guarantee applies only
to that output. For example, these actual calibration-control forms have different constraints:

```typescript
// No raw-text alternative: injection protection can hold; construction practice remains.
const id = req.query.mode === 'numeric' ? Number(req.query.id) : 0;
store.find({ $where: 'this.id == ' + id });

// The unconverted alternative still permits request text in the expression.
const id = req.query.mode === 'numeric' ? Number(req.query.id) : req.query.id;
store.find({ $where: 'this.id == ' + id });
```

The scanner verifies the unshadowed native `Number` binding and records bounded per-alternative
facts, including nested ternaries. It does not infer native semantics for a locally redefined
`Number`. Numeric output may include NaN/Infinity or conversion may throw; this does not establish
business validity. Unmodeled alternatives MUST remain explicit rather than inheriting a sibling's
constraint. The current numeric fact adapter recognizes numeric literals and native Number calls;
it does not claim arbitrary arithmetic/alias/heap reasoning.

Protection requires all relevant feasible alternatives to be protected. A vulnerability can be
scoped to one supported unsafe alternative, with its configuration precondition stated. Supplied
source proving a branch impossible excludes it; an unknown necessary path fact remains Inconclusive.
Do not require runtime exploitation to judge a source-supported path, or assume every configuration
is vulnerable merely because one unsafe path exists.

### Native hexadecimal digest output

A verified immutable namespace/default `crypto` or `node:crypto` import can model the exact chained
`createHash(literal).update(value[, 'utf8']).digest('hex')` result. The bounded algorithms are md5,
sha1, sha256, sha384 and sha512. The output on normal completion is hexadecimal text; errors may throw.
The contract follows helper-return dependencies, with exact import and expression witnesses. It does
not endorse a hash for password storage. Unknown encodings, constructors, mutation and unsupported
chains remain unmodeled. See the [Node Hash API](https://nodejs.org/api/crypto.html#hashdigestencoding).

A raw sibling alternative never inherits the digest's alphabet. If every SQL-text dependency carries
that verified hex transfer, a contradictory vulnerable model answer is conservatively kept in Review
with `injection_constraint_review`; construction practice and raw answers remain visible. This gate
cannot establish protection and is not a general proof of final output constraints after arbitrary
transformations. Fresh calibration found that the current judge can overcall both hex-only SQL and
scalar-guarded NoSQL, so model agreement alone is not an accuracy pass.

## Outcomes

- **Finding / soft red:** an injection-specific vulnerable judgment, required evidence and API
  contract, no claim blockers, and consistent path/coverage answers support a static vulnerability.
- **Finding / soft orange:** established executable-string construction practice to remediate. At
  least one built-in value must have an external origin (request, storage, file, fetched, browser or
  API response); a construction from constants, environment values or no resolved dependency is
  Review with `external_origin_not_established`.
- **Review / soft blue:** the problem or sufficient protection is Inconclusive.
- **Protected / soft green:** protection supported for the named injection claim.

Poor practice can remain orange alongside a protected injection facet. A definitive injection
finding upgrades the same operation record rather than duplicating its construction concern.
Input-validation status does not inherit the injection verdict. Raw answers stay in JSON.
These bounded judgments still require calibration: consistent model answers can be wrong.

## Library contracts

[Sequelize raw queries](https://sequelize.org/docs/v6/core-concepts/raw-queries/) describes query
arguments and value binding. [MarsDB DocumentMatcher](https://github.com/c58/marsdb/blob/master/lib/DocumentMatcher.js)
is the primary implementation reference for executable predicates and operator matching.

## Python adapter

[Python analysis](../python-support.md) verifies sqlite3 connection/cursor provenance and keeps
SQL text separate from the parameter operand. Percent/f-string/format/concatenation construction
remains a practice concern; bound values do not protect dynamic identifiers. Unknown pre-use calls
on the SQL value block an injection claim; transformations of unrelated bound values do not turn
literal SQL into executable interpolation. Python NoSQL is unimplemented and out of the current corpus.

Verified Python connection/cursor bindings also include Psycopg 2/3, PyMySQL and MySQL Connector.
Driver-specific placeholder contracts are supplied to the judge; a parameter operand does not
repair SQL text interpolated earlier. SQLite storage correlation is not extended to those drivers.
Contract references: [Psycopg 3](https://www.psycopg.org/psycopg3/docs/basic/params.html),
[Psycopg 2](https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries),
[PyMySQL](https://pymysql.readthedocs.io/en/latest/modules/cursors.html), and
[MySQL Connector](https://dev.mysql.com/doc/connector-python/en/connector-python-api-mysqlcursor-execute.html).

Generated Python handlers can now retain source-derived registry selection, captured request values,
local callback arguments and helper-returned SQLite connection/cursor provenance. A callback call by
itself is not value flow: the report includes the captured input and actual cursor/SQL-slot witnesses.
Unresolved or mutated registry/callback bindings remain gaps; schema setup and constant SELECT text
are not request-derived SQL findings. See the [bounded Python subset](../python-support.md#finite-generated-http-routes).

## PHP adapter

[PHP analysis](../php-support.md) verifies mysqli (OO and procedural, including the
`$GLOBALS["___mysqli_ston"]` converter idiom), PDO and SQLite3 connection handle provenance and
supplies driver-specific contracts (`php-mysqli-v1`, `php-pdo-v1`, `php-sqlite3-v1`).
Interpolated SQL text — encapsed strings and concatenation with the raw template preserved — is
a construction claim; `prepare`+`bindParam`/`bindValue`+`execute` records binding controls on
the same claim so the judge can assess the actual binding. A shadowed SQL function name stays
negative. INSERT column attribution is exact-count-or-skip and feeds `php-sql:<table>.<column>`
storage keys; SELECT headers resolve string and numeric `fetch_row` access for stored links. An
UPDATE/INSERT whose interpolation count does not match its column list produces no invented
origin. See the [bounded PHP subset](../php-support.md).

String-built SQL is weak construction practice even when no input can change its syntax. For injection on MySQL, a PHP value
cannot end the literal it sits in when it is escaped with `mysqli_real_escape_string` on the connection that runs the statement,
stands in a single-quoted literal and is not changed afterwards. The same escape protects nothing when the value is not in quotes,
is an identifier or a number, is changed after the escape, is sent to another engine, or reaches SQL run from that literal. It also
fails when the connection's character set was changed by a statement (`SET NAMES`) and not by the client. A value converted with `(int)` or `intval`, or checked
with `preg_match` against an anchored all-digit pattern on the path that uses it, is digits with at most a sign or a final line feed;
where it stands apart as a compared or listed value it cannot change syntax either. The scanner states such
a fact, or that a value is a hexadecimal hash, only for a narrow source pattern in which it can check all of this, and only when
every operand has one. The judge decides. The exact pattern and its limits are in
[query judgment](../../../.zazz/architecture/query-judgment.md#facts-about-constructed-php-sql-operands).

## GraphQL resolver sources

The bounded Apollo Node adapter binds schema coordinates to separate resolver invocations and
reuses the existing verified SQL library/API and value-flow rules. Actual `args.email` reads can
reach SQL text or separated bind operands through aliases and supported helpers. Parent, context
and info have independent unknown provenance; they are not relabeled as args. Unknown transforms,
applicable unknown guards, mutation and unsupported projections block definite claims. A guarded
registration cannot lend protection to another registration of the same resolver. Scalar/type names
and GraphQL parsing do not parameterize SQL. See [supported source boundaries](../running-scans.md#bounded-apollo-graphql-analysis).

## Query component selection

Supported SQL and JS/TS NoSQL candidates use an internal embedded component catalog. Static assembly
associates verified language/entry/flow capabilities and database operation contracts with the claim,
selects applicable interpretation material, and preserves required evidence obligations. The judge
consumes the same selection. A declared component does not implement an adapter or establish a source
edge. Unsupported bindings and unresolved applicability retain gaps instead of borrowing another
API's contract. Library-version assumptions remain explicit. NoSQL requires a verified collection or
model contract; Python NoSQL has no adapter and gains no detector.

JSON carries selection IDs, versions and digests; assessed queries also carry request provenance.
Changed effective component content, questions, evidence or protocol cannot replay an old answer.
Historical reports preserve their original evidence and judgments. Component composition leaves
validation, construction practice and injection protection independent and does not broaden existing
SQL or NoSQL coverage.

## Symfony

Symfony Doctrine DBAL and ORM calls separate executable query text from bound parameter values. Prepared statements report at execution and retain the query construction span. Source-backed QueryBuilder text fragments remain in the SQL operand. Bound finder criteria carry storage provenance where the entity mapping is known.

[Symfony analysis coverage](../symfony-support.md)
