# Database injection analysis

[Analysis index](README.md) · [Input validation](input-validation.md) · [Calibration](calibration.md)

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

The bounded automatic adapters currently include verified Sequelize raw-query usage and MarsDB
collection construction/imports. MarsDB has Mongo-style matching semantics; this does not make it
a MongoDB server or establish support for every MongoDB driver. Unsupported bindings remain Review.

## SQL rules

- Values interpolated or concatenated into executable SQL are a construction-practice finding.
- Actual query argument roles matter. Binding parameters or replacements preserve data separately
  from SQL structure; `model` or `plain` options do not protect an already-built SQL string.
- Interpolated ORM search values are not automatically executable SQL. Verify the library slot.
- A string merely constructed or logged without a database call is not an executed SQL sink.
- A vulnerability verdict requires request-controlled syntax on a supported path, independently of
  the construction-practice answer. Missing field validation alone does not prove SQL injection.

## NoSQL rules

- Analyze selector keys/values, update data, and executable expressions as different slots.
- An unconstrained request object in a selector value can introduce operators when the verified
  matcher supports them. Do not assume every structured document or update value is unsafe.
- MarsDB `$where` string values are executable JavaScript predicates. Untrusted expression text
  can change behavior; truncating text or stripping newlines does not exclude expression operators.
- A positively constrained scalar selector value can be protected from operator injection.
- JSON/body parsing is transport handling. It does not establish a per-field scalar schema.

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
- **Finding / soft orange:** established executable-string construction practice to remediate.
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
