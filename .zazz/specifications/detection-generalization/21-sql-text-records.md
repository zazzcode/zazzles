# Detection generalization 21 — SQL records and judgment with no driver contract

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Authorized** by the owner, 2026-11-26: "Yes, build spec 21", on the draft of this file. The decisions below were
  proposals in that draft and are taken as proposed. Measurements before it ran as build overlays outside the repository.
- **Branch** `detgen-02-1-check-fields`, lane A.
- **Evidence** [SQL driver independence](../../learnings/detection-generalization/sql-driver-independence.md): findings 6
  to 8, three paid rounds on Gemini. Overlays and runs: `_test-findings/detgen-sql-origin/` (`ov-judge/`, `ov-rec/`,
  `runs-judged/`).

## Capability

A call that passes SQL statement text to a database is recorded and judged whatever the driver, its version or the
database: Oracle, SQL Server, PostgreSQL, MySQL, SQLite and the next one. No driver, method or package is named in
scanner code or in the request. A new driver needs no change.

## What stays and what is new

| Part | Today | With this specification |
|---|---|---|
| Finding the call | A contract per driver: six in JavaScript, five in Python, five in PHP | The contracts stay. A call none of them records is recorded when an argument is SQL statement text |
| The record | `sql_query_candidate` with a driver contract | The same kind, contract `sql-text-v1`, slots `sql_text` and `sql_parameters` |
| The request | Contract text, binding evidence, coverage, 15 to 36 KB | `sql-text-operation`: SQL notes, the call, the values, the source, two closed questions, 4 to 14 KB |
| Deciding it is a database call | The contract | The judge's `operation` question |
| Language-specific code | Recognition and evidence per driver | One hook per language that reads the argument's text and the request data in it |

## Invariants

1. No list of drivers, packages, methods, applications or routes in the new code or the request.
2. A record a contract makes today keeps its record and its request byte for byte.
3. Protected needs the bound value to be read by the scanner as a separate argument or a bind call (slot
   `sql_parameters`) and the judge's `data_only` at the floor. A judged limit bars Protected (specification 20).
4. A call with SQL text and no request or stored value is not recorded.
5. A stored or session value is sent under its own name; a record with only stored values is Review.
6. The statement test and the record shape are one shared component. A language hook only reads its own syntax.

## Scope

| Path | Change |
|---|---|
| `scan/internal/analysis` or `parse` | Shared: the SQL statement test, the slot rule, the record's completeness roles |
| `scan/internal/langjs`, `langpy`, `langphp` | One hook each after the contract paths: collect the argument's literal text, call the shared test, emit the record |
| `scan/internal/analysispacks` | Register `sql-text-v1` and the protocol `sql-text-operation-v1` |
| `scan/internal/judge` | The request, questions and policy (from `ov-judge/sql_text_operation.go`); source excerpts supplied by the recorder, not read from disk |
| `docs/scan/analysis` | The database injection guide: what is recorded without a contract and how it is judged |
| Tests | The 27 driver forms and their bound twins as fixtures; non-database calls that take SQL text; request shape |

Out of scope: replacing a contract; ORM finders and builders with no SQL text; other sinks; JavaScript tagged templates.

## Decisions

- **D-1. Contract-less JavaScript `query` records.** Today pg, mysql2, mysql and mssql are recorded by "a method named
  `query`" and held at Review by `sink_binding_unverified`. Judged with the driver-free request all four were Confirmed
  and their bound twins not. *Proposed:* these records take `sql-text-v1`. It is the largest single gain and needs no
  recorder.
- **D-2. Duplicates in PHP.** The overlay recorded each bind call of a statement and `prepare` calls whose statement a
  contract records at `execute`. *Proposed:* one record per statement, at the call that runs it; nothing where a contract
  record exists for the same statement.
- **D-3. Where the source comes from.** The overlay read whole files from the scan root in the judge. *Proposed:* the
  recorder attaches the excerpts (the handler, the functions on the path, the file of the call when small, an included
  file) as context evidence, so the judge reads no file.
- **D-4. Invocation ids.** A record added to an entry changes the ids of the entry's other records, because the
  invocation id hashes the entry's controls. Saved traces and equivalence signatures for those records change. *Taken:*
  accepted. A1 compares those records with the two id fields left out.
- **D-5. The Protected floor.** 0.95, taken from MongoDB. On collected answers 0.85 keeps 67 of 79 safe records Protected
  with none wrong, but three wrong answers set that margin. *Proposed:* keep 0.95 until a held-out sample says otherwise.
- **D-6. The escaped, unquoted value.** Three DVWA records are Review under the driver-free request and Confirmed by the
  contract request. A rewording made it worse. *Proposed:* contract records keep the contract request (invariant 2), so
  nothing is lost; the case is open only for records with no contract.
- **D-7. The standing judge.** Every measurement is on Gemini. gpt-6-luna was the noisier judge on the MongoDB lab.
  *Taken:* A2 on Gemini in this work. gpt-6-luna needs the owner's word for the run and is reported as not measured until then.

## Acceptance

| | Check |
|---|---|
| A1 | Every contract record and its request byte-identical on the twelve samples; ids per D-4 |
| A2 | The 27 driver forms: every injectable form with a text record Confirmed, no bound twin Confirmed, on Gemini. gpt-6-luna: D-7 |
| A3 | Non-database calls that take SQL text: recorded, not Confirmed |
| A4 | Not part of this work: a held-out application with an uncontracted driver, found by the owner per the held-out protocol: findings and false findings read by someone who did not write the recorder |
| A5 | Scan time within 10% on Juice Shop, DVWA and vulnpy |

## What is known not to work yet

At the first results below: text built by `join`, a helper or another module; statements outside a short list; a
JavaScript value bound in a different call from the text; a tagged template. The follow-up section at the end covers
these.

## Results (2026-11-26)

Implemented on `detgen-02-1-check-fields`. Paid runs: 174 Gemini `gemini-decision-1` and 72 OpenAI `gpt-6-luna` requests,
pass rule written first (`_test-findings/detgen-21/PASS-RULE.md`; reports and traces under `judged/`).

| | Result |
|---|---|
| A1 | Twelve samples: no existing record missing or changed in content. Added: 43 on DVWA, 1 on vuln-demo-app, 0 elsewhere. Ids of other records change in entries that gain one (D-4) |
| A2 | Gemini: 18 of 18 injectable forms with a text record Confirmed; 0 of 19 bound twins Confirmed (16 Protected, 3 Review). gpt-6-luna: 18 of 18 Confirmed; 0 of 19 twins Confirmed (5 Protected, 12 Review, 2 not a database operation) |
| A3 | `log.info` and `print` taking SQL text with request data: recorded, answered not a database operation by both judges |
| A4 | Not part of this work. One file nobody here wrote (`sast-testbench/js-samples/sql_injection.js`), missed before, is Confirmed by both judges |
| A5 | Juice Shop within noise (28.7 s both), DVWA about 3%, vulnpy about 4% |
| Gates | `go build`, `go vet`, `go test ./scan/...` pass. Goldens updated for the converted `string-flow` record and the new fixtures |

**Driver forms, injectable, Confirmed** (the contract records of the same fixtures included):

| Language | `stage` | This branch, Gemini | This branch, gpt-6-luna |
|---|---:|---:|---:|
| JavaScript, 10 | 1 | 9 | 9 |
| Python, 9 | 4 | 9 | 9 |
| PHP, 8 | 3 | 8 | 8 |

The one not Confirmed is the Sequelize contract record blocked by an enclosing `res.json(...)` call; contract records are
out of scope.

**DVWA, the 43 added records (Gemini)**

| Records | What | Truth | Outcome |
|---:|---|---|---|
| 6 | `$sqlite_db_connection->query($query)` in `sqli` and `sqli_blind`, low, medium and high, under the file's own entry | Injectable | 6 Confirmed |
| 1 | `pg_query($insert)` in the PostgreSQL set-up script, `SERVER_NAME` in a quoted literal | Injectable, set-up script | Confirmed |
| 36 | Bind calls of prepared statements in the `impossible` and `bac` files, under entries where no contract records the statement | Safe | 18 Protected, 10 Review, 8 not a database operation; 0 Confirmed |

**Changes made during the work**

- **A reading limit bars Protected only.** The first version held a text record with any blocker at Review, which lost
  the SQLAlchemy `text()` form the prototype had confirmed. Limits on the text and its values now bar Protected and the
  record is sent, as measured.
- **`bound_parameters_only` applies.** gpt-6-luna Confirmed two bound forms of the extra Python fixture (0.74 and 0.67
  for `statement_text`) though the request value is only in the parameter list. The existing guard of contract records
  now covers text records: such an answer is Review. Unit-tested; the two records were not re-sent.
- **The shared statement test is stricter than the prototypes'** ("Select a file from the list" does not match). It
  gained and lost no record on any sample.

- **The Python wrapper rule is a shape, not a list of names.** The hook first knew a call that only wraps the text
  (`conn.execute(text("..."))`) by eight names. It now knows it by shape: a call with exactly one argument that is a
  string expression, followed one level. The call that takes the wrapper is the record. No record changed on the four
  Python samples or the fixtures. A database call whose result is passed straight to a method
  (`rows.append(db.execute(q))`) is recorded at the outer call, which holds the inner one.

**Known gaps**

- gpt-6-luna keeps few bound twins Protected (5 of 19); they are Review, not findings.
- In DVWA the 36 bound records are for files requested directly, where the database handle is not defined. They are
  safe and not findings, and they add requests.
- No held-out application (A4).

## Follow-up (2026-11-26): text not followed, and where a value lands

Asked by the owner on the gaps above. Pass rules written first (`_test-findings/detgen-21/PASS-RULE.md`). Paid: 16 + 97
Gemini `gemini-decision-1` requests; gpt-6-luna not run.

**Added**

| Part | What |
|---|---|
| All three hooks | Text built by `join`/`implode`, by the returns of one helper in the scanned source, and from a constant or helper of another scanned file; PHP also `sprintf`/`vsprintf` conversions, heredoc and class constants. Definitions read through are attached as source |
| All three hooks | `statement_shape`: the literal text with each non-literal part numbered and placed inside a quoted literal or outside quotes (`parse.SQLTextPlacement`). The request sends it as `statement` |
| JavaScript | One record per statement object for a value bound in a call apart from the text |
| JavaScript | Tagged templates, marked `template_tag`; the request says so |
| Judge policy | **D-8.** A finding on a tagged template needs the tag function in the scanned source; otherwise Review (`template_tag_unresolved`). Protected for a tagged template rests on the judge's reading of the tag, an exception to invariant 3 taken on the owner's standing preference that the judge recognizes libraries |
| PHP | `sprintf`, `vsprintf`, `implode` and `join` are no longer recorded as the call themselves |

**Results (Gemini)**

| Set | Before | After |
|---|---|---|
| Escaped value outside quotes, 7 text records and 1 contract record | 8 Confirmed, one at 0.49 against 0.49 | 8 Confirmed, the lowest text record at 0.93 |
| Escaped value inside a quoted literal, 7 text records | 1 Confirmed (false), 6 Review | 0 Confirmed, 7 Review |
| Driver forms and extra forms, 42 records, contract records included | 36 Confirmed, 2 Protected, 2 not a database call, 1 Review, 1 not sent | The same outcome for every record |
| DVWA `sqli`, `sqli_blind` and set-up script, 7 text records | 7 Confirmed | 7 Confirmed |
| New forms, injectable: join, helper, other file, constant, class attribute; 13 records in three languages | Not recorded | 13 Confirmed |
| New forms, bound twins: 6 records | Not recorded | 3 Protected, 3 Review, 0 Confirmed |
| Tagged templates, 6 forms | Not recorded | Local tag that concatenates: 2 of 2 Confirmed. Library tag called directly: Protected. Local tag that binds, and a Prisma raw tag: Review. A library tag passed as an argument was Confirmed at 0.56, which is false; D-8 makes it Review (unit-tested, not re-sent) |

No existing record on the twelve samples changed apart from the added `statement_shape` key; none of the samples holds
one of the new forms, so no record was added on them. Scan time unchanged on Juice Shop, DVWA and vulnpy.

**Still open**

- Every new form is in fixtures the implementers wrote. No sample application holds one, so this proves the path only.
- The escaped value inside a quoted literal is Review, not Protected: the judge's `data_only` stays below 0.95, and two
  of these records have a reading limit. The existing `php-sqlite3-v1` contract request Confirms that safe form; contract
  records are out of scope here.
- Not followed: a helper called by a helper; a list built by a comprehension, `map` or `filter`; a chained
  `prepare(...).get(x)`; a variable assigned in an included PHP file; a JavaScript list pushed in two-argument calls.
- A SQL fragment appended to a list in Python is recorded at the `append` call as well as at the executing call.
- gpt-6-luna has not seen the `statement` field or a tagged template.
- No held-out application (A4).
