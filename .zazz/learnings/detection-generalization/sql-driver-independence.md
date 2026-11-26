# SQL driver independence: what the scanner recognizes today, and what package origin adds

2026-11-26, branch `detgen-02-1-check-fields` at `stage` `a5fe8c9`. Findings 1 to 6 are offline; findings 7 and 8 used about
480 paid Gemini requests in three rounds. Evidence is in
`_test-findings/detgen-sql-origin/` (diagnostic build by `go build -overlay`, fixtures, run outputs, `compare.py`).

**The goal (owner, 2026-11-26).** Code Scan stays accurate with no code or rule change for a new database version or a
different driver (Oracle, MySQL, PostgreSQL, SQL Server). Working across application languages is a plus. Options are judged
on accuracy equal to or better than today's, with a strategy that is less fragile and serves other databases and other sinks.

## The findings

1. **Recognition is per driver in every language, and most drivers are not recognized.** The same injectable handler,
   written once per driver, is judgeable for 9 of 27 driver forms.
2. **Package origin finds the SQL call for every JavaScript driver tried, with no driver code.** 10 of 10 forms, against 2
   judgeable today.
3. **On real samples origin matches the contracts where the client comes from a package import, and misses two shapes**: a
   model class that inherits from a package class, and Prisma raw calls on the reserved control (cause not confirmed).
4. **Origin as written is too slow to switch on for a large application.** Juice Shop took 128 s with the SQL packages in the
   table; specification 19 records 28 s for `stage`. Not timed side by side.
5. **Python and PHP have no origin search.** Each lists its drivers by name.
6. **Recognizing SQL by the text in the argument, whatever the callee, found every contract record that carries request data
   in its SQL text**: 159 of 159 across twelve samples and three languages, and 27 of 27 driver forms. It also logged one
   call that is not a database call. See [the section below](#recognition-by-the-sql-text-in-the-argument).
7. **A judge request that carries nothing from a driver contract gave the same outcome on 131 of 164 records compared, and missed the pass rule by one record** (Gemini, paid). It lost one true finding to Review, confirmed two the
   contract path blocks, cleared five false findings and made three of another kind. It kept fewer safe records Protected.
   A second round kept one fix (stored values named as such) and reverted one (a rewording that lost two more).
   See [judged without a contract](#judged-without-a-contract).
8. **A recorder that names no driver made records for all 18 driver forms missed today, and the judge got 26 of 27
   injectable forms right, with no bound twin Confirmed** (Gemini, paid, forms written by the implementers). A file nobody
   here wrote, missed today, was Confirmed. See [records made with no contract](#records-made-with-no-contract-judged).

## Driver swap (forms the author of this page wrote)

One route per driver, the request value concatenated into the SQL text. These forms show what is recognized. They are not
evidence of accuracy: forms an implementer writes pass.

| Language | Judgeable today | Recorded, blocked by `sink_binding_unverified` | Not recorded |
|---|---|---|---|
| JavaScript, 10 | better-sqlite3, Sequelize | pg, mysql2, mysql, mssql (a method named `query`) | oracledb (`execute`), sqlite3 (`all`), knex (`raw`), postgres (`unsafe`) |
| Python, 9 | sqlite3, psycopg2, pymysql, mysql.connector | | oracledb, cx_Oracle, pyodbc, pymssql, SQLAlchemy `text` |
| PHP, 8 | mysqli, `new PDO`, SQLite3 | | `new \PDO` in a namespace, a class that extends `PDO`, `pg_query`, `sqlsrv_query`, `oci_parse` |

With 30 SQL packages added to `storePackages` under a diagnostic kind that records nothing, the origin search of
`langjs/package_origin.go` returned the package for all 10 JavaScript calls, each with the request value in argument 0.

## Origin against the contract records of real samples

A distinct call is counted once. "Origin" means the call derives from a table package and an argument holds request data.
Every report was byte-identical to the base report, as a diagnostic must be.

| Sample | SQL calls the contracts record | Found by both | Contract only | Origin only |
|---|---:|---:|---:|---:|
| vuln-nextjs `f5d47de` (PGlite) | 10 | 10 | 0 | 0 |
| vuln-demo-app `d27b35b` (sql.js) | 2 | 2 | 0 | 1 |
| Juice Shop `f189f52` (Sequelize) | 3 | 2 | 1 | 0 |
| nodejs-goof `add14ba` (TypeORM) | 0 | 0 | 0 | 1 |
| vulnerable-typescript-app `7f8b240` | 0 | 0 | 0 | 0 |
| oss-oopssec-store `2d530ef`, counts only | 5 | 2 | 3 | 0 |

- **Contract only, Juice Shop:** `ProductModel.findAll` in `routes/chat.ts`. The model is `class Product extends Model`, with
  `Model` imported from `sequelize`. The origin search follows names, members, calls, parameters and constructed objects. It
  does not follow a superclass, so none of the 72 model calls in `routes/` derives from the package.
- **Contract only, oss-oopssec-store:** three `prisma-raw-v1` records. The source was not opened (reserved control), so the
  cause is not confirmed. The Prisma contract accepts a client generated to another path; the origin table lists only
  `@prisma/client`.
- **Origin only, vuln-demo-app:** `db.run` with the request value in the bound-values argument. The contract leaves it out by
  design: only request data in the SQL text slot is a claim.
- **Origin only, nodejs-goof:** TypeORM `repo.save(user)` with an object built from the request body. Not SQL text.
- **vulnerable-typescript-app** lists pg, knex, mysql, sequelize and typeorm in `package.json` and imports none of them.

So the statement in [package knowledge](package-knowledge.md) still holds for the nine samples: none has a call that puts
request data into the SQL text of a driver without a contract. Driver independence cannot be measured on them.

## Recognition by the SQL text in the argument

The second probe ignores the callee. It logs any call with an argument whose string is built from SQL text (a statement
such as `SELECT … FROM`, `INSERT INTO`, `UPDATE … SET`), and whether the flow carries request data into that argument. One
diagnostic overlay per language, written by subagents to one brief; none changes a report (every report byte-identical).

**Driver swap:** 10 of 10 JavaScript, 9 of 9 Python and 8 of 8 PHP forms logged with request data, against 9 of 27 judgeable
today. `new \PDO`, a PDO subclass, `pg_query`, `sqlsrv_query` and `oci_parse` need nothing: the text is the same.

**Against the contract records.** A record counts once per entry here. "Found" means the probe logged a request-carrying
SQL-text call at the record's position, or at another call of the same entry (a helper that takes the text as a parameter).

| Sample | SQL records | Request data in the SQL text | Found by text | Other records | Text calls in entries with no such record |
|---|---:|---:|---:|---:|---:|
| Juice Shop | 3 | 2 | 2 | 1 | 0 |
| vuln-demo-app | 5 | 5 | 5 | 0 | 0 |
| vuln-nextjs | 10 | 3 | 3 | 7 | 0 |
| oss-oopssec-store, counts only | 5 | 5 | 5 | 0 | 0 |
| nodejs-goof | 0 | 0 | 0 | 0 | 0 |
| vulnerable-typescript-app | 0 | 0 | 0 | 0 | 1 |
| DVWA | 108 | 61 | 61 | 47 | 1 |
| vuln-symfony | 3 | 2 | 2 | 1 | 0 |
| vulnpy | 78 | 78 | 78 | 0 | 0 |
| ThreatByte | 29 | 2 | 2 | 27 | 0 |
| vulnerable-flask-app | 1 | 1 | 1 | 0 | 0 |
| python-insecure-app | 0 | 0 | 0 | 0 | 0 |
| **All** | **242** | **159** | **159** | **83** | **2** |

- **Every record that can be an injection through the SQL text was found without naming a driver**: 159 of 159, in three
  languages, including the three Prisma raw calls and the Doctrine DBAL calls that package origin did not reach.
- **The 83 other records are not candidates for text injection.** 48 hold request data only in bound values (`sql_parameters`,
  `sql_options`): the safe controls a report shows as Protected. 33 in DVWA hold no request data (set-up scripts). One is a
  Sequelize finder and one a Doctrine query builder, which have no SQL text. The text probe sees the text of the 48 and logs
  it without request data; a recorder would need the second argument, or the later bind, to keep them.
- **The two extra calls show both sides.** `pg_query` in DVWA's PostgreSQL set-up is a database call no contract knows.
  `console.log('Query:', query)` in vulnerable-typescript-app is not a database call: the text is SQL and nothing runs it.
  Text alone cannot tell these apart. Package origin, the existing log-sink binding, or the judge's `operation` question can.
- **The first Python run missed all 78 vulnpy records**, because the probe did not follow a module-level constant used with
  `.format` inside a nested function. That was the probe's text collection, fixed in one pass; the flow already carried the
  request data. It shows where this approach is fragile: finding the literal text, not naming the callee.

**How firm.** The samples are the development set, and "found" is measured against records the contracts already make, so
this shows equivalence of recording on known code, not new findings. The driver-swap forms are the author's. The statement
test is a short list of patterns; it was not tried on stored procedures, dialect-specific statements or text built by
`join`, a builder or another module.

## Judged without a contract

The first paid comparison (2026-11-26, Gemini `gemini-decision-1`, SQL family only, about 280 requests). The records are the
ones the contracts make today. Each was judged twice: with today's contract request, and with a request that sends no
contract text, no binding evidence and no blocker. Evidence: `_test-findings/detgen-sql-origin/runs-judged/` (reports,
traces, `PASS-RULE.md` written before the first request) and `ov-judge/` (the overlay).

**The driver-free request** (`sql-text-operation-v1`, modelled on protocol v2 for MongoDB): notes on SQL as a query language
that name no driver; the entry note where one exists; the call; the request values; the handler, the functions the values
pass through and the file of the call when it is under 16 KB; two closed questions (`operation`, `request_control`).
Protected needs `data_only` at 0.95 or more. Scanner blockers of the contract path are not applied.

| Sample | Records compared | Same outcome | Different |
|---|---:|---:|---:|
| vulnerable-flask-app, vuln-demo-app, vuln-nextjs, vuln-symfony, Juice Shop, oss-oopssec-store (counts only) | 27 | 27 | 0 |
| ThreatByte | 29 | 16 | 13 |
| DVWA (75 sent driver-free, 53 by contract; 33 not sent either way) | 108 | 88 | 20 |
| vulnpy, driver-free only; all 78 injectable by construction | 78 | 78 Confirmed | |

**The 33 disagreements, each labelled from the source**

| Contract request | Driver-free request | Records | Truth | Reading |
|---|---|---:|---|---|
| Confirmed | Review | 1 | Injectable | `sqli/source/medium.php`: the value is escaped and placed unquoted. Answered `data_only` at 0.74. **A true finding lost** |
| Confirmed | Review 4, Protected 1 | 5 | Safe | `login.php`, `xss_s` medium and high: escaped inside a quoted literal. Five false findings of the contract request gone |
| Review, blocked | Confirmed | 2 | Injectable | `bac` low and medium: `X-Forwarded-For` inside a quoted literal of an `INSERT`. Two true findings gained |
| Review, blocked | Confirmed | 3 | Not a request injection | `bac`: the session user name concatenated into the text. The request listed a session value as a request value |
| Review | Protected | 2 | Safe | A digits check with `intval`; bound values |
| Protected | Review | 20 | Safe | `data_only` chosen at 0.62 to 0.94, below the floor. 12 in ThreatByte are plain bound values |

**Against the pass rule**

1. *No true finding lost*: **failed by one record** (`sqli/source/medium.php:12`). The twin in `sqli_blind` was Confirmed.
2. *No injectable record Protected*: held.
3. *False findings not up*: held, 3 against 5, and of a different kind.

**What it shows**

- **The contract is not what makes most SQL records judgeable.** With no contract text, 27 of 27 records in six samples and
  78 of 78 in vulnpy have the right outcome, including eight safe controls whose request data is only in bound values. The
  judge read the placeholder and the separate argument from the source.
- **Whole categories of scanner blocker were not needed by a reader.** The contract path withholds 22 DVWA records before
  sending (`php_loop_unresolved`, `storage_origin_unresolved`). Sent, two are true findings. This is rule 10 again.
- **The contract request confirms escaped quoted literals; the driver-free one does not.** Five against none. The same
  sentence about escaping is the likely cause of the one loss: the model accepted escaping where there are no quotes.
- **Protected is weaker.** 20 safe records fell to Review because the answer was not certain enough. The 0.95 floor was set
  for MongoDB documents; it was not tuned here. The weight left over went to `statement_text` in 40 of 44 such answers.
- **The request must say what kind of value it lists.** A session value sent as a "request value" was judged as one.
- **The requests are a quarter of the size where the handler is a function** (median 4 to 9 KB against 15 to 36 KB). On
  DVWA, whole included files make them 14 KB against 26 KB.

**How firm.** One run, one model, one wording. These are development samples. The 131 agreements were not labelled one by
one, so an outcome both requests share can still be wrong. DVWA and ThreatByte carry every disagreement; the other samples
are easy. The policy floor and the question were written once and not iterated.

### Round 2: one fix kept, one reverted

104 requests (DVWA 75, ThreatByte 29), pass rule written first. Two changes in one request version:

| Change | Result | Keep |
|---|---|---|
| Session and database values sent as `stored_values`; a record with only stored values is Review by policy | The three session records are no longer Confirmed. Both `X-Forwarded-For` findings stayed Confirmed. ThreatByte Protected went from 12 to 15 of 24 | **Yes** |
| "Escaping does not help outside a quoted literal" written into the `statement_text` and `data_only` choices | The target (`sqli/source/medium.php:12`) stayed `data_only` at 0.75, and two near twins that were Confirmed fell to Review (0.68 to 0.32, 0.62 to 0.46 for `statement_text`) | **No**, reverted |

- **Round 2 failed its pass rule**: three true findings in Review against one in round 1. No injectable record is Protected.
- **The escaped, unquoted number is a weak answer for this model, not a missing sentence.** The same call at the same line
  is Confirmed in one entry and Review in another, and a wording change moved two of five such records. This is rule 16
  and rule 18 again: a wording change reshuffles the weak answers and need not hit its target.
- **Today's contract request confirms all of them**, and also confirms the five escaped *quoted* values, which are safe. It
  does not tell the two cases apart either; it answers "vulnerable" to both.
- The five escaped quoted records stayed out of Confirmed in both rounds (two are now Protected, correctly).

**State of the overlay after round 2:** round 1 wording with `stored_values`. That combination was not sent as such.

### The Protected floor, from the answers collected

No new request. All `data_only` answers of the driver-free request for a record with a request value: 79 on a safe record,
3 on an injectable one (the `sqli` medium records, at 0.48, 0.67 and 0.75).

| Floor for Protected | Safe records Protected, of 79 | Injectable records Protected |
|---:|---:|---:|
| 0.95 (in use) | 43 | 0 |
| 0.90 | 58 | 0 |
| 0.85 | 67 | 0 |
| 0.80 | 74 | 0 |
| 0.76 | 76 | 0 |
| 0.70 | 76 | 1 |

- **A lower floor would keep most safe records Protected**: 0.85 keeps 67 of 79 with 0.10 above the worst wrong answer.
- **It is not a reason to lower it yet.** Three wrong answers in one run, one model and one wording set that margin, and
  rule 19 stands: on the MongoDB lab a wrong answer reached 0.98. The lowest safe answers (0.65) are plain bound values in
  ThreatByte, below the highest wrong one (0.75), so no floor separates the two.
- The floor is a cost setting, not an accuracy fix. What would move it is the injectable answers leaving `data_only`.

## Records made with no contract, judged

Round 3 (2026-11-26, Gemini, 89 requests, pass rule written first). Three recorder overlays, one per language, written
by subagents to one brief (`_test-findings/detgen-sql-origin/RECORDER-BRIEF.md`, overlays in `ov-rec/`). Each turns the
SQL-text probe into a recorder: a call with SQL statement text in an argument, that no contract records, becomes a
`sql_query_candidate` with the neutral contract id `sql-text-v1`. Request data in the text gives slot `sql_text`; request
data only in another argument, or in a bind call on a statement prepared from the text, gives `sql_parameters`. The judge
uses the driver-free request for these records and today's request for contract records.

**The 27 driver forms, injectable, and their bound twins**

| Language | Injectable forms Confirmed, today | With the recorder | Bound twins Protected | Bound twins Confirmed |
|---|---:|---:|---:|---:|
| JavaScript, 10 | 1 | 9 | 4 of 7 recorded (3 Review) | 0 |
| Python, 9 | 4 | 9 | 9 of 9 | 0 |
| PHP, 8 | 3 | 8 | 8 of 8 | 0 |
| **All, 27** | **8** | **26** | **21 of 24 recorded** | **0** |

- **Oracle, SQL Server, PostgreSQL and MySQL drivers are judged in all three languages with no driver named anywhere**:
  oracledb, cx_Oracle, pyodbc, pymssql, SQLAlchemy `text`, `pg_query`, `sqlsrv_query`, `oci_parse`, `new \PDO`, a PDO
  subclass, sqlite3, knex, postgres.
- **The four common JavaScript drivers (pg, mysql2, mysql, mssql) needed no recorder.** They already have a record from "a
  method named `query`", held at Review by `sink_binding_unverified`. Judged with the driver-free request, all four are
  Confirmed and their bound twins are Protected or Review.
- **The one form not Confirmed is a contract record.** Sequelize `query` inside `res.json(...)` carries
  `input_helper_unresolved` from the enclosing call and is not sent.
- **A file nobody here wrote**: `sast-testbench/js-samples/sql_injection.js`, `db.get(query, cb)` on the `sqlite3` package.
  No record today; recorded and Confirmed at 1.00.
- **Calls that are not database calls were sorted by the judge.** `log.info` and `print` taking SQL text with request data
  were recorded and answered `not_database_operation` (Python fixture). The `operation` question does the work package
  origin was meant to do here.
- **Forms beyond the fixtures** (Python, the agent's own): f-string, `%`, `.format` of a constant, keyword argument,
  `CREATE TABLE` and `DROP TABLE` with a request name: all Confirmed; two bound forms Protected.

**On the real samples**

| Sample | Records added | What they are |
|---|---:|---|
| Juice Shop, vuln-nextjs, nodejs-goof, vulnerable-typescript-app, oss-oopssec-store, vuln-nestjs, vuln-drupal | 0 | Contracts cover every SQL call there |
| vulnpy, ThreatByte, vulnerable-flask-app, python-insecure-app | 0 | The same |
| vuln-demo-app | 1 | A bound `db.run` the contract leaves out. Protected |
| vuln-symfony | 2 | `prepare($rawSql)`, the same statements a contract records at `executeQuery`. Duplicates |
| DVWA | 49 | 42 bind calls of statements a contract records at `execute()` (duplicates); 6 SQLite `query` calls under another entry; 1 `pg_query` in a set-up script. Not judged |

- **No existing record changes its content.** In an entry that gains a record, the ids of the other records change,
  because the invocation id is a hash of the entry's controls (13 uses in DVWA, 1 in vuln-demo-app).
- **Cost:** none measurable on Juice Shop (27 s) and DVWA; about 20% on vulnpy (2.5 s to 3.1 s).

**Against the pass rule:** every injectable form with a new record is Confirmed; none is Protected; no safe twin is
Confirmed; the non-database calls are not Confirmed. **Passed.**

**How firm.** The fixtures and twins were written by the implementers, so this shows the path works end to end and not
how accurate it is on code in the wild (rule 20). One held-out file is one file. The development samples add almost no
records, so they cannot measure it either. What is still needed is an application nobody here tuned for that uses an
uncontracted driver; none is on this machine.

**What the recorders do not do, as built**

- Text built by `join`, a helper that returns SQL, a class constant or another module is not followed.
- Statements outside a short list (`PRAGMA`, `SET`, `SHOW`, `TRUNCATE`) are not recognized.
- JavaScript: a value bound in a different call from the text (`prepare(lit).all(v)`, `request().input().query(lit)`) gets
  no record, so that safe form is simply absent. A tagged template is recorded as text even where the driver binds it.
- PHP: one record per bind call, and duplicates of contract records at `prepare`. Both need removing.
- The contract id is not registered: outside the overlay the standard judge path rejects it.

**Next, in order.** (1) Specify and build the recorder in the repository: one shared SQL-text test and record shape, three
thin language hooks, the `sql-text-operation` request and its policy in the judge, with the duplicates above removed.
(2) Judge the contract-less JavaScript `query` records the same way; that alone covers pg, mysql2, mysql and mssql.
(3) Find a held-out application with an uncontracted driver before any accuracy claim. (4) The same shape for other sinks
that pass text to an interpreter (commands, templates, LDAP, XPath) is untested.

### In the repository (specification 21)

The recorder and the request are now code, not overlays:
[specification 21](../../specifications/detection-generalization/21-sql-text-records.md) holds the results. On the same
fixtures, with no overlay and no switch: 18 of 18 injectable forms with a text record Confirmed on Gemini and on
gpt-6-luna, no bound twin Confirmed on either. Three things the overlays did not show:

- **gpt-6-luna Confirmed two bound forms** until the existing `bound_parameters_only` guard was applied to these records.
  The scanner knew the value was in the parameter list; the model's answer had no witness.
- **gpt-6-luna keeps 5 of 19 bound twins Protected, Gemini 16.** The rest are Review.
- **Holding a record at Review for a limit on its own text lost a true form** (SQLAlchemy `text()`). Rule 10 applies to
  the text's own limits too: show the code, bar only Protected.

### Earlier next steps, still open

(1) The escaped-unquoted case needs evidence, not wording: whether the value sits inside quotes in the
statement text is something a recorder can read from the literal. Record it and try it as the scanner's statement of where
the value lands, replacing the model's reading of it, on the six `sqli` medium records only. (2) Set the Protected floor
from the answers collected (the weight below 0.95 goes to `statement_text` on plain bound values). (3) Done for the loop gap in
[specification 20](../../specifications/detection-generalization/20-sql-flow-wide-limits.md): the two real findings are Confirmed by the contract request, with one new false finding. (4) Then build the recorder for
drivers with no contract, which no run here tested: every record was made by a contract.

## What this means

- **Text recognition and package origin are complements.** Text finds raw SQL for any driver, version and language, and needs
  no table. Origin finds calls with no SQL text (ORM finders, builders, document databases) and tells a database call from a
  log line. Neither needs a contract per driver.
- **A contract is still worth keeping where it computes evidence** (which argument is bound, single or multiple statements).
  Moving Mongoose records to the generic request lost findings
  ([request wording and agreement](request-wording-and-agreement.md)).
- The origin search is the part that already works across drivers. For SQL it needs three things first: a superclass step,
  a client generated outside its package, and a cost that does not grow with every call of a large application.
- "A method named `query`" is today's fallback in JavaScript. It records four common drivers and then blocks them, so a real
  injection through `pg` or `mysql2` can at best be Review.
- A table of packages is still a list. It is one line per package and not one adapter per driver, and it does not help PHP's
  built-in functions, which have no import.
- The origin-only calls are the kind a judge has to sort: a bound value, an ORM write. They are few here (2 in six samples).

## Not measured

A held-out application with an uncontracted driver. The same comparisons on gpt-6-luna, the standing judge.
Origin for Python or PHP. The scan-time cost of the text probe. Scan time side by side. An application nobody tuned for that uses an uncontracted SQL driver.
