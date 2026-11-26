# Detection generalization 21 — SQL records and judgment with no driver contract (draft)

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Status** Draft for the owner. **Not authorized, not implemented.** Everything measured so far ran as build overlays
  outside the repository.
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

## Scope (proposed)

| Path | Change |
|---|---|
| `scan/internal/analysis` or `parse` | Shared: the SQL statement test, the slot rule, the record's completeness roles |
| `scan/internal/langjs`, `langpy`, `langphp` | One hook each after the contract paths: collect the argument's literal text, call the shared test, emit the record |
| `scan/internal/analysispacks` | Register `sql-text-v1` and the protocol `sql-text-operation-v1` |
| `scan/internal/judge` | The request, questions and policy (from `ov-judge/sql_text_operation.go`); source excerpts supplied by the recorder, not read from disk |
| `docs/scan/analysis` | The database injection guide: what is recorded without a contract and how it is judged |
| Tests | The 27 driver forms and their bound twins as fixtures; non-database calls that take SQL text; request shape |

Out of scope: replacing a contract; ORM finders and builders with no SQL text; other sinks; JavaScript tagged templates.

## Decisions to take before implementation

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
  invocation id hashes the entry's controls. Saved traces and equivalence signatures for those records change. *Open:*
  accept, or keep the new record's controls out of the hash.
- **D-5. The Protected floor.** 0.95, taken from MongoDB. On collected answers 0.85 keeps 67 of 79 safe records Protected
  with none wrong, but three wrong answers set that margin. *Proposed:* keep 0.95 until a held-out sample says otherwise.
- **D-6. The escaped, unquoted value.** Three DVWA records are Review under the driver-free request and Confirmed by the
  contract request. A rewording made it worse. *Proposed:* contract records keep the contract request (invariant 2), so
  nothing is lost; the case is open only for records with no contract.
- **D-7. The standing judge.** Every measurement is on Gemini. gpt-6-luna was the noisier judge on the MongoDB lab.
  *Proposed:* gate G-acceptance on both.

## Acceptance (proposed)

| | Check |
|---|---|
| A1 | Every contract record and its request byte-identical on the twelve samples; ids per D-4 |
| A2 | The 27 driver forms: every injectable form Confirmed, no bound twin Confirmed, on Gemini and on gpt-6-luna |
| A3 | Non-database calls that take SQL text: recorded, not Confirmed |
| A4 | A held-out application with an uncontracted driver, found by the owner per the held-out protocol: findings and false findings read by someone who did not write the recorder |
| A5 | Scan time within 10% on Juice Shop, DVWA and vulnpy |

## What is known not to work yet

Text built by `join`, a helper or another module; statements outside a short list; a JavaScript value bound in a
different call from the text; a tagged template whose driver binds its substitutions. Each is listed with its overlay in
the learnings page.
