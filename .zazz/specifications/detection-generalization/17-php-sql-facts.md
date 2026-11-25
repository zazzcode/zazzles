# Detection generalization 17 — computed facts for PHP SQL operands

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Authorized** by the owner, 2026-11-25: "Implement arm B", after the arm missed the bar written before its paid test
  and met [contract §7](contract.md#7-detection-and-false-positive-accuracy-must-not-fall) A1 to A3 on the 56 records it
  changes. That choice, and the missed bar, are stated in the pull request.
- **Branch** `detgen-17-php-sql-facts` from `origin/stage`, lane B. **Review artifact** one draft PR to `stage`.
- **Evidence** is in specification 15's results, on `detgen-14-sql-calls-redesign` (not merged). The
  [results of this branch](../../evaluation/detection-generalization-results/17.md) restate what they need.

## Capability

A PHP SQL record states facts the scanner proves about the operands of constructed SQL text: a value escaped on the
query's own connection and alone in a single-quoted literal, a hexadecimal hash there, an integer conversion, or a request value an
anchored digit pattern accepted. The request of a record with the
escape fact says what an escape does and does not protect. The judge decides as before.

## Invariants

1. A fact decides nothing. No scanner rule gives or removes a verdict.
2. Facts are stated only for a source pattern in which every part is on an allow-list, and only when every operand has one.
   Anything else states none: an unknown is not a fact.
3. A request changes only when its record states a fact. Every other record, PHP SQL ones too, keeps its request byte for byte.
4. The facts are language-neutral codes with one note each. No list of applications, fields or routes.

## Scope

| Path | Change |
|---|---|
| `scan/internal/langphp/sql_facts.go` | New. The source pattern of the operands, the connection and the program |
| `scan/internal/langphp/sql_operand_text.go` | New. The tokens and positions of the SQL text |
| `scan/internal/langphp/sql_digit_guard.go` | New. The `preg_match` branch that guards a request element |
| `scan/internal/langphp/sql.go`, `modules.go` | The record carries the facts; the program check is kept once per scan |
| `scan/internal/guidelines/facts.md` | Four codes: `integer_conversion_result`, `digit_pattern_value`, `escaped_in_quoted_literal`, `hash_hex_result` |
| `scan/internal/guidelines/facts.go`, `families.go`, `scan/internal/judge/client.go`, `bundle.go` | The sentences a fact replaces in its own record's request |
| Tests | `langphp/sql_facts_test.go`, `sql_operand_text_test.go`, `testdata/sql-fact-review-forms.txt`, `guidelines/facts_test.go`, `judge/fact_notes_test.go` |
| Documents | Query judgment, database injection guide, SQL capability page, results, this file, delivery plan row |

Out of scope: floats, bound parameters, other PHP drivers and their escapes, methods, pattern guards such as `preg_match`,
JavaScript and Python, question wording, policy, and any list or threshold.

## Decisions

- **D-1. Facts, not a rule.** *Why:* contract §1.2. *Rejected:* suppressing a record with all-operand facts; it would
  let the scanner decide.
- **D-2. Read the syntax tree, not the flow.** *Why:* the flow's value of a join, an unresolved call or an array element can
  miss a path, so facts read from it were false in 48 reviewed forms. *Rejected:* a list of transfers that break a fact; it
  fails open, and closing one form at a time kept missing others.
- **D-3. Straight-line assignments that run no code of the program.** *Why:* nothing can then change an operand, the text or the
  connection between the escape and the query. *Rejected:* looking for writes by name; references, `$GLOBALS`, closures and
  callbacks write without it. *Cost:* a function call between the two withholds the fact.
- **D-4. Keep the guideline, fact-document and protocol versions.** *Why:* a version is in other families' requests.
- **D-5. Procedural `mysqli` only.** *Why:* the built-ins accept only a native connection, so its origin needs no proof.
  *Rejected:* methods; a class can replace them. *Cost:* no fact for `$db->query`, PDO and SQLite3.
- **D-6. Text per record.** *Why:* contract §1.7, and the general sentence was false for another engine or connection.
  *Rejected:* the changed guideline and contract for every PHP SQL request; they moved one false record (0.35 against 0.34)
  and one safe record without any fact. *Rejected:* a second contract identifier; it changes the answered text of seven records
  and nothing the judge reads.
- **D-7. No bound-value fact.** *Why:* its connection cannot be shown to be native where the class and the variable come from
  another file, so a sound rule states it for none of the ten records it was made for. With D-6 those ten keep their request
  and their saved answer, Protected. *Cost:* the higher certainty measured with it.
- **D-8. Integers, not numbers.** *Why:* the old note was false (`-`, `INF`). `(int)` and `intval` give a sign and digits, which cannot
  change syntax where the value stands apart. *Rejected:* floats. *Cost:* `s-float`.
- **D-9. A digit pattern that guards its branch.** *Why:* the owner wants no record of the recorded gains lost, and `bac/medium.php:22`
  was cleared only by text that was false in general. Its shape is general: a request element read first in the block that runs only when
  `preg_match` of an anchored digit pattern accepted it. *Rejected:* any other condition, flag or pattern, and a read after other code.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Each safe form gives exactly the stated facts, and each trap makes a record with none | `go test ./scan/internal/langphp -run 'TestPHPSQLFact\|TestPHPQuotedOperands'` |
| AC2 | Every produced code has a note; the list of codes is complete; the replaced sentences reach only a record with the fact | `go test ./scan/internal/guidelines -run 'TestFact\|TestProducedFact'`, `go test ./scan/internal/judge -run 'TestEscapeFact'` |
| AC3 | On the judged applications each request equals an answered one (the text before the feature, or the text paid for in arm B), except two whose paid check is prepared | Comparison, `pf17-paid/` |
| AC4 | Nine samples: no record missing or added; only PHP SQL requests with a fact change | Comparison |
| AC5 | G1 to G7, the reserved control by script | Commands |
| AC6 | Documents, with the tested benefit in `.zazz/architecture/` | `doc-check` |

**Not met, and stated in the pull request:** held-out PHP applications; the reserved control; three planned answers for three of the
seven changed ledger records (A4; done for the four moved outcomes). Each needs the owner's word. The full judged scan (A6) is due after two merged
specifications.

## Stop rule

Stop when a request differs from the tested one, a record of another family changes, or any gate fails for a reason not
fixed in two tries.

## Implementation and review change log

### 2026-11-25 — Written with the implementation

The owner's word came after the paid test. No paid request is part of this work.

### 2026-11-25 — The tested code was unsound, and is fixed

An adversarial check found facts stated where a path did not prove them: an apostrophe in a SQL comment counted as a quote,
a raw value appended after an escape, a branch with an unresolved call, a later write. The facts are now all or nothing and
withhold on each of these (11 failing tests first). So AC3 and the stop rule are **not met as written**: 401 of 403 requests
equal the paid ones; two judged records and three trap forms now state no fact and have no paid answer. No wording changed.
The five were then sent on the owner's word: all `vulnerable`, the true record stays Confirmed, no trap is protected. AC3 is met
in substance: every changed judged request has an answer for its final text.

### 2026-11-25 — Moved records repeated; A3, A4 and A6 corrected

The first text said A3 was met with one answer per new Protected record, and omitted that `brute/impossible.php:96` moved from
Protected to Review. 24 requests on the owner's word: A3 is met, and the move repeats. A6 was listed as missing; it is not due.

### 2026-11-25 — Bound-value fact added

The owner asked for a general answer to the safe record that had left Protected. 15 requests on the owner's word, 19 approved:
10 of 10 records and 5 of 5 forms Protected. The first rules were wrong on trap forms, and again after the paid test on seven
more; each is a test now. The requests of the final code equal the paid ones byte for byte.

### 2026-11-25 — Independent review: 29 findings, both fact sets unsound

All 89 forms of the review reproduced. The facts were read again from the source pattern of D-2 to D-5, the changed text was limited
to records with the fact (D-6), and the bound-value and numeric facts were removed (D-7, D-8). Every form is a test. The entries above
describe code that is gone. Benefit on DVWA: 4 of 14 false findings no longer Confirmed, where it was 5: `bac/medium.php:22` had no
fact and moved by the general text alone. No paid request was made, and none is needed for an answer that does not exist.

### 2026-11-25 — No regression against the recorded results

The owner asked that no result be lost. The numeric fact returned as an integer fact with a true note (D-8), and a digit-pattern fact was
added for the general shape of `bac/medium.php:22` (D-9), each with its own traps. Two judged requests now have new text: a paid check of
35 requests is prepared, with its rule written first, and not sent.
