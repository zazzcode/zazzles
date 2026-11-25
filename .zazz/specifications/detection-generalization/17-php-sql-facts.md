# Detection generalization 17 — computed facts for PHP SQL operands

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Authorized** by the owner, 2026-11-25: "Implement arm B", after the arm missed the bar written before its paid test
  and met [contract §7](contract.md#7-detection-and-false-positive-accuracy-must-not-fall) A1 to A3 on the 56 records it
  changes. That choice, and the missed bar, are stated in the pull request.
- **Branch** `detgen-17-php-sql-facts` from `origin/stage`, lane B. **Review artifact** one draft PR to `stage`.
- **Evidence** is in specification 15's results, on `detgen-14-sql-calls-redesign` (not merged). The
  [results of this branch](../../evaluation/detection-generalization-results/17.md) restate what they need.

## Capability

A PHP SQL record states facts the scanner proves about the operands of constructed SQL text: a numeric conversion result,
a value escaped and placed inside a quoted literal, a hexadecimal hash. The text sent with PHP SQL records says what an
escape and a cast do and do not protect. The judge decides as before.

## Invariants

1. A fact decides nothing. No scanner rule gives or removes a verdict.
2. Facts are stated only when every operand has one, every path proves it and nothing later can change its text.
   Otherwise none is stated: an unknown is not a fact.
3. Only PHP SQL requests change. Every other record, family and language keeps its request byte for byte.
4. The facts are language-neutral codes with one note each. No list of applications, fields or routes.

## Scope

| Path | Change |
|---|---|
| `scan/internal/langphp/sql_facts.go` | New. Reads the parts of the SQL text and each path's transfers |
| `scan/internal/langphp/sql.go` | One line: the record carries the facts |
| `scan/internal/guidelines/facts.md` | Three codes: `numeric_conversion_result`, `escaped_in_quoted_literal`, `hash_hex_result` |
| `scan/internal/guidelines/php.md` | Escape and cast sentences |
| `scan/internal/analysispacks/contracts.go` | The escape sentence of `php-mysqli-v1` |
| Tests | `langphp/sql_facts_test.go`, `guidelines/facts_test.go`, the `scan/cli` architecture golden (digests of PHP SQL records) |
| Documents | Query judgment, database injection guide, SQL capability page, results, this file, delivery plan row |

Out of scope: other PHP drivers' escapes, pattern guards such as `preg_match`, JavaScript and Python, question wording,
policy, and any list or threshold.

## Decisions

- **D-1. Facts, not a rule.** *Why:* contract §1.2. *Rejected:* suppressing a record with all-operand facts; it would
  let the scanner decide.
- **D-2. Read the scanner's text parts.** *Why:* they already hold the order of literal text and values, so the quote
  position comes from the program. *Rejected:* matching the source with expressions.
- **D-3. Withhold on any transfer not known to keep the text.** *Why:* `stripslashes` after an escape keeps the escaped
  label. *Rejected:* a list of transfers that break it; it fails open.
- **D-4. Keep the guideline, fact-document and protocol versions.** *Why:* a version is in other families' requests; the
  digest already covers the text. No question changed.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Each safe, trap and plain form gives exactly the stated facts | `go test ./scan/internal/langphp -run TestPHPSQLFacts` |
| AC2 | Every produced code has a note; the list of codes is complete | `go test ./scan/internal/guidelines -run TestFact` |
| AC3 | On the four judged applications each request equals the one paid for in arm B | Comparison |
| AC4 | Nine samples: no record missing or added; only PHP SQL requests change | Comparison |
| AC5 | G1 to G7, the reserved control by script | Commands |
| AC6 | Documents, with the tested benefit in `.zazz/architecture/` | `doc-check` |

**Not met, and stated in the pull request:** held-out PHP applications, three planned answers for every changed ledger
record and moved outcome (A4), and a full judged scan (A6). Each needs the owner's word.

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
The owner decides on five requests for them.
