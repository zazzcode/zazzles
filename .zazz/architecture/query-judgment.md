# SQL/NoSQL judgment design

Product-facing [analysis rules](../../docs/scan/analysis/README.md) own the interpretation and refinement
guidelines. This internal document owns data flow and implementation boundaries. The implementation
contract is [SQL/NoSQL judgment](../specifications/sql-nosql-judgment.md).

## Data flow

`parse.Strings` discovers sensitive uses, then automatically assembles query checks using the
claim-scoped checked-mode machinery. Route/field requirements derive from source, never benchmark
answers. Existing use IDs remain stable. Verified import/constructor/operation evidence identifies
the library contract in `api_model`, independently of source snippets.

A completeness record carries required evidence roles, actual evidence, blockers, remaining coverage
limits, resolved discovery gaps, and explicit model facts. Raw discovery gaps remain in the use
record. Source and comments are untrusted data; scanner-authored adapter contracts are separate.
Question bundles deduplicate source spans and retain role/transfer/control references.

`query_evidence.go` assembles supported transformations, middleware, wrappers, and conditional helper
context. Unsupported relevant definitions remain blockers. `query_constraints.go` records each
conditional output alternative and proves numeric output only for supported numeric literals and
unshadowed native Number calls, with bounded nested ternaries. A sibling conversion is never a
global guarantee. This produces type facts for semantic assessment, not a hardcoded verdict.

### Facts about constructed PHP SQL operands

`langphp/sql_facts.go` states facts about the operands of a constructed PHP SQL text. Their codes and notes are in
`scan/internal/guidelines/facts.md`:

| Code | Stated when the operand is |
|---|---|
| `escaped_in_quoted_literal` | `mysqli_real_escape_string` on the connection of the query, alone in a single-quoted SQL literal |
| `hash_hex_result` | A one-argument `md5` or `sha1` in the same position |
| `integer_conversion_result` | `(int)` or `intval` of one argument, compared, listed or a row count, or inside a single-quoted literal |
| `digit_pattern_value` | A request element read first in a block that runs only when a native `preg_match` of `^\d+$` or `^[0-9]+$` accepted it; same positions |

- **A fact decides nothing.** The judge reads it with the code. No verdict, suppression or policy uses it.
- **A source pattern, not the flow.** A join of two branches keeps one branch's text and an unresolved call adds no dependency,
  so a fact read from the flow was false again and again. The rule reads the syntax tree and allows only what it names:
  - the sink is `mysqli_query` with two positional arguments, a direct call of the built-in: no namespace or import in the file,
    and no declaration of that name in any scanned file. The same holds for every other call the rule allows;
  - the text is written in the call, or in the statement just before it, with literals, variables and concatenation only;
  - each operand is the call itself, or a variable whose last write is one. Both stand in one unbroken run of assignments that
    run no code of the program. After the first operand is written, only operands are written;
  - every alternative of a conditional is the same kind of call, or the empty string; an integer has no alternative;
  - after the first operand only operands are written, or `true`, `false`, `null` and integers, which are safe in any position;
  - names that share a value through a reference end on the last value written to any of them, and every operand value is safe
    in quotes. So after the last write of an integer or digit operand, which may stand bare, only integers, booleans and null
    may be written. This holds whatever made the reference, so it needs no search for one;
  - escape and query use one connection: the same variable, or the same literal key of `$GLOBALS`, not written between;
  - `sql_operand_text.go` knows every token. The statement is one `SELECT`, `INSERT`, `UPDATE`, `DELETE` or `REPLACE`; each
    operand is compared, assigned or listed in `VALUES` or `IN`; a bare integer may also follow `LIMIT` or `OFFSET`, and stands apart
    from a sign, digit, point or letter. A function call, backslash, double quote, comment, variable,
    character set introducer, byte outside ASCII or second statement fails.
- **Program conditions.** No fact is stated when any file under the scanned root, whatever its extension and including
  `vendor/`, names an error handler or tick function (also as part of a longer string), declares `__destruct`, `__toString` or
  `ArrayAccess` methods, redefines a function, or holds `SET NAMES`, a character set or a change of `sql_mode`; when the tree is
  over 256 MiB; when a PHP file cannot be parsed; or when a scanned file takes one of the variables by reference with `&$name`.
- **All or nothing.** Facts are stated only when every operand has one. Never stated as unknown: in an experiment a fact that
  said `not established` made the judge doubt a true finding.
- **Text per record.** The PHP guideline and the `php-mysqli-v1` contract say that an escaped value remains a finding, and that a
  cast or type check does not make a statement safe. In the request of a record with one of these facts, and in no other,
  `guidelines/facts.go` replaces those sentences: they would contradict the fact. Every other PHP SQL request is the same as
  without this feature.

**Limits.** The rule cannot see code outside the scanned root (an extension, a library installed elsewhere, `eval` of text made
at run time), a handler or setting whose name is put together from smaller pieces, a character set or SQL mode set by the server or
by text put together at run time, or a trigger of the database. The `escaped_in_quoted_literal` note the judge reads does not repeat
these conditions. The statement is taken to run on MySQL or MariaDB. Methods (`$db->query`), PDO, SQLite3, PostgreSQL, floats and
bound parameters have no fact.

**Tested benefit** (2026-11-25, outcomes by policy replay; [results and
limits](../evaluation/detection-generalization-results/17.md)): of 14 known false SQL findings 5 are no longer Confirmed, each 3 of 3,
0 of 25 true findings are lost, none becomes Protected, and no safe record moves. Nine requests of 403 differ from those before the
feature, and each has three paid answers for its exact text. All of it is measured on DVWA and on forms its author wrote. No held-out PHP
application has been used.

## Semantic questions and policy

Protocol `candidate-use-v9` retains validation and construction-practice questions, plus a distinct
injection_protection question. SQL/NoSQL use vulnerable/protected/unknown/not_applicable choices for
injection. NoSQL additionally assesses source/library/guard/path coverage and all_paths_protected.
Strict response decoding rejects missing, duplicate, unexpected, or invalid answers.

Policy requires a verified API model and source, binding, route-handler and control evidence.
Declared blockers prevent a definitive result. NoSQL diagnostic coverage must be yes; vulnerable
requires all_paths_protected=no and protected requires yes. Contradictions remain needs_evidence.
These gates cannot make a consistently wrong model answer correct; calibration controls are required.

Raw provider answers remain auditable. Normalized protection follows the injection-specific answer,
while the original practice answer stays in `assessment.answers`. Missing/inconclusive injection
judgment cannot be replaced with the practice answer. Human labels use Inconclusive without changing
raw protocol values. Independent Findings Review and runtime confirmation remain separate.

## Reporting and verification

JSON is canonical; Enrich derives one presentation record per use, and HTML/SARIF share it. A supported
injection finding upgrades the construction record. Field validation remains a separate facet and
category; definitive injection does not turn incomplete validation evidence into a finding.
A protected injection facet can coexist with an orange construction-practice record.

Calibration caught both incorrect protection borrowed from a numeric sibling and a false positive on
a numeric/constant conditional. Per-alternative facts and balanced question wording corrected the
focused live controls. See [evaluation](../evaluation/juice-shop/query-judgment-calibration.md).
This bounded evidence is not held-out accuracy measurement. Full final target runs, scalar-selector
controls on the latest protocol, and independent review remain follow-up work.
