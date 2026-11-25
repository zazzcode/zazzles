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

`langphp/sql_facts.go` states facts about the operands of a constructed PHP SQL text, from the ordered parts of that text and
each path's transfers. Their codes and notes are in `scan/internal/guidelines/facts.md`:

| Code | Stated when the operand is |
|---|---|
| `numeric_conversion_result` | The result of a numeric cast or conversion |
| `escaped_in_quoted_literal` | Escaped by the database client and placed inside a quoted SQL literal |
| `hash_hex_result` | The hexadecimal text of a one-argument `md5` or `sha1` |

- **A fact decides nothing.** The judge reads it with the code. No verdict, suppression or policy uses it.
- **All or nothing.** Facts are stated only when every operand has one. Every path must prove it, every alternative of a
  conditional must be the value or a literal, and after the value is made no variable that carries it may be written, passed
  to a call or reached by a construct that writes variables it does not name. A SQL comment ends what the text shows.
- **Never stated as unknown.** In an experiment, a fact that said `not established` made the judge doubt a true finding.
- **The text says the same as the facts.** The PHP guideline and the `php-mysqli-v1` contract used to say that an escaped
  value remains a finding and that escaping is never protection. They now separate construction practice from injection.
  Facts without that text cleared 1 of 14 false findings, and nearly the same text without facts cleared 2.
- **Versions are unchanged.** A version is part of other families' requests; the component digest covers the text.

**Tested benefit** (2026-11-25, one paid answer per request, outcomes by policy replay; [results and
limits](../evaluation/detection-generalization-results/17.md)): of 14 known false SQL findings 5 are no longer Confirmed,
0 of 25 true findings on changed requests are lost, and none becomes Protected. One safe record moves from Protected to Review.
The six moved records gave the same answer three times. It was below the bar set before the test,
and is measured on DVWA and on forms its author wrote. No held-out PHP application has been used.

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
