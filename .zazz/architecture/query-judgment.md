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
