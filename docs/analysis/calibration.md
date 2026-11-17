# Improving and calibrating analysis

[Analysis index](README.md) · [Database injection](database-injection.md)

Analysis improvements MUST generalize from source semantics and verified API contracts. Target names,
challenge identifiers, answer documents, manually reproduced exploits, and expected labels MUST NOT
supply production verdicts or appear as hints in decision-model bundles.

Known answers help evaluate outcomes. They do not replace source, path, guard, and library evidence.
Correctly detecting a vulnerable example is insufficient when a protected counterpart is flagged.

## Regression pairs

Keep paired cases for raw/bound SQL, executable/raw versus numeric-constrained NoSQL expressions,
operator-valued versus constrained scalar selectors, real versus same-name fake APIs, native versus
shadowed conversions, safe versus unsafe sibling branches, and missing/ineffective/effective guards.
Preserve cases with incomplete evidence: a model or parser failure must not become a safe verdict.

For a conditional expression, test both Number(input)/raw-input and Number(input)/constant forms,
plus nested and shadowed-conversion variants. This detects both borrowed protection and invented
unsafe branches. The scanner's AST facts describe types per output; they do not force model labels.

## Evaluation and audit

Keep expected labels outside source/model bundles. Version the questions, library models, target
snapshot, and assessment provenance. Use deterministic offline tests for evidence/protocol changes
and bounded live batches for semantic calibration. Retain failed iterations and negative controls;
do not silently rewrite past answers to match the desired result.

A candidate's original discovery warnings remain auditable. Claim assembly may resolve a warning
only with stronger evidence; it must not hide missing relevant helper, middleware, or path facts.
Distinguish resolved discovery warnings, remaining coverage limits, and actual claim blockers.

Before declaring a rule ready, verify positive, protected, and inconclusive controls, inspect novel
cases, and check JSON/HTML/SARIF agreement. Model answer consistency is necessary for a definitive
judgment but does not by itself establish accuracy. Independent review and broader held-out
validation remain separate from these bounded checks.

Accuracy measurements MUST name the source-reviewed corpus and publish counts with denominators.
Known-positive recall includes missed and unjudged selected cases. Genuine safe controls, justified
candidate exclusions, unresolved trust, model failures and practice observations are separate
populations. A Review result is not automatically a false positive, and zero offline Confirmed
records cannot estimate semantic error rates. Report assessed coverage beside false Confirmed/false
Protected rates; an empty assessed population is unmeasured. Preserve repeated-context coverage
alongside source-defect counts so deduplication cannot hide missing paths.

The shared evidence wire format includes an explicit static trace graph and supplied/missing
role ledger. Template context includes focused source markup rather than only the expression.
Neither a graph edge nor a supplied-role index proves complete execution coverage. Calibrate
changed evidence with fresh exact requests; never relabel an old answer onto a changed trace.
