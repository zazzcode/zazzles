# Agent-first security and remediation

[Documentation index](README.md) · [Interpreting results](scan/interpreting-results.md)

## Fix code correctly

Zazzles exists to help developers and coding agents improve application security. Its useful output is
a concrete problem, source evidence, the protection already present, and an appropriate correction
that preserves intended behavior. Agent-assisted hardening makes small, worthwhile improvements
practical; do not discard them simply because a human might defer the work.

## Findings include poor practice

A finding can describe an established vulnerability or an established poor practice. Both merit
remediation or refactoring. Demonstrating exploitability is not required to report a proven practice
violation. A true positive is relative to the named rule: a string-built executable query can be a
true-positive construction-practice finding even if a guard prevents an injection exploit.

Name the actual problem precisely. A query-construction finding must not silently become a confirmed
SQL-injection exploit. Likewise, an insecure default can need correction without any request-value
dataflow. Refactor established weak construction, improve an established field-policy violation, and
add regression checks appropriate to each change.

## Review is a question to resolve

Review means Zazzles cannot yet establish a problem or sufficient protection. A validator's unknown
effect, an unresolved library binding, or missing business requirements belongs here. The fact that
Zazzles did not model a check is not proof that the application has no check. Investigate the named
blocker and decide whether a fix is needed; avoid speculative edits that reject valid inputs or
remove existing protection.

Uncertainty about exploitability alone does not remove an established poor-practice finding.
Uncertainty about whether the poor practice exists does require Review. A semantic model answer
cannot supply missing source facts or turn an unresolved operation into an established vulnerability.

## Validation and destination protection are separate

Constrain fields as tightly as their business requirements allow. Independently use the database,
HTTP, logging, template, or other destination API correctly. A valid email does not prove SQL
parameter separation. Binding a SQL value does not enforce every email/business requirement.

A free-text review can legitimately contain punctuation and many characters. Preserve valid content;
use appropriate destination protection rather than an arbitrary character filter. For NoSQL,
inspect scalar types, allowed keys/operators, and executable-expression slots separately.

## Preserve protection and verify fixes

Protected results describe a named field, operation slot, and claim. Preserve protection that already
holds. A protected claim does not certify the entire route, and an empty report is not a safety verdict.

For each change, connect the fix to its finding, preserve intended behavior, and verify normal input,
rejection behavior, and the property being protected. Illustrative report snippets require adaptation;
they are not verified patches. Keep independent review and runtime confirmation separate from static
analysis. User-facing guidance belongs in this root documentation, alongside the code it helps improve.
