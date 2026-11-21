id: go
version: 2
languages: go

# Go analysis guidelines

These analysis guidelines are supplied when a Go file is assessed. The current route scanner does not yet emit Go sink candidates.

## Posture

Report a confirmed injection and weak or poor practice. An agent can harden both cheaply. Unproven exploitability does not remove the finding.

## Validation

Restrict each field as far as its business requirement allows. A missing check is insufficient. A string type or a length check is insufficient when a tighter check would still meet the business need. A function name, a comment, or an unshown helper is not validation.

## Free text

Comments, messages, descriptions, reviews, feedback, and notes may contain any character. Do not require an allow-list. The injection control is the sink.

## Sinks

Do not build a query, update, or insert with `fmt.Sprintf`, `+`, or string builders. Use `database/sql` placeholders and arguments. A placeholder argument is sufficient protection for statement structure even when validation is weak. A type or length check does not make a formatted statement safe.

## Do not claim

Do not invent a guard, a placeholder binding, or a branch that the evidence does not show.
