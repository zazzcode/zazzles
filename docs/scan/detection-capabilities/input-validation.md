# Input validation coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/input-validation.md) · [CWE-20](https://cwe.mitre.org/data/definitions/20.html)

The standalone claim concerns enforcement of a source-backed or explicitly configured field requirement. Its finding classification is poor practice where the missing enforcement is established.
In a judged scan, select this family with `--only-family input-validation`.

The report uses CWE-20 for this practice family. [MITRE discourages using CWE-20 as a generic real-world vulnerability mapping](https://cwe.mitre.org/data/definitions/20.html).

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Declared policy with inconsistent enforcement | A required field can reach a modeled handler path without the necessary server-side check | May produce a Poor Input Validation finding |
| Declared policy with an enforced rejecting path | A source-backed constraint rejects invalid input before the covered use | May be Protected for that exact field requirement |
| Client and server checks | A submitted form declares a field limit and the scanner follows the target handler | The form supplies policy evidence. Enforcement is assessed independently on the server |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `VAL-R01` | Missing business requirement | A field is read and the scanner has no source-backed or declared constraint | Review, often with `validation_evidence_missing` before a model request | Supply an applicable explicit check or recover the application policy |
| `VAL-R02` | Unresolved validator | A helper receives a field, but its returned value or failure path is unclear | Review when the scanner cannot establish enforcing behavior | Resolve the validator semantics and its rejection path |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `VAL-N01` | Unresolved application entry | Default or unresolved GraphQL resolver or unsupported parent-result transition | Resolve the entry or result transition and establish the field origin |

## Outside this claim

SQL binding is part of the SQL claim. A standalone validation claim requires its own field policy and enforcement.
