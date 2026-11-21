# Finding categories and terminology

[Documentation index](../README.md) · [Interpret results](interpreting-results.md) · [Philosophy](../philosophy.md)

## Categories are not verdicts

Categories group related concerns. **Findings**, **Review**, and **Protected** describe the evidence
and required action. A finding can be an established vulnerability or a poor practice worth fixing
without a demonstrated exploit. A Review category is a question, not an established defect.

The [coverage index](detection-capabilities.md) links each weakness to its CWE, analyzer family
and class-specific coverage. Four report terms also describe how a record is presented:

| Label | Meaning |
|---|---|
| **Input Validation** | A field policy or its enforcement is being assessed. Poor Input Validation requires an applicable requirement and evidence of inadequate enforcement |
| **Account Creation Validation** | A field policy applies to account creation before persistence |
| **Outbound Request Safety** | An outbound call carries destination-origin evidence. A verified SSRF claim has its own outcome |
| **Sensitive Operation Review** | A possible operation needs review when no more specific supported category applies |

## Other terms

- **Poor practice:** an established construction or rule violation worth remediation/refactoring;
  demonstrated exploitability is not required.
- **True positive:** the named finding is supported against its actual rule/claim. A true-positive
  practice finding is not automatically proof of a related injection exploit.
- **Claim:** a specific question about a field, operation slot, validation rule, or protection.
- **Source / transfer / use:** where a value originates, how the supported analysis carries it, and
  where an operation consumes it. These are bounded static relationships, not an execution trace.
- **Blocker:** a missing fact needed to decide the named claim. A coverage gap may affect a broader
  analysis without blocking every local conclusion.
- **Protected:** sufficient protection for one named claim, not a route-wide security certification.

In HTML, select a category pill for the full definition, interpretation, coverage, and remediation
approach. The inline glossary provides the same information without a side panel. JSON carries the
shared definition registry for agents, and SARIF retains it in namespaced scan properties. Type
counts overlap; do not sum them as independent findings.
