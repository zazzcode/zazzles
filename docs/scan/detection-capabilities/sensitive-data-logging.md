# Sensitive data in logs coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/sensitive-data-logging.md) · [CWE-532](https://cwe.mitre.org/data/definitions/532.html)

The claim concerns sensitive content reaching a verified log emission. Source data class and the effect of redaction or reduction determine the result.
In a judged scan, select this family with `--only-family logging`.

Verified bindings include the global console, supported pino, winston and morgan bindings, and the documented Python logging and print forms.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Protocol credentials | A verified logger writes the contents of an Authorization or Cookie credential | Can produce a practice finding. A complete consistent assessment can Confirm the exposure |
| Access logging of credentials in URLs | A verified morgan format includes a query value with credential-use evidence | Can produce a finding when access logging is registered on the path |
| Content-derived facts | A verified logger records the length or presence of a credential | May be Protected for content exposure |
| Symfony PSR-3 logging | A typed PSR-3 logger emits a credential sourced from a request argument or context item | Separate emission of credential content from logs of operational values |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `LOG-R01` | Sensitive-field hint | A log contains a whole request body or a field whose name suggests personal data | Review when the actual data class is unestablished | Confirm the field’s application role and log content |
| `LOG-R02` | Unverified masking | A custom masking helper runs before the log call | Review when the helper’s effect on content is unknown | Verify the redaction output and its enforcement on every path |
| `LOG-R03` | Unresolved PHP sensitive-data class | A typed logger emits a whole request container | Review while the sensitive value within the container is unestablished | Trace the particular emitted field and any reduction |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `LOG-N01` | Unverified logger binding | An arbitrary object has a method named `log` | Establish the actual logger binding and emitted argument |
