# Argument injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/command-injection.md#facets-and-outcomes) · [CWE-88](https://cwe.mitre.org/data/definitions/88.html)

The claim covers a request-derived argument that a verified utility or interpreter treats as an option or executable operand.
In a judged scan, select this family with `--only-family command`.

The same `command` family also reports [OS command injection](command-injection.md) when a request controls shell text or executable selection.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Known interpreter argument | A fixed interpreter receives request text in its documented code-evaluation argument | A complete source path and established interpreter semantics can support CWE-88 |
| Enforced argument restrictions | An allow-list restricts a value to documented data arguments before the verified process call | May be Protected when the rule covers every relevant path and the utility semantics support it |
| Symfony Process argument vector | A literal PHP array gives the executable and argument slots for `Process` | Evidence retains the executable, argument positions, and applicable value controls |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `ARG-R01` | Unknown option semantics | A request argument reaches a shell-disabled invocation of an opaque utility | Review even with a verified process API | Identify the executable and establish how it parses that slot |
| `ARG-R02` | Unresolved argument layout | A dynamic argument array determines where an input appears | Review when the effective slot or protection is unknown | Recover the argument layout and the relevant guard |
| `ARG-R03` | Unresolved Process argument vector | The argument shape is computed by an unsupported helper | Review when executable or argument roles are unresolved | Establish the argument vector and per-slot sources |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `ARG-N01` | Unverified launcher | A custom wrapper hides the executable and argument vector | Trace through the wrapper to the verified process call |
