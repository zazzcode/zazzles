# OS command injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/command-injection.md) · [CWE-78](https://cwe.mitre.org/data/definitions/78.html)

The claim covers request control over effective shell syntax or executable selection at a verified process API. Utility option behavior has its own coverage page.
In a judged scan, select this family with `--only-family command`.

Verified APIs span Node `child_process`, Python `os` and `subprocess`, and plain-PHP shell APIs. See [argument injection](argument-injection.md) for the separate option facet.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Request-derived shell text | A request field is concatenated into the command passed to Node `exec` | A complete raw operand path can be Confirmed |
| Shell mode on a process call | A supported `spawn` or Python `subprocess` call uses a verified shell option | Evaluate the effective command text and the paths into it |
| Fixed executable and constrained operands | A fixed absolute program is used with separate arguments and the shell disabled | The shell facet can be absent or protected according to the effective operands. Options are evaluated separately |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `CMD-R01` | Unresolved guard semantics | A custom validator accepts an input that reaches shell text | Review when the evidence cannot establish the guard’s behavior or its bypass | Recover the guard semantics and the exact path covered |
| `CMD-R02` | Unknown shell or executable selection | A subprocess call uses a dynamic `shell` option or a bare executable whose PATH binding is unresolved | Review for the missing mode or executable identity | Resolve the effective options and executable binding |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `CMD-N01` | Unverified process wrapper | A project-specific launcher hides the actual execution API | Resolve the wrapper and trace the correct command or executable operand |
