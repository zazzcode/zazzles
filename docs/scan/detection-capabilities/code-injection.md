# Code injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/code-injection.md) · [CWE-95](https://cwe.mitre.org/data/definitions/95.html)

The claim concerns a request value entering the code operand of a verified interpreter. Server-side template source has its own coverage page.
In a judged scan, select this family with `--only-family code`.

See [server-side template injection](template-injection.md) for the other class selected by `--only-family code`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Raw interpreter operands | JavaScript `eval`, Python `exec` or PHP `eval` receives request-dependent code text | A complete raw path can be Confirmed. A path under a condition that mentions the operand can be Confirmed when the assessment answers that the condition imposes no restriction |
| Supported interpreter contexts | Browser string timers or Node `vm` receives a code string | Assess the code slot separately from context objects and callbacks |
| Full operand restriction | An enforced grammar or a recognized conversion constrains the entire operand | May be Protected when all code-bearing paths are covered |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `CODE-R01` | Unproven library isolation | A verified evaluator library advertises a sandbox | Review when its isolation or relevant restriction is unestablished | Establish the effective containment or applicable advisory evidence |
| `CODE-R02` | Unresolved code origin or transformation | An opaque helper constructs the source string | Review when a relevant step or linked stored origin is missing | Trace the complete source string and model its restrictions |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `CODE-N01` | Execution outside modeled interpreter APIs | WebAssembly compilation or unmodeled dynamic module loading | Define and verify the operation and its executable operand |
| `CODE-N02` | Unverified dynamic evaluator aliases | Runtime aliasing conceals which function will evaluate input | Resolve the effective interpreter binding |
