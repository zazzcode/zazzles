# Server-side template injection coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/code-injection.md#server-side-template-injection) · [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html)

The claim concerns request-derived template source compiled by a verified engine. Separately assess how data is rendered into browser output.
In a judged scan, select this family with `--only-family code`.

See [code injection](code-injection.md) and [cross-site scripting](cross-site-scripting.md) for the companion claims.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Python template source | A request string reaches Jinja2 `Template`, Flask `render_template_string` or Mako `Template` | A complete raw source path can be Confirmed |
| Node and PHP template source | A verified Node compile/render operation or Twig `createTemplate` receives request-dependent source text | Assess the template source operand with its engine contract |
| Enforced restriction on source | A complete, verified grammar or type control constrains what reaches compilation | May be Protected when the assessed restriction covers every path |
| Symfony Twig extensions | A resolved project Twig function compiles supplied template source | Follow the context value to the compilation operand |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `SSTI-R01` | Sandbox without established restrictions | A template environment is marked sandboxed while it compiles request content | Review when the effective restriction is unknown | Prove the effective scope and restrictions of that environment |
| `SSTI-R02` | Unresolved template source | An opaque helper returns the template text | Review when relevant transfers or protections are unresolved | Resolve the effective source and controls |
| `SSTI-R03` | Unresolved Twig function | A template calls a function whose registration or callable cannot be resolved | Review when the source-to-compiler path is unresolved | Resolve the extension service and method binding |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `SSTI-N01` | Unsupported source-creation binding | A Jinja environment calls `Environment.from_string` | Add a verified receiver and source-operand contract |

## Outside this claim

A constant template with request values passed as render variables can have an XSS claim for its output.
