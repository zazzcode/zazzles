# Cross-site scripting coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/xss.md) · [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

The claim concerns a single value rendered into a specific browser output context. The same input can be protected in one context and unsafe in another.
In a judged scan, select this family with `--only-family xss`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Reflected HTML | An Express HTML response or a PHP template emits a request field | Raw text can produce a construction finding. A complete supported path and consistent assessment can be Confirmed |
| Verified templates and browser sinks | An EJS raw interpolation or a browser assignment to `innerHTML` | Assess the effective HTML, attribute, URL or script context |
| Context-appropriate encoding or sanitization | HTML encoding before rendering into HTML text | May be Protected when the relevant context and every input path are covered |
| Linked stored rendering | A supported model-field request write reaches a later rendered read | Use the linked writer to establish origin and see what controls the stored value |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `XSS-R01` | Unresolved content type or output context | A response uses a dynamic Content-Type header | Review when the scanner cannot establish how the browser interprets the value | Resolve the response type and rendering position |
| `XSS-R02` | Unverified sanitizer or stored writer | A custom sanitizer transforms a value read from a store with no linked request writer | Review for the missing transformation or origin | Resolve the sanitizer behavior and trace reachable writers |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `XSS-N01` | Unsupported rendering library | A custom engine renders a template outside the modeled contracts | Resolve the engine binding and model escaping for its output contexts |

## Outside this claim

An explicit JSON response has no supported HTML rendering context.
