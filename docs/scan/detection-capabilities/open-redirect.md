# Open redirect coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/open-redirect.md) · [CWE-601](https://cwe.mitre.org/data/definitions/601.html)

The claim concerns the effective redirect or navigation destination and which parts the request can select.
In a judged scan, select this family with `--only-family redirect`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Verified navigation destination | Express `res.redirect`, Next navigation, browser location, Python redirect helpers or PHP `Location` uses a request value | A complete raw destination that can select an external location can be Confirmed |
| Verified origin or relative path restriction | A check enforces a parsed allowed origin for the final unchanged destination | May be Protected when every relevant path has the restriction |
| Weak raw URL checks | A raw prefix or substring is used as the restriction | Assess the form of the check and which destination forms remain possible |
| Symfony redirects | `redirect()` and `RedirectResponse` consume a URL operand | Trace the destination and same-value controls on the path |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `REDIR-R01` | Unknown redirect status | A `Location` header is set after dynamic status selection | Review where redirect behavior needs status evidence | Resolve the status and its path to the header write |
| `REDIR-R02` | Unresolved navigation chain | An unmodeled helper rewrites the destination after a check | Review when the final value or its restriction is unresolved | Follow the value through rewriting to navigation |
| `REDIR-R03` | Unresolved Symfony destination | A service returns an opaque redirect destination | Review when a transfer or control remains unresolved | Establish the effective URL and its source |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `REDIR-N01` | Unsupported dynamic navigation mechanism | A destination is passed through an unmodeled renderer or navigation wrapper | Resolve the effective browser or server navigation operation |

## Outside this claim

The claim requires request control of the destination. Constants, fixed origins and query-only or fragment-only changes fall outside it.
