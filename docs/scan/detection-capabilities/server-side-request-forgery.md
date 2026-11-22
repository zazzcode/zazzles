# Server-side request forgery coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/ssrf.md) · [CWE-918](https://cwe.mitre.org/data/definitions/918.html)

The claim concerns the destination operand of a verified server-side HTTP client. Other outbound traffic is presented as an observation.
In a judged scan, select this family with `--only-family ssrf`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Request-controlled host or URL | A request value reaches the URL parameter of a verified `fetch`, axios, Node `http` or Python HTTP client | A complete raw destination path can be Confirmed |
| Parsed destination restrictions | A scheme and host check restricts the final URL on every path | May be Protected for the observed destination |
| Raw string restrictions | A prefix check runs on an unparsed destination | Can produce a practice finding. A scheme-only check leaves host control open |
| PHP URL operations and Symfony HttpClient | A URL-capable PHP function or verified HttpClient call receives a request destination | Record the verified destination slot independently of file paths and request data |
| Address-guarded endpoint | An authorization record with an address check in the same report | The authorization finding links to the SSRF finding in `related_findings`. After SSRF judgment, its finding also links back. The SSRF judge request is unchanged |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `SSRF-R01` | Path or query control only | A modeled request value only affects the path or query portion of a destination claim | Review when host or URL control is unestablished | Resolve the URL construction and authority semantics |
| `SSRF-R02` | Unresolved wrapper or transformation | A helper returns the outbound destination, but its relevant effects are unknown | Review when the destination path or enforcing guard is incomplete | Resolve the client binding and effective destination |
| `SSRF-R03` | Unresolved PHP destination | A verified URL-capable call receives a transformed destination | Review when destination shape or guard semantics are unresolved | Establish URL construction and same-value controls |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `SSRF-N01` | Stored-only or response-only destination | An outbound destination depends solely on a stored or fetched value | The outbound observation keeps its origin. An SSRF claim needs a modeled request-to-destination path |
| `SSRF-N02` | Runtime network behavior | DNS, proxies or runtime redirects alter the actual destination | Establish runtime reachability and deployment policy independently |
| `SSRF-N03` | Unsupported client configuration | A request value appears inside an unmodeled axios config object | Model the effective destination in object-form calls |
