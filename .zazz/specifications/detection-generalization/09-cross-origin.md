# Detection generalization 09 — credentialed cross-origin reads

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing. Reads 08's role if merged.
  **Effort** small. **Review artifact** one draft PR.

## Capability

Records where another site could read a response made with the caller's credentials: an origin policy that
reflects the request origin and allows credentials, and a response a script element can load while cookies
authenticate the entry. An open policy without credentials is a fact, not a finding.

## Required reading

`langjs/configuration.go`, `middleware_context.go`, `web_request.go`, `express_access.go`;
[configuration](../../../docs/scan/analysis/configuration.md); [Fetch standard, CORS protocol and
credentials](https://fetch.spec.whatwg.org/#cors-protocol-and-credentials); CWE-942, CWE-346; [Express
`res.jsonp`](https://expressjs.com/en/api.html#res.jsonp); [cors
options](https://github.com/expressjs/cors#configuration-options).

## Semantics

**Policy facts**, from the verified `cors` middleware or literal CORS response headers: origin (`any`,
`reflected`, literal list, callback with body, `unknown`), credentials (`true`, `false`, `absent`), scope
(application, mount, route). `any` with credentials is rejected by browsers; the fact says so.

**Script-readable response:** `res.jsonp` on the verified response, or a script content type whose body
wraps request text as a callback.

**Join:** how the covered entries authenticate (`cookie`, `header`, `none`, `unresolved`), from access
facts, cookie `same_site` where known, and the guards on a callback origin (spec 02's record when merged).

## Scope

New `langjs/cross_origin.go`, configuration check registration (one check, its SARIF rule and help), tests
and fixtures. Out of scope: CSRF, WebSocket origin, `postMessage`, proxies and server configuration files,
PHP.

## Decisions

- **D-1. One check with joined facts.** *Why:* the weakness is the combination.
- **D-2. A permissive policy without credentials is not sent.** It is stated as a report fact. *Why:* a
  public API is not a defect; sending it would buy noise.
- **D-3. A callback origin is judged with its body.** *Why:* it is a guard written by the application.

## Fixtures

Positive: reflected with credentials (option and headers); callback that accepts any; regular expression
matching a suffix of a foreign host; JSONP on a cookie entry. Negative: `any` without credentials; literal
list; callback with exact list; JSONP on a public entry; header-authenticated entry; reflected on a static
mount.

## Held-out

One application with a cookie session and a CORS policy, and one ordinary public API.

## False-positive controls and G7 bound

Open policies without credentials: no record. At most two added records per sample.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestCrossOrigin` |
| AC2 | No request for a policy without credentials | `TestCrossOriginNotSent` |
| AC3 | G1 to G7 | Comparison |
| AC4 | Paid checkpoint passes | Results |
| AC5 | Pages: insecure configuration, information exposure; guides; `configuration-analysis.md` | `doc-check` |

## Paid checkpoints

Fixtures and held-out. Cap 40. Pass: no control Confirmed; at least 80% of keyed positives Confirmed.

## Stop rule

Stop when authentication of the covered entries is `unresolved` on more than half of keyed rows (the join
does not carry), a public API is Confirmed, or fewer than two pool applications have a credentialed policy.

## Juice Shop check

`JS-X-EXPO-04` may have a record. `JS-X-CONF-05` should have a report fact and no finding. If the owner
keeps that row as a vulnerability, it stays a miss by design.

## First failing test and order

`TestCrossOrigin/reflected_with_credentials`. Then policy facts, join, JSONP, checkpoint.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
