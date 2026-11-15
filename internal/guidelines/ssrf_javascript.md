id: zazzles.ssrf.javascript
version: 1
languages: javascript, typescript

# JavaScript and TypeScript server-side request forgery guidelines

TypeScript types, casts and annotations are not runtime validation. The same rules apply to `.js`, `.jsx`, `.ts` and `.tsx`. These guidelines interpret one outbound HTTP call at a time whose destination operand a request value reaches.

## Posture

Report a source-confirmed server-side request forgery separately from field validation. A request value that reaches the destination argument of a verified `fetch` or `axios` call is the claim; exploitability is a static judgment, not runtime confirmation. Prefer selecting a destination from a fixed table of trusted URLs by a request-supplied key over accepting a URL.

## Operations

`fetch(input, init)` requests `input`; `init.method`, `init.headers` and `init.body` do not change the destination. `axios(url, config)`, `axios.get(url, config)` and `axios.post(url, data, config)` request `url`; `data` and `config.headers` do not change the destination, and `config.baseURL` applies only to a relative URL. A request value sent as a body or header to a fixed URL is not destination control. Both clients follow redirects by default.

## Destination control

The whole request value passed as the URL controls scheme, host, port and path. A template or concatenation whose fixed prefix ends after the host (`https://api.example.com/` + value) leaves the host fixed only when the prefix includes the path separator after the host; `https://api.example.com` + value can become `https://api.example.com.attacker.test`. A value that supplies the host with a fixed scheme controls the authority. `new URL(value, base)` lets an absolute value replace the base.

## Restriction

A restriction must parse the same value (`new URL(value)`) and compare its `hostname` (and scheme) with trusted constants, or compare the whole URL with a finite allow-list, and reject before the call. `startsWith`, `includes`, `indexOf` and regular expressions on the raw string are prefix-only: userinfo (`https://trusted@evil`), alternative IP forms and encodings pass them. A check that a value is a string or a URL, a `try`/`catch` around parsing, a content-type check of the response and an error after the request are not restrictions. A deny-list of internal hosts is incomplete unless it is applied to the resolved address.

## Protection coverage

Protection must cover every request-derived path to the destination operand and every feasible branch, and redirects must be disabled (`redirect: 'error'` or `'manual'`, `maxRedirects: 0`) or unable to leave the permitted hosts. A control on one value, branch or invocation never protects another. Unknown helpers and reassignments after the check stay unknown.

## Do not claim

Do not claim network reachability, cloud metadata exposure, DNS rebinding or a deployed proxy policy. Do not treat a body, header or query parameter sent to a fixed destination as server-side request forgery. Do not infer an allow-list from a variable name or comment.
