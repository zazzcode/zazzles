id: zazzles.ssrf.python
version: 1
languages: python

# Python server-side request forgery guidelines

Type hints are not runtime validation. These guidelines interpret one outbound HTTP call at a time whose destination operand a request value reaches.

## Posture

Report a source-confirmed server-side request forgery separately from field validation. A request value that reaches the URL argument of a verified `requests`, `httpx` or `urllib.request.urlopen` call is the claim; exploitability is a static judgment, not runtime confirmation. Prefer selecting a destination from a fixed mapping of trusted URLs by a request-supplied key over accepting a URL.

## Operations

`requests.get(url, ...)`, `requests.request(method, url, ...)`, the same `httpx` functions and `urllib.request.urlopen(url)` request `url`; `params`, `data`, `json` and `headers` do not change the destination host. A request value sent as data or a header to a fixed URL is not destination control. `requests` and `urllib` follow redirects by default; `urlopen` also opens `file:` and `ftp:` URLs.

## Destination control

The whole request value passed as the URL controls scheme, host, port and path. An f-string or concatenation whose fixed prefix ends after the host leaves the host fixed only when the prefix includes the path separator after the host; `"https://api.example.com" + value` can become `https://api.example.com.attacker.test`. `urllib.parse.urljoin(base, value)` lets an absolute value replace the base.

## Restriction

A restriction must parse the same value (`urllib.parse.urlparse(value)`) and compare its `hostname` (and scheme) with trusted constants, or compare the whole URL with a finite allow-list, and reject before the call. `startswith`, `in` and regular expressions on the raw string are prefix-only: userinfo, alternative IP forms and encodings pass them. A type check, a `try`/`except` around the request, a status or content-type check of the response and an error after the request are not restrictions. A deny-list of internal hosts is incomplete unless it is applied to the resolved address.

## Protection coverage

Protection must cover every request-derived path to the destination operand and every feasible branch, and redirects must be disabled (`allow_redirects=False`) or unable to leave the permitted hosts. A control on one value, branch or invocation never protects another. Unknown helpers and reassignments after the check stay unknown.

## Do not claim

Do not claim network reachability, cloud metadata exposure, DNS rebinding or a deployed proxy policy. Do not treat data, json or headers sent to a fixed destination as server-side request forgery. Do not infer an allow-list from a variable name or comment.
