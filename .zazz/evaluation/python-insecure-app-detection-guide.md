# Python insecure app detection guide and answer key

[ThreatByte guide](threatbyte-detection-guide.md) ·
[App overview](../../docs/samples/python-insecure-app/README.md) ·
[Existing comparison cases](../../docs/samples/python-insecure-app/cases.json)

## How to use this guide

This living guide defines source-backed expectations and reusable acceptance checks for
`trottomv/python-insecure-app`. It is not a frozen scan snapshot or a claim that the app has only
one vulnerability. Update it as source and supported vulnerability families change. Expected
answers remain evaluation material and must not enter detector logic or model requests.

Current families are SQL injection, input validation, logger leaks and supported XSS flavors.
SSTI, secret scanning, dependency auditing and configuration/availability checks are planned work
for future branches. Report those gaps explicitly; do not count unimplemented families as passed.

Reviewed source: revision `b188493768ca2c1ef003e08148fb2e4577219c36`,
[app/main.py](https://github.com/trottomv/python-insecure-app/blob/b188493768ca2c1ef003e08148fb2e4577219c36/app/main.py),
[configuration](https://github.com/trottomv/python-insecure-app/blob/b188493768ca2c1ef003e08148fb2e4577219c36/app/config.py),
[README](https://github.com/trottomv/python-insecure-app/blob/b188493768ca2c1ef003e08148fb2e4577219c36/README.md).
The clean verification checkout and its source hashes were checked; application modules were not
imported/executed, dependencies installed, or network requests made by the app during this review.

## What the author actually demonstrates

The author's [FastAPI security walkthrough](https://dev.to/trottomv/secure-by-design-in-python-a-fastapi-app-with-5-devsecops-tools-and-a-real-time-ssti-vulnerability-2e6n)
demonstrates server-side template injection using an arithmetic template expression supplied in
`name`. It recommends using constant template source with separately supplied variables, and
surveys dependency, static, dynamic, container and fuzz testing. It does not demonstrate a SQL
injection in this application's route. Its sample advisory identifier ending in `XXXXX` is
illustrative, not a real CVE answer key. The README separately advertises insecure dependencies,
hardcoded secrets and SSTI. Neither document is a complete location-level inventory.

Internet research found the upstream repository and this author walkthrough, not an exhaustive
independent answer key. The expectations below therefore identify author-confirmed cases,
additional source-derived cases, negative controls and questions still requiring evidence.

## Route and complete input trace

The application has one declared route: `GET /`, with an explicit HTML response contract.
One route or one sink can contain multiple source paths and distinct vulnerability mechanisms.

| Step | Source | Meaning |
| --- | --- | --- |
| Route | main 18–19 | FastAPI query parameter `name: str`; response_class is HTMLResponse |
| External call | main 31–32 | requests GET to a configuration-derived URL, then status checking |
| Fallback | main 33–34 | Two named exception types produce constant public-IP text |
| Remote input | main 36 | Response body text becomes `public_ip` |
| Name fallback | main 37 | A falsey name uses a configured name; nonempty attacker input still survives |
| HTML construction | main 38 | Both name and public_ip enter an f-string used as HTML/template source |
| Execution/output | main 41 | `Template(content).render()` compiles that source, then returns HTML |

A string annotation does not exclude HTML or template syntax. The template constructor does not
sanitize source characters. Successful HTTP status checking does not validate response-body content.
The `public_ip` variable name is not evidence that its value is a parsed or validated IP address.

## Current-family expected answers

| ID | Expected case | Classification and evidence |
| --- | --- | --- |
| PI-XSS-NAME | Query name → f-string → Template/render → HTML | XSS finding; raw request content reaches browser markup at main 41 |
| PI-XSS-REMOTE | Remote body text → public_ip → same HTML/template sink | Separate untrusted-origin witness; output vulnerability if that response is attacker-influenced; no claim every visitor controls the configured service |
| PI-VAL-NAME | Business validity of name | Review unless an actual policy is supplied; no required email/identifier/length rule is established merely by `str`. Keyed `review` in `cases.json` |
| PI-SSTI-NAME | Query name → f-string → `Template(content)` | `template_injection_candidate` with the `name` source (main 19); see [SSTI](#ssti-author-confirmed-request-path-and-source-derived-response-path) |
| PI-SSTI-REMOTE | Remote body → `public_ip` → `Template(content)` | `template_injection_candidate` with the response-body source (main 36) |
| PI-SQL-NONE | SQL injection | No demonstrated SQL sink in application source; do not invent a SQL finding |
| PI-LOG-NONE | Password/email logger leak | No application logging/print emission of those values is shown; do not invent a leak from secret variable names |
| PI-OUTBOUND | Destination of requests.get | Configuration-derived, not a direct request-to-URL SSRF witness; remote response remains a distinct input |
| PI-XSS-FALLBACK | Constant public-IP fallback | The constant alone is not an unsafe source; it does not protect a simultaneously unescaped name |
| PI-STORED-DOM | Stored or DOM XSS | No persistence/browser script sink is established here; do not relabel server HTML flow as stored/DOM XSS |

Key corrections (2026-11-19): `PI-VAL-NAME` was keyed `candidate`, which the scorer counted as a
required positive although this guide expects Review; it is now `review`. `PI-SSTI-NAME` and
`PI-SSTI-REMOTE` are new `candidate` rows with source anchors at main 19 and main 36; main 41
compiles `content` as template source (`Template(content).render()` with no variables).

Two XSS source witnesses converge at the same vulnerable construction/output site. A report may
group them as one sink-level defect, but must retain both sources and their different control
assumptions. Counting one sink is not proof that only one app vulnerability exists. SSTI below is
a distinct server-side mechanism even though it shares the same construction site.

There is no database import, cursor/ORM operation or SQL execution in the reviewed `app/` code.
The README's generic explanation of what scanners can detect does not add such an operation.
The proxy's SQL-themed regular expression is a defense configuration, not an SQL sink.

### Protective patterns and regression cases

The author-proposed constant-template change addresses template-source injection but does not
by itself enable Jinja HTML escaping. [Jinja's documented default](https://jinja.palletsprojects.com/en/stable/faq/#why-is-html-escaping-not-the-default)
requires deliberate escaping configuration. For both current inputs, the combined repair pattern is:

```python
template = Template(
    "<h1>Hello, {{ name }}!</h1><h2>Public IP: <code>{{ public_ip }}</code></h2>",
    autoescape=True,
)
return template.render(name=name, public_ip=public_ip)
```

This is a candidate source pattern, not a patch applied to the vulnerable app. An alternative is a
verified framework template environment with appropriate autoescaping. Escaping values does not
make attacker-controlled template source safe to compile; keep the template itself constant.

- [ ] Catch the request-name XSS path with the explicit HTML response contract.
- [ ] Preserve the successful remote-body path and the exception fallback separately.
- [ ] Exercise name absent, empty, normal, HTML-significant and template-expression values.
- [ ] Mock the remote service with normal text, markup-like text and template-expression text.
- [ ] Verify constant-template/no-autoescape remains an XSS positive.
- [ ] Verify constant-template/autoescape protects both name and remote text.
- [ ] Verify template expressions passed as values remain literal rather than being evaluated again.
- [ ] Do not demand arbitrary business validators or flag a fixed URL as request-controlled SSRF.
- [ ] Do not classify commented test examples as executed security tests.

`tests/test_main.py:16–40` tests ordinary response behavior with a mocked service.
Its SSTI checks at 42–46 are comments, not active protection or successful exploit assertions.
A future runtime validation should use an isolated copy, mock outbound traffic and test both inputs.

## Future-branch expected cases

### SSTI: author-confirmed request path and source-derived response path

- **PI-SSTI-NAME:** main 19 → 37 → 38 → 41. A template expression in the nonempty query value becomes
  executable template source. The author's arithmetic example supports the expected SSTI finding.
- **PI-SSTI-REMOTE:** main 36 → 38 → 41. External text becomes the same executable template source.
  Retain the remote-service control precondition. This is a source-derived additional path, not a
  second author demonstration or proof of arbitrary visitor control over that service.
- A benign arithmetic-expression check suffices to test template interpretation. Do not equate that
  check with a demonstrated remote-code-execution chain or attempt destructive payloads.
- [ ] Add an SSTI-specific source/sink contract, question protocol and protected constant-template pair.
- [ ] Keep SSTI and browser XSS as separate claim kinds while correlating their shared root construction.

### Hardcoded configuration and potential secrets

`app/config.py:15` contains an intentionally embedded token-like literal and ignores the environment
variable shown in the example configuration. The README identifies hardcoded secrets as deliberate.
Future secret scanning should recognize the demonstration credential material and its configuration
precedence, while preserving provenance and not claiming the token is live or externally usable.

The name literal at config 13 is returned in ordinary greeting behavior when name is omitted/empty.
A variable named SUPER_SECRET_NAME is not enough to prove confidential personal data or a logger
leak. Determine intended confidentiality and usage before promoting that separate case. The token
literal itself is not directly emitted by the shown route; do not invent a dataflow from it to logs.

- [ ] Add secret-material detection with contextual positive/demo/placeholder controls.
- [ ] Distinguish a hardcoded credential from a name, an environment placeholder and a secret's use.
- [ ] Assess response disclosure separately if a future requirement establishes confidentiality.

### Dependencies and containers

`requirements/common.in` constrains Jinja to the 3.0.x series. The upstream
[Jinja advisory GHSA-cpwx-vrp4-4pq7](https://github.com/pallets/jinja/security/advisories/GHSA-cpwx-vrp4-4pq7)
identifies affected versions through 3.1.5 for a sandbox issue. This is a concrete future SCA
investigation, unlike the article's placeholder CVE. Resolve the actual built dependency set and
current advisory metadata before recording package/version findings. This application uses ordinary
Template, not a shown SandboxedEnvironment; do not conflate a sandbox advisory with the existing
unsandboxed template-source defect or claim advisory reachability without its preconditions.

- [ ] Audit resolved Python packages, transitive dependencies and each selected image/SBOM.
- [ ] Record package version, advisory ID/range, fix metadata and separate reachability evidence.
- [ ] Preserve distinct Docker build variants rather than asserting every image has the same issues.

### Configuration and availability

- **Missing request deadline:** main 31 calls requests.get with no timeout. A stalled service can
  hold the request; additionally, this synchronous network call executes inside an async route.
  Track for future availability/async-I/O practice analysis, not as SQL injection or a PII leak.
- **Incomplete network-error handling:** only HTTPError and InvalidSchema are caught. Other connection
  failures can escape; assess exception behavior independently rather than declaring an exploit.
- **Conditional debug exposure:** main 14 reads config.DEBUG, whose default is false; `.env_temp:3`
  enables it in the example setup. Require actual configuration/exception evidence rather than an
  unconditional “production debug exposed” verdict.
- **Disabled WAF:** `caddy/Caddyfile:13` sets `SecRuleEngine Off`, despite rules with deny actions below.
  [Coraza's directive contract](https://www.coraza.io/docs/seclang/directives/#secruleengine)
  distinguishes Off from active enforcement. Rule names or a proxy do not establish protection.
- [ ] Give each future configuration/availability case a source-backed condition and negative control.
- [ ] Keep desired source-code protection independent of optional proxy presence and deployment state.

## Comparing Zazzles, Semgrep and Bearer

The existing Semgrep CE 1.183.0 rule snapshot and pinned Bearer baseline both contain zero results
for this source revision. See [Semgrep evidence](../../docs/samples/python-insecure-app/semgrep/baseline.json)
and [Bearer evidence](../../docs/samples/python-insecure-app/bearer/baseline.json).
Zero means the selected configurations reported nothing; it is not a clean bill of health or an
assertion about every Semgrep product/rule pack. Zazzles' current XSS report groups the HTML sink;
its separate validation review is not an additional confirmed app vulnerability.

- [ ] Compare coverage case by case using IDs above, not raw result totals.
- [ ] Verify both untrusted witnesses are present in the sink evidence.
- [ ] Record which cases a tool supports, misses, cannot resolve, or has not implemented yet.
- [ ] Reject SQL false positives in a route without an SQL operation.
- [ ] Never call the entire application safe because SQL is absent or only one sink is reported.
- [ ] Expand automated comparison cases beyond the existing three checks as each family is implemented.
