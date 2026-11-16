# Proposal: code injection and open redirect analyzers

**Status:** Proposal, not an implementation contract. It authorizes no coding or paid model calls.
**Drafted:** 2026-11-16, after Next.js support (draft PR zazzcode/zazzles#18).
**Driving rows:** vuln-nextjs `JS-001`, `JS-002` (CWE-95), `REDIR-001` (CWE-601); vulnerable-typescript-app
`TS-CODE-01`, `TS-REDIRECT-01`; VulnPy `unsafe_code_exec`; Juice Shop `/redirect`.
**Out of scope here:** `SCA-001` (dependency advisory). See [§2](#2-one-analyzer-or-several).

## 1. Summary

Add two Scan analyzer families on the shared engine:

| Family | CWE | Question it answers | Main sinks |
| --- | --- | --- | --- |
| **Code injection** (`code`) | CWE-94, CWE-95 | Can request data become code that a JavaScript or Python interpreter evaluates? | `eval`, `new Function`, `setTimeout(string)`, `vm.run*`, Python `eval`/`exec`/`compile` |
| **Open redirect** (`redirect`) | CWE-601 | Can request data choose where a redirect or navigation sends the user, off this site? | `res.redirect`, `Location` headers, Next `redirect()` / `NextResponse.redirect` / `getServerSideProps` `redirect`, `window.location`, Flask/Django/Starlette redirects |

Both reuse entry discovery, input acquisition (Express, Fastify, Hapi, Next.js, Python adapters),
the guard engine, evidence wire v7, completeness gates, the decision model, exact replay and the
reports. Each adds its own sink contracts, claim protocol, judge policy, catalog components,
fact codes, report finding type and analysis guide. Neither changes another family's results.

## 2. One analyzer or several

**Two families, plus SCA kept separate.**

- **Code injection and open redirect are separate families.** They differ in every part a family
  owns: sinks, operand roles, what counts as protection, questions, verdict rules, CWE, severity
  and remediation. `eval(x)` is protected only when `x` cannot form code. `res.redirect(x)` is
  protected when `x` cannot leave the site. Folding them together would blur both judgments and
  their reports. They can ship in one milestone and share slice C0 (§6).
- **SCA (`SCA-001`) is not a Scan analyzer.** It reads manifests and lockfiles against an advisory
  database. It has no source-to-sink flow, no evidence bundle and no model judgment. It belongs to
  the planned **Audit** capability ([design](.zazz/architecture/sca-design.md)). The owner has
  deferred it. The existing NX-BP-01 practice check already reports known-vulnerable Next.js
  versions as an observation.

## 3. Roadmap position (owner order, 2026-11-16)

1. **Code injection and open redirect** (this proposal).
2. **Prototype pollution** (CWE-1321): JS/TS recursive merge, `set`/`defaultsDeep`-style library
   calls and computed `obj[a][b] = v` writes with request-controlled keys.
3. **Drupal / PHP support**: a PHP language adapter and Drupal routing, controllers, Form API,
   database API and Twig/render-array output.
4. **Agent skills fixes, the scan/fix loop, and importing external SAST findings.**

Deferred: **XXE** and **SCA / dependency Audit**.

## 4. Family A: code injection (CWE-94/95)

### 4.1 Claim

Request-derived text reaches the code operand of a verified evaluation API, so an attacker can
run code in the server process (CWE-94/95, remote code execution) or in the victim's browser
(CWE-95 in a browser module: script execution with the page's privileges). Data passed *as data*
into code that is fixed (a sandbox variable, a JSON value) is not this claim.

### 4.2 Sink contracts

| Contract | Operation | Code operand | Notes |
| --- | --- | --- | --- |
| `js-eval-v1` | global `eval(x)`, `globalThis.eval`, `window.eval` (unshadowed) | arg 0 | Direct and indirect eval; both evaluate code |
| `js-function-constructor-v1` | `new Function(...a, body)`, `Function(...)` | every argument (parameter list and body) | Parameter strings are code too |
| `js-timer-string-v1` | `setTimeout(x)`, `setInterval(x)`, `setImmediate` in the browser | arg 0 when it is not a function | A function argument is not a claim |
| `node-vm-v1` | `vm.runInThisContext`, `runInNewContext`, `runInContext`, `new vm.Script`, `vm.compileFunction`, `vm.SourceTextModule` | the code string | The fact `vm_not_security_boundary` applies: Node documents `vm` as not a sandbox. Request data only in the context object is data, not code |
| `js-safe-eval-libs-v1` | `notevil`, `safe-eval`, `vm2`, `static-eval`, `expr-eval`, `mathjs.evaluate` | the expression | Library-specific facts and advisories: `vm2` and `safe-eval` have sandbox escapes, `notevil` has known bypasses, `mathjs` evaluate is not sandboxed for function definitions. These are Review or poor practice unless an advisory applies |
| `python-eval-v1` | `eval`, `exec`, `compile` (unshadowed builtins) | arg 0 | `ast.literal_eval` is the safe parser and is not a sink |
| (browser) | the same JS contracts in `"use client"`, Pages components and browser modules | — | Entry kind `browser`; the claim reports the browser execution context |

Out of scope, with explicit `not_covered` notes: server-side template injection (Jinja/EJS/Pug
compiling request templates: a later family), deserialization (`pickle`, `node-serialize`), dynamic
`import()`/`require(x)` (module loading, recorded as an observation), WebAssembly.

### 4.3 Operand facts and transforms

- **Code shape:** whether request text forms the whole program, or is interpolated into a JavaScript
  string literal inside fixed code (`` eval(`setResult('${x}')`) `` in JS-001). Interpolating into a
  literal is still injectable: quote break-out.
- **Recognized transforms:** `Number()`, `parseInt` / `parseFloat`, `JSON.stringify` (which makes
  a valid literal and blocks quote break-out inside one), `JSON.parse` *instead of* eval, and
  numeric `zod`/`typeof` checks.
- **Allow-list guards:** character-class regexes with no identifier characters (for example
  `^[0-9+\-*/ ().]+$`) are a containing control. Partial blacklists (`replace(/[;]/g, '')`,
  rejecting `require` or `process`) are not containing.
- **Origins:** `JS-001`'s value comes from `getServerSideProps` `query.input`, passed as a prop to
  a component `useEffect`. That needs a props link from the server stage to the browser module
  (§6, C2).

### 4.4 Questions (`code-components-v1`)

1. `code_control`: `whole_program`, `inside_string_literal`, `data_only` (passed as a value to
   fixed code), `none`, `unknown`.
2. `code_restriction`: `allowlist_grammar` (the value can only match a grammar with no identifiers
   or calls), `type_conversion` (numeric or JSON-literal), `blacklist_only`, `sandbox_library`,
   `none`, `unknown`.
3. `protection_coverage`: `complete`, `incomplete`, `unknown` (the same semantics as SSRF and path).

### 4.5 Judge policy (`internal/judge/code.go`)

- **Confirmed:** `whole_program` or `inside_string_literal`, a raw path, restriction `none` or
  `blacklist_only`, and no claim blocker.
- **Protected:** `allowlist_grammar` or `type_conversion` on every path with complete coverage,
  backed by a source-established guard or transform.
- **Poor practice or Review:** a `sandbox_library` with no applicable advisory (Review); one with an
  advisory (poor practice, citing the advisory).
- **No claim:** `data_only`. The finding says code is fixed and the value is data.
- Contradictions (for example a restriction claimed where the source has no guard) are blocked as
  `code_answers_inconsistent`.

### 4.6 Expected results (answer-key draft)

| Row | Location | Expected |
| --- | --- | --- |
| vuln-nextjs `JS-002` | `pages/api/vulnerable-submit.js:15`, eval of a template literal | Confirmed (`inside_string_literal`) |
| vuln-nextjs `JS-002-safeControl` | `pages/api/protected-example.js` | No record (no eval) |
| vuln-nextjs `JS-001` | `pages/vulnerable/eval-injection.js:8`, browser `useEffect` eval of a prop from `query.input` | Confirmed, browser context |
| vulnerable-typescript-app `TS-CODE-01` | `src/server.ts:137`, `eval(req.body.expression)` | Confirmed (`whole_program`) |
| VulnPy `unsafe_code_exec` | `trigger/unsafe_code_exec.py` `exec` and `eval`, 11 adapters | Confirmed per context |
| Juice Shop captcha | `routes/captcha.ts:22`, eval of a server-generated expression | No record (no request data) |
| Juice Shop B2B order | `routes/b2bOrder.ts:23`, `notevil` on the request body through `vm` | Review or poor practice (`sandbox_library`); the owner decides the key |
| Juice Shop `lib/xml.ts`, `fileUpload.ts` `vm.runInContext` | constant code, request data in the sandbox | No claim (`data_only`), possibly an observation |
| Juice Shop `new Function('specifier', ...)` | constant | No record |

## 5. Family B: open redirect (CWE-601)

### 5.1 Claim

Request-derived text chooses the destination of an HTTP redirect, or of a browser navigation the
page performs, so a victim following a trusted link can be sent to an attacker's origin. Executing a
`javascript:` URL stays an **XSS** claim (the `browser_navigation_sink` fact). The same sink can
carry both claims, with separate records that are linked in the report.

### 5.2 Sink contracts

| Contract | Operation | Destination operand |
| --- | --- | --- |
| `express-redirect-v1` | `res.redirect([status,] url)`, `res.location(url)`, Next Pages API `res.redirect` | url |
| `node-location-header-v1` | `res.setHeader('Location', v)`, `res.writeHead(3xx, { Location: v })`, `res.set/header('Location')` | v, only when the status is 3xx or set on the same response |
| `fastify-redirect-v1`, `hapi-redirect-v1` | `reply.redirect(url)`, `h.redirect(url)` | url |
| `next-redirect-v1` | `redirect()` / `permanentRedirect()` from `next/navigation`, `NextResponse.redirect(url)`, `getServerSideProps` / `getStaticProps` return `{ redirect: { destination } }`, middleware redirects | destination |
| `browser-navigation-v1` | `window.location = v`, `location.href/assign/replace(v)`, `window.open(v)`, Next `router.push/replace(v)` with an absolute URL, `<meta http-equiv=refresh>` | v |
| `python-redirect-v1` | Flask `redirect(v)`, Django `redirect` / `HttpResponseRedirect`, Starlette/FastAPI `RedirectResponse(v)`, aiohttp `HTTPFound(v)` | v |

### 5.3 Destination facts (shared with SSRF)

- **Origin class:** reuse `destinationOrigin` (`request`, `constant`, `environment`,
  `external_data`). Only `request` destinations become claims.
- **Shape:** `full_url`, `path_only` (a fixed `/` plus request text is still dangerous when the
  value can begin with `/` or `\`: `//evil.example` and `/\evil` are protocol-relative),
  `fixed_origin` (a literal origin plus a trailing `/`, then request data: no claim),
  `query_only`.
- **Guards:** reuse the shared guard engine and the `url_scheme_only_test` fact. Classify:
  - same-site relative checks (`startsWith('/') && !startsWith('//')` plus a backslash
    exclusion);
  - `new URL(v, base).origin === base.origin`;
  - host allow-lists on a parsed URL;
  - `startsWith` or `includes` on the raw string (Juice Shop's `isRedirectAllowed` uses
    `includes`, which an attacker satisfies by putting the allowed text in a query string).
- **Framework facts:** Next.js `redirect()` accepts absolute URLs; Express `res.redirect('back')` uses
  the `Referer` header, which is request-controlled.

### 5.4 Questions (`redirect-components-v1`)

1. `destination_control`: `full_url`, `host`, `path_only`, `fixed_origin`, `none`, `unknown`.
2. `destination_restriction`: `same_site_relative`, `parsed_origin_check`, `host_allowlist`,
   `prefix_or_substring`, `none`, `unknown`.
3. `protection_coverage`: `complete`, `incomplete`, `unknown`.

### 5.5 Judge policy (`internal/judge/redirect.go`)

- **Confirmed:** `full_url`, `host` or `path_only` control, restriction `none`, a raw path, and no
  claim blocker. A scheme-only test counts as `none`, as in SSRF.
- **Protected:** `same_site_relative`, `parsed_origin_check` or `host_allowlist` on every path with
  complete coverage and a source-backed guard.
- **`prefix_or_substring`:** owner decision. Recommendation: `includes`/`indexOf` is **Confirmed**,
  because an attacker can always place the allowed text in a query string; a `startsWith` with a
  full origin and trailing `/` is **Protected**; any other `startsWith` is **poor practice** (the
  SSRF rule).
- **No claim:** `fixed_origin` or a constant destination.

### 5.6 Expected results (answer-key draft)

| Row | Location | Expected |
| --- | --- | --- |
| vuln-nextjs `REDIR-001` | `pages/vulnerable/redirect.js:18`, `getServerSideProps` `redirect.destination = query.to` | Confirmed |
| vuln-nextjs `REDIR-001-safeControl` | `pages/secure/redirect.js:10`, `^\/[^/]` plus no-scheme regex | Protected |
| vulnerable-typescript-app `TS-REDIRECT-01` | `src/server.ts:239` `res.redirect(req.query.url)` | Confirmed |
| Juice Shop `/redirect` | `routes/redirect.ts:18`, `includes` allow-list | Confirmed under the recommendation (the known bypass challenge) |
| nodejs-goof login | `routes/index.js:29`, `res.redirect(req.body.redirectPage)` after login | Confirmed |
| OopsSec login form | `app/login/LoginForm.tsx:37` `?redirect=` → `window.location.href` | Confirmed as open redirect, linked to the existing XSS record |
| OopsSec middleware, Juice Shop `BASE_PATH + '/profile'` | fixed destinations | No record |

## 6. Required functionality (shared and per family)

| # | Area | Code injection | Open redirect | Files |
| --- | --- | --- | --- | --- |
| C0.1 | Candidate kinds | `code_execution_candidate` | `open_redirect_candidate` | `internal/analysis` (kinds, `CodeFacts`/`RedirectFacts` operand-path structs like `OutboundFacts`) |
| C0.2 | Family registration | `code`, languages JS/TS/Python, `RequiresAPI`, entries http/graphql/grpc plus **browser** | `redirect`, the same, plus browser | `internal/analysispacks/families.go`, `select.go`, `descriptors.go` |
| C0.3 | Protocols and questions | `code-components-v1` | `redirect-components-v1` | `analysispacks/code.go`, `redirect.go`, `questions.go` |
| C0.4 | Catalog components | `pack.code`, `claim.code`, `evidence.code`, `api.*` contracts | `pack.redirect`, … | `analysispacks/catalog.go`, `material.go`, `.zazz/architecture/analysis-packs.md` |
| C0.5 | Sink detection | contracts in §4.2 | contracts in §5.2 | new `internal/parse/code_*.go`, `redirect_*.go`; hooks in `flow.go` call evaluation; Python `python_code.go`, `python_redirect.go` |
| C0.6 | Claim assembly | operand paths, guards, transforms, completeness | destination paths via the SSRF machinery | `assembleClaims` hooks like `assembleSSRFClaims` |
| C0.7 | Judge policy | `judge/code.go` | `judge/redirect.go` | `judge/policy.go` dispatch, `bundle.go` roles, `client.go` |
| C0.8 | Fact codes | `vm_not_security_boundary`, `code_inside_string_literal`, `sandbox_library_advisory` | `protocol_relative_path`, `redirect_back_referer`, `redirect_also_xss` | `internal/guidelines/facts.md`, `facts_test.go` |
| C0.9 | Reports | finding type `code-injection` (CWE-94/95), guidance, SARIF rule | `open-redirect` (CWE-601) | `internal/report/finding_types.go`, `guidance.go`, `sarif.go`, `scoped_guidance.go` |
| C0.10 | CLI | `--only-family code` | `--only-family redirect` | `cmd/scan/main.go` help and validation |
| C0.11 | Equivalent-context reuse and budget | the role budget | the role budget | `judge/budget.go`, E1 reuse keys |
| C0.12 | Docs | `docs/analysis/code-injection.md` | `docs/analysis/open-redirect.md` | plus `docs/analysis/README.md`, `nextjs.md`, the README security-checks list |
| C1 | JS/TS server code injection | §4.2 server contracts | — | Express, Fastify, Hapi, Next route handlers, Pages API, Server Actions |
| C2 | Browser code injection | client eval, timers, Function | — | props link from `getServerSideProps` and Server Component props into client components (needed for JS-001) |
| C3 | Python code injection | `eval`/`exec`/`compile` | — | all 11 VulnPy adapters, Flask, FastAPI, Django |
| C4 | Server open redirect | — | Express, Fastify, Hapi, Next (all four shapes), Pages API | reuses `destinationOrigin` and the guard engine |
| C5 | Browser open redirect | — | `browser-navigation-v1`, linked to the XSS navigation record | `xss_claims.go` link and report pairing |
| C6 | Python open redirect | — | Flask, Django, Starlette, aiohttp | Python adapters |
| C7 | Evaluation | answer keys §4.6 / §5.6, the lab test picks up CWE-95/601 rows automatically | the same | `nextjs_lab_test.go` `labFamilies`, sample catalog, paid runs plus exact replay |

### 6.1 Tests

- Paired positive and negative fixtures per contract (shadowed `eval`, function-argument timers,
  `ast.literal_eval`, fixed-origin redirects, protocol-relative `/\`).
- `TestNextJSVulnLab` adds `CWE-95 → code_execution_candidate` and
  `CWE-601 → open_redirect_candidate` to `labFamilies`; those rows then fail until detected.
- The OopsSec and Node sample regression comparison must stay byte-identical outside the new kinds.
- Exact replay of every paid run.

### 6.2 Paid budget estimate

About 15 new code records and 15 new redirect records across the samples (VulnPy contexts add about
22). Two passes plus a final replay run come to roughly 150 `gpt-6-luna` requests. This needs a
separate owner cap.

## 7. Owner decisions needed

1. Confirm two families (`code`, `redirect`) rather than one combined family.
2. `prefix_or_substring` redirect policy (§5.5 recommendation).
3. Juice Shop B2B `notevil`: Review or poor practice.
4. Browser eval (JS-001): report under code injection only, or also as an XSS record.
5. Whether Python ships in the same milestone (C3, C6) or follows JS/TS.
6. Paid cap and model for evaluation.

## 8. Next after this

- **Prototype pollution (CWE-1321).**
  - Sinks: lodash `merge` / `mergeWith` / `defaultsDeep` / `set` / `setWith` / `zipObjectDeep`
    with versions checked, `jquery.extend(true, …)`, hand-written recursive merges, and computed
    two-level assignment `o[k1][k2] = v` with request-controlled keys.
  - Protections: key deny-lists (`__proto__`, `constructor`, `prototype`), `Object.create(null)`,
    `Map`, schema validation.
  - Samples: nodejs-goof (lodash) and vulnerable-typescript-app (CWE-1321 row).
- **Drupal / PHP support.**
  - A tree-sitter PHP grammar and source adapter.
  - Drupal `*.routing.yml` routes to controller methods, Symfony `Request` inputs and Form API
    `$form_state` values.
  - SQL through `\Drupal::database()->query()` placeholders versus concatenation, entity queries,
    and Twig autoescape with `|raw` and render-array `#markup` for XSS.
  - Command, path and SSRF contracts on PHP built-ins and Guzzle.
- **Then:** fixes to the agent skills, the scan/fix loop, and importing external SAST findings with
  provenance.
- **Deferred:** XXE, and SCA / dependency Audit.
