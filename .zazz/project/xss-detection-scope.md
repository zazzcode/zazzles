# XSS detection scope (`xss-response`)

**Status: first-pass discovery/reporting implemented; analysis/judging hardening handed off.** Chosen by the user on 2026-11-01 as the next capability. All XSS work below is
delivered in one worktree from `stage` (created after `logger-leak` merged and the project was
renamed to Zazzles), in the order of [delivery increments](#delivery-increments): backend/API first,
browser last. This document records scope, targets and rules; the user authorized implementation on 2026-11-01
under the [implementation contract](../specifications/scan/xss-response.md). When implemented, the product rules move to a root `docs/analysis/` guide, as for
[logging](../../docs/scan/analysis/sensitive-data-logging.md).

## What the claim means

Cross-site scripting (XSS) occurs when untrusted data reaches a browser context that interprets it as
markup or code. TypeScript types do not prevent it: they check structure at compile time, not data at
runtime. The claim is about one flow into one rendering sink in one output context.

| Type | Where data enters | Where it executes | Example shape |
|---|---|---|---|
| Reflected (server) | Request field | Server-built HTML response | `` res.send(`<h1>${req.query.q}</h1>`) `` |
| Stored (persistent) | Request saved to a database or file | Any later page rendering it | comment saved, then `div.innerHTML = comment` |
| DOM-based (client) | Browser source: `location`, `URLSearchParams`, `window.name`, `postMessage`, form input | Client-side sink | `el.innerHTML = params.get('name')` |
| Cross-tier reflected | Request field echoed by an API response | Client-side sink rendering that response | API returns `id`; client renders it as HTML |

Reading `window.location.search` in the browser and writing it into `innerHTML` is DOM-based XSS in
OWASP's taxonomy even though it is often described as "reflected": no server reflects the data.
Scan keeps the four shapes distinct because each needs different evidence.

## Sinks

- **Server:** `res.send`/`res.write`/`res.end` with a string body (Express defaults a string to
  `text/html`), an explicit HTML `Content-Type`, string replacement into an HTML template, and
  unescaped template output: Pug `!{}` or compiling request-influenced template text, EJS `<%-`,
  Handlebars `{{{ }}}`. `res.json` and non-HTML content types are negatives.
- **DOM:** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`/`writeln`, jQuery
  `.html()`/`.append(html)`, `Range.createContextualFragment`; URL sinks (`href`, `src`, `location`)
  with a `javascript:` scheme; string-evaluating `setTimeout`/`setInterval`/`new Function`.
- **Frameworks:** Angular `DomSanitizer.bypassSecurityTrustHtml`/`Script`/`Url`/`ResourceUrl` and the
  template binding that renders the trusted value (`[innerHTML]`, `[href]`); React
  `dangerouslySetInnerHTML`; Vue `v-html`.

## Protections

- **Context encoding:** text APIs (`textContent`, `innerText`, `createTextNode`), framework
  interpolation (React JSX `{value}`, Angular `{{value}}`), template escaped output (Pug `#{}`, EJS
  `<%=`, Handlebars `{{ }}`), and verified HTML-entity encoders for HTML text. The encoding must match
  the context: HTML-entity encoding does not make a value safe in a script, URL, or unquoted attribute.
- **Sanitization for rich HTML:** a verified binding to DOMPurify or `sanitize-html` applied before
  the sink, on every path. A custom regex such as Juice Shop's `sanitizeLegacy` is not established
  protection; a function named `sanitize` whose body is not shown stays Inconclusive.
- **Angular default sanitization:** `[innerHTML]` with an untrusted string is sanitized by Angular;
  it becomes a sink only when the value was marked trusted with a `bypassSecurityTrust*` call.
- **Content Security Policy:** defense in depth. CSP reduces impact but does not make a sink safe; a
  missing or weak CSP header is reported by the separate `cookie-session-headers` capability.

## Evidence before judgment

As with database and logging claims, analysis MUST establish the binding of the sink API, the source,
the transfers into the sink argument, the output context, and every encoding or sanitization on the
path and its order. Names alone never establish a sink or a sanitizer.

- Response context: content type, template engine and output form (escaped versus raw).
- Client sources: browser APIs and Angular `ActivatedRoute` query parameters are DOM sources; API
  response fields are sources whose origin must be linked to the producing route.
- Stored XSS needs a cross-route link: a write route persists a request field into a model attribute
  or file, and a read route or client component renders that attribute. This uses the
  [repository graph](../architecture/repository-graph.md) persistence and response edges.
- Client analysis must parse Angular component templates (`.html`) and connect bindings to component
  fields; the current Tree-sitter inventory parses only JS/TS. This is new extraction work.
- Exploit payloads are never detector input and are not required for a static judgment. Challenge
  names and `vuln-code-snippet` comments in targets are evaluation labels only, never evidence.

## Outcomes

- **Finding / soft orange:** request or client-source data reaches a verified raw-HTML sink with no
  encoding or verified sanitizer on the path (construction practice to fix even before judgment).
- **Finding / soft red:** a versioned XSS judgment (context, encoding adequacy, sanitizer
  effectiveness, exposure) is consistent and claim evidence is complete.
- **Review / soft blue:** unresolved content type, template mode, sanitizer body, or stored-data origin.
- **Protected / soft green:** context-appropriate encoding or a verified sanitizer on every path.

## Acceptance targets from the sample applications

Source-inspected 2026-11-01. Juice Shop challenge keys identify the evaluation case only.

Rows follow delivery order. Increment 3 reports the backend half (unencoded data stored or echoed by
the API); increment 5 completes the case at the browser sink.

| Target | Case | Type | Code path | Increments |
|---|---|---|---|---|
| Vulnerable TypeScript app | `GET /api/search` | Reflected (server) | `req.query.query` interpolated into `res.send` HTML (`src/server.ts:114-117`) | 1 |
| Node.js Goof | `GET /login?redirectPage=…` | Reflected, server template / attribute | `routes/index.js:80-85` passes query field to `views/admin.ejs:17` raw `<%- redirectPage %>` inside quoted `value` attribute | 1 |
| Juice Shop `usernameXssChallenge` | Profile username | Stored, server template | `routes/userProfile.ts:73` replaces `_username_` in Pug template text before compiling | 2 |
| Juice Shop `videoXssChallenge` | Subtitle file | Stored, server template | `routes/videoHandler.ts` inserts subtitle content into a Pug template script | 2 |
| Node.js Goof | Todo content | Stored, server template | `/create` and `/update/:id` persist content → `/` reads todos → `views/index.ejs:20` raw `marked(...)`; `app.js:75` enables old `marked` sanitization, effectiveness unresolved | 1–3 |
| Juice Shop `reflectedXssChallenge` | Track order | Cross-tier reflected | `routes/trackOrder.ts` echoes `id` (filtered only when the challenge is disabled) → `track-result.component.ts:49` `bypassSecurityTrustHtml` | 3, 5 |
| Juice Shop `httpHeaderXssChallenge` | `True-Client-IP` header | Stored | `routes/saveLoginIp.ts` (sanitized only when the challenge is disabled) → `last-login-ip.component.ts:40` | 3, 5 |
| Juice Shop `persistedXssUserChallenge` | User email | Stored | user API write → `administration.component.ts:74` `bypassSecurityTrustHtml` | 3, 5 |
| Juice Shop `persistedXssFeedbackChallenge` | Feedback comment | Stored | feedback write → `about.component.ts:120`, `administration.component.ts:92` | 3, 5 |
| Juice Shop `restfulXssChallenge` | Product description via API | Stored | product API write → `search-result.component.ts:113` `bypassSecurityTrustHtml(description)` | 3, 5 |
| Juice Shop `localXssChallenge`, `xssBonusChallenge` | Search box | DOM | `search-result.component.ts:146` `bypassSecurityTrustHtml(queryParam)` → `[innerHTML]="searchValue"` | 5 |

Goof's pinned revision, escaped EJS/Handlebars controls and comparator boundaries are in the
[target inventory](../evaluation/nodejs-goof-capabilities.md). The
[initial comparison](../evaluation/nodejs-goof-results.md) preserves the Bearer/current-zazzles
baseline and the [answer key](../../docs/samples/nodejs-goof/xss-answer-key.md) owns scanner-independent
expected labels. These added backend cases fit the existing delivery order.

Negatives to keep: Juice Shop `[innerHTML]` bindings of translated constants (`translate` pipe),
`data-export.component.ts:58` captcha image from the server, Angular `{{ }}` interpolation, `res.json`
responses, and values passed through `entities.encode` into HTML text.

## Controls

Pair each sink with its protected counterpart: `innerHTML` versus `textContent`; `res.send` HTML versus
`res.json`; Pug `!{}` versus `#{}`; `bypassSecurityTrustHtml(x)` versus plain `[innerHTML]`; DOMPurify
before the sink versus after it or on one branch only; a real DOMPurify import versus a local function
named `sanitize`; entity encoding in HTML text versus inside a `<script>` or `href`.

## Delivery increments

All increments belong to the single `xss-response` worktree. Backend and API work comes first because
it uses the existing Express route analysis; browser-side work comes last because it needs new
extraction.

1. **Backend reflected responses.** Express string responses with an HTML content type, `res.write`/
   `res.end`, and template engines' unescaped output on analyzed routes.
   - Sinks and response-context model (`res.send` string defaults to `text/html`; `res.json` negative).
   - Verified encoders and sanitizers (`entities.encode`, `sanitize-html`, DOMPurify on the server).
   - Targets: vulnerable TypeScript app `GET /api/search`; Node.js Goof `GET /login` raw EJS
     attribute output. Goof stored Markdown rendering additionally needs the persistence links below.
2. **Backend template injection.** Request or stored data inserted into template text before compiling
   (Pug, EJS, Handlebars), and raw template output forms.
   - Track template file reads, string replacement into template text, and compile/render calls.
   - Targets: Juice Shop profile username (`routes/userProfile.ts`) and video subtitles
     (`routes/videoHandler.ts`).
3. **API-side stored and echoed data.** Routes that persist request data without encoding or
   sanitization into fields later served by the API, or that echo request data in API responses.
   Reported as the backend half of a stored or cross-tier claim, with Review until a rendering sink
   is linked.
   - Persistence edges from request fields to model attributes and files; response edges from model
     attributes to API JSON fields (see the [repository graph](../architecture/repository-graph.md)).
   - Conditional sanitization, such as Juice Shop sanitizing only when a mode is disabled.
   - Targets: Juice Shop track order, login IP header, user email, feedback comment, product description.
     Node.js Goof adds todo writes linked to the server-rendered Markdown output; no browser
     extraction is required for that case.
4. **Judgment.** An `xss-use` question protocol (output context, encoding adequacy, sanitizer
   effectiveness, exposure) and a rule-pack section, with offline tests and later capped live batches.
5. **Browser side (last).** DOM sources and sinks in client JS/TS, Angular and React framework sinks,
   and links from API response fields to client sinks to complete the stored and cross-tier cases.
   - **Parse Angular component templates (`.html`).** The scanner currently parses only JS/TS, so
     `[innerHTML]` and other bindings are invisible. Add template extraction and connect each binding
     to its component field.
   - Model `DomSanitizer.bypassSecurityTrust*` as the step that turns Angular's default sanitization off.
   - Link frontend HTTP service calls to backend route responses.
   - Targets: Juice Shop search box DOM case, then the browser half of every increment 3 case.

Each increment keeps code, tests, the product guide, and the sample outputs aligned.

## Client results and language adapters

Client-side claims appear in a separate **Browser / client-side** results section, alongside
**Server / API routes**. A browser record identifies component/file, browser or API source, sink,
output context, sanitization/trust bypass and source spans; it does not invent an HTTP route.
Stored/cross-tier claims retain related server/client evidence and a shared flow identity.

Source, transfer, rendering context, protection and persistence facts are language-neutral.
JS/TS/framework/template adapters supply these facts to shared judgment and reporting code.
After XSS, a Python vulnerable application will exercise a separate Python adapter and template
contracts; current work does not claim Python security analysis. Keep Express/Angular assumptions
in adapters rather than embedding them in the shared claim or report schema.

The [first-pass results](../evaluation/xss-implementation-results.md) own achieved behavior and
saved report counts. Continue deeper analysis/judging hardening from the
[local, gitignored handoff](../ephemeral/xss-analysis-handoff.md) in this same worktree. Source-reviewed expected labels
are reusable reference documentation; baseline applications stay unchanged and fixes use copies.
