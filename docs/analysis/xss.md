# Cross-site scripting analysis

[Analysis index](README.md) · [Result interpretation](../interpreting-results.md) · [Coverage and known gaps](../detection-capabilities/cross-site-scripting.md)

XSS is a source-to-rendering claim in a specific browser output context. Runtime input types and
validation do not replace context-appropriate encoding or HTML sanitization. The same value may
be protected in an escaped edit form and dangerous in a different raw template output.

## Implemented: reflected server output

The JS/TS adapter resolves verified Express receivers, direct handlers, named relative ESM imports
and literal CommonJS requires/exported functions. Shadowed or reassigned bindings are not trusted.
Request fields reaching `res.send` with string HTML, or `res.write`/`res.end` with an established HTML
content type, produce rendering claims. `res.json` and explicit non-HTML content types are negatives.
An unresolved content type stays Review. Response parameter names are taken from the handler,
rather than assumed to be `res`. `res.send` with an object literal is JSON, not HTML.

In a Next.js route handler or page server stage, a web-standard `new Response(body, init)`, or
`new NextResponse(body, init)` imported from `next/server`, is an HTML response only when
`init.headers` sets a literal `text/html` or `application/xhtml+xml` `Content-Type`. The headers
can be an object literal or `new Headers({...})`. The Fetch constructor sends a string body as
`text/plain` when no type is set, so an omitted or non-HTML type produces no record. A headers
variable, a non-literal type, or a spread that can replace the type stays Review. A locally bound
`Response` or a `NextResponse` from another module is not trusted. The claim uses the
`html-output-v1` contract with library `fetch-response`, following the
[Response constructor](https://developer.mozilla.org/en-US/docs/Web/API/Response/Response).

A template literal gives each substitution an output context from the markup before it. That context
follows the value through local wrappers such as `layout(title, body)`, and a helper that returns markup
establishes an HTML response. One response with raw values in two contexts produces one claim per
context. Inline callbacks that write the handler's response, such as `http.get(url, cb)` or
`stream.on("end", cb)`, are followed with the handler's closure bindings; their parameters are external
results, not request data.

Static Express render configuration links render locals to EJS and Handlebars template outputs.
Raw EJS `<%- … %>` and Handlebars `{{{…}}}` output is distinguished from escaped `<%= … %>` and
`{{…}}`. Custom unresolved engines stay Review. Templates are bounded to the target root and their
source locations/hashes appear in the evidence. Template expressions not yet resolved do not become
protected claims. Pug raw/escaped output and verified file-read/replacement/compile/render flows are also modeled.
Unresolved template expressions and configured file origins stay Review.

These contracts follow the official [Express response API](https://expressjs.com/en/api.html#res.send),
[EJS tags](https://ejs.co/index.html), and [Handlebars escaping](https://handlebarsjs.com/guide/security.html).

## Output context and protection

The adapter distinguishes HTML text, quoted non-active attributes, URL attributes, script/style
content, active attributes and unresolved/mixed contexts. HTML escaping establishes protection only
for HTML text and quoted non-active attributes. It does not establish URL scheme policy, JavaScript
encoding, safe CSS or protection in an unquoted attribute.

Verified imports for `entities`/`he` HTML encoders, `escape-html`, `sanitize-html` and DOMPurify
sanitization supply bounded protection contracts for appropriate contexts. Plain `dompurify` is trusted only in
browser code (without a window it returns its input); a verified Handlebars `SafeString` disables
`{{…}}` escaping. A global negated allow-list `replace` (for example `[^\w-]+` to `''`) is
sanitization in text, attribute and URL contexts; removing only line breaks is neutral. Other deletions
follow the [replacement rules](#sanitizer-advisories-and-replacements) below. Unknown functions,
same-name fake libraries, shadowed imports and custom sanitizer options are not trusted. Every
modeled path must be protected; protection on one branch does not protect a raw sibling branch.

In PHP each path states its own context (`xss.paths[].output_context`): the markup position where
that path's value lands in the constructed string, including markup built in a helper and echoed
later. A record states the context its raw paths share; when they differ it keeps the echo-level
context, and each path still carries its own.

A cookie is request input the client sends, like a query or form field. A raw cookie value
rendered into markup is a supported source path. Whether an attacker can set another user's cookie
is a delivery question the scanner does not establish, so it alone does not make exposure unknown.

When the output context is unresolved (`unknown`), the record-level protection is `unknown` too:
raw, encoded or sanitized are relative to a context. Per-path protection facts keep what each path
showed.

A response `Content-Type` read from a closed constant map resolves to the map's values. The map is
closed when it is a module-level `const` object literal with literal keys and string values that is
only read by subscript (never assigned, exported or passed out), the type is a `const` set from
`MAP[key]`, and a missing-key branch returns or throws before the response. If every value is a
non-HTML type (for example raster images) the response cannot render markup and no XSS record is
made. Any HTML-capable value, including `image/svg+xml` and other XML types, leaves the record at
Review with a `content_type_map_html_capable` gap naming the values.

## Stored and browser analysis

Model-field writes/reads are linked for bounded Mongoose and Sequelize shapes. Storage identity,
field, originating request and rendering evidence are retained; unresolved origins remain Review.
A read with no write stays visible, but cannot hide a complete unsafe sibling path. Such a record
carries `stored_origin` write-set evidence (every write found for its storage key, whether each is
literal, whether the read query is static, whether the store is closed); it stays Review, and whether
a request value can reach the stored data is left to judgment over that evidence.

A Next.js server helper that fetches a same-origin GET route of the repository and returns
`response.json()` yields that route's response. A field read from it takes the origin the route gives
the field: a stored row column is a storage read (Review until its writers are judged), a value the
handler built from the request stays request-derived. The request value that built the URL is
recorded as `api_selector` context. When no single route (a dynamic route is preferred over static
siblings the URL template does not name) or field origin is established, the previous flow is kept. A generated Mongoose
`_id` with no request write is not a claim.

A keyed read of a server-owned in-module store (`this.tokenMap[key]` on a const object literal, or a
module-level `const {}`/`Object.create(null)`) yields stored state: the request-derived key selects an
entry but is not the value. This applies only when the store is not aliased, spread, returned,
exported or written in the same flow. The read is recorded as a storage read with no linked writer:
writes by other requests or other modules are second-order flows the scanner does not model. Any claim,
in any family or language, whose operand comes only from unlinked storage reads carries
`storage_origin_unresolved` and stays Review; it is neither request-derived nor proven safe.

SQL-backed storage covers sql.js connections and Sequelize raw queries. Bound `INSERT` and `UPDATE`
columns of a verified sql.js connection are writes. Literal `SELECT` text, including through local query
helpers, is a read; `.map` results keep their row fields. A Sequelize raw `SELECT` resolves through the
model's literal `tableName`. Other SQL clients are not modeled, and a same-named receiver with no
verified `sql.js` binding is not storage.

A Sequelize attribute setter runs on written values, so its branches and sanitizers stay on the stored
path. A finale-rest resource makes each string attribute writable by its collection `POST`, unless that
`POST` is registered with `denyAll` in the same module, and returns rows from `GET` minus
`excludeAttributes`. Sinks with many stored paths keep one path per source, write and protection class,
and record how many were omitted.
<a id="sanitizer-advisories-and-replacements"></a>

Markdown with marked's `sanitize` option is an unsafe-rendering contract for versions with a listed advisory
(see [upstream PR 592](https://github.com/markedjs/marked/pull/592)). Sanitizer bypasses come from a cited advisory table in `internal/langjs/xss_versions.go`. An advisory applies only to
an exact resolved version in its affected range, and only to a call with default options; a version range or
custom options never match. The version is resolved for the source file that calls the library: a lockfile from
the nearest workspace upward (npm, pnpm, Yarn) is authoritative, otherwise the nearest ancestor `package.json`
that declares the dependency supplies a literal pin, so monorepo workspaces resolve independently. It currently lists marked before 0.3.6
([CVE-2016-10531](https://github.com/advisories/GHSA-vfvf-mqq8-rwqc)), sanitize-html before 1.4.3
([CVE-2016-1000237](https://advisories.gitlab.com/pkg/npm/sanitize-html/CVE-2016-1000237)) and sanitize-html 2.17.3
([CVE-2026-44990](https://github.com/advisories/GHSA-rpr9-rxv7-x643)). Advisories that need non-default options are
not listed. An unlisted version keeps its ordinary contract, so this is not a dependency audit.

`replace`/`replaceAll` deletions are classified by what they remove. Removing every `<`, or replacing every `<` with
`&lt;`, protects HTML text; also removing both quote characters protects a quoted attribute. A deletion that can
match a tag fragment, such as `/<[^>]*>/g`, `/(<…>)/`, an alternative starting with `<`, or a literal `'<script>'`,
is ineffective, because one pass can reassemble a tag; so is any non-global deletion. A deletion after an encoder
leaves the value encoded. Any other pattern or replacement is unknown. Unknown versions/configurations are
not treated as protected. Each source path must retain its own transformations and blockers.
Every branch body that can fall through is explored, including `else`, `catch` and `finally`; a
branch-only path records its condition as a precondition. When paths at one sink differ, `xss.paths`
gives each one's protection and writing entry. A raw path stays a finding beside unknown siblings,
and an unknown sibling keeps an otherwise escaped sink out of Protected.
Local helpers whose branch conditions are content-neutral (lengths, `typeof`, literal-token tests without
HTML-significant characters) and that never return early are followed precisely; other branching
helpers stay unknown, because their conditions may guard content. `a += b` string building keeps both
operands, including DOM `innerHTML +=` sinks.

Browser entries have their own identity, component/source location and sink context. Supported
bounded patterns include location/URL parameters, explicit DOM/window events, verified DOM nodes and HTML,
text, URL and string-code sinks, imported jQuery, React JSX, Vue single-file script/template output,
and Angular injected sources/trust APIs with template bindings. An unlinked trust bypass is Review.
A browser output that reads an API response field is linked to its origin only when exactly one server
route or finale-rest resource matches the request method and path pattern and provides that field, from
request data or a storage column with an established write. Each browser path keeps its own field, and
`map((r) => r.field)` in a service method projects the response.

Angular links are bounded by source edges, never by field name alone. A trusted field reaches a template
through an iteration variable only when the template declares it (`let row`), and also through gallery
`args`. A dialog is linked only when its template renders `MAT_DIALOG_DATA` at that field, a component
opens that dialog, and that component's selector appears in the template of the component that trusted
the value. A verified `jwt-decode` claim links to a model field only when a verified `jsonwebtoken` sign
call holds that model at the same claim path. Unmatched claims and fields stay Review.

Literal `addEventListener` registrations for `click`, `input`, `change`, `submit` and
`message` on verified DOM/window bindings have explicit event entries. Inline callbacks and
immutable local named functions retain registration/callback locations and independent invocation
contexts, including when a callback is registered twice. Direct `event.target.value` reads and
`message.data` reads have event-input provenance; location and independent DOM reads retain their
own origins. A message-origin condition is control evidence and does not establish HTML encoding.
The report retains registrations with no discovered sink and unresolved callback bindings.

Discovery is bounded to traversed source, with four callback levels, 128 callback expansions per
file and eight receiver-alias resolution levels. Dynamic/unsupported event names, custom receivers,
mutated receivers or callbacks, destructured callback parameters and unreached registrations retain
explicit gaps. Mutated input projections are not seeded; mutable captured values remain unresolved.
Mutation checks are conservative across same-name lexical bindings. Imported callbacks, event-object
aliases/destructuring and arbitrary event-property projections are outside the supported binding
subset. Imported helper registrations are inventoried in their own module with a caller-context
gap when reached through another module. Existing unbound script/component observations retain their exposure limitations; discovery
of a registration does not prove the application executes it or a runtime exploit succeeds.

Default Angular protection requires a demonstrated plain-value path, not merely absence of a known
bypass. Unknown trusted-wrapper transformations remain Review. Whole-object request render locals
can control engine options/layout; escaped field syntax alone cannot make that flow Protected.

## Selected interpretation and method provenance

Supported rendering claims select registered XSS questions, validated language guidance and one
primary rendering contract, with context/protection and applicable stored/browser/response roles.
Selected material does not certify a sanitizer or fill a missing source path. JSON-only observations
remain unassessed. Historical `xss-use-v1` answers retain their original protocol when exported;
changed material, context, origin or request method rejects replay.

Browser fetch without options, with unshadowed `undefined`, or with a direct method-free literal
options object uses GET. A direct
literal `method` uses that method, normalized to uppercase. Dynamic methods/options, Request objects,
spreads, duplicate/computed properties and unsupported aliases retain a method gap and no guessed
server producer. GET and POST at the same path cannot exchange origins or protection facts.

## Outcomes and limits

- **Finding / orange:** a supported source path reaches verified raw output without appropriate
  protection. Other uncertain paths remain in the evidence.
- **Review / blue:** unknown source, context, origin, options, sanitizer or transformation.
- **Protected / green:** verified output binding, exact context and appropriate protection on every
  modeled path, without relevant unresolved options/transformations. This applies only to that output.
- **Red:** complete consistent `xss-components-v1` answers and source evidence establish a static XSS claim.
  Runtime confirmation and independent review remain separate.

A rendering record whose evidence is over the request limit is judged in path groups: one ordinary
request per group of dependency paths (by source file, packed while a request still fits, at most
five), each stating how many paths it withholds per source file. One Confirmed group makes the
record Confirmed for that path; Protected needs every group judged and Protected; anything else is
Review. Groups past the cap or still over the limit are reported, never read as safe.

The protocol asks output context, encoding adequacy, sanitizer effectiveness, path protection and
exposure. Provider confidence/probabilities are retained for audit but never establish a verdict.
Unknown middleware and unsupported paths remain visible. No output or finding is not a safety verdict.

HTML has separate Server/API and Browser/client headings. Hide protected results changes the view
only; canonical JSON/SARIF retain all records. Reusable source-reviewed sample references belong in
[the sample baseline documentation](../samples/reference-policy.md), outside detector/model inputs.
The shared facts use language-neutral source/context/protection/storage/entry fields. The [Python adapter](../python-support.md) supplies those facts for bounded Flask, Quart, FastAPI,
Django, Pyramid, Bottle, aiohttp, Falcon, WSGI and Jinja flows and literal inline browser scripts. Unresolved renderer settings, template constructs and
storage origins remain Review. The [PHP adapter](../php-support.md) supplies them for `echo`/`print`
render values (`render.php-html-output-v1`): reflected claims from superglobal HTML values, stored
claims linked through `php-sql:<table>.<column>` keys with exact-count-or-skip INSERT attribution,
and `htmlspecialchars`/`htmlentities` transforms as encoding evidence on the value paths.

Finite Express table registrations and local literal-argument handler factories retain separate
closure/control contexts. A factory's encoded branch cannot protect a raw sibling registration.
Bounded generated Flask/FastAPI handlers also resolve source-backed registry names before evaluating
supported literal conditions; raw HTML concatenation is associated with its actual generated route.
An unrelated unknown template-content value does not erase an established raw-output witness, while
unknown transformations or relevant guards still prevent protection claims. Runtime registration data,
mutation, unknown wrappers, unresolved callbacks and reached limits remain explicit gaps. See the
[Python subset and limits](../python-support.md#finite-generated-http-routes).
