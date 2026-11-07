# Cross-site scripting analysis

[Analysis index](README.md) · [Result interpretation](../interpreting-results.md)

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
sanitization in text, attribute and URL contexts; removing only line breaks is neutral; other
replacements are unknown. Unknown functions,
same-name fake libraries, shadowed imports and custom sanitizer options are not trusted. Every
modeled path must be protected; protection on one branch does not protect a raw sibling branch.

## Stored and browser analysis

Model-field writes/reads are linked for bounded Mongoose and Sequelize shapes. Storage identity,
field, originating request and rendering evidence are retained; unresolved origins remain Review.
A read with no write stays visible, but cannot hide a complete unsafe sibling path. A generated Mongoose
`_id` with no request write is not a claim.

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
The marked 0.3.5 sanitize-option bypass is a versioned unsafe-rendering contract, supported by
[upstream PR 592](https://github.com/markedjs/marked/pull/592). sanitize-html before 1.4.3 is not applied
recursively ([CVE-2016-1000237](https://advisories.gitlab.com/pkg/npm/sanitize-html/CVE-2016-1000237)), and is
an ineffective contract for an exact pinned version; a version range establishes nothing. A single-pass
regex that deletes tag fragments can reassemble a tag, so it is also ineffective. Unknown versions/configurations are
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

The protocol asks output context, encoding adequacy, sanitizer effectiveness, path protection and
exposure. Provider confidence/probabilities are retained for audit but never establish a verdict.
Unknown middleware and unsupported paths remain visible. No output or finding is not a safety verdict.

HTML has separate Server/API and Browser/client headings. Hide protected results changes the view
only; canonical JSON/SARIF retain all records. Reusable source-reviewed sample references belong in
[the sample baseline documentation](../samples/reference-policy.md), outside detector/model inputs.
The shared facts use language-neutral source/context/protection/storage/entry fields. The [Python adapter](../python-support.md) supplies those facts for bounded Flask, Quart, FastAPI,
Django, Pyramid, Bottle, aiohttp, Falcon, WSGI and Jinja flows and literal inline browser scripts. Unresolved renderer settings, template constructs and
storage origins remain Review.

Finite Express table registrations and local literal-argument handler factories retain separate
closure/control contexts. A factory's encoded branch cannot protect a raw sibling registration.
Bounded generated Flask/FastAPI handlers also resolve source-backed registry names before evaluating
supported literal conditions; raw HTML concatenation is associated with its actual generated route.
An unrelated unknown template-content value does not erase an established raw-output witness, while
unknown transformations or relevant guards still prevent protection claims. Runtime registration data,
mutation, unknown wrappers, unresolved callbacks and reached limits remain explicit gaps. See the
[Python subset and limits](../python-support.md#finite-generated-http-routes).
