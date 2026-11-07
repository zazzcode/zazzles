# Python analysis

[Documentation](README.md) · [Analysis rules](analysis/README.md) · [Python sample reports](samples/README.md)

Zazzles analyzes a bounded Python subset through the same evidence, decision and reporting pipeline
as JavaScript/TypeScript. It reads source; it does not run the application, install its dependencies,
open its database, or make the outbound requests found in the code.

```sh
go build -o bin/scan ./cmd/scan
./bin/scan --routes --json /path/to/python-app
./bin/scan --analyze --entry server/routes.py --output-dir /path/to/findings /path/to/python-app
```

Omit `--entry` to discover all supported registration files, including mixed JS/TS/Python repositories.
The output directory receives `<app>/run-<id>/findings.json`, `findings.html` and `findings.sarif`.
Optional [decision assessment](decision-models.md) transmits bounded evidence only when requested.
Structural findings remain useful without a model; neither mode certifies an application as safe.

| Area | Implemented subset |
| --- | --- |
| Entries | Verified Flask/Blueprint and FastAPI decorators, bounded generated Flask add_url_rule/FastAPI registrations, separate verified generated-route application mounts, RESTX Resource methods |
| Sources | Flask args/form/values/JSON/cookies/headers/session, RESTX payload, FastAPI parameters; HTTP response text is a separate source |
| Flow | Assignments/reassignments, f-strings, percent/format/concatenation, output alternatives, bounded direct helpers and local imports; explicit request-method guards exclude impossible method branches |
| SQL | sqlite3 connection/cursor provenance, SQL text versus parameter tuple/list, statement construction and separate validation evidence |
| Validation | Policy-backed standalone field judgments and SQL facets; actual handler/helper guards and matching forms' field requirements are evidence. A browser constraint is not server enforcement. Missing policy stays uncertain. |
| Logging | Unshadowed print/logging bindings, credential/personal field hints, HTTP credentials, literal email and verified database-result candidates; length/presence/comparison controls |
| XSS | Flask HTML string returns, render_template/render_template_string, Jinja template variables and source construction, safe/Markup/escape/forceescape, autoescape blocks, explicit FastAPI HTML, `jinja2.Environment` file templates, Django and Pyramid responses, aiohttp and Falcon responses with a literal HTML content type, Quart and Bottle string returns, WSGI appends under a dispatch test for a literal HTML response, bounded sqlite table/field stored-origin links |
| Browser XSS | Literal inline scripts in resolved templates reuse the browser adapter. Canonical versioned code.jquery.com script tags establish bounded jQuery bindings; input val() → append()/html() and nested callbacks are modeled. Native DOM append(string) is text. |
| Outbound | Request-influenced URL slots for requests/httpx functions and urllib.request.urlopen; method/body/response slots stay separate |

SQL construction is a practice finding independently of an injection judgment. Bound parameters
protect their data slots, not interpolated identifiers. Input-validation policy, injection protection,
HTML context and sensitive-data classification remain distinct questions.

Default Flask/Jinja escaping is trusted only in HTML text and quoted non-active attributes with a
verified binding and supported configuration. Script, URL, style, custom filters/options and unresolved
origins stay Review. Markup and safe mark text as trusted; applying escape to a trusted value does
not necessarily escape it. Forceescape and an already-escaped value are distinct controls.

Stored links use supported literal sqlite table/column writes and reads, retaining writing entries,
source hashes and transfer evidence. They are potential field flows, not proof that a particular row
was written or a deployed database matches the source. Row identity, migrations, arbitrary SELECT
projections/joins, ORM dispatch and mutation remain limitations. Unlinked origins remain Review.

Helper expansion is bounded to depth 3 and 24 calls per route, source files to 2 MiB, dependency paths
to 64 and transfers to 48. Loops, comprehensions, custom decorators, dynamic mounts, arbitrary
exceptions/heap aliases, template inheritance/macros and library extensions are incomplete. Reached
bounds and unresolved pre-use calls remain visible and cannot establish protection. Source-only
exception paths carry explicit preconditions; runtime feasibility still needs separate confirmation.

Python NoSQL extraction is not implemented: none of the three pinned Python apps uses PyMongo or
another MongoDB API. Existing JS/TS NoSQL support remains unchanged. SCA and new vulnerability families
are separate work. See the [Python evaluation](../.zazz/evaluation/python-support-results.md) for actual
sample coverage, comparator observations and remaining gaps.

Library contracts: [Flask templates](https://flask.palletsprojects.com/en/stable/templating/),
[sqlite3 parameters](https://docs.python.org/3/library/sqlite3.html#sqlite3.Cursor.execute),
[FastAPI HTML responses](https://fastapi.tiangolo.com/advanced/custom-response/#html-response),
[MarkupSafe escaping](https://markupsafe.palletsprojects.com/en/stable/escaping/).

The shared [trace judgment design](../.zazz/architecture/trace-judgment.md) documents evidence
roles, trace/control edges, exact named-field policies, model consistency gates and reporting.
Verified Psycopg 2/3, PyMySQL and MySQL Connector cursor bindings now use driver-specific
parameter contracts. SQLite storage correlation remains SQLite-only. Request aliases and
relative package imports are bounded; variadic helper binding stays explicit uncertainty.
Constant Jinja templates require autoescaping for substituted HTML variables; `.render()` alone
does not establish XSS protection. Reports provide source-specific preservation, repair or
investigation guidance according to the final claim status. Only Protected is green.

## Finite generated HTTP routes

Finite source-backed registries, local registration factories and captured literal values can
expose generated Flask GET/POST and FastAPI GET handlers. Selected local module/member inventories
and supported name transformations are derived from parsed source, without importing Python modules
or executing discovery/reflection. Every registration retains generation, member, factory and mount
provenance; different application instances and closure values have separate contexts.

Nested local callbacks preserve captured request values and actual argument bindings, including
SQLite connections returned by helpers and cursors passed to callbacks. SQL construction uses the
executable-text slot; a separate bound parameter does not repair interpolated SQL. Constant setup
queries do not become request-controlled findings. Literal factory conditions exclude impossible
raw-output branches while unknown conditions remain explicit.

Discovery is bounded to 128 generated registrations per site before mount projection, finite loops
of 128 members, eight discovery-factory levels, 10000 syntax steps per registration module and 10000
new entry/binding/context records per scan. Runtime helper depth 3 / work 24 and existing path/transfer
limits remain. Unsupported registry/member mutation, shadowed lookups, unresolved callbacks,
external members and reached bounds leave gaps; absence of a use is not evidence of protection.
The source-backed glob/member subset is an analysis of selected files, not general Python reflection.
Other VulnPy families remain outside this subset.
