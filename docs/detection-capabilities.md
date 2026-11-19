# Detection capabilities

[Documentation](README.md) · [Interpreting results](interpreting-results.md) · [Analysis rules](analysis/README.md)

This page summarizes what `zazzles` can currently detect, in which languages and frameworks, and what
it can recognize as protection. Each family's guide owns the exact rules; this page is the map.

A result is a **claim about one operand of one verified operation**. It is never a certificate that a
route or application is safe. Outcomes are Confirmed, Poor practice, Protected (for that claim only),
or Review when evidence is incomplete; see [interpreting results](interpreting-results.md). Without
`--judge`, scans are offline: they establish candidates, per-path protection facts and blockers, and
every record says `assessment_state: not_run`.

## Languages, frameworks and entries

| Language | Entry adapters | Guide |
|---|---|---|
| JavaScript / TypeScript (Node.js) | Express (including route chains and mounts), Fastify, Hapi, Next.js (App Router, Pages Router, Server Actions, pages), browser sources, Apollo GraphQL resolvers, unary gRPC | [Node inputs](analysis/node-inputs.md), [Next.js](nextjs-support.md) |
| Python | Flask, FastAPI, Quart, Django, Falcon, Bottle, Pyramid, aiohttp and WSGI dispatch | [Python analysis](python-support.md) |

Source is read only: no dependency installation, build, execution or network requests to the target.

### How frameworks and languages share analysis

**Next.js is not a separate scanner.** It is an entry adapter on top of the same JavaScript/TypeScript
analysis that Express, Fastify and Hapi use. All of them share the value-flow engine, the library
contracts (Sequelize, Prisma, Mongoose, `fetch`/axios, `fs`, `child_process`, `eval` and others),
every vulnerability family and the same verdict rules. What differs is how entries and inputs are
found:

| | Express, Fastify, Hapi | Next.js |
|---|---|---|
| Entries | `app.get`/router registrations, middleware chains, mounts | File-system routes, App and Pages Router, Server Actions, pages |
| Request inputs | `req.body`, `query`, `params`, `headers`, `cookies` | Web Request API, route params, `searchParams`, Server Action arguments |
| Rendering | `res.send`/`write`, EJS, Pug, Handlebars | Server pages, Client Components, React props, context and stores |
| Additional | — | Framework practice observations (NX-BP), Next.js redirect APIs |

A JavaScript/TypeScript flow or library improvement therefore helps Express and Next.js applications
alike, unless it depends on a framework construct (for example a Next.js catch-all `[...path]` route).

**Python** has its own adapters for entries and its own flow analysis. It shares the vulnerability
families, verdict rules, report fields and stored-value rule with JavaScript/TypeScript, but a
JavaScript/TypeScript flow rule does not apply to Python until Python gets its own equivalent. The
table under [Which rules are generic](#which-rules-are-generic) shows the current split.

## Vulnerability families

| Family (`--only-family`) | JavaScript / TypeScript | Python | Protection it can recognize | Guide |
|---|---|---|---|---|
| SQL injection (`sql`) | Sequelize raw and finders, sql.js, Prisma raw, better-sqlite3, sqlite3 | sqlite3, Psycopg 2/3, PyMySQL, MySQL Connector | Bound parameters; verified numeric/hex conversions; per-operand SQLite/PostgreSQL quote doubling | [Database injection](analysis/database-injection.md) |
| NoSQL injection (`nosql`) | Mongoose/MongoDB, MarsDB | not implemented | Enforced type guards, ObjectId casts, scalar selector facts | [Database injection](analysis/database-injection.md) |
| Cross-site scripting (`xss`) | Express HTML responses, EJS, Pug, Handlebars/hbs, React/Vue rendering, browser DOM sinks, stored paths through Mongoose, Sequelize, sql.js and Prisma | HTML responses and supported templates | Context-appropriate escaping, verified sanitizers (for example DOMPurify defaults) | [XSS](analysis/xss.md) |
| Command injection (`command`) | `child_process` `exec`/`execFile`/`spawn` families | `os.system`, `os.popen`, `subprocess` | Fixed executables, argument arrays without shell, verified guards | [Command injection](analysis/command-injection.md) |
| Path traversal (`path`) | `fs` and `fs/promises`, Express `sendFile`/`download`, `adm-zip`, `unzipper`, `hbs` layouts | `open`, `pathlib`, archive modules, `os.remove`, Flask `send_file`/`send_from_directory`, werkzeug `save` | Containment checks, `..`/separator reject guards on the final operand, library roots, `secure_filename` | [Path traversal](analysis/path-traversal.md) |
| Unrestricted upload (`upload`) | not implemented | Werkzeug `FileStorage.save` (PHP: `move_uploaded_file`) | Generated names, server-chosen or allow-listed extensions, content checks, unserved destinations | [File upload](analysis/file-upload.md) |
| SSRF (`ssrf`) | global `fetch`, `axios`, Node `http`/`https` | `requests`, `httpx`, `urllib.request.urlopen` | Parsed host allow-lists and scheme-and-host checks on every path | [SSRF](analysis/ssrf.md) |
| Code injection (`code`) | `eval`, `Function`, browser string timers, Node `vm`, sandbox evaluator libraries | `eval`, `exec`, `compile` | Grammar allow-lists, type conversions of the complete operand | [Code injection](analysis/code-injection.md) |
| Open redirect (`redirect`) | Express/Fastify/Hapi redirects, Location headers, Next.js redirects and router, browser navigation | Flask/Django redirects, Starlette/FastAPI `RedirectResponse`, aiohttp | Parsed-origin checks, host allow-lists, same-site relative paths that exclude `//` and `\` | [Open redirect](analysis/open-redirect.md) |
| Sensitive-data logging (`logging`) | global `console`, pino, winston, morgan | supported `logging` bindings | Derived or masked values instead of content | [Logging](analysis/sensitive-data-logging.md) |
| Input validation (`input-validation`) | Field requirements and enforcing checks (zod, validator.js and others) | Field requirements and enforcing checks | Enforced validation separate from destination protection | [Input validation](analysis/input-validation.md) |
| Outbound observations (`outbound`) | Every verified outbound call, classified by destination origin | same | Observation only; not an SSRF claim | [SSRF](analysis/ssrf.md#destination-origin) |

Next.js framework practice checks (NX-BP codes) are separate observations; see
[Next.js analysis](nextjs-support.md#framework-practice-observations).

## Which rules are generic

The verdict gates, report fields and stored-origin rule apply to every language. Most flow and
protection recognition is implemented per language adapter:

| Capability | Scope |
|---|---|
| Verdict gates, Protected/Confirmed policy, judged/unjudged state, blocking evidence, linked claims | All languages |
| Stored values with no linked writer stay Review (`storage_origin_unresolved`) in every family | All languages |
| Redirect bypass forms (`\`, `/\`, `//`, origin prefix, decode after check) blocking Protected | Policy for all; predicate facts JS/TS only |
| Non-enforcing URL checks, module-constant destination folding, loops that cannot affect the sink | JS/TS |
| Keyed server-store reads (`store[key]` yields stored state, not the key) | JS/TS |
| zod `safeParse` field evidence, Next.js catch-all `join` modeling | JS/TS |
| Prisma quote-doubling facts, Sequelize stored value into code operands | JS/TS |
| Percent-decoders and query parsers keep request provenance | Python |

## Second-order and stored values

A value read from storage is linked to its request writer when the write and read are modeled, for
example Mongoose, Sequelize, sql.js and Prisma fields. Then the stored path can reach Confirmed. When no writer is linked,
the read stays visible as Review: it is not treated as request input and not treated as safe. This
includes in-memory session stores read by key. Tracking writers across requests through such stores
(for example registration → login store → page) is not yet implemented.

## Not covered

Dependency vulnerabilities, runtime behavior (DNS, proxies, deployment policy), template injection,
deserialization, Windows path semantics, Python NoSQL, Python equivalents of the JS/TS-only rules
above, and frameworks or libraries not named in the family guides. Unsupported code stays Review or
produces no candidate; it is never reported as safe. Each guide lists its own bounds.
