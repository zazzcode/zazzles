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
| Code injection (`code`) | `eval`, `Function`, browser string timers, Node `vm`, sandbox evaluator libraries; template source in ejs, Handlebars, pug, nunjucks, lodash (CWE-1336) | `eval`, `exec`, `compile`; template source in Jinja2, Flask `render_template_string`, Mako (PHP: Twig `createTemplate`) | Grammar allow-lists, type conversions of the complete operand | [Code injection](analysis/code-injection.md) |
| Prototype pollution (`pollution`) | Verified Lodash `merge`, `mergeWith`, `defaultsDeep`, `set`, `setWith` and `zipObjectDeep` by resolved version; source-visible recursive merges, path walks (index, `for…of`, `while`, `forEach`, `reduce` and recursive forms over split, matched or array paths), unflatten, and direct nested computed assignments, in JavaScript and TypeScript, in application source and in library source kept in the repository. [Known gaps](#prototype-pollution-known-gaps) | — | Literal key exclusions on string keys, written in place or as a one-line helper; whole-path `includes`/`indexOf` deny-lists; own-property checks at each lookup; a fresh null-prototype target for one lookup. An incomplete exclusion is listed with the names it leaves open | [Prototype pollution](analysis/prototype-pollution.md) |
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
| Prototype-write shapes, the listing of what a key guard blocks, and unread guards on the key kept in Review | JS/TS |
| zod `safeParse` field evidence, Next.js catch-all `join` modeling | JS/TS |
| Prisma quote-doubling facts, Sequelize stored value into code operands | JS/TS |
| Percent-decoders and query parsers keep request provenance | Python |

## Second-order and stored values

A value read from storage is linked to its request writer when the write and read are modeled, for
example Mongoose, Sequelize, sql.js and Prisma fields. Then the stored path can reach Confirmed. When no writer is linked,
the read stays visible as Review: it is not treated as request input and not treated as safe. This
includes in-memory session stores read by key. Tracking writers across requests through such stores
(for example registration → login store → page) is not yet implemented.

## Prototype pollution: known gaps

The source-visible shapes are matched by syntax inside one function body. Code outside them is
not reported as safe. The table lists the forms known to be missed or left in Review. The
[guide](analysis/prototype-pollution.md#limits) owns the full rules.

| Form | What a scan shows |
|---|---|
| Write reached only after a call that takes the key, such as `if (!known.has(key)) return` or `const row = find(key); if (row == null) return` | Review (`key_guard_coverage_unknown`). The scanner does not read what the call accepts, so the record is neither Confirmed nor Protected |
| Key test in a helper that calls another function, or an assertion on the key before a recursive walk | Review (`key_guard_coverage_unknown`). One-line helpers that test the key directly are read |
| Literal comparison on the parts of an array the caller passes, with no `typeof` test first | Review (`key_guard_coverage_unknown`). A nested array such as `['__proto__']` passes the comparison |
| Key guard written as a regular-expression test on the whole path | The record omits that control. An assessment that relies on it stays in Review |
| Keys taken from a query string or another input whose shape is not typed | Review (`key_control_unknown`) |
| Nested write after the slot is replaced on a branch that does not test for its absence | No record. The slot's identity then needs heap-flow evidence |
| Recursive merge through a local that a branch replaces: `if (!slot) slot = {}` then `merge(slot, value)` | No record. This can be a missed write |
| Path normalised before the walk by anything but its own split: `String(path).split('.')`, a conditional, or a helper such as `toPath(path)` | No record. `path = path.split('.')` in place is read |
| Path walk from a path parameter into a local or module-level object, as in `setPath(path, value)` writing to a module store | No record. Only the unflatten shape accepts a start that is not a parameter. A walk written directly in the route handler, with no helper function, is not read either |
| A merge reached through more than one forwarding helper, a walk split across functions, or a write through `Object.defineProperty` | No record |
| A walk whose step and write are one chained assignment, `t = t[k] = …` | No record |
| A dynamic-key write that matches none of the listed shapes | No record |
| Merge and set-by-path libraries other than Lodash (`dset`, `merge-deep`, `set-value` and others) called as installed dependencies | No record. `node_modules/` is not read, and only Lodash has version contracts. A dependency audit reports published advisories |
| A published library's source copied into the repository and called through its public API | Usually no record. In a check of eleven advisory packages one, `set-in`, is detected this way. Wrapper functions that read `arguments`, functions nested in the export and factory exports stand between the route and the write |
| Library source kept under `vendor/` | No record. The file walk skips that directory. Library source elsewhere in the repository is read when a route imports it |
| A library repository scanned on its own, with no application route | No record. Exported functions are not entries yet |
| The effect of a polluted property: readers, gadgets and code execution | Not claimed. A finding states the write only |
| Browser entries, deletion APIs (`unset`, `omit`) | Not covered by this family |

## Not covered

Dependency vulnerabilities, runtime behavior (DNS, proxies, deployment policy), template injection,
deserialization, Windows path semantics, Python NoSQL, Python equivalents of the JS/TS-only rules
above, and frameworks or libraries not named in the family guides. Unsupported code stays Review or
produces no candidate; it is never reported as safe. Each guide lists its own bounds.
