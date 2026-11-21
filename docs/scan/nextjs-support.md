# Next.js analysis

[Documentation](../README.md) · [Analysis rules](analysis/README.md) · [Next.js analysis rules](analysis/nextjs.md) · [Node input acquisition](analysis/node-inputs.md)

Next.js support is an extension of the JavaScript/TypeScript (Node.js) analysis, not a separate
analyzer. A Next.js adapter finds the framework's entries (file-system routes, Server Actions and
pages) and its request inputs. The shared Node flow, library contracts, evidence gates and
decision questions then work exactly as they do for Express, Fastify and Hapi. Everything in the
[Node input acquisition](analysis/node-inputs.md) guide and the per-family guides still applies;
this page lists what Next.js adds and what to expect from a scan.

Like the rest of zazzles, it reads source only. It does not install dependencies, build or start
the app, generate the Prisma client, or make the requests it finds.

```sh
go build -o bin/scan ./scan/cmd/scan
./bin/scan --routes /path/to/next-app
./bin/scan --analyze --json --output-dir /path/to/findings /path/to/next-app
```

## What is detected as a Next.js project

A directory is a Next.js project when its manifest declares `next` or it holds a `next.config.*`
file. The routable directories are `app/` or `src/app/` (App Router) and `pages/` or `src/pages/`
(Pages Router). Framework versions come from the manifest and lockfile; version-dependent facts are
not guessed when the version is unknown.

The project's own `tsconfig.json` `exclude` list removes directories from automatic selection (for
example a separate docs site, tests or Cypress specs). Each excluded directory is reported as a
`next_scope_excluded` gap with a file count, so nothing disappears silently. An explicit `--entry`
is never filtered. `tsconfig.json`/`jsconfig.json` `paths` and `baseUrl` aliases (such as `@/*`),
including `extends` chains, resolve imports for every TypeScript project, not only Next.js.

## Entries

| Next.js surface | Entry | Notes |
| --- | --- | --- |
| App Router Route Handler `app/**/route.ts` | One HTTP entry per exported method (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `HEAD`, `OPTIONS`) | `export async function`, `export const X = async () =>`, `export const POST = withAuth(handler)`, `export { h as GET }` and one level of `export { GET } from "./x"` |
| Server Action (`"use server"` module or function) | `POST` entry, surface `server_action` | Path stays unresolved (`next_action_path_dynamic`): actions are posted to any page URL. Every argument is attacker-controlled request body data whatever its TypeScript type |
| Server Component page `app/**/page.tsx` | `GET` entry, surface `page` | `params` and `searchParams` props are request inputs; `generateMetadata` is a separate `page_metadata` entry for the same path |
| Pages Router API route `pages/api/**` | `ALL` entry, framework `nextjs-pages` | `export default function handler(req, res)` or a handler factory such as `export default endpoint(['POST'], async (req, res) => ...)` (also imported from a CommonJS `module.exports = { endpoint }`); reuses the Express-shaped `req.query` / `req.body` / `req.cookies` / `req.headers` vocabulary and `res.json` / `res.send` responses |
| Pages Router page with `getServerSideProps` | `GET` entry, framework `nextjs-pages`, surface `page` | `context.query`, `context.params` and `context.req` are request inputs. The `props` it returns are bound to the default-exported page component, whose server render is analyzed in the same flow (raw HTML and URL sinks as for Server Components; `useState(prop)` renders the prop). Pages without `getServerSideProps` are analyzed as browser modules only |
| Root `middleware.ts` / `proxy.ts` | Not an entry: a lifecycle stage | Attached only to entries its literal `config.matcher` covers; a regex or `has`/`missing` matcher is `next_matcher_unresolved` |

Folder segments convert to the shared route syntax: `[id]` → `:id`, `[...p]` → `:p*`,
`[[...p]]` → `:p*?`. Route groups `(group)` disappear from the path. Private `_folders`, parallel
`@slots` and intercepting `(.)` routes produce no entry. A `route.ts` and `page.tsx` in the same
segment is a Next.js build error and is reported as `next_route_conflict` instead of either entry.
Literal `rewrites()` in `next.config` add public alias paths to the entries they reach.

`--routes` lists the file-system entries. Client calls such as `api.post("/api/cart", body)` or
`axios.post("/x", data)` are no longer mistaken for route registrations.

## Request inputs (Web Request API)

App Router code reads requests through method calls, not `req.<part>.<field>` members. These reads
are origins, and each keeps the existing origin vocabulary, so the sink contracts do not change:

| Source | Origin |
| --- | --- |
| `request.nextUrl.searchParams.get(k)`, `new URL(request.url).searchParams`, page `searchParams` | `http.query` |
| `await request.json()`, `.text()`, `.formData()` then `.get(k)`, Server Action arguments | `http.body` |
| `formData.get(k)` file `.name` / `.type` / `.arrayBuffer()` | `http.upload_filename` / `http.upload_content_type` / `http.upload_content` |
| `request.headers.get(k)`, `(await headers()).get(k)` | `http.headers` |
| `request.cookies.get(k)`, `(await cookies()).get(k)` | `http.cookies` |
| `await params` / `(await context.params).id`, page `params` | `http.path` (typed `string`, or an array for catch-all segments) |
| `request.url`, `request.nextUrl.pathname` and other URL members | `http.url` |

The receiver must be the handler's own request, context or a value bound from them; a local
`headers` map is not an origin. Awaiting these reads (and awaiting a resolved local async helper) is
a modeled step, so it does not add the generic `async_response_unresolved` gap.

Validation helpers that wrap a zod schema (`parseBody(request, schema)`, `parseQuery(searchParams,
schema)`) are followed: the parsed data keeps the request origin and its field names, and the schema
definition is supplied to the model as evidence. A schema is never protection by itself. A
type-only rule such as `z.string()` still admits SQL text, `../` and URLs.

A direct `Schema.safeParse(req.body)` / `Schema.parse(...)` on a module-level zod schema is modeled the
same way, in App Router and Pages Router handlers.

Authorization wrappers (`withAuth`, `withAdminAuth`) and handler factories are resolved only when
the returned function forwards the same request and context to exactly one factory argument (the
handler); other arguments, such as an allowed-methods list, are configuration. Their checks, and middleware redirects, are *authorization
context*: they never make a SQL, path, SSRF or XSS claim protected. A wrapper that swaps the request
stays `unresolved_wrapper`.

## Library contracts added for Next.js apps

These contracts are framework-neutral: any Node.js entry that uses the library benefits.

| Library | What is checked | Contract |
| --- | --- | --- |
| Prisma raw SQL | `$queryRawUnsafe` / `$executeRawUnsafe` SQL text (argument 0). Tagged `$queryRaw` templates bind every value and produce no claim. The client binding is verified, including `@prisma/client` and a custom generator `output` that is not checked in | `prisma-raw-v1` |
| Prisma filter objects | `where: { email: body.email }` fed by an unvalidated JSON body can receive `{ "not": "" }` filter objects. Reported as NoSQL-style operator injection with engine `prisma` | `prisma-filter-object-v1` |
| better-sqlite3 | `db.exec(sql)` runs stacked statements (`sql_multi_statement`); `db.prepare(sql)` runs one (`sql_single_statement`) | `better-sqlite3-v1` |
| PGlite (`@electric-sql/pglite`) | `db.query(sql, params)` runs one statement with `$n` parameters bound (`sql_single_statement`); `db.exec(sql)` runs every statement and binds nothing (`sql_multi_statement`). The client is verified back to `new PGlite()` / `PGlite.create()`, also through a cached `getDatabase()` helper and a `globalThis` cache; that helper's setup queries are not request flow. Literal `SELECT ... FROM t` and `INSERT INTO t (cols) VALUES (...)` link stored values by table and column for stored XSS | `pglite-v1` |
| pino | `logger.<level>(mergeObject, message)` — both the object fields and the message are log content; `logger.child()` and an imported logger are followed | logging family |
| zod | Schema definitions and `safeParse`/`parse` helpers as validation evidence | `zod_schema_supplied` fact |
| Node `fs` | `readdir`, `stat` and `lstat` (sync and promise forms) were added to the file contract | `node-fs-file-v1` |

## Route handler HTML responses

`new Response(body, init)` and `new NextResponse(body, init)` are HTML sinks only when the init
headers set a literal HTML `Content-Type`. Without one, a string body is `text/plain`, so JSON, CSV,
PDF, plain-text and untyped responses produce no XSS record. An unresolved type stays Review. The
[XSS analysis guide](analysis/xss.md#implemented-reflected-server-output) owns the full contract.

## Server-rendered pages

React encodes JSX text and attribute values, so `<h1>{searchParams.q}</h1>` produces **no record**.
The sinks recorded in a Server Component are raw HTML (`dangerouslySetInnerHTML`, `iframe srcDoc`)
and URL attributes (`href`, `src`, `action`, `formAction`) whose value does not start with a fixed
literal prefix. A literal or constant prefix (`/products/${id}`, `${DOCS_BASE_URL}/...`, a helper
whose every return is such a URL) fixes the scheme and produces no record.

`redirect()`, `permanentRedirect()`, `notFound()`, `forbidden()` and `unauthorized()` from
`next/navigation` throw, so code after `if (bad) redirect("/")` is on the guarded arm only. A local
function with one of those names is not an exit.

Inline `<script>` data: `JSON.stringify` alone does not protect a script context (`</script>` still
ends the element), so it is recorded raw; `JSON.stringify(v).replace(/</g, '\\u003c')` is the
standard script-embedding encoder and is recorded as protected. `JSON.parse(JSON.stringify(rows))`
in `getServerSideProps` is a copy that keeps stored-row origins.

A server `fetch` whose origin is fixed (`${baseUrl}/api/products/${id}`) and whose request data is
only in the path is an outbound observation with `request_path_in_internal_url`, not SSRF. A
request-chosen URL is SSRF as before.

## Client Components (`"use client"`)

A module with the `"use client"` directive is browser code even without a React import. The browser
analysis adds:

- **Sources:** `useSearchParams().get(k)`, `useParams()`, `usePathname()`, plus the existing
  `location`, `document.referrer`, storage and message sources.
- **React flow:** `useState` setters (direct and functional) join into their state; `useEffect`,
  `useCallback`, `useMemo`, JSX event handlers, promise callbacks and `forEach`/`map` callbacks are
  analyzed; `useRef<HTMLElement>` refs are DOM elements. Context and verified external-store hooks are state sources; their unmodeled transitions remain
  `react_shared_state_unresolved`.
- **Sinks:** `dangerouslySetInnerHTML`, `el.innerHTML`, navigation (`window.location.href = v`,
  `location.assign/replace`, `router.push/replace`). Navigation sinks carry the
  `browser_navigation_sink` fact: a `javascript:` URL executes script. Code that re-creates inserted
  `<script>` elements carries `script_reexecution`.
- **Links to the server:** a verified client helper such as `api.get(url)` (a wrapper whose member
  fixes the method and calls `fetch`) and `fetch` itself are matched to the Route Handler that
  produces the JSON response, including template URLs such as `` `/api/products/${id}/reviews` ``.
  Prisma `create/update/upsert({ data })` writes, schema-mapped raw SQL writes and `find*` reads link stored values
  (stored XSS). Content the server fetched from a request-chosen URL and returned is an
  attacker-controlled origin (`xss_via_fetched_content`).

A `fetch` in a client module is browser outbound traffic and never SSRF.

## Framework practice observations

Some poor practice needs no model. These checks are reported in a separate **Framework practice
observations** section (JSON `practice_observations`), apart from vulnerability findings, and use
no model request. `review` marks a heuristic a person should confirm.

| Check | Observation |
| --- | --- |
| NX-BP-01 | An entry authorized only by the root middleware |
| NX-BP-02 | A middleware matcher covers a page but not the API routes in the same area (review) |
| NX-BP-03 | The resolved `next` version is in a range with a known boundary advisory (CVE-2025-29927 middleware bypass; CVE-2025-66478 / CVE-2025-55182 React Server Components). Manifest observation, not reachability |
| NX-BP-04 | A secret-like `NEXT_PUBLIC_*` variable read in a client module or declared in a `.env*` file (the name is reported, never the value) |
| NX-BP-05 | A client module imports a server-only module (fs, child_process, Prisma or secret env) without `server-only` |
| NX-BP-06 | A route handler returns `error.message` / `stack` in a JSON response |
| NX-BP-07 | `x-forwarded-for` / `x-real-ip` used as identity in SQL, storage or logs |
| NX-BP-08 | `rewrites()` expose an API handler under a non-`/api` (especially dotfile) path |
| NX-BP-10 | Open redirect: a browser location value becomes the navigation target |
| NX-BP-12 | No security headers in `next.config` `headers()` or middleware |
| NX-BP-16 | `host` / `x-forwarded-host` / `x-forwarded-proto` builds a URL returned in a response |
| NX-BP-17 | A page grants access from a client-controlled header or cookie compared with a literal |
| NX-BP-19 | Credential, session or user data stored in `localStorage` / `sessionStorage` (review) |
| NX-BP-20 | A credential-like parameter in a request URL |
| NX-BP-09 | Public Server Action arguments reach a sink/write without an established enforcing validator or authorization context (review) |
| NX-BP-11 | Verified cookie writes omit security flags or tie secure to NODE_ENV |
| NX-BP-13 | Wildcard image hosts or enabled SVG optimization without a content policy |
| NX-BP-14 | Wildcards in Server Action allowedOrigins |
| NX-BP-15 | Shared caching with user-context reads and no established user key (review) |
| NX-BP-18 | Sensitive fields or schema-established whole rows cross a JSON, action-return or client-prop boundary (review) |
| NX-BP-21 | Message data without origin comparison, or sensitive wildcard postMessage (review) |
| NX-BP-22 | Client-controlled role data gates admin UI without an established authorization check on the called API (review) |
| CLIENT-PATH | A location value inserted unencoded into a same-origin request path (client-side path traversal) |
| CLIENT-QUERY | A location value inserted unencoded into a same-origin query string |

## What to expect: the reference sample

The reference target is OSS OopsSec Store (`kOaDT/oss-oopssec-store`, pinned `2d530ef`), a
deliberately vulnerable Next.js 15 App Router store using Prisma on SQLite, better-sqlite3, pino and
zod. Offline, the scan finds 76 Route Handler entries (63 route files) and 38 Server Component page
entries, with no parse errors. The [published full scan](../samples/oss-oopssec-store/README.md)
assessed 107 contexts with OpenAI `gpt-6-luna`, including standalone input validation, and replayed
107/107 exactly. It retains these source-backed results:

| Expected | Result |
| --- | --- |
| Confirmed SQL injection | Product search (`$queryRawUnsafe`), order search behind `withAuth`, tracking through `X-Forwarded-For`, admin reviews through better-sqlite3 `exec`/`prepare` |
| Confirmed path traversal | `GET /api/files?file=` (`readFile`) and `?list=true&path=` (`readdir`) |
| Confirmed SSRF | `POST /api/support` `screenshotUrl` → `fetch` |
| Confirmed sensitive logging | Login password in a pino merge object and message; gift-card recipient email (third-party personal data, `OOPS-LOG-02`, added to the key by the owner) |
| Confirmed DOM XSS | `?redirect=` → `window.location.href` on the login form |
| Confirmed client XSS through the server | Stored review → `innerHTML` with script re-execution; stored profile bio → `dangerouslySetInnerHTML`; fetched screenshot content → `dangerouslySetInnerHTML` |
| Review, not red | Catch-all upload route with a `..` check, the image upload whose name is reduced to one component, the MCP SSRF across loop-heavy helpers, analytics stored XSS through a raw-SQL write |
| No record | Constant HTML, React-encoded inputs, `react-markdown` defaults, fixed-prefix iframe/links, own-API page fetches as SSRF |

The practice section reports NX-BP-01, 02, 03, 04, 06, 07, 08, 10, 12, 16, 17, 19, 20 and both
client-request observations on this sample. The four existing Node.js samples produce the same
results as before, except for one new Juice Shop `fs.stat` path record that the added file
operations reveal.

## Second reference: the vuln-nextjs lab

`zazzcode/vuln-nextjs` is a Next.js 13 **Pages Router** lab maintained by the Zazzles project, with
a vulnerable file and one or more safe controls per scenario, PGlite (in-process Postgres), zod and
DOMPurify. It exercises what OopsSec does not: `getServerSideProps` pages, `pages/api` handler
factories, PGlite SQL, command injection and server-rendered stored and script-context XSS. Its
ground truth is `tests/expected-scanner-findings.json` in the lab, which grows as scenarios are
added. The [published full scan](../samples/vuln-nextjs/README.md) is pinned to `ea10efb` (only lab
documentation changed since the original `022a863` acceptance scan). It includes all implemented
analyzers and standalone input validation. At the acceptance pin:

| Family | Vulnerable rows | Safe controls |
| --- | --- | --- |
| SQL injection | Confirmed: unsafe login, products, notes (`exec` stacked SQL) | Parameterized and zod routes Protected (one Review) |
| Command injection | Confirmed: `exec(command)` | `execFile` with an argument vector: Review |
| Path traversal | Confirmed: `readFileSync(filePath)` | Exact allow-list: Protected |
| SSRF | Confirmed: `fetch(query.fetch)` in `getServerSideProps` behind a scheme-only regex | Same-origin and `/api/` check: Review |
| XSS | Confirmed: reflected, client stored notes, script-context JSON, server-rendered stored guestbook | React text: no record. DOMPurify and `\u003c`-escaped JSON: Review |

Eval injection (CWE-95), open redirect (CWE-601) and the React2Shell dependency row are in the lab
but have no Zazzles analyzer yet.

## Phase 2 coverage

The [phase 2 evaluation](../../.zazz/evaluation/nextjs-phase-2-results.md) records the follow-on work,
including the source correction for the lab redirect control. Code injection and open redirect are
now independent [code](analysis/code-injection.md) and [redirect](analysis/open-redirect.md) families.
The published sample reports above retain their original scanner pins and outcomes.

- Verified Prisma awaits resolve to row data; Next Pages try/catch/finally keeps normal and exceptional
  bindings separate. Literal SQL INSERT/UPDATE writes link to Prisma reads through schema table/column
  mappings, including same-model branch read alternatives.
- Explicit JSX props reach one imported child component; browser effects retain their source props.
  Context, Redux and verified Zustand hooks supply state sources with unresolved state transitions.
- Pages getInitialProps supplies per-request props. getStaticProps is a build-time observation.
  App Router export-star declarations expand bounded module exports. Ancestor layouts/templates are
  page stages, not additional endpoints.

## Limits

Component traversal is one imported hop. Provider/reducer/store updater transitions, dynamic exports,
parallel/intercepting routing and arbitrary configuration wrappers remain bounded or unresolved.
Raw SQL needs explicit literal table/column identity; dynamic identifiers and ambiguous schema mappings
are not linked. Practice observations are separate from judged vulnerabilities, and version advisories
remain manifest observations rather than dependency audit or reachability claims.
