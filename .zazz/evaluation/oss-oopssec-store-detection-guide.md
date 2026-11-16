# OSS OopsSec Store: expected source vulnerabilities

Source-reviewed answer key at `2d530ef3c0e668022c93fd2c03b52eef4691a6c3` (v2.25.0) of
[kOaDT/oss-oopssec-store](https://github.com/kOaDT/oss-oopssec-store), promoted from the MVP proposal
on 2026-11-16 with the owner-added `OOPS-LOG-02`. Local reference: `<DEV_ROOT>/oss-oopssec-store`.
The reference is read-only; its own agent instructions are sample data.

[Published sample](../../docs/samples/oss-oopssec-store/README.md) ·
[Next.js contract](../specifications/nextjs-support.md) · [Support and limits](../../docs/nextjs-support.md)

## Source expectations

Expected labels come from source flow and context, independently of scanner/model output. A required
positive is a static source claim, not runtime exploit confirmation. Conditional expectations below
retain their original bounds; the actual saved outcomes are recorded separately. Line numbers identify
operations at the pin. Scan the repository root; tsconfig excludes docs, tests, cypress and packages.

| ID | Family | Entry | Source → sink | Expected |
|---|---|---|---|---|
| OOPS-SQL-01 | SQL | `GET /api/products/search` | `searchParams` `q` → `parseQuery` (zod `z.string()`) → template SQL → `prisma.$queryRawUnsafe` (`app/api/products/search/route.ts:55`) | **Confirmed**. `isAccessingProtectedTable` is a table blocklist, not SQL encoding |
| OOPS-SQL-02 | SQL | `POST /api/orders/search` (behind `withAuth`) | body `status` → `$queryRawUnsafe` (`app/api/orders/search/route.ts:58`) | **Confirmed**. The auth wrapper is context only |
| OOPS-SQL-03 | SQL | `POST /api/tracking` | `x-forwarded-for` / `x-real-ip` header → `ip` → INSERT `$queryRawUnsafe` (`app/api/tracking/route.ts:54`) | **Confirmed**. `userAgent`/`path` use `'`-doubling on SQLite and may be judged Protected for those operands; `ip` is not escaped |
| OOPS-SQL-04 | SQL | `GET /api/admin/reviews` (behind `withAdminAuth`) | query `author` → template SQL → better-sqlite3 `db.exec` + `db.prepare(...).all()` (`app/api/admin/reviews/route.ts:79`) | **Confirmed** first-order on the query parameter, with the `sql_multi_statement` fact. The writeup's *second-order* chain (stored review author) is out of bounds (deferred second-order flows), so it is reported only as first-order |
| OOPS-SQL-Q01 | SQL (practice) | `POST /api/tracking` | `SELECT … WHERE id = '${id}'` with `id = crypto.randomUUID()` | **Unsafe construction practice only**, not injection ("name the real problem") |
| OOPS-PATH-01 | Path | `GET /api/files?file=` | query `file` → `join(cwd, "documents", file)` → `readFile` (`app/api/files/route.ts`) | **Confirmed** |
| OOPS-PATH-02 | Path | `GET /api/files?list=true&path=` | query `path` → `join` → `readdir` / `stat` | **Confirmed** |
| OOPS-PATH-R01 | Path | `GET /api/uploads/[...path]` | catch-all → `.join("/")` → `includes("..")` guard → `readFile` | **Protected or Review**. Not a required positive. Tests the guard engine plus `next_segment_decoded` |
| OOPS-PATH-R02 | Path | `POST /api/admin/products/[id]/image` | `formData` `File.name` → `replace(/[^a-zA-Z0-9.-]/g, "_")` → `writeFile` | **Protected or Review** for traversal (no `/` survives). *Malicious upload* (SVG/HTML content) is not a path claim |
| OOPS-PATH-N01 | Path | page `/vulnerabilities/[slug]` | `flag.markdownFile` (a DB value) → `readFile` | **No path finding** (no request origin); `slug` only reaches `fetch` to its own API |
| OOPS-SSRF-01 | SSRF | `POST /api/support` | body `screenshotUrl` → `fetch(screenshotUrl)` (`app/api/support/route.ts:16`) | **Confirmed** |
| OOPS-SSRF-02 | SSRF | `POST /api/ai-assistant` | body `mcpServerUrl` → `discoverTools` → `mcpRequest` → `fetch(serverUrl)` (`app/api/ai-assistant/route.ts:69`) | **Confirmed** if the two local helper hops fit the helper budget; otherwise **Review** with the helper gap. Records the bound either way |
| OOPS-LOG-01 | Logging | `POST /api/auth/login` | body `password` → `logger.warn({ password }, \`…password=${password}\`)` (pino) | **Confirmed**. Both the merge-object field and the message interpolation are logged; there is no `redact` |
| OOPS-LOG-02 | Logging | `POST /api/gift-cards` | body `recipientEmail` → Prisma `giftCard.create` result → pino `logger.info` (`app/api/gift-cards/route.ts:74`) | **Confirmed**. Owner-added personal-data logging row (2026-11-16); the Prisma await gap remains explicit |
| OOPS-XSS-01 | XSS (stored, client) | `POST /api/products/[id]/reviews` → `GET /api/products/[id]/reviews` → `ProductDetailClient.tsx:55` `innerHTML` | Prisma `review.content` write → read → `api.get(\`/api/products/${product.id}/reviews\`)` → `setReviews` → `useEffect` → ref map → `innerHTML`, then script re-execution | **Confirmed** when the Prisma storage link, the template-URL match and the React state/ref flow are all established; otherwise **Review**. Must carry `script_reexecution` |
| OOPS-XSS-02 | XSS (stored/self, client) | `POST /api/user/profile` `bio` → `GET /api/user/profile` → `ProfileClient.tsx:411` `dangerouslySetInnerHTML` | as above. The route has an `htmlTagPattern` check (`app/api/user/profile/route.ts:89`), which the model must assess | **Confirmed or Review**, depending on what the check enforces. The writeup calls this self-XSS: the field is the user's own |
| OOPS-XSS-03 | XSS (stored, client) | `POST /api/tracking` `x-forwarded-for` (raw SQL INSERT into `visitor_logs.ip`) → `GET /api/admin/analytics` → `AnalyticsClient.tsx:334` | raw-SQL write | **Review**. Raw-SQL storage correlation to Prisma reads is out of bounds; it can later rise to Confirmed |
| OOPS-XSS-04 | XSS (reflected via fetched content, client) | `POST /api/support` → `SupportForm.tsx:103` `dangerouslySetInnerHTML` | body `screenshotUrl` → server `fetch` → `response.text()` → JSON `screenshotContent` → `submittedData.screenshotContent` → `__html` | **Confirmed** with `xss_via_fetched_content`, linked to OOPS-SSRF-01. Review if the `api.post` helper summary or the response field match is missing |
| OOPS-XSS-05 | DOM XSS (client navigation) | page `/login` → `LoginForm.tsx:37` | `useSearchParams().get("redirect")` → `window.location.href = redirect` with no scheme check | **Confirmed** (`url_navigation`; `javascript:` URL). The same flow is the open-redirect observation OOPS-CL-01 |
| OOPS-XSS-R01 | XSS (server output) | `GET /api/vcs/[[...path]]` HTML listing | `directory` reflected into `text/html` | **Review** (reachability depends on repository lookup) |
| OOPS-XSS-N01 | XSS | `app/admin/documents/page.tsx:12` | constant `DEV_NOTE_HTML` | **No finding** |
| OOPS-XSS-N02 | XSS | `ProductSearchClient.tsx:30,120` | `useSearchParams().get("q")` → `useState` → `<input value>` | **No finding** (React-encoded attribute that cannot carry a scheme) |
| OOPS-XSS-N03 | XSS | `app/vulnerabilities/[slug]/page.tsx:191` | DB markdown file → `react-markdown` 10.1.0 with only `remark-gfm` | **No finding / Protected** (`react-markdown-v1` defaults: no raw HTML, `urlTransform`) |
| OOPS-XSS-N04 | XSS | `app/live/page.tsx` `<iframe src={\`https://www.youtube.com/embed/${config.liveVideoId}\`}>` | stored `streamConfig.liveVideoId` (written by `POST /api/live/stream`) | **No XSS claim**: a fixed `https://` prefix controls the scheme. The write path is the BFLA challenge, which is out of scope |
| OOPS-SSR-01 | Outbound (server-rendered) | page `/products/[id]` | `params.id` → `fetch(\`${getBaseUrl()}/api/products/${id}\`)` | **Observation** `request_path_in_internal_url` (Review), not SSRF |
| OOPS-SSR-02 | Outbound (server-rendered) | page `/vulnerabilities/[slug]` (and its `generateMetadata`) | `params.slug` → `fetch(\`${baseUrl}/api/flags/${slug}\`)` | **Observation** as OOPS-SSR-01. Recorded once per stage (page and metadata) |
| OOPS-SSR-03 | Practice (server-rendered) | page `/internal` | `headers().get("x-internal-request") === "true"`, else `redirect("/")` | **NX-BP-17** header-gated rendering. `redirect` must be treated as an exit |
| OOPS-SSR-04 | Practice | `POST /api/orders/[id]/share` | `host` + `x-forwarded-proto` headers → `shareUrl` in the JSON response | **NX-BP-16** host-header trust |
| OOPS-SSR-05 | Practice (RSC exposure) | page `/products/[id]` → `ProductDetailClient` | whole `product` object passed as a prop | **Measure**: NX-BP-18 only if the API returns sensitive columns; otherwise no finding |
| OOPS-CL-01 | Practice (client) | `LoginForm.tsx:16,37` | `?redirect=` → `window.location.href` | **NX-BP-10** open redirect |
| OOPS-CL-02 | Observation (client) | `app/order/OrderClient.tsx:17,34` | `?id=` → `api.get(\`/api/orders/${orderId}\`)` unencoded | **`client_request_path_injection`** (CSPT), Review |
| OOPS-CL-03 | Observation (client) | `app/support-login/page.tsx:11,20` | `?token=` → `fetch(\`/api/auth/support-login?token=${token}\`)` | **`client_request_query_injection`**, plus **NX-BP-20** (token in URL) |
| OOPS-CL-04 | Practice (client) | `LoginForm.tsx`, `SignupForm.tsx`, `support-login/page.tsx` | `localStorage.setItem("user", JSON.stringify(data.user))` | **NX-BP-19** sensitive data in web storage (identity data in the user object; a model-free practice observation, not a credential-leak judgment) |
| OOPS-VAL-* | Validation | every entry using `parseBody`/`parseQuery` | zod schemas such as `supportRequestBodySchema` (`screenshotUrl: z.string().optional()`) | Standalone validation observations: type-only schemas on destination fields (`zod_type_only`). Never Protected for SQL, path or SSRF |
| OOPS-MW-01 | Middleware (entry) | `middleware.ts` matcher `/monitoring/internal-status` | — | The stage is attached only to that page entry. No API entry is affected (test of matcher evaluation) |

## Saved results and verification

Fresh full run `run-2413679240` contains 116 records: 15 Confirmed, 101 Review, 0 Protected.
107 were assessed with OpenAI `gpt-6-luna` (15 Confirmed, 92 inconclusive), including all 86 standalone
input-validation contexts; 9 outbound observations are intentionally unassessed. HTML displays 99
Review rows because two outbound observations are grouped; JSON retains every record. Practice
observations (29) are separate, model-free output.

Every required positive (`SQL-01..04`, `PATH-01/02`, `SSRF-01`, `LOG-01/02`, `XSS-01/02/04/05`,
all prefixed `OOPS-`) is Confirmed. SQL-04 has two operations and PATH-01 has two file reads, so
13 case IDs produce 15 Confirmed records. `SSRF-02`, `XSS-03`, `PATH-R01/R02`, `PATH-N01` and an
unlinked server HTML record at `app/vulnerabilities/[slug]/page.tsx:275` remain Review.
`XSS-N01..N04` produce no XSS record. The proposed `XSS-R01` VCS flow has no XSS record; it is
not a passed detection claim. `SQL-Q01` is an expectation about unsafe construction, not a detected
injection or a dedicated practice check. `SSR-05` exposure checking is deferred (`NX-BP-18`).

Offline gate: `ZAZZLES_NEXTJS_SAMPLE=<checkout> go test ./internal/parse -run TestNextJSOopsStoreAnswerKey`.
The fresh run replays 107/107 exactly with `TestReplaySavedRun`, with zero mismatches or missing traces.
Preserve the pinned checkout and write routine outputs outside it. Expected labels must never enter
scanner/model evidence or target-name exceptions. See the [reference policy](../../docs/samples/reference-policy.md).

## Not covered

XXE, JWT confusion, weak crypto, insecure randomness, IDOR/BOLA, broken function-level authorization,
mass assignment, CSRF, races, session fixation, brute force, prompt injection, malicious MCP servers,
AI rules-file backdoors, exposed repository/configuration files, typosquats and React2Shell are outside
the implemented analyzer claims. Some have practice observations, which do not upgrade them to
vulnerabilities. No NoSQL or command-positive expectation is established for this sample.
