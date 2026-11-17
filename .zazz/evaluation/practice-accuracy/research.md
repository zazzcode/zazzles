# Practice accuracy: implementation research

Research performed 2026-11-16 in `accuracy-false-positive-eval`, baseline
`cb40f370594948181594b2dbc1b5576157b1ba95` (merged PR #20). This record supports the
[implementation contract](../../specifications/practice-accuracy-and-false-positive-evaluation.md).
It is a measured starting point, not a claim that the proposed corrections have shipped.
The [implementation results](results.md) record the completed corrections and final verification.

## Pinned corpus

The predecessor's retained source-integrity manifest was rechecked against source bytes. All seven
Git targets have no tracked changes and match their full pins. The lab has five preexisting ignored
paths; they were not removed or modified. Commerce's 78-file archive has zero hash mismatches.
No target dependencies were installed and no target application was executed.

| Target | Full revision |
|---|---|
| Next.js lab | `ea10efb960d5bf4dbabbfee01dc6e5f881b22898` |
| OopsSec | `2d530ef3c0e668022c93fd2c03b52eef4691a6c3` |
| vuln-demo-app | `d27b35bdd2d599f1f79dace71d5272215df04423` |
| vulnerable-typescript-app | `7f8b240a2f02beba099da3632d1ba679ff8bc32f` |
| nodejs-goof | `add14ba59e98240d9e00a235dd7d42cd61ae9912` |
| Juice Shop | `f189f521266f42c6bd05884468292000cee852ed` |
| VulnPy | `b81885e58283a3449b578d20c20557aff637e5ea` |
| Commerce | `f7521d57d29f0eb3d23c1399cf9bb299d61fcd21` |

## Reproduced practice defects

The existing extended-practice and cookie/projection tests pass. They exercise simple literals and
direct predicates, leaving the composition/enforcement cases below untested. All seven added
research expectations fail against the unchanged scanner. These are observation errors, not false
Confirmed/Protected security verdicts.

| Probe | Expected observation | Baseline | Source-backed cause |
|---|---|---|---|
| `cookie_composed_safe` | absent | emitted | Object spread of three safe flags is not resolved |
| `cookie_override_unsafe` | emitted | absent | A later spread overriding `secure:true` with false is ignored |
| `message_comparison_unused` | emitted | absent | An unused equality expression suppresses the listener observation |
| `message_comparison_after_use` | emitted | absent | Origin comparison after consuming data still suppresses the observation |
| `cache_identity_name_only` | emitted | absent | `const user='global'` passes the identifier-name identity heuristic |
| `cache_public_unrelated` | absent | emitted | A public catalog fetch is conflated with a separate cookie read |
| `admin_ignored_auth` | Review | absent | Presence of an imported `auth()` call suppresses Review without enforcing its result |

The last case does not establish that the missing helper is unsafe: its enforcement is unknown.
That uncertainty is precisely why the expected practice outcome remains Review.

Relevant source: `internal/parse/next_practice_extended.go` functions
`practiceModuleBoundaries`, `cacheKeyHasIdentity`, `verifiedCookieWrite`, and
`practiceClientAuthorization`; sensitive projections live in `next_boundary.go`.

The exact synthetic source is retained in [research-probes.txt](research-probes.txt).
The [runner](run_research.py) injects it through a temporary Go overlay; it does not edit installed
tests or targets. It verifies both the exact seven subtest outcomes and the Go exit code, so a build
failure cannot masquerade as reproduced defects. Run from the source checkout with Go 1.27.2+:

```bash
python3 .zazz/evaluation/practice-accuracy/run_research.py --expect baseline
```

Exit 0 means all seven expected baseline defects reproduced; the inner Go test exits 1. After
implementation, use `--expect improved`: that mode requires all seven inner tests to pass.
Use a writable `GOCACHE` if the normal host cache is restricted. These tests send no model requests.
The probes are a focused diagnostic set, not an estimate of practice accuracy over real applications.

## Primary-source findings

- Next.js 15's [`unstable_cache` contract](https://nextjs.org/docs/15/app/api-reference/functions/unstable_cache)
  includes function arguments in the cache identity and permits additional key parts for captured
  values. This supports checking actual value provenance and invocation arguments rather than names.
  Dynamic request data must be handled at the documented cache boundary.
- Next.js's [cookie API](https://nextjs.org/docs/app/api-reference/functions/cookies) documents
  `httpOnly`, `secure`, and `sameSite` options. Ordinary ordered JavaScript object composition determines
  the values actually passed; a literal earlier in an object does not override a later spread.
- The [web-messaging contract](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)
  requires checking sender identity before acting on the message. A comparison whose result is
  unused or computed after the use cannot enforce the sender boundary.
- Next.js's [JSON-LD guidance](https://nextjs.org/docs/app/guides/json-ld) recommends escaping `<`
  after serialization. Commerce performs only `JSON.stringify`; this does not establish HTML-script
  safety. Attacker control of the product fields is still a separate unresolved premise.
- Shopify's [HTML scalar](https://shopify.dev/docs/api/storefront/latest/scalars/HTML) describes
  HTML content and maps `Page.body`/`Product.descriptionHtml`. It does not establish a sanitization
  or publisher-authorization guarantee. The archived `2023-01` scalar URL could not be retrieved;
  current documentation is corroborating context, not an inferred historical safety contract.
- NextAuth v4's [server-session API](https://next-auth.js.org/configuration/nextjs#getserversession)
  returns an authenticated session or null. The implemented authorization observation recognizes
  that library binding plus an explicit admin-role rejection; arbitrary local helpers named `auth`
  remain unknown. This is bounded practice evidence, not an audit of auth callbacks or configuration.

Commerce pins Next.js `15.6.0-canary.60`, React `19.0.0`, and the Shopify `2023-01` endpoint in
`lib/constants.ts`. Do not apply current Next.js 16 caching semantics to that pin without checking
the relevant API/version. No new `use cache` analyzer is proposed by this contract.

## Commerce record audit

A fresh offline scan reproduces the predecessor's **16 entries, 23 uses, 23 findings and two practice
observations**. All security findings have `status=needs_review`, `assessment_state=not_run`.
The complete `uses` and `findings` arrays are structurally identical to the retained proposal-1
after report. Raw report SHA-256:
`75d54c575055300fe656e965de596fda5e791573c37ae0e01f2fa4a740402719`.

All rows below remain unjudged Review. The table records individual inspection, not newly assigned
safe/vulnerable oracle labels. Repeated cookie reads belong to distinct invocation contexts.

| Row | Source at pin | Individual interpretation |
|---|---|---|
| C01 | `app/[page]/page.tsx:11`, `params.page` | Metadata lookup passes handle as GraphQL variable; missing business handle constraints remain separate |
| C02 | `components/prose.tsx:10`, raw HTML | `Page.body` is passed by the page component; product description HTML also uses Prose. Publisher trust and sanitization are unresolved |
| C03 | `app/[page]/page.tsx:30`, `params.page` | Page lookup uses the same variable API, with `notFound()` for absent pages; this is not general input validation |
| C04 | `lib/shopify/index.ts:519`, topic header | Topic must match a finite collection/product webhook list before revalidation; unknown topics return without revalidating |
| C05 | `lib/shopify/index.ts:520`, secret query | Missing/mismatched secret returns before revalidation; actual secret configuration and business policy are not in the archive |
| C06 | `app/product/[handle]/page.tsx:17`, handle | Metadata uses a GraphQL variable and `notFound()`; does not imply every business constraint is established |
| C07 | `app/product/[handle]/page.tsx:79`, JSON-LD | Product fields reach a raw script via JSON serialization without `<` escaping; external field authorship/control unresolved |
| C08 | `app/product/[handle]/page.tsx:54`, handle | Product page's distinct lookup context; safe parameter transport is not a whole-page security verdict |
| C09 | `app/search/[collection]/page.tsx:13`, collection | Metadata passes collection handle to lookup; missing collection becomes `notFound()` |
| C10 | `app/search/[collection]/page.tsx:36`, collection | Product collection query uses a variable; supported handle format/business policy remains unspecified |
| C11 | `app/search/[collection]/page.tsx:32`, sort | `sorting.find` selects a server constant or `defaultSort`; request does not directly become the GraphQL sort key |
| C12 | `app/search/page.tsx:15`, q | Search string is a GraphQL variable and React text; search-language semantics/business constraints still need their own contract |
| C13 | `app/search/page.tsx:15`, sort | Same finite server sort mapping as C11 in a different entry |
| C14 | `lib/shopify/index.ts:231`, cartId | `addToCart` sends cookie value as a GraphQL variable; cart ownership/token policy is not established locally |
| C15 | `components/cart/actions.ts:16`, prevState | Argument is unused; candidate workload should be reported explicitly, without inventing a vulnerable use |
| C16 | `components/cart/actions.ts:17`, selectedVariantId | Presence check precedes adding one item; TypeScript type is not runtime validation or a business rule |
| C17 | `lib/shopify/index.ts:275`, cartId | `getCart` read in remove-item context; lookup result constrains later line IDs, ownership remains an external API boundary |
| C18 | `components/cart/actions.ts:31`, merchandiseId | Finds a matching line from fetched cart, then passes its server-returned line ID to removal |
| C19 | `components/cart/actions.ts:31`, prevState | Unused in removal action; not an injection or authorization defect merely because it is a parameter |
| C20 | `lib/shopify/index.ts:275`, cartId | `getCart` read in quantity-update context; external cart identity contract remains unproven |
| C21 | `components/cart/actions.ts:56`, payload | Destructured ID/quantity has zero/positive branches; negative/invalid quantities and API policy need explicit analysis |
| C22 | `components/cart/actions.ts:55`, prevState | Unused in quantity action; retain distinct workload accounting |
| C23 | `lib/shopify/index.ts:275`, cartId | `getCart` read in checkout-redirect context; external checkout URL trust is separate from cookie validation |

The two practice observations are separate from the 23 security records. Zero offline red findings
is not a measured false-Confirmed rate. This scan measures Review burden **23/23**, not-run workload
**23/23**, validation **21/23**, and rendering **2/23**. No security oracle denominator has yet been
established for a new paid accuracy study, so recall and semantic error rates remain unmeasured.

## Verification and evidence locations

Go toolchain: `go1.27.3 darwin/arm64`. The two initial answer-key skips were resolved by setting the
sample environment variables; the actual gates pass at the pins, including 29 supported lab rows.

```bash
go test ./internal/parse -run 'TestNextPractice|TestNextCookie' -count=1 -v
ZAZZLES_VULN_NEXTJS=<lab> ZAZZLES_NEXTJS_SAMPLE=<oopssec> \
  go test ./internal/parse -run 'TestNextJSVulnLab|TestNextJSOopsStoreAnswerKey' -count=1 -v
go build -o <external-output>/scan ./cmd/scan
<external-output>/scan --analyze --json <commerce-archive>
python3 .zazz/evaluation/practice-accuracy/run_research.py --expect baseline
go vet ./...
go build ./...
```

All listed checks pass, with the research runner confirming expected baseline failures.
Raw Commerce JSON is retained in the external temporary evaluation directory as
`zazzles-accuracy-commerce-baseline.json`; no model was enabled. Detailed command output is local
under `.zazz/ephemeral/accuracy-*.log`. Durable full-race/doc-check results are appended after completion.

**Paid requests sent: 0 / 300 authorized for this session.** There is no retained new paid assessment
to replay. No product behavior was changed by this research; implementation acceptance remains open.
