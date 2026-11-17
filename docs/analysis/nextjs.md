# Next.js acquisition and practice rules

[Analysis rules](README.md) · [Node input acquisition](node-inputs.md) · [Next.js support](../nextjs-support.md)

This addendum to [Node input acquisition](node-inputs.md) governs the Next.js adapter. The adapter
supplies entries, request bindings and origins only. Sink operand contracts, guard classification,
questions and verdicts stay with the shared engine and the family guides. The user-facing summary
and reference results are in [Next.js support](../nextjs-support.md).

## Rules

1. **The file path is the registration.** An App Router entry is `route.*` plus an exported method
   name; a page is `page.*` plus its default export; a Pages Router page is a `pages/**` file that
   exports `getServerSideProps`, whose returned `props` feed its default-exported component. Evidence carries the route file and export
   declaration. Never infer an entry from a URL string elsewhere in the code.
2. **Origins come from verified receivers.** A web-request read (`searchParams.get`, `headers.get`,
   `cookies.get`, `json()`, `formData()`, `params`) is an origin only when its receiver chain reaches
   the handler's own request or context parameter, a page prop, a `next/headers` import, or a value
   already bound from one of them. Names alone never qualify.
3. **Wire vocabulary is fixed.** Origins reuse `http.query`, `http.body`, `http.headers`,
   `http.cookies`, `http.path`, `http.url` and the upload origins. `input_facts.acquisition` stays
   `http` (it must equal the entry kind); initial types use `string`, `array`, `object` or `unknown`.
4. **Model only verified awaits.** Awaiting a web-request read or a resolved local async helper is a
   transfer. Verified Prisma row operations are also modeled awaits. Every other `await` keeps `async_response_unresolved`.
5. **Wrappers and middleware are authorization context.** A higher-order wrapper is resolved only
   when its returned function forwards the same request and context. Its checks, middleware
   redirects and header/cookie gates are context and practice evidence, never destination
   protection for any family.
6. **TypeScript types are not validation.** Server Action arguments are `http.body` whatever their
   annotation. A zod schema is supplied as evidence; its effect is the model's question. In Next.js
   code a truthiness test of the value, an extension comparison, a sibling-field comparison and a
   `success` test of a schema whose rule for the field is type-only are not containment or
   destination controls. A schema rule with a regex, enum, refine or similar keeps the test as a
   possible control.
7. **Encoded output is not a record.** React-encoded JSX text and attributes produce no XSS record.
   Only raw HTML, script, and URL sinks without a fixed literal prefix are recorded.
8. **A fixed origin is not SSRF.** A server request whose origin is constant or configured and whose
   request data is only in the path or query is an outbound observation
   (`request_path_in_internal_url`). Client-module `fetch` is browser traffic.
9. **Practice checks are separate.** NX-BP observations are source-established, use no model, and
   are reported apart from vulnerability findings. They name what the source shows and never claim
   exploitability. Environment values are never read into evidence; only variable names are.
10. **Version facts come from the target.** Promise `params`, advisories and similar facts use the
    resolved manifest/lockfile version; an unknown version records nothing rather than guessing.

## Fact codes

The adapter adds these notes to [`facts.md`](../../internal/guidelines/facts.md): `scope_nextjs`,
`zod_schema_supplied`, `sql_multi_statement`, `sql_single_statement`, `browser_navigation_sink`,
`xss_via_fetched_content` and `script_reexecution`. `url_scheme_only_test` (SSRF) is
framework-neutral and was added with the vuln-nextjs lab.

## Regression evidence

Each rule has paired fixtures in `internal/parse/nextjs_test.go` (segment conversion, wrappers,
web-request origins and a shadowed `headers`, tsconfig aliases, zod/pino/SSRF, client React flow,
pages/middleware/actions, Pages Router API routes, navigation exits, client calls that are not routes, upload filename
sanitizers, Prisma stored and fetched-content links, `getServerSideProps` pages with PGlite).
`TestNextJSVulnLab` (`ZAZZLES_VULN_NEXTJS`) is driven by the vuln-nextjs lab's own
`tests/expected-scanner-findings.json`, so lab rows added later are checked without a code change.
`TestNextJSOopsStoreAnswerKey` checks the
offline answer key against the pinned reference sample when `ZAZZLES_NEXTJS_SAMPLE` names a clean
checkout at `2d530ef`. Every fixture record must pass judge component selection, so a record that a
model request would reject fails the test offline.

## Phase 2 flow and practice boundaries

Pages handler try/catch/finally bodies retain separate normal and exceptional bindings; catch guards
are never borrowed from the try arm. One imported JSX component hop transfers explicit props, including
browser effects. Layouts/templates are stages of their page invocation. `getInitialProps` supplies
per-request props; `getStaticProps` is a build-time observation without request-source claims.
Literal App Router export-star declarations expand bounded re-exports.

React context, Redux and verified Zustand hooks are browser state sources; provider/reducer/updater
transitions remain `react_shared_state_unresolved`. Literal raw-SQL writes link to Prisma fields only
through physical table/column identities established by the Prisma schema. Dynamic SQL identifiers
and ambiguous schemas remain unresolved.

Loops do not block a claim when they start after the sink or, before it, neither leave the handler,
assign an outer binding nor contain the sink; this only removes `control_flow_unresolved` and never
adds a guard. Python percent-decoders and query-string parsers (`unquote`, `unquote_plus`,
`unquote_to_bytes`, `parse_qs`, `parse_qsl`) keep the argument's provenance; a raw value stays raw and
an earlier protection becomes unknown after decoding.

NX-BP-09/11/13/14/15/18/21/22 supplement the existing model-free practice checks. Cookie checks require
a verified receiver. Sensitive row exposure requires schema-established sensitive columns and honors
literal select projections. Action writes/returns and explicit client props are browser boundaries.
Message sender and client-only authorization checks are Review observations, not vulnerability claims.
Caching observations require a registered entry's actual user-context reads; a constant key named
`users` is not a user-specific cache key.

Cookie option checks resolve bounded immutable local aliases and ordered literal spreads; a later
override wins. Mutation, an escaped options object or unknown composition remains a Review
observation, rather than a claim that an individual flag is definitely absent. Image/Server Action
configuration whose relevant values cannot be resolved is also reported as an unresolved practice
boundary.

Shared-cache checks follow actual request-context values into the same cached computation.
`unstable_cache` key parts must cover the captured request value; a different cookie or a whole
cookie jar does not establish the same identity. Known callback invocation arguments participate in
the key. An unresolved callback cannot establish protection. A public cached request beside an
unrelated cookie read does not establish personalized caching.

Message origin checks must enforce an exact origin before the same callback's data use. Ignored
comparisons, checks after use, mutated events and nested callback checks cannot suppress the
observation. A client role gate is associated with its actual request/method/route; merely calling
an auth helper on the server is not evidence of enforcing the relevant admin permission. The bounded
server check recognizes a `next-auth` `getServerSession` identity and an explicit role rejection
with a 401/403 response before the operation. Unknown local helpers, successful responses from the
rejecting branch and unsupported authorization forms remain Review. Neither sender origin nor
server authentication supplies output encoding.
Direct `if` and ternary branches establish the client request association. Mutating a session
through a local alias invalidates the role evidence; unsupported escapes remain unresolved.

Server Action validation is checked per request-derived value, including sibling object fields.
An ignored parsed result or a validated sibling cannot supply another value's validation evidence;
authorization remains a separate boundary. These checks use no model and express no exploitability
verdict. [Accuracy evaluation](../../.zazz/evaluation/practice-accuracy/results.md) records the pinned
research, results and the distinction between this practice tier and security assessment.

[Code injection](code-injection.md) and [open redirect](open-redirect.md) remain independent shared
families. Their API semantics and verdict gates are not Next.js acquisition rules.
