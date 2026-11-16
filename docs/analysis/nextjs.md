# Next.js acquisition and practice rules

[Analysis rules](README.md) · [Node input acquisition](node-inputs.md) · [Next.js support](../nextjs-support.md)

This addendum to [Node input acquisition](node-inputs.md) governs the Next.js adapter. The adapter
supplies entries, request bindings and origins only. Sink operand contracts, guard classification,
questions and verdicts stay with the shared engine and the family guides. The user-facing summary
and reference results are in [Next.js support](../nextjs-support.md).

## Rules

1. **The file path is the registration.** An App Router entry is `route.*` plus an exported method
   name; a page is `page.*` plus its default export. Evidence carries the route file and export
   declaration. Never infer an entry from a URL string elsewhere in the code.
2. **Origins come from verified receivers.** A web-request read (`searchParams.get`, `headers.get`,
   `cookies.get`, `json()`, `formData()`, `params`) is an origin only when its receiver chain reaches
   the handler's own request or context parameter, a page prop, a `next/headers` import, or a value
   already bound from one of them. Names alone never qualify.
3. **Wire vocabulary is fixed.** Origins reuse `http.query`, `http.body`, `http.headers`,
   `http.cookies`, `http.path`, `http.url` and the upload origins. `input_facts.acquisition` stays
   `http` (it must equal the entry kind); initial types use `string`, `array`, `object` or `unknown`.
4. **Model only verified awaits.** Awaiting a web-request read or a resolved local async helper is a
   transfer. Every other `await` keeps `async_response_unresolved`.
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
`xss_via_fetched_content` and `script_reexecution`.

## Regression evidence

Each rule has paired fixtures in `internal/parse/nextjs_test.go` (segment conversion, wrappers,
web-request origins and a shadowed `headers`, tsconfig aliases, zod/pino/SSRF, client React flow,
pages/middleware/actions, navigation exits, client calls that are not routes, upload filename
sanitizers, Prisma stored and fetched-content links). `TestNextJSOopsStoreAnswerKey` checks the
offline answer key against the pinned reference sample when `ZAZZLES_NEXTJS_SAMPLE` names a clean
checkout at `2d530ef`. Every fixture record must pass judge component selection, so a record that a
model request would reject fails the test offline.
