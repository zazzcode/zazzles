# Open redirect

[Analysis rules](README.md) · [Code injection](code-injection.md) · [Next.js](nextjs.md) · [Coverage and known gaps](../detection-capabilities/open-redirect.md)

The `redirect` family asks whether request data chooses an off-site redirect or navigation
destination. It uses `open_redirect_candidate`, protocol `redirect-components-v1` and CWE-601.
A navigation capable of executing a `javascript:` URL can also have an independent XSS claim;
`redirect.related_use` links records from the same invocation and sink.

## Verified operations

Supported bindings include Express/Next Pages `res.redirect`, response Location header writes with
an established redirect status, Fastify/Hapi redirects, imported Next navigation redirects,
`NextResponse.redirect`, Pages data-function redirect destinations, browser location assignments,
`assign`/`replace`, `window.open`, Next router navigation and JSX meta refresh. Next explicitly
[accepts external absolute URLs](https://nextjs.org/docs/app/api-reference/functions/redirect).
Python bindings include Flask/Django redirects, Starlette/FastAPI RedirectResponse and aiohttp
redirect exceptions. PHP bindings cover `header('Location: …')` under `php-header-redirect-v1`:
a Location value is an implied 302 (the `Location:` prefix is matched case-insensitively, matching
PHP behavior), non-Location headers are not redirects, and only the destination operand is the
claim.

Only the destination operand is the claim. A body, unrelated header or data sent to a fixed
endpoint does not select the destination. Constants, query/fragment-only navigation and fixed
literal origins or relative path prefixes produce no redirect claim. Mutable variables do not inherit
an initializer's fixed-origin guarantee. Express `redirect('back')` derives its destination from
request Referer.

## Evidence and decisions

The questions separate destination control (`full_url`, `host`, `path_only`, `fixed_origin`, `none`,
`unknown`), restrictions and complete protection coverage. A single `/` prefix permits `//host` or
`/\host`, so it is insufficient. A scheme-only test restricts no host.

- A complete raw path with no effective restriction supports Confirmed.
- An enforcing parsed origin/host allowlist or relative-path check excluding double slash and
  backslash on every path supports Protected.
- An `includes`/`indexOf` test on the *raw destination string* is bypassable by allowed text in a
  query and supports Confirmed. An array allowlist of parsed hostnames is a different operation.
- An enforced `startsWith` prefix containing a full trusted origin and trailing slash supports
  Protected. Other raw prefixes are poor practice.
- Unknown bindings, unresolved relevant helpers, missing status evidence and inconsistent answers
  remain Review. A model's `fixed_origin` answer cannot erase a source-established raw operand.

Prefer a small identifier mapped to trusted constant destinations. Otherwise parse and restrict the
same final URL on every path. Check after decoding and before navigation; an earlier check of a
subsequently reassigned value protects no later value.

Destinations fixed by construction are not candidates: a ternary whose every branch is a fixed
same-site path, concatenation or a template led by such a path, a module `const` literal, and
`new URL(fixedPath, base)` (an unshadowed `URL`). A fixed path is one `/` followed by a character
other than `/` or `\`. `let`, reassigned, `process.env` and request-led prefixes stay candidates.

For JS/TS validator predicates the scanner records which destination forms each path still permits
(fact `redirect_predicate_bypass`: `backslash_prefix`, `slash_backslash`, `protocol_relative`,
`absolute_url`, `origin_prefix`, `parsed_origin_unfixed`, `checked_operand_differs`,
`percent_encoded_after_decode`, `reassigned_after_check`) and what it excludes
(`redirect_predicate_excludes`). A `same_site_relative` or `parsed_origin_check` answer is not
effective while a bypass form is recorded, so `^\/[^/]` (which permits `/\host`) stays Review.
`new URL(x, base).origin|host|hostname` compared with a literal, a `const` literal or the base's own
origin is a parsed-origin check only for the same unreassigned value. Python predicates are not yet
classified this way.

## Bounds

The scanner establishes source-level paths, not runtime redirect behavior, DNS, proxy policy or
site ownership. Location status inference is deliberately limited to dominating direct statements in
the same block and explicit `writeHead(3xx, ...)`; unknown status flow is not a confirmed redirect.
Unmodeled framework wrappers, dynamic HTML and multi-step navigation stay unresolved.

Use `--only-family redirect` with a judged scan to select this family.
