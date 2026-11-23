# Server-side request forgery (SSRF)

[Analysis index](README.md) · [Result interpretation](../interpreting-results.md) · [Coverage and known gaps](../detection-capabilities/server-side-request-forgery.md)

An SSRF claim exists when a request value reaches the **destination operand** of a verified outbound
HTTP client. Request data sent as a body, header or query parameter to a fixed destination is not
destination control.

## Verified clients

| Contract | Binding the scanner must verify | Destination operand |
|---|---|---|
| `fetch-url-v1` | global `fetch`, not imported, declared, reassigned or shadowed in scope | argument 0 |
| `axios-url-v1` | `axios` (or `axios.default`) imported or required from `axios` | argument 0 of `axios(url)` and `get/delete/head/options/post/put/patch`; a config object stays an observation |
| `node-http-url-v1` | verified Node `http` or `https` `get` and `request` bindings | first URL argument or recognized destination fields in a literal options object |
| `python-http-url-v1` | existing `requests`, `httpx` or `urllib.request.urlopen` binding | `url` argument or keyword (`requests.request` argument 1) |
| `php-shell-url-client-v1` | a shell command whose literal program token is `curl` or `wget` | a URL position: a word that is not an option and not the value of a value-taking option. The value of `-x`, `--proxy` and `--url` is a destination with `operand` `proxy` or `url`, whether it is the next word or attached with `=` |

## Destination origin

Every outbound record classifies the destination operand: `request` (a request input reaches it),
`external_data` (only stored or remote-response data), `constant`, `environment` (an unshadowed
`process.env` read, directly or through one local or parameter default) or `unestablished`. Only a
`request` destination with a verified client becomes a claim. Second-order destinations stay
observations; `unestablished` is not proof that no request value reaches the call.

Module-level `const` string literals and templates of such constants, including named imports up to
four hops, fold to a `constant` destination. `process.env` (also `env || literal`), `let`, reassigned
and locally shadowed bindings do not fold. A constant destination with request values only in the
headers or body is explained in the record and its blocking reasons
(`constant_destination_no_request_dependency`); its status is unchanged.

## Assessment and outcomes

The model answers `destination_control` (`full_url`, `host`, `path_or_query`, `none`, `unknown`),
`destination_restriction` (`host_allowlist`, `scheme_and_host_check`, `prefix_only`, `none`,
`unknown`) and `protection_coverage`. Guards come from the shared guard engine and attach only to the
destination value they mention.

- **Confirmed (CWE-918):** host or full-URL control, no restriction, a raw destination path and no
  claim blocker.
- **Poor practice:** host control restricted only by an unparsed string prefix, substring or pattern.
  When the source establishes that every raw-text URL test in the handler fixes only the scheme (for
  example `/^https?:\/\//.test(url)`; fact `url_scheme_only_test`), that test restricts no host and a
  `prefix_only` answer is treated as `none`.
- **Protected:** an allow-list or scheme-and-host check on the same value on every path, with complete
  coverage.
- **Inconclusive:** blockers, `path_or_query` only, unknown answers, or answers that contradict the facts
  (for example a restriction claimed where no guard exists).

Network reachability, DNS answers, redirects at runtime, proxies and deployment policy are not inferred.
A handler reached through an unmodeled wrapper keeps `unresolved_wrapper` blockers.

A URL test is non-enforcing when the source shows it cannot stop or change the call: it runs after
the call, or its only effect is setting a flag or variable that no branch on the sink reads. Such a
test is not a supported transfer or restriction, and the path stays raw. A loop that starts after the
sink, or that precedes it without leaving the handler, assigning an outer binding or containing the
sink, no longer adds `control_flow_unresolved`; removing that blocker never records a guard.

## Symfony

In Symfony projects, PHP URL-capable functions, cURL, and verified Symfony HttpClient calls identify the destination operand. A fixed local path prefix excludes the URL claim, and an HTTP-only prefix excludes the local path claim. A URL-format check establishes syntax evidence without a destination restriction.

[Symfony analysis coverage](../symfony-support.md)
