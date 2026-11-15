# Server-side request forgery (SSRF)

[Analysis index](README.md) · [Result interpretation](../interpreting-results.md)

An SSRF claim exists when a request value reaches the **destination operand** of a verified outbound
HTTP client. Request data sent as a body, header or query parameter to a fixed destination is not
destination control.

## Verified clients

| Contract | Binding the scanner must verify | Destination operand |
|---|---|---|
| `fetch-url-v1` | global `fetch`, not imported, declared, reassigned or shadowed in scope | argument 0 |
| `axios-url-v1` | `axios` (or `axios.default`) imported or required from `axios` | argument 0 of `axios(url)` and `get/delete/head/options/post/put/patch`; a config object stays an observation |
| `python-http-url-v1` | existing `requests`, `httpx` or `urllib.request.urlopen` binding | `url` argument or keyword (`requests.request` argument 1) |

## Destination origin

Every outbound record classifies the destination operand: `request` (a request input reaches it),
`external_data` (only stored or remote-response data), `constant`, `environment` (an unshadowed
`process.env` read, directly or through one local or parameter default) or `unestablished`. Only a
`request` destination with a verified client becomes a claim. Second-order destinations stay
observations; `unestablished` is not proof that no request value reaches the call.

## Assessment and outcomes

The model answers `destination_control` (`full_url`, `host`, `path_or_query`, `none`, `unknown`),
`destination_restriction` (`host_allowlist`, `scheme_and_host_check`, `prefix_only`, `none`,
`unknown`) and `protection_coverage`. Guards come from the shared guard engine and attach only to the
destination value they mention.

- **Confirmed (CWE-918):** host or full-URL control, no restriction, a raw destination path and no
  claim blocker.
- **Poor practice:** host control restricted only by an unparsed string prefix, substring or pattern.
- **Protected:** an allow-list or scheme-and-host check on the same value on every path, with complete
  coverage.
- **Inconclusive:** blockers, `path_or_query` only, unknown answers, or answers that contradict the facts
  (for example a restriction claimed where no guard exists).

Network reachability, DNS answers, redirects at runtime, proxies and deployment policy are not inferred.
A handler reached through an unmodeled wrapper keeps `unresolved_wrapper` blockers.
