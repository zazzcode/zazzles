# Detection generalization 08 — credential cookie settings

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** 08. **Depends on** nothing. **Effort** small. **Review artifact** one draft PR.

## Capability

A cookie the application itself sets and itself reads to authenticate is a session cookie, whatever library
or name. Its flags are recorded, an absent flag with the documented default. Today Node reads only an
explicit `false` of two session libraries.

## Required reading

`langjs/configuration.go` (its stated exclusion of `res.cookie`), `next_handlers.go`, `express_access.go`;
[configuration](../../../docs/scan/analysis/configuration.md); [configuration
design](../../architecture/configuration-analysis.md); CWE-1004, CWE-614, CWE-1275; [Express
`res.cookie`](https://expressjs.com/en/api.html#res.cookie).

## Semantics

**Set.** `res.cookie(name, value, options)` on the verified response; the Next.js cookie setter; a
`Set-Cookie` header with a literal cookie name.

**Credential role**, with evidence, one of: the same literal name is read in a listed access middleware's
options, or in a check (spec 02's record if merged, otherwise an `if` that ends the response) or a lookup
that yields the caller; the value is the result of a token-signing call of a verified package. A name alone
gives no role and no record.

**Facts.** `http_only`, `secure`, `same_site`: `true`, `false`, a literal, `absent` with the default, or
`unknown` for a computed option. Plus where it is set, where it is read, and whether browser code of the
project also writes it (then it can never be `HttpOnly`).

## Scope

`langjs/configuration.go`, a new `credential_cookies.go`, tests and fixtures; configuration checks' text in
`analysispacks`; finding help text. Out of scope: lifetimes, prefixes, signing strength, PHP (has its own).

## Decisions

- **D-1. Role by use.** *Why:* the existing exclusion is right that a name establishes nothing. This
  supplies what it lacked.
- **D-2. Existing check identifiers.** *Why:* extend before add. `same_site` is a joined fact, not a check.
  *Why:* its browser default varies.
- **D-3. Environment conditions are joined facts.** *Why:* `secure` in production only is common and
  correct.

## Fixtures

Positive: no options; explicit false; options constant; Next.js setter; header. Negative: preference cookie
read by no check; all flags set; `secure` by environment; computed options (`unknown`); a cookie set and
never read; clearing a cookie; a CSRF cookie that must be readable.

## Held-out

One application that sets its own token cookie and one ordinary application.

## False-positive controls and G7 bound

Preference and CSRF cookies. At most two added records per sample.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestCredentialCookies` |
| AC2 | No record without a role | `TestCredentialCookieRole` |
| AC3 | Existing session-library records byte-identical; G1 to G7 | Comparison |
| AC4 | Paid checkpoint passes | Results |
| AC5 | Pages: insecure configuration; its guide; `configuration-analysis.md` | `doc-check` |

## Paid checkpoints

Fixtures and held-out. Cap 40. Pass: no control Confirmed; every keyed positive Confirmed.

## Stop rule

Stop when the role cannot be shown for at least half of keyed session cookies, or a preference or CSRF
cookie is recorded, or fewer than two pool applications set a cookie of their own (too rare to keep).

## Juice Shop check

`JS-X-CONF-06`, server anchor, should have a record.

## First failing test and order

`TestCredentialCookies/token_without_options`. Then set, role, facts, checkpoint.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
