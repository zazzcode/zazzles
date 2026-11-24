# Account enumeration

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/account-security.md) · [CWE-204](https://cwe.mitre.org/data/definitions/204.html)

Code Scan reports an entry that needs no login when it looks up an account by a request
value and answers differently when the account exists. The scanner records the lookup,
the branch on its result and the responses on each side. It compares the two response
lists with each other and never with expected wording. The decision model judges
whether the difference tells a caller that an account exists. Select the family with
`--only-family account`.

A confirmed record is `account-enumeration`.

## What is reported

| Shape | Reported when | Remediation |
| --- | --- | --- |
| Symfony finder | `find`, `findOneBy`, `findBy` or `count` on an account class (a `UserInterface` class or the entity of a `security.yaml` user provider) whose criteria hold a request value, under an entry with access `none` or `unresolved` | Answer the found and not-found branches the same way |
| Plain PHP lookup | A literal SQL `SELECT`, in the query call or in the one string assignment to its variable that reaches the call, on a table that a statement writes from `password_hash` or a fast digest, with a request value in the query | The same |
| Responses | On each side, in order until the action returns: an `addFlash` literal, a `Response`, `JsonResponse`, `json()` or `echo` literal, a status code, a `redirectToRoute` name, a `render` template, a thrown exception, `header('Location: …')`, `http_response_code` and `die` | Identical lists record nothing |

## Recorded and decidable

The lookup class, the criteria fields with their census roles, the request source, the
branch condition and both response lists, and the entry's access. A record is made only
when the two lists differ in a literal, a status, a redirect target or a template.

## Recorded in Review

| Gap | Why it is in Review |
| --- | --- |
| `response_unresolved` | A response on one side is not reduced to literals, for example a message built in another service |
| Entry-access gaps | The entry's access rule is unresolved (`access_rule_unresolved`, `access_rule_condition_unmodeled`, `voter_unmodeled`, `access_expression_unmodeled`, `authenticator_unmodeled`, `symfony_config_unread`) |

## Not recorded

An entry whose access is `required`. A lookup by a value that is not from the request. A
lookup on a class that is not an account. A lookup that includes the credential field,
which is a login. Responses inside a nested condition on one side. Timing differences,
rate limiting and lockout.

## Remediation

Return the same message, status and redirect whether or not the account exists, and send
account-specific information to the address stored for the account.

## JavaScript and TypeScript (Express)

An entry with no authentication that looks a record up by a request value through a Sequelize or
Mongoose finder, and whose branches on the result answer with a different status or body, records a
candidate. A lookup that also compares a credential (an attribute a set accessor fills from a fast
digest, or a digest value) is a login and records nothing. The finder may be on any verified
model, so a lookup of a non-account record can also be recorded; the decision model judges it.
