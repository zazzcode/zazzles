# Missing authorization

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/authorization.md) · [CWE-862](https://cwe.mitre.org/data/definitions/862.html) · [CWE-639](https://cwe.mitre.org/data/definitions/639.html) · [CWE-291](https://cwe.mitre.org/data/definitions/291.html)

Code Scan reports an operation that changes or reveals a record the request selects when
no recorded guard and no entry rule covers it. The scanner lists the guards and the
entry's access. The decision model judges whether they are enough. Select the family
with `--only-family authorization`.

A confirmed record is `missing-authorization`, or `address-based-access` when the only
guard is an address check.

## What is reported

| Facet | Reported when | Remediation |
| --- | --- | --- |
| `object_level` | A request-selected record is updated or deleted, or a file named by one of its fields is written or deleted, with no adequate guard and inadequate entry access | Authorize the operation on that record |
| `function_level` | A role-source field is written. On a created record the written value comes from the request | Do not let the request choose a privilege, and require the same access on every entry that writes the field |
| `data_exposure` | A response or template returns a credential, login identifier or role source of a request-selected or enumerated record | Return those fields only to a caller the entry's access admits |

## Access sources

| Source | What is read | Result |
| --- | --- | --- |
| `access_control` `path` | A supported prefix pattern against the route path up to the first `{` | First match wins |
| `access_control` `route` | The route name | Exact match |
| `PUBLIC_ACCESS`, `IS_AUTHENTICATED_ANONYMOUSLY` | The role string | Authentication `none` |
| Any other role | The role string | Authentication `required`, role listed |
| Firewall `security: false` | The same path subset | Authentication `none` |
| `form_login`, `http_basic`, `json_login` | The firewall key | Evidence on the entry |
| `#[IsGranted]`, `@IsGranted`, `denyAccessUnlessGranted` | A role argument on the class or the action | Merged with the rule. A non-role leaves access unresolved |

## Subject and operation

The subject is `request_selected` when a route placeholder or a request value chooses
the record, `enumerated` when every record is loaded, `session_user` when the record is
the logged-in user, and `created` when the action constructs it. A session user and a
created record that receives no request-derived role are not candidates. A dynamic
property write stays a mass-assignment candidate and is not also an authorization
candidate.

## Guards

| Kind | What it is |
| --- | --- |
| `ownership_check` | The record is compared with the session user, or the query is scoped to that user |
| `role_check` | `isGranted` exits before the operation |
| `authenticated_check` | A missing user exits before the operation |
| `secret_check` | A stored field of the record is compared with a request value |
| `address_check` | The peer address is compared with literal addresses |
| `guard_unclassified` | A private helper was followed and its body is not one of those kinds |

## Recorded and decidable

An entry rule that matches, a modeled guard, the subject, the operation and the census
fields of a write or a read. Peer entries that write the same field are listed with
their access. An address-guarded record lists the server-side requests in the same
report. Those requests are not changed.

## Recorded in Review

| Gap | Why it is in Review |
| --- | --- |
| `access_rule_unresolved` | The path expression is outside the supported subset |
| `access_rule_condition_unmodeled` | The rule uses `ips`, `host`, `port`, `allow_if`, `requires_channel`, `request_matcher` or `attributes` |
| `voter_unmodeled` | `IsGranted` is not a role, or it takes a subject |
| `access_expression_unmodeled` | The check is an expression |
| `authenticator_unmodeled` | The firewall uses `custom_authenticators` |
| `guard_unclassified` | A private helper's check has no modeled kind |
| `symfony_config_unread` | `security.yaml` could not be read |
| `address_trust_configuration_unread` | A framework client address depends on trusted-proxy configuration, which is not read. This gap does not by itself block the claim |

## Not recorded

A write of the session user's own record. A created record whose role fields are not
request-derived. A key-controlled write, which mass assignment already owns. A read of
a field that is not a credential, a login identifier or a role source. Command
execution guarded only by an address. Voters, expressions and custom authenticators
beyond the gap. Access is not a protection for any other claim.
