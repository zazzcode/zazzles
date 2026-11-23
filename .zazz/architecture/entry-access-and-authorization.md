# Entry access and authorization

An authorization candidate is one protected operation. The scanner records who the entry
admits, which record the operation uses, and which checks dominate the operation. It does
not decide that a check is enough. The decision model answers that with
`authorization-components-v5`.

## Access model

`accessFor` reads `config/packages/security.yaml` in this order.

1. A firewall with `security: false` whose pattern matches the route's static prefix
   (the path up to the first `{`) sets authentication to `none`. The same path subset
   is used as for access-control rules. Nested groups of literal alternatives are
   accepted so the standard development firewall can be decided. Quantifiers, character
   classes and lookaheads stay unresolved.
2. Otherwise the first access-control rule whose `path` matches that prefix, or whose
   `route` equals the route name, wins. `PUBLIC_ACCESS` and
   `IS_AUTHENTICATED_ANONYMOUSLY` are authentication `none`. Any other role is
   `required` and is listed. An empty method list matches every method. The matched
   methods are evidence on the rule, not a separate field.
3. `form_login`, `http_basic` and `json_login` on the matching firewall are evidence.
   `custom_authenticators` is a gap and leaves access unresolved. A `role_hierarchy`
   entry is attached when a required role appears as a hierarchy key or value.
4. `#[IsGranted]`, a Sensio `@IsGranted` docblock, and a leading
   `$this->denyAccessUnlessGranted()` merge with the rule. A role argument
   (`ROLE_…` or `IS_AUTHENTICATED…`) is required. Anything else, a subject argument,
   or an `@Security` expression leaves access unresolved. Class and method sources
   merge. An unresolved side wins.

No matching rule is authentication `none` with the text "no rule matched". A missing
`security.yaml` is recorded at `config/packages/security.yaml` line 1. An earlier
unresolved rule is not skipped.

Access is context on the entry and on the authorization request. It is not protection
for an injection claim, an exposure claim, or any other family. A file entry carries
no access.

## Subject provenance

| Provenance | When |
| --- | --- |
| `request_selected` | The entity argument is bound from a route placeholder, or `find` / `findOneBy` / `findBy` / `getReference` takes a request value. The selecting source is a dependency of the authorization candidate. A route-placeholder source is marked `route placeholder`. |
| `enumerated` | `findAll`, or `findBy` with only literal criteria |
| `session_user` | `#[CurrentUser]`, `getUser()`, `Security::getUser()`, or a relation of that user |
| `created` | `new` of an entity |

A finder whose criteria include the session user is `request_selected` and also an
`ownership_check` of form `query_scope`.

## Operations

One candidate per write or output, with every facet that applies.

| Rule | Facet | Operation |
| --- | --- | --- |
| E1 | `object_level` | Update or delete of a request-selected record, or a file write or delete whose path comes from a field of that record |
| E2 | `function_level` | A write of a `role_source` field. On a request-selected record the written value may be a literal. On a created record the value must come from the request |
| E3 | `data_exposure` | A response or template carries a `credential`, `login_identifier` or `role_source` of a request-selected or enumerated record. The operation is `read` |

Reads are limited to census fields. A response that prints a title or a body is not an
authorization record. State changes are recorded for every named stored write on the
entry, including writes that are not candidates, so a later branch can read them.
Wildcard writes are not state changes.

`method_safe` is `yes` when the entry accepts only GET or HEAD, or any method, and the
operation is a state change. A read is `no`.

## Guards

A guard is a check that dominates the operation and exits by return, throw, or exit.
The scanner lists the kind. It does not decide the kind is enough.

| Kind | Shape |
| --- | --- |
| `ownership_check` | The subject, its id, or a relation is compared with the session user or its id, or the finder criteria include the session user (`query_scope`) |
| `role_check` | `isGranted` inside a condition that exits |
| `authenticated_check` | A null test of `getUser()` or a `$_SESSION` test that exits |
| `secret_check` | A stored field of the subject is compared with a request value that is not written to that field on the path |
| `address_check` | The peer address is compared with literals. See the address sources below |
| `guard_unclassified` | Following a private helper of the same class does not establish one of the kinds above |

Other unclassified conditions, including inline validation checks that return early,
are not recorded as authorization guards. A comparison with no early exit is not a
guard. A condition that dominates only one branch is recorded only for operations on
that branch. One private helper is followed. A second step is `guard_unclassified`.

The address guard is separate because a network address is a property of the
connection, not of the user. Sources: `getClientIp` / `getClientIps`
(`framework_client_ip`), `REMOTE_ADDR` (`peer_address`), and `HTTP_X_FORWARDED_FOR`,
`HTTP_CLIENT_IP`, `HTTP_X_REAL_IP`, `HTTP_FORWARDED` (`forwarded_header`). Literals are
classified loopback, private, or public. A framework client address also carries
`address_trust` status `unread`.

## Peer access

After every entry is analyzed, a state-changing candidate lists up to eight other
entries that write the same storage key, with each entry's access and guard kinds,
sorted by entry name, then entry ID.

## SSRF links in the report

An address-guarded candidate lists the ids of the report's `ssrf_candidate` uses in
`server_side_requests`. The authorization finding links to the corresponding SSRF findings
in `related_findings`. When the SSRF assessment has completed, its finding also links
back to the authorization finding. Neither link changes the SSRF use or its judge
request. The authorization judge request omits the IDs because a use ID contains a
snapshot hash.

## Plain PHP

A plain PHP script gets an authorization candidate in two shapes.

**Address guard.** An `address_check` is the only guard on a modeled SQL `INSERT`,
`UPDATE` or `DELETE` with constant text, or on a file write or delete. A `$_SESSION` test
is an `authenticated_check` and the shape does not apply. Command execution is not in the
operation list, so it is not recorded.

**Request-selected row** (`notePlainSelected` in `langphp/authorization.go`). A SQL
`UPDATE` or `DELETE` is built by concatenation or interpolation, and a part its `WHERE`
clause compares to a column by `=` carries a request dependency that did not pass through
session storage. The statement's parts are read in order, so a request value in `SET`
alone selects nothing. The record has facet `object_level`, subject `table:<name>` with
provenance `request_selected`, and the request sources of that part as its selecting
sources. Dominating guards are recorded and none suppresses the record. A `WHERE` part
read from `$_SESSION` adds an `ownership_check` guard of form `query_scope`. A row
selected only by a session value is not recorded.

This shape also records flows that are anonymous by design, such as a recovery page that
stores a token on the row a submitted address selects. The model judges them from the
recorded guards and source. `SELECT`, `INSERT`, bound parameters and comparisons other
than `=` are not read.

## Gaps

| Gap | What resolving it needs |
| --- | --- |
| `access_rule_unresolved` | A path expression outside the supported subset, or a placeholder match that is not decided |
| `access_rule_condition_unmodeled` | `ips`, `host`, `port`, `allow_if`, `requires_channel`, `request_matcher` or `attributes` on a rule |
| `voter_unmodeled` | An `IsGranted` argument that is not a role, or an `IsGranted` subject |
| `access_expression_unmodeled` | An `@Security` expression or an expression argument |
| `authenticator_unmodeled` | `custom_authenticators` |
| `guard_unclassified` | A private helper whose body is not a modeled kind |
| `symfony_config_unread` | A `security.yaml` that exists but cannot be read |
| `security_fields_unresolved` | The census could not decide a role, and the candidate's only facet is `function_level` or `data_exposure` |
| `address_trust_configuration_unread` | Trusted-proxy configuration. Recorded on a framework client address. It does not block the claim |

Role names are strings. `ROLE_ADMIN` has no meaning in the scanner beyond the text the
configuration wrote.
