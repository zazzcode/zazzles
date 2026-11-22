# Application-security analyzers

This document owns the design of the application-security families added by the
[Symfony application-security lane](../specifications/symfony-more-analyzers.md): how they record
evidence, what they leave to the decision model, and the shared facts later families read. The
[analysis rules](../../docs/scan/analysis/README.md) own the user-facing rule tables. Branch
specifications own the decisions and their acceptance evidence.

## Why these families are operation-centered

The injection families are flow-centered. Their claim is that a request value reaches an
operand, so the record is a set of dependency paths from a source to a sink slot, and each path
carries its own protection.

The application-security claims are about what an operation does on a reachable entry, not about
which bytes reach it:

- **Information exposure** has no request source at all. A reachable `phpinfo()` discloses the
  same configuration whatever the caller sends.
- **Mass assignment** has a source, but the claim is about the *names* the request supplies, not
  the values. The record follows key origin, not value content.

So these records center on the operation: the operation and its contract, the entry, the
conditions that dominate it, and the facts of the object it acts on. Dependency paths appear only
where the claim has a source, and only for the part of the value the claim is about.

## What is recorded and what the model judges

The scanner records source evidence with a cited contract. It adds no scanner-side verdict.

| Family | Scanner records | Model judges |
| --- | --- | --- |
| `exposure` | The diagnostic operation, what its contract says it reveals, the entry and whether it is served, every dominating condition | Whether the output is internal state and whether a recorded guard restricts the caller |
| `mass-assignment` | That the property names come from a whole request bag, the write shape, the target class and storage, key guards, the census roles of the target's fields | Whether the names are request-chosen, whether a guard limits them adequately, whether the target has a field the request should not choose |

A guard is evidence, not a filter. The scanner emits the candidate either way, because whether
`if ($debug)` or a role check is enough is a judgment. The only "no claim" cases are a missing
entry (exposure) and a name the code fixes (mass assignment).

## Security-field census

The census is the shared fact of the lane (lane contract §2.3). For each stored field of a
Symfony project it records the roles that source evidence establishes, one evidence item per role
at the establishing source. It is computed once per project, deterministically, and cached on the
PHP source set (`langphp/security_fields.go`).

| Role | Evidence | Limit |
| --- | --- | --- |
| `credential` | `getPassword()` of a `PasswordAuthenticatedUserInterface` class, or a field written from a password-hash call | A hash written through more than one setter step is not followed |
| `login_identifier` | The entity user provider `property` in `security.yaml`, or `getUserIdentifier()`/`getUsername()` | Custom user providers are not read |
| `role_source` | Fields `getRoles()` reads, and fields a lifecycle callback reads when it writes one | One step: a call into another method or service records `security_fields_unresolved` |
| `name_hint` | A closed list of field names | A hint only; it never sets another role |
| `recovery_secret` | Added by branch 3 | — |

Roles come from what the framework or the code does with a field. An application can call its
privilege flag anything, and the framework contract still finds it; the transfer fixture proves
that with different class, field, route and shape names. The hint list exists for code with no
contract (plain PHP, non-user entities) and is passed to the model labeled as a hint.

The census keys fields by the storage key `doctrine_storage.go` builds (`php-sql:<table>.<column>`).
A plain-PHP target has no table; its hints are keyed `php-object:<class>.<property>`.

## Key origin versus value origin

The PHP flow model tracks value origin as dependency paths. A foreach over a request bag binds
both its key and its value variable to the bag's paths, which is right for content: either
variable carries request text.

Mass assignment needs a narrower fact: that the *keys* are request-controlled. A value whose keys
the request controls comes only from a whole-bag reader (`all()`, `getPayload()->all()`,
`toArray()`, a whole superglobal). The key variable of a foreach over such a value carries a
request-key side fact (`phpValue.keySources`), with the iteration binding as its transfer. An
array built with literal keys never does, even when its values are request text.

The side facts (`keySources`, `keyGuards`, the `toArray` bag source and the exposure
`diagnostic` marker) ride through joins and transfers but are never content. No other claim reads
them, so no existing record changes. A literal `array_intersect_key` list rides the bag as a
`key_allow_list`; dominating `in_array` and `property_exists` tests are read from the write's
enclosing conditions.

## Family registration pattern

Each family is wired like `deserialization` but owns every component it selects:
`pack.<family>`, `claim.<family>`, `evidence.<family>`, `flow.<family>`,
`language.<family>.php`, its contract (`api.php-diagnostic-output-v1` for exposure; mass
assignment has none), and its own copies of the PHP and Symfony input components
(`source.php-input-<family>-v1`, `source.symfony-input-<family>-v1`). No shared component gains a
compatibility entry, so no existing selected digest or request changes.

The policy order is lane contract §2.7: protocol, claim facts, required evidence roles,
inconsistent answers, blocking gaps, Protected, Confirmed, otherwise Review. Facts reach the
request as `exposure` and `mass_assignment` objects whose evidence is cited by `eN` reference.
Finding types are listed in a report only when a record of the kind exists.

## Information exposure

Record shape (`analysis.ExposureFacts`): `operation`, `subject` (`configuration`,
`environment`, `runtime_state`, `stack`), `flag`, `entry_served`, `guards`. One candidate per
operation per entry. Required roles: `diagnostic_operation`, `entry`, `control_flow`.

Direct-output operations are recorded at the call. A value-returning operation marks its value,
and the candidate is recorded at the output sink that emits it (`echo`, `print`, a `Response`
body, a Twig interpolation). A Twig record is anchored at the interpolation in the template, and its
guards are the conditions that dominate the `render` call. A marked value never output records
nothing.

Guards are the guard engine's dominating conditions. The shared engine does not treat `throw` as
terminating; changing that would change existing requests, so the exposure record also cites an
earlier `if` whose only branch ends in `throw`. Making the shared engine model `throw` is a
recorded follow-up.

Bounds: debug-mode and profiler configuration (branch 4), exception output, Twig `dump()`.

## Mass assignment

Record shape (`analysis.MassAssignmentFacts`): `shape`, `target_class`, `target_stored`,
`key_guards`, `security_fields`, `mapped_fields`. One candidate per write per entry. Required
roles: `input_source`, `key_origin`, `property_write`, `target_class`, `control_flow`.

The existing wildcard storage writer (`storage_write_wildcard`) stays a writer of every mapped
field exactly as before; the claim cites the same position as its sink and changes no stored link.
Form, serializer and request-payload mapping onto an entity are recorded with a named gap: their
field sets depend on form types, serializer groups and validation that this version does not read.

Bounds: one census step, no Doctrine XML or YAML mapping, no `extract`/`parse_str`, no named-setter
authorization (branch 2).

## Authorization

Record shape (`analysis.AuthorizationFacts`): facets, subject class and provenance, the
operation, census fields, guards, `method_safe`, peer access and, for an address guard,
the ids of SSRF uses in the same report. One candidate per operation per entry. Protocol
`authorization-components-v1`. Required roles: `subject_selection`, `protected_operation`,
`entry_access`, `control_flow`. Contract `php-authorization-operation-v1`.

Entry access is context. It is computed from `access_control`, firewalls and
`IsGranted` before the action is walked, and it never protects another family's claim.
The design is [entry access and authorization](entry-access-and-authorization.md).

Bounds: one private helper, no voters or expressions beyond a gap, no trusted-proxy
configuration, no command-execution claim. A role name is a string.

## Account security (branch 3)

Filled by [branch 3](../specifications/symfony-more-analyzers-3.md): account enumeration,
recovery-secret delivery and weak password hashing.

## Configuration (branch 4)

Filled by [branch 4](../specifications/symfony-more-analyzers-4.md): framework and deployment
configuration checks and SSRF through a shell URL client.
