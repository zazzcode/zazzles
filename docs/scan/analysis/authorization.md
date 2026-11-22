# Authorization

Zazzles emits an `authorization_candidate` for one protected operation: a stored write,
a file write or delete, or a response that carries a census field. The facts are the
subject, the operation, the entry's access and the guards that dominate the operation.
A judged scan uses protocol `authorization-components-v3`.

## Questions

| Question | Answers |
| --- | --- |
| `subject_control` | `request_selected`, `not_selected`, `unknown` |
| `guard_adequacy` | `none`, `adequate`, `inadequate`, `unknown` |
| `access_adequacy` | `adequate`, `inadequate`, `unknown` |

`guard_adequacy` `none` contradicts a recorded guard. `adequate` contradicts no guard.
`access_adequacy` `adequate` contradicts authentication `none`. `not_selected`
contradicts a subject selected by a route placeholder.

The claim is protected when a guard is adequate, or when there is no guard and the
entry's access is adequate. It is confirmed when the request selects the record, the
guard is `none` or `inadequate`, and access is `inadequate`. A data-exposure of an
enumerated subject does not also need `subject_control` `request_selected`. Any other
answer is `needs_evidence`.

Blocking gaps are `access_rule_unresolved`, `access_rule_condition_unmodeled`,
`voter_unmodeled`, `access_expression_unmodeled`, `authenticator_unmodeled`,
`guard_unclassified`, `symfony_config_unread`, and `security_fields_unresolved` when
the only facet depends on the census. `address_trust_configuration_unread` is recorded
and is not blocking.

## Facts

`authorization.facets` is `object_level`, `function_level`, `data_exposure`, or empty
for a plain-PHP address guard. `subject_provenance` is `request_selected`,
`enumerated`, `session_user` or `created`. `operation.operation` is `create`, `update`,
`delete`, `file_write`, `file_delete` or `read`. `method_safe` is `yes` or `no`.
`security_fields` repeats the census roles of the fields the operation writes or
returns. `peer_access` lists other writers of the same key. `server_side_requests`
lists SSRF use ids when a guard is an `address_check`.

Required evidence roles are `subject_selection`, `protected_operation`, `entry_access`
and `control_flow`.

## Bounds

Role names are strings. The scanner does not treat one role as stronger than another.
One private helper is followed. Command execution is not an authorization operation.
Trusted-proxy configuration is unread. The SSRF request is not modified when an
authorization record points at it.
