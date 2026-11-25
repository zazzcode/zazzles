# Authorization

Zazzles emits an `authorization_candidate` for one protected operation: a stored write,
a file write or delete, or a response that carries a census field. The facts are the
subject, the operation, the entry's access and the guards that dominate the operation.
A judged scan uses protocol `authorization-components-v9`.

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
One private helper of the same class is followed. Outside that case, unclassified
early-exit conditions are not recorded as authorization guards.
Command execution is not an authorization operation.
Plain PHP has two shapes. An address check that is the only guard on a constant SQL write or
a file write or delete records a candidate with no facet. A SQL `UPDATE` or `DELETE` whose
`WHERE` clause compares a column with a request value records an `object_level` candidate
with subject `table:<name>`; a `WHERE` part read from `$_SESSION` is recorded as an
`ownership_check` guard of form `query_scope`, and a row selected only by a session value is
not recorded. That shape also records pages that are anonymous by design, such as a recovery
page that stores a token on the row a submitted address selects; the model judges them.
`SELECT`, `INSERT`, bound parameters and comparisons other than `=` are not read.
Trusted-proxy configuration is unread. The SSRF request is not modified when an
authorization record points at it.

## JavaScript and TypeScript

A Node entry has no roles; its access is whether an authentication middleware precedes the handler. A selector key filled from a keyed store or overwritten by a chain middleware scopes the write to the caller and is recorded as `ownership_check` / `query_scope`.

**Reads of an owned record.** A Sequelize `findOne`, `findByPk` or `findAll`, or a Mongoose `findById` or `findOne`, is recorded with the facets `object_level` and `data_exposure` and the operation `read` when a request value selects the record, the entry sends the result in a response, and the model is owned: a Sequelize `belongsTo` association or a Mongoose `ref` path links it to a model that holds a credential attribute. The association and the response call are evidence (`owner_association`, `response_emission`). A selector key read from a member that a listed authentication middleware fills from the verified token (`req.auth`, `req.user`, `req.oidc`) is a guard, not a request key. A model with no such association, a list with no selector, a selector that a constant narrows and a result that is not sent are not recorded.

**What an update writes.** An update record carries `written_values`: `request_dependent` is `yes` when a written value reads the request, `no` when every written value is built from literals and those values are the whole write, and `unknown` otherwise. The amount of a Sequelize `increment` or `decrement` is its `by` option. A `save` writes what the handler put on the instance: its member assignments, plain or computed, and the arguments of any call that can change it (a method of the instance, or a call that receives it); such a call makes the write `unknown` unless one of its arguments reads the request. For a Mongo-style update document `operators` names the operators used (`$set`, `$inc`, `$push`). The fact describes the write; it does not decide who may perform it. PHP records do not carry it.
