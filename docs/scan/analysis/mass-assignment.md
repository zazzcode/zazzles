# Mass assignment

Zazzles emits a `mass_assignment_candidate` when a write selects its property by a name the
request chose, on an object of a known class. Three facts are established: the keys come from the
request, the write selects the property by that key, and the target's class and storage. A
judged scan uses them with the target's security-field roles to classify CWE-915.

## Key origin

Key origin is tracked separately from value origin. A whole-bag reader yields a value whose keys
are request-controlled: `$request->request->all()`, `->query->all()`, `->getPayload()->all()`,
`->toArray()` and a whole `$_GET`, `$_POST` or `$_REQUEST`. The key variable of a `foreach` over
such a value carries the request-key origin, cited by its `iteration_binding` evidence. The value
variable does not. A loop over an array literal, or over the return of a method that builds one,
carries none.

| Guard | Fact |
| --- | --- |
| `array_intersect_key($data, array_flip([...]))` or a literal-key array | `key_allow_list` with the literal list |
| A dominating `in_array($k, [...])` with a literal list, as an enclosing `if` or an earlier `if (…) continue;` | `key_allow_list` |
| A dominating `property_exists(…)` | `key_existence_check` |

## Shapes

`mass_assignment.shape` is one of `dynamic_property_write`, `dynamic_setter_call`,
`property_accessor`, `reflection_property_write`, `form_submission`, `serializer_population` or
`request_payload_mapping`. The receiver type of `setValue`, `deserialize` and `denormalize` comes
from a declared parameter, promoted property or typed property. A form is matched to its data
through `$form = $this->createForm(Type::class, $entity)` in the same action.

## Security-field census

The census is computed once per Symfony project. Each stored field carries the roles that source
evidence establishes, with one evidence item per role at the establishing source.

| Role | Contract |
| --- | --- |
| `credential` | `PasswordAuthenticatedUserInterface::getPassword()` returns the field, or the field is written from a password-hash call (directly or through a one-property setter) |
| `login_identifier` | `security.providers.<name>.entity.property`, or the field `getUserIdentifier()` / `getUsername()` returns |
| `role_source` | Every mapped field `getRoles()` reads, plus every field a lifecycle callback reads when it writes a role source |
| `name_hint` | The lower-cased name without separators is on the closed hint list. Never sets another role |

A `getRoles()` body that calls a method or service records `security_fields_unresolved` at the
method. So does a project with no `UserInterface` class. A plain-PHP target has no framework
contract: it carries the gap and name hints only, keyed `php-object:<class>.<property>`.

## Questions and outcomes

Protocol `mass-assignment-components-v1` asks three questions.

| Question | Answers |
| --- | --- |
| `key_control` | `request_chosen`, `fixed`, `unknown` |
| `key_restriction` | `none`, `adequate`, `inadequate`, `unknown` |
| `field_impact` | `privileged_field`, `no_sensitive_field`, `unknown` |

| Outcome | Condition |
| --- | --- |
| Review (inconsistent) | `adequate` with no `key_allow_list`, `privileged_field` with no security fields, or `fixed` for a whole-bag key origin |
| Review (blocked) | A form, serializer or payload gap; `security_fields_unresolved` when the target has no security field |
| Protected | `adequate` with a `key_allow_list` guard |
| Confirmed | `request_chosen`, restriction `none` or `inadequate`, and `privileged_field` |
| Review (poor practice) | `no_sensitive_field` |

Required evidence roles are `input_source`, `key_origin`, `property_write`, `target_class` and
`control_flow`. A stored target also cites the storage model's `storage_write_wildcard` at the
same position; the stored links of other claims are unchanged.

## Bounds

The census follows one step: a field read through another method or service is not followed. Form
types, serializer groups, validation, Doctrine XML or YAML mappings and named-setter
authorization are not read.

See [coverage and remediation](../detection-capabilities/mass-assignment.md).

## JavaScript and TypeScript

The ORM writes each key of a whole request bag to the attribute of the same name, so the shape is `dynamic_property_write`. A `fields` option with a literal array is the fix. A library option that only hides attributes from reads (`excludeAttributes`) is not.

The JavaScript census has three roles. `credential` marks an attribute a set accessor fills from a
fast digest, and `name_hint` an attribute whose name is on the hint list. `owner_reference` marks the
foreign key of a declared association to the account model, which is the model with a `credential`
attribute. That role covers a Sequelize `belongsTo`, with a literal `foreignKey` or the documented
default (camel-cased `as` or model name plus `Id`), and a Mongoose `ref` path. It is one
association step, taken from the association, never from a name. A record with an
`owner_reference` field uses question version `mass-assignment-components-v2`, whose
`field_impact` says that choosing the field chooses whose record is written. Every other record
keeps v1.

Before the census, an attribute assigned as `req.body.<name> = …` is left out of the written
attributes. That covers a middleware registered for the entry, an earlier matching stage, or a
top-level statement of the handler before the write. The assignment is cited as `chain_overwrite`
evidence, and the scanner does not judge where its value comes from.
[Specification 22](../../../.zazz/specifications/scan/detection-generalization/22-owner-reference-fields.md)
