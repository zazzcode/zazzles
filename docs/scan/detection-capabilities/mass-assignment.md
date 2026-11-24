# Mass assignment

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/mass-assignment.md)

The `mass-assignment` family records a write whose property names the request chooses on an
object. A judged scan can report **Mass assignment**
([CWE-915](https://cwe.mitre.org/data/definitions/915.html)) when that object has a field the
request should not choose, such as a role source, a credential or the login identifier. Use
`--only-family mass-assignment` with `--analyze --judge` to assess this family alone.

| Shape | Example | Outcome |
| --- | --- | --- |
| Dynamic property write | `foreach ($data as $k => $v) { $obj->$k = $v; }` or `$obj->{$k}` | Judged |
| Dynamic setter call | `$obj->{'set' . ucfirst($k)}($v)`, `$obj->$setter($v)`, `call_user_func([$obj, 'set' . …], $v)` | Judged |
| Property accessor | `PropertyAccessorInterface::setValue($obj, $k, $v)` | Judged |
| Reflection | `$rp = new ReflectionProperty($obj, $k); $rp->setValue($obj, $v)` and `$rc = new ReflectionClass($obj); $rc->getProperty($k)`, recorded at the `setValue` or `getProperty` call. Constructing a `ReflectionProperty` alone records nothing | Judged |
| Plain PHP | The same loops over `$_POST`, `$_GET` or `$_REQUEST` | Judged |
| Symfony Form | `$form->handleRequest($request)` or `submit()` for a form created with an entity | Review |
| Serializer | `SerializerInterface::deserialize` or `DenormalizerInterface::denormalize` into an entity class | Review |
| Request payload | `#[MapRequestPayload]` on an action argument whose type is an entity | Review |

The names come from the request when the loop iterates a whole request bag:
`$request->request->all()`, `->query->all()`, `->getPayload()->all()`, `->toArray()`, or a
whole superglobal. An array built with literal keys does not choose names.

## Recorded and decidable

Each record names the shape, the target class, whether it is a stored Doctrine entity, its
mapped fields, and the **security-field roles** of those fields:

| Role | Established by |
| --- | --- |
| `credential` | The field `getPassword()` returns on a class implementing `PasswordAuthenticatedUserInterface`, or a field written from `password_hash`, `PasswordHasherInterface::hash` or `UserPasswordHasherInterface::hashPassword` |
| `login_identifier` | The `property` of an entity user provider in `security.yaml`, or the field `getUserIdentifier()` (or `getUsername()`) returns |
| `role_source` | A field `getRoles()` reads, and any field a `#[ORM\PrePersist]` or `#[ORM\PreUpdate]` callback reads to write it, one step deep |
| `name_hint` | A field whose name is on a fixed hint list (for example `isAdmin`, `roles`, `password`, `ownerId`). A hint only |

A literal key allow-list (`array_intersect_key($data, array_flip([...]))`, or a dominating
`in_array($k, [...])`) is recorded as `key_allow_list`. A `property_exists` test is recorded as
`key_existence_check`; it restricts nothing. Either way the record stays and the guard's adequacy
is judged.

A write on an object with no field that needs protection stays in Review: it is poor practice,
not a confirmed privilege defect.

## Recorded in Review

| Gap | Meaning |
| --- | --- |
| `mass_assignment_form_unmodeled` | Form type fields and validation decide which properties a form writes. They are not read in this version |
| `mass_assignment_serializer_unmodeled` | Serializer groups and `object_to_populate` decide the written properties. They are not read |
| `mass_assignment_payload_unmodeled` | Payload mapping depends on the entity's serializer metadata, which is not read |
| `security_fields_unresolved` | No class implements the Symfony `UserInterface`, a `getRoles()` body calls another method or service, or the target is plain PHP with no framework contract. A candidate with no field roles stays in Review |

## Not recorded

- A named setter fed by a named request field, whatever the field is. Whether that write is
  authorized for the caller is a separate claim.
- `extract($_POST)` and `parse_str` into the local scope.
- Doctrine XML or YAML mappings, API Platform resources and Laravel `$fillable`.

## Remediation

Write each permitted field through a named setter from a named request field. If a generic copy
is required, intersect the request keys with a literal allow-list that excludes privilege,
credential and identity fields.

## JavaScript and TypeScript (Express)

A whole request bag (`req.body`, `req.query`, a constant alias, or a spread of one that does not
override every model attribute) that reaches a model write records a candidate with shape
`dynamic_property_write`:

- Sequelize `Model.create`, `build`, `bulkCreate`, `update`, and an instance `update` or `set`;
- Mongoose `new Model(x)`, `Model.create`, `findByIdAndUpdate` and `updateOne`;
- `Object.assign(instance, x)` on a model instance;
- a [finale-rest](https://github.com/tommybananas/finale#readme) or epilogue `resource({ model, endpoints })`:
  each generated create and update endpoint, including a resource in a loop over a literal
  array. `excludeAttributes` hides attributes from reads and is not a write limit.

A `fields` option with a literal array, or a bag built as an object literal of named properties,
records nothing. Attributes whose names are on the hint list are carried as `name_hint`; an
attribute that a set accessor fills from a fast digest is a `credential`. A resource whose model
or endpoints cannot be resolved records gap `generated_resource_unresolved`.
