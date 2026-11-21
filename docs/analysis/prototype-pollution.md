# Prototype pollution

[Analysis guidelines](README.md) · [Detection capabilities](../detection-capabilities.md)

The `pollution` family evaluates JavaScript and TypeScript application writes that can reach
`Object.prototype`. Its evidence record is `prototype_write_candidate` and its finding type is
`prototype-pollution` (CWE-1321). The finding establishes a write capability. The consequence
depends on how the application uses inherited properties.

## Writes and key operands

| Operation | Key-bearing operand |
|---|---|
| Lodash `merge`, `mergeWith`, and `defaultsDeep` | Every source object after the destination. A verified `mergeWith` customizer is separate |
| Lodash `set`, `setWith`, and `zipObjectDeep` | The path argument. Deep zip takes paths in the first argument |
| Repository recursive merge | A parameter enumerated with `for…in`, `Object.keys`, or `Object.entries`, with a matching target write and recursion through the keys |
| Repository path walk | A parameter split into parts, a loop that follows those parts, and a final indexed assignment |
| Direct nested computed assignment | The request-derived key in the lookup before the final assignment |

Source-visible detection follows resolved imports into scanned modules and matches the supported
write shapes by syntax and data flow. The built-in npm API contracts cover Lodash. The scanner
uses the source package's lockfile or an exact manifest pin for those contracts. Resolved patched operations are excluded.
A version range or an unresolved distribution stays in Review. The detector reads repository
source and package files.

JSON request data and values from a verified `JSON.parse` can carry keys. Scalar URL parameters,
headers, and cookies are excluded as raw key-bearing inputs. Indeterminate operand shapes remain
in Review. A request value supplied only as the assigned value cannot choose the lookup.
[Supported inputs](node-inputs.md).

## Controls and outcomes

The scanner lists prototype-related names blocked by literal, enforcing key guards on the
relevant lookup paths. A guard covers an operation only where the scanner can show that it
applies across its modeled write sites. Own-property checks must apply at every recursive lookup. A fresh
null-prototype object can protect one lookup. Deep traversal also needs evidence about nested
containers.

A consistent assessment can Confirm a complete raw request path to a verified write. Protected
requires source-backed controls covering all recorded paths and consistent answers about coverage
and guards. An incomplete guard keeps excluded and remaining key names visible. Unverified
versions, controls, or input shape stay in Review.

Shallow copies, JSON parsing without a write, single-level writes, and deletion APIs sit outside
this assignment claim. The direct-write detector requires an unchanged receiver lookup. Earlier
conditional reassignment of that slot requires heap-flow evidence. Standalone npm library exports,
browser entries, inherited-property access and gadget chains have separate scope.
[Implementation contract](../../.zazz/specifications/prototype-pollution.md).
