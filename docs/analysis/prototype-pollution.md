# Prototype pollution

[Analysis guidelines](README.md) · [Coverage and known gaps](../detection-capabilities/prototype-pollution.md) · [Detection capabilities](../detection-capabilities.md)

The `pollution` family evaluates JavaScript and TypeScript application writes that can reach
`Object.prototype`. Its evidence record is `prototype_write_candidate` and its finding type is
`prototype-pollution` (CWE-1321). The finding establishes a write capability. The consequence
depends on how the application uses inherited properties.

## Writes and key operands

| Operation | Key-bearing operand |
|---|---|
| Lodash `merge`, `mergeWith`, and `defaultsDeep` | Every source object after the destination. A verified `mergeWith` customizer is separate |
| Lodash `set`, `setWith`, and `zipObjectDeep` | The path argument. Deep zip takes paths in the first argument |
| Repository recursive merge | A parameter whose keys are enumerated, with a matching target write and recursion through the keys |
| Repository path walk | A parameter that supplies the parts of a path, a walk that follows those parts, and a final indexed assignment |
| Repository unflatten | The keys of a parameter, where each key is split and walked as a path |
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

## Where the write can be

A record always starts at an application entry, such as an Express route, and follows request
data to the write. What is found depends on where the vulnerable function lives:

| Location of the vulnerable write | Result |
|---|---|
| The application's own source: the handler or a function it calls | Detected by the source-visible shapes below |
| A library's source kept in the scanned repository, for example under `lib/`, and called from a route | Detected by the same shapes. The call must resolve through a relative import: CommonJS `module.exports = fn`, `module.exports = { fn }` or `exports.fn`, or an ESM named, namespace or default import. The record's sink is the call in the application and its write evidence is in the library file |
| Code under `vendor/` or `node_modules/` | Not read |
| An installed dependency called from a route | Lodash merge and set-by-path calls are judged by the resolved version. Other packages have no record. A dependency audit covers published advisories for installed packages |
| A library repository scanned on its own, with no application entry | No record. Scanning a package's exported functions is planned work |

A finding in application source is a statement about that source. It is not a CVE lookup: the
scanner reports no advisory for the application's dependencies except through the Lodash
version contracts.

## Source-visible shapes

Each shape is read inside one function body, with one forwarding helper for a recursion.

| Part of the shape | Accepted forms |
|---|---|
| Key enumeration | `for…in`, or `Object.keys`, `Object.entries`, `Object.getOwnPropertyNames`, or `Reflect.ownKeys` on the parameter, iterated by `for…of`, `forEach`, `map`, or a `reduce` whose callback always returns its accumulator. The built-in must be the global one |
| Recursion | A call on `target[key]` and the source value, or on one local declared from each. A slot local may be assigned the same slot again, as in `t = target[key] = {}` |
| Source value | `source[key]`, the value of an `Object.entries` pair, or `Object.getOwnPropertyDescriptor(source, key).value` |
| Path parts | The parameter itself as an array, `split` by a non-empty string or a regular-expression literal, `match` with a global regular-expression literal, or matches pushed by one `exec` loop |
| Walk | An index or `for…of` loop, a `while` loop that takes parts with `shift()` or `pop()` while parts remain, a `forEach` over the parts whose callback steps the cursor, `parts.reduce((cursor, part) => cursor[part], target)`, or a function that calls itself on `obj[key]` with the next index or `path.slice(1)` |
| Final write | An indexed assignment through the walk result, keyed by the last part. In a recursive walk, an assignment to `obj[key]` in the function or in a helper it calls |

The shapes are read the same way in TypeScript: typed callback parameters, a cast around the key
enumerator and a cast or non-null assertion on a path part do not change the match.

A test on another parameter that encloses the recursion, such as `options.deep`, is recorded as
branch evidence. The caller sets that option and it places no restriction on the key. A walk
that only reads or returns the value has no record.

## Controls and outcomes

The scanner lists prototype-related names blocked by literal, enforcing key guards on the
relevant lookup paths. A guard covers an operation only where the scanner can show that it
applies across its modeled write sites. Own-property checks must apply at every recursive lookup. A fresh
null-prototype object can protect one lookup. Deep traversal also needs evidence about nested
containers. A test that rejects the whole path, `path.includes('__proto__')` or the `indexOf`
equivalent, blocks that name in every part while the path stays unchanged up to the walk.

A key test may be written as a one-line helper of the same module, such as
`function isValidKey(key) { return key !== '__proto__' && … }` or a wrapper around
`hasOwnProperty`. The helper's single returned expression is read with the call's arguments. A
helper that calls another function is not read. `object.hasOwnProperty(key)` is an own-property
test on the target and says nothing about the lookup on any other object. In a recursive walk, a
call that takes the key before the recursion, such as an assertion, is an unread guard.

The parts of an array the caller passes need not be strings. A nested array such as
`['__proto__']` is not equal to `'__proto__'` and still names that key in a lookup. For such a
path a literal comparison counts only after a `typeof part !== 'string'` test that exits, and a
test on the whole array is not read. Own-property checks apply unchanged. Keys from `for…in`,
the key enumerators, `split` and `match` are strings.

A direct nested write is read when its receiver slot is unchanged, or when an earlier statement
only fills the slot while it is absent: `if (!store[k]) store[k] = {}`, the `=== undefined`,
`typeof` and `!(k in store)` forms, `store[k] = store[k] || {}`, `||=` and `??=`. An inherited
slot such as `__proto__` already has a value and stays in place. A slot that is always replaced
by a fresh object has no record, and neither does one replaced after an own-property test, which
replaces an inherited slot too.

A test on the request path whose outcome depends on a call that takes the key operand is a guard
the scanner has not read: `if (!known.has(key)) return`, `const row = find(key)` followed by
an exit when `row` is missing, or the same test written as `known.has(key) && write(key)` or a
conditional expression. A `Map` lookup rejects a prototype key and another function may
accept it. The record carries the test as key-guard evidence and stays in Review with
`key_guard_coverage_unknown`. A test on the operand itself and a plain `store[key]` existence
test are not such guards, because an inherited key passes both.

A consistent assessment can Confirm a complete raw request path to a verified write. Protected
requires source-backed controls covering all recorded paths and consistent answers about coverage
and guards. An incomplete guard keeps excluded and remaining key names visible. Unverified
versions, controls, or input shape stay in Review.

## Limits

Recognition is bounded to the shapes above. A form outside them has no record, and no record is
not a statement that the code is safe.
[Coverage and known gaps](../detection-capabilities/prototype-pollution.md) lists every form by outcome: recorded
and decidable, recorded and left in Review, and not recorded. Each gap has an identifier and an
example.

A finding states that `Object.prototype` can be written. It makes no statement about what reads
the polluted property.
[Implementation contract](../../.zazz/specifications/prototype-pollution.md),
[write shapes contract](../../.zazz/specifications/pollution-write-shapes.md).
