# Prototype pollution: coverage and known gaps

[Detection capabilities](../detection-capabilities.md) · [Prototype pollution rules](../analysis/prototype-pollution.md) · [Analysis guidelines](../analysis/README.md)

This page lists what the `pollution` family finds, what it leaves in Review, and what it does not
record at all. The [rules guide](../analysis/prototype-pollution.md) explains how each form is read. Every
row was checked with the scanner on a small application, a published library or a sample.

A scan result for a write to `Object.prototype` (CWE-1321) is one of three things:

- **Recorded and decidable.** The scanner establishes the write, the key operand and the guard.
  A judged scan can Confirm it or mark it Protected.
- **Recorded, left in Review.** The scanner sees the write and cannot settle one fact about it.
  The record names the reason.
- **Not recorded.** The scanner has no record. That is not a statement that the code is safe.

Each gap has an identifier, so it can be taken up as a later capability.

## Recorded and decidable

| Form | Example | Notes |
|---|---|---|
| Lodash `merge`, `mergeWith`, `defaultsDeep`, `set`, `setWith`, `zipObjectDeep` called with request data | `_.merge({}, req.body)` | Judged by the version in the lockfile or an exact manifest pin. A patched version has no record |
| Recursive merge | `for (key in source) { … merge(target[key], source[key]) … }` | Keys from `for…in`, `Object.keys`, `Object.entries`, `Object.getOwnPropertyNames` or `Reflect.ownKeys`, iterated by `for…of`, `forEach`, `map` or `reduce`. The recursion may go through one local |
| Path walk over a split string | `parts = path.split('.')`, then `cursor = cursor[part]` | Split by a string or a regular expression, `match` with a global pattern, or matches collected by an `exec` loop |
| Path walk over an array path | `setIn(obj, ['a', 'b'], v)` | Also when the function splits a string path in place first |
| Walk forms | Index loop, `for…of`, consuming `while`, `forEach`, `reduce`, or a function that calls itself on the next object | The final assignment must go through the walk result |
| Walk into module, local, or fixed-property state | `let cursor = store`, `let cursor = holder.state` | The declaration is included in the record. Reassignment of the start or a property in its chain prevents a match |
| Walk inside the route handler | Split `req.body.path` and walk its parts in the handler | The final assignment is the sink. A constant path produces no record |
| Unflatten | `{ "a.b": 1 }` expanded key by key | Dotted or bracketed keys. The walk may start from a local object |
| Nested computed assignment | `store[a][b] = v` | Also after the slot is created only when absent: `if (!store[a]) store[a] = {}` |
| Library source kept in the repository | `require('./lib/merge')` called from a route | CommonJS exports and ESM named, namespace or default imports, imported from the defining file. The write evidence is in the library file |
| TypeScript | Typed callbacks, `as` casts, non-null assertions | Read like the JavaScript forms |

Guards the scanner reads and credits:

| Guard | Example | Result |
|---|---|---|
| Comparison of the key with all three names | `if (key === '__proto__' \|\| key === 'constructor' \|\| key === 'prototype') continue` | Guarded |
| The same for only some names | `if (key === '__proto__') continue` | Raw, with the open names listed. It can never be Protected |
| Literal Set or array deny-list | `if (BAD.has(key)) continue`, `if (LIST.includes(key)) continue` | Guarded when all three names are excluded and the collection cannot change. A partial list leaves the other names open |
| Closed Map allow-list | `if (!known.has(key)) return` before `store[key][field] = value` | Guarded when the unchanged Map has literal keys excluding all three names and the test covers the same lookup key |
| Own-property test on the target | `if (!Object.hasOwn(target, key)) continue` | Guarded |
| Whole-path deny-list | `if (path.includes('__proto__') …) return` | Guarded, while the path is unchanged up to the walk |
| One-line helper that tests the key | `function isValidKey(key) { return key !== '__proto__' && … }` | Read like the test written in place |
| Type test before a comparison on array parts | `if (typeof part !== 'string') return` | Lets the comparison count |
| Fresh null-prototype target for one lookup | `Object.create(null)[a][b] = v` | Guarded |

## Recorded, left in Review

| ID | Form | Why it is Review | To close it |
|---|---|---|---|
| `PP-R01` | A key gate relies on a Map populated at runtime or on a call whose effect is unresolved | `key_guard_coverage_unknown`. A verified Map records membership evidence, with its exact key set still unknown | Track the possible Map keys and resolve other key-taking guards |
| `PP-R02` | A key test in a helper with more than one statement, imported from another module, or calling another function; an assertion on the key before a recursive walk | `key_guard_coverage_unknown`. Only a one-line helper in the same module is read | Read assertions, imported helpers and longer helpers |
| `PP-R03` | An array part compared with no type test: `if (part === '__proto__') return` | `key_guard_coverage_unknown`. `['__proto__']` passes the comparison. Exploitable, not Confirmed | Claim the nested-array bypass |
| `PP-R04` | Array parts type-checked another way: `path.every(p => typeof p === 'string')` | `key_guard_coverage_unknown`. Only an exit on `typeof part !== 'string'` is credited. Safe, not Protected | Credit `every` and a positive `typeof` test |
| `PP-R05` | A whole-path guard other than `includes` or `indexOf`: a regular-expression test, `parts.some(part => LIST.includes(part))`, `path.toLowerCase()` | Recorded raw without the guard. Review once the assessment relies on it | Read these as key guards |
| `PP-R07` | Keys from untyped input: `store[req.query.a][req.query.b] = v` | `key_control_unknown` | Model how the query parser treats keys |
| `PP-R08` | A Lodash version range with no lockfile | `version_unresolved` | Needs a lockfile or an exact pin |
| `PP-R09` | A deep write into an `Object.create(null)` root | `null_prototype_root`. Only the first lookup is covered | Track the nested containers |
| `PP-R10` | The key is checked in route middleware: `app.post('/w', checkKey, handler)` | Not read as a guard. Raw unless another blocker applies | Read key tests in middleware |

## Not recorded

Each of these can hide a real write.

| ID | Form | Example | To close it |
|---|---|---|---|
| `PP-N03` | A path normalised other than by its own split | `String(path).split('.')`, `toPath(path)` | Read string conversions and one-line normalisers |
| `PP-N04` | A path decoded at use, or into a new variable, after a check | `decodeURIComponent(path).split('.')` | Follow the path through transforms |
| `PP-N05` | A merge whose slot local is replaced on a branch | `if (!slot) slot = {}; merge(slot, v)` | Decide which branches an object skips |
| `PP-N06` | A slot filled in an unread form before a nested write | A ternary default; a branch with a second statement; `if (!s \|\| reset)`; `typeof s !== 'object'`; an `if` with an `else` | The same branch model |
| `PP-N07` | A merge through more than one helper, or a loop walk split across functions | | Follow more than one helper |
| `PP-N08` | A write through `Object.defineProperty` | `Object.defineProperty(target, key, d)` | Read it as an assignment |
| `PP-N09` | Step and write in one chained assignment | `t = t[k] = …` | Read the chained form |
| `PP-N10` | Any other dynamic-key write | | Emit a Review record for unmatched writes |
| `PP-N11` | An array part converted before use | `const part = String(path[i])` | Read a converted part as a string part |
| `PP-N13` | A walk in a callback form other than a plain `forEach` step | A `forEach` whose callback also makes the final write (`if (i === last) cursor[part] = v; else cursor = cursor[part]`); `map` or `every` used for the step; `for…of` over `parts.entries()` | Read the final write inside the callback, and the other iteration methods |
| `PP-N14` | A recursive walk in a form other than `path[i]` or `path[0]` with `slice(1)` | `const [head, ...rest] = path`; `path.shift()`; a string path re-split at each level; two functions that call each other | Read destructured and consumed paths, and recursion across two functions |
| `PP-N12` | The vulnerable function is reached through a re-export or a dynamic import | `export { merge } from './merge.js'`, `export * from …`, `export { merge as default }`, `await import('./merge.js')` | Follow re-exports and literal dynamic imports. This is shared by every vulnerability class |
| `PP-N15` | A walk starts from an instance field in a class method | `settings.set(path, value)` uses `this.state` | Resolve the call to the class method and verify the instance field |
| `PP-N16` | A walk starts from a computed property or a property that may be replaced | `let cursor = holder[name]` | Resolve the property name and the value held there on the write path |
| `PP-N17` | An inline walk follows a request field from a container that was reassigned | The handler assigns `req.body` before splitting `req.body.path` | Track the assigned container and the operand captured by the split |

Libraries and dependencies:

| ID | Form | What a scan shows | To close it |
|---|---|---|---|
| `PP-L01` | A package other than Lodash called as an installed dependency: `dset`, `merge-deep`, `set-value` | No record. `node_modules/` is not read | Version contracts for more packages, or a dependency audit |
| `PP-L02` | A published library's source in the repository, called through its public API | Usually no record: 1 of 11 advisory packages is detected. Wrappers that read `arguments`, nested functions and factory exports are not followed | Library mode |
| `PP-L03` | Library source under `vendor/` | No record. The file walk skips it | An option to scan it |
| `PP-L04` | A library repository with no application route | No record. Exported functions are not entries | Library mode |

One assumption can keep a record that should be dropped:

| ID | Form | What a scan shows | To close it |
|---|---|---|---|
| `PP-A01` | `Object` or `Reflect` replaced through `globalThis`, or a built-in method patched in another module | The record is kept as if the built-in were genuine | Track those writes across modules |

## Outside this claim

- **Effects.** A finding states that `Object.prototype` can be written. It makes no statement
  about what reads the polluted property, and none about code execution.
- **Writes that cannot reach a shared prototype.** `Object.assign`, object spread, `JSON.parse`
  alone, a one-level `obj[key] = value`, and a slot that is always replaced by a fresh object
  before the nested write.
- **Deletion APIs** such as Lodash `unset` and `omit`.
- **Browser entries**, and Python and PHP, which have no prototype chain.

## How this was checked

- Fixtures in the scanner's tests hold a vulnerable, guarded and bypass-sibling function plus
  controls for each form in the first section.
- The [vuln-nextjs prototype pollution fixture report](../../samples/vuln-nextjs/README.md#prototype-pollution-fixture-scan)
  judges 19 records against labels confirmed by running each fixture: 14 of 15 exploitable
  sources Confirmed, no false positive and no false Protected.
- [Node.js Goof](../../samples/nodejs-goof/README.md) and the
  [Vulnerable TypeScript app](../../samples/vulnerable-typescript-app/README.md) each have their
  Lodash merge Confirmed.
- Twenty-five versions of eleven published advisory packages were scanned as source. The
  readings behind `PP-L01`, `PP-L02`, `PP-N08` and `PP-N09` come from that check.
