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
| Unflatten | `{ "a.b": 1 }` expanded key by key | Dotted or bracketed keys. The walk may start from a local object |
| Nested computed assignment | `store[a][b] = v` | Also after the slot is created only when absent: `if (!store[a]) store[a] = {}` |
| Library source kept in the repository | `require('./lib/merge')` called from a route | CommonJS exports and ESM named, namespace or default imports. The write evidence is in the library file |
| TypeScript | Typed callbacks, `as` casts, non-null assertions | Read like the JavaScript forms |

Guards the scanner reads and credits:

| Guard | Example | Result |
|---|---|---|
| Comparison of the key with all three names | `if (key === '__proto__' \|\| key === 'constructor' \|\| key === 'prototype') continue` | Guarded |
| The same for only some names | `if (key === '__proto__') continue` | Raw, with the open names listed. It can never be Protected |
| Own-property test on the target | `if (!Object.hasOwn(target, key)) continue` | Guarded |
| Whole-path deny-list | `if (path.includes('__proto__') …) return` | Guarded, while the path is unchanged up to the walk |
| One-line helper that tests the key | `function isValidKey(key) { return key !== '__proto__' && … }` | Read like the test written in place |
| Type test before a comparison on array parts | `if (typeof part !== 'string') return` | Lets the comparison count |
| Fresh null-prototype target for one lookup | `Object.create(null)[a][b] = v` | Guarded |

## Recorded, left in Review

| ID | Form | Example | Reason on the record |
|---|---|---|---|
| `PP-R01` | A test that depends on a call taking the key | `if (!known.has(key)) return`, or `const row = find(key); if (row == null) return` | `key_guard_coverage_unknown`. The scanner does not read what the call accepts |
| `PP-R02` | A key test in a helper that calls another function, or an assertion on the key before a recursive walk | `assert.ok(!BAD.includes(key))` | `key_guard_coverage_unknown` |
| `PP-R03` | A comparison on the parts of a caller's array with no type test | `if (part === '__proto__') return; cursor = cursor[part]` | `key_guard_coverage_unknown`. A nested array such as `['__proto__']` passes the comparison. The code is exploitable and is not Confirmed |
| `PP-R04` | Array parts type-checked another way | `path.every(p => typeof p === 'string')`, or `if (typeof part === 'string') { … } else return` | `key_guard_coverage_unknown`. Only an exit on `typeof part !== 'string'` is credited |
| `PP-R05` | A whole-path guard other than `includes` or `indexOf` | A regular-expression test, `parts.some(…)`, a deny array, a test on `path.toLowerCase()` | The record is raw without that control. An assessment that relies on it is a contradiction |
| `PP-R06` | Another call with no definition in the scan receives the same input | `console.log(req.body)` before the write, or an unknown call after it | `input_helper_unresolved`, although neither can stop the write |
| `PP-R07` | Keys from an input whose shape is not typed | `store[req.query.a][req.query.b] = v` | `key_control_unknown` |
| `PP-R08` | A Lodash call with a version range and no lockfile | `"lodash": "^4.17.4"` | `version_unresolved` |
| `PP-R09` | A deep write into a null-prototype root | `merge(Object.create(null), req.body)` | `null_prototype_root`. Only the first lookup is covered |

## Not recorded

Writes in application code that can pollute and have no record:

| ID | Form | Example |
|---|---|---|
| `PP-N01` | A path walk that starts from a module-level object, a local object or a property | `let cursor = store` in `setPath(path, value)` |
| `PP-N02` | A path walk written in the route handler, with no helper function | `req.body.path.split('.')` walked in the handler |
| `PP-N03` | A path normalised by anything but its own split | `String(path).split('.')`, `toPath(path)`, `Array.isArray(path) ? path : path.split('.')` |
| `PP-N04` | A path decoded at the point of use or into a new variable, after a check on the undecoded path | `decodeURIComponent(path).split('.')` |
| `PP-N05` | A merge whose slot local is replaced on a branch | `let slot = target[key]; if (!slot) slot = {}; merge(slot, value)` |
| `PP-N06` | A nested write after the slot is filled or replaced in a form the scanner does not read | `store[k] = store[k] ? store[k] : {}`; `if (!store[k]) { store[k] = {}; count++; }`; `if (!store[k] \|\| reset) store[k] = {}`; `if (typeof store[k] !== 'object') store[k] = {}`; an `if (!store[k])` with an `else`; `if (reset) store[k] = {}`. An inherited slot survives each of the first five |
| `PP-N07` | A merge reached through more than one forwarding helper, or a loop walk split across functions | |
| `PP-N08` | A write through `Object.defineProperty` | `Object.defineProperty(target, key, descriptor)` |
| `PP-N09` | A walk whose step and write are one chained assignment | `t = t[k] = (i === l) ? val : …` |
| `PP-N10` | A dynamic-key write that matches none of the forms above | |
| `PP-N11` | An array-path walk whose part is converted before use | `const part = String(path[i])` or `'' + path[i]`, then `cursor = cursor[part]`. With a deny-list this is safe. Without one it is exploitable, and neither has a record |

Libraries and dependencies:

| ID | Form | What a scan shows |
|---|---|---|
| `PP-L01` | A merge or set-by-path package other than Lodash called as an installed dependency (`dset`, `merge-deep`, `set-value`) | No record. `node_modules/` is not read and only Lodash has version contracts. A dependency audit reports published advisories |
| `PP-L02` | A published library's source copied into the repository and called through its public API | Usually no record. Of eleven advisory packages checked, one (`set-in`) is detected this way. Wrapper functions that read `arguments`, functions nested in the export and factory exports stand between the route and the write |
| `PP-L03` | Library source under `vendor/` | No record. The file walk skips that directory |
| `PP-L04` | A library repository scanned on its own, with no application route | No record. Exported functions are not entries yet |

One assumption can keep a record that should be dropped:

| ID | Form | What a scan shows |
|---|---|---|
| `PP-A01` | `Object` or `Reflect` replaced through `globalThis`, or a built-in method patched in another module | The record is kept as if the built-in were genuine. A same-named variable, parameter, function or class in the module is noticed |

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
- The [vuln-nextjs prototype pollution sample](../samples/vuln-nextjs-prototype-pollution/README.md)
  judges 19 records against labels confirmed by running each fixture: 14 of 15 exploitable
  sources Confirmed, no false positive and no false Protected.
- [Node.js Goof](../samples/nodejs-goof/README.md) and the
  [Vulnerable TypeScript app](../samples/vulnerable-typescript-app/README.md) each have their
  Lodash merge Confirmed.
- Twenty-five versions of eleven published advisory packages were scanned as source. The
  readings behind `PP-L01`, `PP-L02`, `PP-N08` and `PP-N09` come from that check.
