# Prototype pollution write shapes results

[Implementation contract](../specifications/pollution-write-shapes.md) · [Stage 1 results](prototype-pollution-results.md) · [Analysis guide](../../docs/analysis/prototype-pollution.md)

Verified on 2026-11-20 in `prototype-polution-analyzer`, on top of the stage 1 tip `31380d5`. Every scan read source and package files. The assessment tests used fixed
responses through an in-memory transport. No provider request was made.

## Probes

The eight probe applications are committed under
`internal/langjs/testdata/pollution/probes/`, byte-identical to the originals. "Before" is a
scanner built from `31380d5`. "After" is the working tree.

| Probe | Shape | Before | After | Record |
|---|---|---|---|---|
| `p0` | Recursive merge with `for…in` | 1 | 1 | `recursive_merge`, `source` |
| `p1` | `Object.getOwnPropertyNames`, recursion behind `options.deep` | 0 | 1 | `recursive_merge`, `source`, branch evidence `(options.deep)` |
| `p2` | Recursion through a local alias of `target[key]` | 0 | 1 | `recursive_merge`, `source` |
| `p3` | `Reflect.ownKeys(source).forEach(…)` | 0 | 1 | `recursive_merge`, `source` |
| `p4` | Path passed as an array | 0 | 1 | `path_walk`, `path` |
| `p5` | Path split by a regular expression | 0 | 1 | `path_walk`, `path` |
| `p6` | Unflatten | 0 | 1 | `path_walk`, `source_keys` |
| `p7` | Path walk written with `reduce` | 0 | 1 | `path_walk`, `path` |

Each record is one complete raw candidate with no completeness blocker.

## Shape fixtures

One application per shape under `testdata/pollution/shapes-*`. Each holds the vulnerable
function, the same function behind a guard on all three names, its bypass sibling that rejects
only `__proto__`, and controls.

| AC | Fixture | Vulnerable | Guarded | Bypass sibling | Controls without a record |
|---|---|---|---|---|---|
| AC2 | `shapes-own-property-names` | Raw | Guarded | Raw, `key_guard_incomplete` | One-level copy |
| AC3 | `shapes-alias-recursion` | Raw | Guarded | Raw, `key_guard_incomplete` | Alias replaced by a fresh object |
| AC4 | `shapes-reflect-own-keys` | Raw | Guarded | Raw, `key_guard_incomplete` | Local class `Reflect`; local function `Object` |
| AC5 | `shapes-array-path` | Raw | Guarded, with a `typeof` test before the comparison | Raw, `key_guard_incomplete` | Constant array in the function; constant array at the call; read-only walk |
| AC6 | `shapes-regex-split` | Raw | Guarded | Raw, `key_guard_incomplete` | Read-only walk |
| AC7 | `shapes-unflatten` | Raw | Guarded | Raw, `key_guard_incomplete` | One-level write of the first part |
| AC8 | `shapes-reduce-walk` | Raw | Guarded | Raw, `key_guard_incomplete` | `reduce` result only returned, inline and through a local |

**AC9.** `TestPollutionShapePolicy` sends stub answers for all eleven fixtures, the seven above
and the four exploration fixtures. With `protected`, `no_bypass` and `complete`, each guarded
function is Protected and each bypass sibling is Review with `pollution_answers_inconsistent`.
A `bypass_identified` answer on a complete guard is Review with `pollution_bypass_unsupported`.
The vulnerable function and the bypass sibling can each be Confirmed. Every assessment replays
with the same request digest.

`TestPollutionShapeVariants` adds 58 spellings and near misses. Two controls were checked by
removing their rule: without the path-stability rule a whole-path test before
`decodeURIComponent` reads as a guard, and without the returns-only rule a key `reduce` that
returns the looked-up slot gains a record. Both tests fail under those removals.

## Independent verification

A fresh-context verifier built its own scanner, scanned the eight probes and the eleven
fixtures, drove every fixture route with payloads in Node, and enumerated 180 answer
combinations per record against the policy. Verdict: PASS on all three checks.

- Each probe has exactly one raw record with the operation and operand in the table above.
- No bypass sibling reaches Protected under any answer combination. Each lists `__proto__` as
  blocked and `constructor` as open.
- Every control stays without a record and none pollutes when run. Every flagged function
  pollutes when run.

It also found one unsound guard, now fixed. The first `shapes-array-path` guard compared each
part with the three names. A request can pass a nested array, `[["__proto__"], "polluted"]`,
which fails the comparison and still names the key, and the scanner recorded that guard as
complete. A string comparison on the parts of a caller's array now counts only after a `typeof`
test that exits, and a deny-list on the whole array is not read. Without the type test the
record is Review with `key_guard_coverage_unknown`. Node confirms both nested-array payloads
pollute through the comparison-only guard and neither does after the type test. Other shapes
take their keys from `for…in`, a key enumerator, `split` or `match`, which yield strings.

## Exploration items

Each item began as a fixture without a record, and one bounded recogniser was attempted.

| Item | Outcome | Fixture |
|---|---|---|
| `while` loop that consumes parts with `shift()` or `pop()` | Implemented. The loop must run while parts remain, and the final key is the remaining or previously taken part | `explore-while-shift` |
| Whole-path deny-list read as a key guard | Implemented for `includes` and `indexOf` tests that exit or enclose the walk, on the path, the parts array, or an unflatten key. The path must stay unchanged up to the walk | `explore-path-deny-list` |
| Key enumeration through `reduce` or `map` | Implemented. `map` reads as `forEach`. `reduce` needs a block callback whose every return hands back the accumulator, which then names the start object | `explore-keys-reduce-map` |
| Bracket-flattened keys parsed by a regular-expression loop | Implemented for one `exec` loop that pushes its matches, and for `match` with a global literal | `explore-bracket-keys` |

## Noise check

Six JS/TS samples at their pins, each checkout clean before and after. Reports were written
with `scan --analyze --json`, no judge, in an empty environment.

| Sample | Pin | Uses before | Uses after | Pollution records before → after | Report bytes |
|---|---|---|---|---|---|
| Juice Shop | `f189f521266f` | 251 | 255 | 0 → 4, all Review (`JS-PP-R01`, `lib/accuracy.ts:71`) | The 251 earlier records are unchanged |
| Node.js Goof | `add14ba59e98` | 36 | 36 | 1 → 1 (`GOOF-PP-01`, `routes/index.js:360`) | Identical |
| OSS OopsSec Store | `2d530ef3c0e6` | 128 | 128 | 0 → 0 | Identical |
| Vuln Demo App | `d27b35bdd2d5` | 19 | 19 | 0 → 0 | Identical |
| Vulnerable TypeScript app | `7f8b240a2f02` | 27 | 27 | 1 → 1 (`TS-PP-01`, `src/server.ts:246`) | Identical |
| vuln-nextjs | `a6f6c815e4ca` | 54 | 54 | 0 → 0 | Identical |

The added write shapes gave no new record in any sample: after the seven shapes, the exploration
items and the array-path fix, all six reports were byte-identical to the baseline. The four
Juice Shop records come from the later slot rule and are reviewed below. No keyed control gained
a record, and the five other reports are still byte-identical. The recall checker's output moves
by one row, `JS-PP-R01`, from missing to present, and by one precision line that counts four
Juice Shop pollution records and no finding.

## Juice Shop `lib/accuracy.ts:71`

A source search of the samples found one nested dynamic write that neither scanner version
recorded: `solves[challengeKey][phase] = verdict` in Juice Shop's own source, reached through two
helpers from `POST /snippets/verdict` and `POST /snippets/fixes`. It is application code. No
library or dependency is involved, no advisory covers it, and prototype pollution is not among
the 116 documented Juice Shop challenges.

**Why it had no record.** The slot is created just before the write, `if (!solves[key])
solves[key] = {…}`. Stage 1 dropped any nested write whose slot had an earlier conditional
write. That was the wrong way round: an inherited slot such as `__proto__` already has a value,
skips the branch and reaches the write, while a slot that is always replaced by a fresh object is
safe and stage 1 recorded it.

**Change.** A write that only fills an absent slot no longer hides the nested write. A slot that
is always replaced now has no record.

**Verdict: a finding here would be a false positive.** The write itself pollutes when called
with `__proto__`, but neither route can reach it with a prototype key:

| Route | What happens with `key` set to `__proto__`, `constructor`, `toString` or `["__proto__"]` |
|---|---|
| `POST /snippets/verdict` | `retrieveCodeSnippet` asks a `Map` for the key, finds none, and the handler returns 404 |
| `POST /snippets/fixes` | `readFixes` returns the inherited object from its cache lookup, `fixData.fixes` is undefined, and reading `.length` throws before the write |

A Node transcription of both routes and the helper confirms it: ten payloads, no change to
`Object.prototype`, and the same helper called without a gate does pollute. The live application
was not run.

**Second change, so the scanner does not confirm it.** A path test whose outcome depends on a
call that takes the key operand is now an unread guard. All four records carry that test as
key-guard evidence and `key_guard_coverage_unknown`, so the policy can make them neither
Confirmed nor Protected. An existence test on a plain object, `if (!store[key]) return`, is not
such a guard, because an inherited key passes it, and that write stays confirmable.

| Record | Gate recorded | Outcome |
|---|---|---|
| `/snippets/verdict`, two call paths | `routes/vulnCodeSnippet.ts:75` `(snippetData == null)` | Review |
| `/snippets/fixes`, two call paths | `routes/vulnCodeFixes.ts:76` `(fixData.fixes.length === 0)` and `:87` | Review |

The recall key holds it as `JS-PP-R01` with expectation `review`. `GOOF-PP-01` and `TS-PP-01`
are unchanged: one complete raw candidate each.

The same search found a read-only walk in browser code,
`frontend/src/hacking-instructor/helpers/helpers.ts:49`, which is not a write.

## Isolation and gate

- The architecture baseline keeps all 48 earlier rows unchanged, including the two stage 1
  pollution fixtures, and adds 11 fixture rows. The slot rule and the lookup gates changed no row. The golden diff has 869 added lines and none
  removed.
- Existing pollution tests are unmodified and pass.
- `gofmt -l cmd internal` printed nothing. `go vet ./...`, `go build ./...`,
  `go test -race ./... -count=1` and `git diff --check` passed on Go 1.27.3.

## Limits found

- A slot local replaced on a branch, `if (!slot) slot = {}`, ends the alias and the function has
  no record. An inherited slot is truthy and would skip that branch, so this is a missed write.
- A path walk from a path parameter into a local or module-level object has no record. Only the
  unflatten shape accepts a non-parameter start.
- A write reached only after a call that takes the key stays in Review. The scanner does not
  read what that call accepts, so a real missing check behind such a call is not confirmed.
- A nested write whose slot is replaced on a branch that does not test for its absence has no
  record.
- Calls to `deepmerge` and `set-value` from an application have no record, and a nested write
  keyed from a query string is Review with `key_control_unknown`. Both were checked with the
  final scanner.
- A whole-path test written as a regular-expression test is not read. The record is raw, and a
  model answer that relies on the test is a contradiction, Review.
- A write nested in a call that takes its result, `res.json(unflatten(req.body))`, carried a
  helper blocker under stage 1. The pollution claim now treats a call that encloses the write
  as a consumer of its result. This applies to every pollution shape, including stage 1's.
- The owner asked for the gaps in the user documentation. They are listed in
  [detection capabilities](../../docs/detection-capabilities.md#prototype-pollution-known-gaps)
  and in the guide's [limits](../../docs/analysis/prototype-pollution.md#limits).
