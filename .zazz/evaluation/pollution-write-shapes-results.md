# Prototype pollution write shapes results

[Implementation contract](../specifications/pollution-write-shapes.md) · [Stage 1 results](prototype-pollution-results.md) · [Analysis guide](../../docs/scan/analysis/prototype-pollution.md)

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

## Where the write lives

`TestPollutionLibrarySourceInRepository` pins the answer for a recursive merge kept as library
source in the scanned repository:

| Case | Records |
|---|---|
| Called from a route through CommonJS `module.exports = fn`, `module.exports = { fn }` or `exports.fn` | 1 each, sink in the application, write evidence in the library file |
| Called through an ESM named or namespace import | 1 each |
| Called through an ESM default export: `export default function`, `export default name` or `export default { fn }` | 1 each. These had no record until the module index learned default exports |
| The library alone, with no application entry | 0 |

The default-export index is shared by every family's helper resolution. After the change the
architecture baseline still has its 59 rows unchanged, the six sample reports are byte-identical
to the reports from just before it, and the vuln-nextjs lab's four offline pollution regressions
pass with the final scanner.

Checked with the built scanner and not pinned by a test: the same library under `vendor/` has
no record because the walker skips that directory, and an import by package name from
`node_modules/` has no record. No pinned source of the advisory libraries in the parent
contract's D-3 table is present on this machine, and none was downloaded, so those packages
were not scanned.

## TypeScript

Scanning new TypeScript fixtures in the vuln-nextjs lab showed that a key loop written with
`forEach`, `map` or `reduce` had no record in a `.ts` file, because a TypeScript callback
parameter is a wrapper node. That affected the stage 1 `forEach` merge too. A cast around the
key enumerator and a cast on the last path part also broke the match.
`TestPollutionTypeScriptShapes` pins eight TypeScript spellings; seven failed before the change.
The architecture baseline and the six sample reports are unchanged by it.

The lab now holds 25 pollution fixtures in seven projects. Its ten offline scanner tests pass
with the final scanner, and each fixture's label was confirmed by running it in Node with its
payload. [Lab guide](https://github.com/zazzcode/vuln-nextjs/blob/main/docs/vulnerabilities/prototype-pollution.md).

## Live judgment of the lab fixtures

The owner asked for a paid run on vuln-nextjs. The lab's combined export at `8d26f52` was
scanned once with `--judge openai --judge-model gpt-6-luna` and the default limit, scanner
`d68fec6`: 19 requests planned for the 19 pollution records and 19 sent, 48,693 input tokens, no
failure. The 44 other records are observations that are not sent.

| Ground truth | Records | Confirmed | Protected | Review |
|---|---|---|---|---|
| Exploitable | 15 | 14 | 0 | 1 |
| Safe | 4 | 0 | 2 | 2 |

No false positive and no false Protected. The exploitable source in Review is the array path
compared without a type test, which the scanner leaves unread by design. One safe source,
`pages/api/guarded.ts`, is in Review because the model answered that coverage was incomplete at
0.49 confidence against the recorded guard. Two exploitable sources, the `dset` and `merge-deep`
calls, have no record: the documented dependency gap. The run was repeated with traces on
2026-11-21 ([AC8](#ac8-live-judgment)). The lab's application scan was not repeated, because
its records are identical before and after this work.
[Published sample](../../docs/samples/vuln-nextjs/README.md#prototype-pollution-fixture-scan).

## Real advisory libraries

On the owner's approval, 25 published versions of 11 packages were downloaded from the npm
registry as source and scanned: `lodash`, `minimist`, `yargs-parser`, `merge`, `set-in`, `dset`,
`object-path`, `merge-deep`, `jsonpath`, `putil-merge` and `counterpart`. No library code was
executed. The files are under the container's
`_test-findings/prototype-pollution-library-check/` and are not committed.

The first scan, at `89a87da`, detected none of them through a public API. Three forms found in
that code were then added (`6006eaa`): a `forEach` walk, a walk that recurses on the next
object, and key tests written as one-line helpers. `TestPollutionLibraryShapes` pins thirteen
cases written in the shape of the library code; ten failed before. The readings below are from
the scanner at `6006eaa`.

**The core write function called directly from a route:**

| Package | Affected pin | Patched pin | Reading |
|---|---|---|---|
| `merge` (CVE-2020-28499) | 2.1.0: raw | 2.1.1: guarded, all three names blocked | Correct at both pins |
| `merge-deep` (CVE-2021-26707) | 3.0.2: raw, `__proto__` blocked and `constructor` open | 3.0.3: guarded | Correct at both pins. 3.0.2 is the bypass sibling |
| `minimist` (CVE-2020-7598) | 1.2.0: raw | 1.2.6: Review | Correct at the affected pin. The fix tests the key in a helper that is not a plain key test |
| `set-in` (CVE-2020-28273) | 2.0.0: raw | 2.0.4 and 2.0.5: Review | Correct at the affected pin. See the note on 2.0.3 below |
| `object-path` (CVE-2021-23434) | 0.11.5: Review | 0.11.6: Review | Recorded, not separated. The parts are untyped and the guard is not credited |
| `dset` (CVE-2024-21529) | 3.1.3: no record | 3.1.4: no record | Step and write are one chained assignment in a `while` loop |
| `putil-merge` (CVE-2021-25953) | 3.6.6: no record | 3.8.0: no record | Keys held in a local, writes through `Object.defineProperty`, slot local replaced on a branch |

**Through the public API,** with the library copied into an Express application: `set-in` is
detected at every version, with the same readings as above. The other ten packages have no
record. Each library scanned alone has no application entry and no record.

**`set-in` 2.0.3.** The parent contract listed 2.0.3 as the fix for CVE-2020-28273 and
CVE-2022-25354. The scanner records it as raw. Reading the source agrees with the scanner: 2.0.3
checks the key in the write helper, after the recursive call has already written one level
down, so the deepest write to the prototype happens before the outer level throws. A
transcription of that logic, run in Node, pollutes `Object.prototype` for
`["__proto__", "polluted"]` and for `["constructor", "prototype", "polluted"]`. Version 2.0.4
moves the check before the recursion and 2.0.5 replaces `includes` with comparisons. The
package itself was not executed, so this rests on the transcription. Version 2.0.2 was never
published. 2.0.1 is also recorded as raw.

Two more readings confirm rules from this contract on real code. `dset` 3.1.3 already compares
each part with the three names, and its fix is a string conversion of the part: the nested-array
bypass. `merge-deep` 3.0.2 skips `__proto__` only.

**Why most public APIs are not reached.** The exported function is a wrapper around the core
function, and request data crosses forms the flow does not follow: `arguments[i]` in place of
named parameters (`merge`, `merge-deep`), a function nested in the exported function
(`minimist`), `module.exports = fn` with methods attached to it (`merge`), and a factory that
returns the API object (`object-path`). The paper's own motivating example, `putil-merge`, is
not detected in its published form. Reaching a core function through a library's public API
belongs to phases 7 and 8.

The architecture baseline and the six sample reports are unchanged by the three added forms. A
one-line type validator on a key is now read as blocking no name, where it was unknown before.

## AC8 live judgment

On the owner's word, three judged scans on 2026-11-21 with `--judge openai --judge-model
gpt-6-luna`, the default limit, and the scanner at `6006eaa`. Request traces were saved, and
each was replayed offline against a fresh analysis of the same source.

| Target | Pin | Requests | Input tokens | Failures | Traces replayed exactly | Pollution outcome |
|---|---|---|---|---|---|---|
| Node.js Goof | `add14ba59e98` | 12 | 63,118 | 0 | 12 of 12 | `GOOF-PP-01`, `routes/index.js:360`: Confirmed |
| Vulnerable TypeScript app | `7f8b240a2f02` | 8 | 30,454 | 0 | 8 of 8 | `TS-PP-01`, `src/server.ts:246`: Confirmed |
| vuln-nextjs pollution fixtures | lab `8d26f52` | 19 | 48,693 | 0 | 19 of 19 | 14 Confirmed, 2 Protected, 3 Review |

Planned 39 requests, sent 39. Both sample checkouts were clean before and after.

- **Both keyed positives are Confirmed.** Each is a complete raw path to Lodash 4.17.4 `merge`,
  answered `vulnerable`, `not_applicable`, `incomplete`.
- **No control is a finding.** The pollution controls have no record. Against every answer key,
  Goof has 8 of 8 expected positives found and the TypeScript app 7 of 7, with no keyed safe
  case and no unkeyed record reported as a finding.
- **The vuln-nextjs report is byte-identical** to the run of 2026-11-20 at `d68fec6`: 14 of 15
  exploitable sources with a record Confirmed and 1 Review, 2 of 4 safe sources Protected and 2
  Review, no false positive and no false Protected.
- **One difference from the previous Goof report.** The two escaped outputs in `views/edit.ejs`
  are keyed safe and were Protected in the report of 2026-11-19. In this run the model answered
  that they were exposed, against the recorded encoding, and they are Review. This work did not
  change those records: the offline Goof report is byte-identical before and after it.

All three reports are published under `docs/samples/`.

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
  [detection capabilities](../../docs/scan/detection-capabilities.md#prototype-pollution-known-gaps)
  and in the guide's [limits](../../docs/scan/analysis/prototype-pollution.md#limits).
