# Prototype pollution write shapes (exploration and tests)

- **Status** Implemented, verified and reviewed by the owner on 2026-11-21, on the assigned
  branch. AC1 to AC12 pass. Merge is pending.
- **Worktree and branch** `prototype-polution-analyzer`, the worktree that holds the analyzer.
- **Baseline** Branch tip `31380d5`, stage 1 of [prototype pollution](prototype-pollution.md).
- **Prerequisite** Stage 1 of that contract, which is committed on this branch.
- **Delivery** Commits on this branch, in the same draft PR as stage 1 unless the owner splits it.
- **Run log** `.zazz/ephemeral/pollution-write-shapes-run-log.md`
- **Verification** [Results](../evaluation/pollution-write-shapes-results.md)
- **Source** T. Houis, S. Jiang, M. Mannan, A. Youssef, "Bullseye: Detecting Prototype Pollution
  in NPM Packages with Proof of Concept Exploits", NDSS 2026,
  [doi:10.14722/ndss.2026.230211](https://dx.doi.org/10.14722/ndss.2026.230211). The owner supplied
  the paper on 2026-11-20.

## 1. Capability

Widen the source-visible write claim to the code shapes that published tools are shown to miss,
without leaving syntax-bounded recognition. Each shape is first a failing fixture. It is kept
only if a bounded recogniser detects it and its guarded, bypass-sibling and control fixtures
behave. A shape that does not fit is recorded as a limit with the reason.

The paper is a dynamic tool: it installs each package and runs its exports with crafted inputs.
This contract adopts none of that. It takes three things from the paper:

1. **Which shapes static tools miss.** Its motivating example is missed by a static tool until
   `Object.getOwnPropertyNames` is replaced by `for…in`. Its seed inputs show how a key operand
   reaches a write: nested objects, arrays of path parts, separator strings and flattened keys.
2. **What is not pollution.** Two published advisories turn out to change only the target object,
   and exploits that need a function-valued payload or an already modified builtin are infeasible.
3. **What the numbers say about static tools.** On 134 known sinks the CodeQL-based baseline found
   112 and raised 113 false positives, mostly sinks guarded by code that is not next to the write.
   That supports the existing guard listing and sets the bar for the noise check in AC10.

### Baseline today

Probe fixtures, one Express application each, scanned with the analyzer built from `31380d5`. They
are kept under the container's `_test-findings/prototype-pollution-write-shapes/probes/`.

| Probe | Shape | Pollution records |
|---|---|---|
| `p0` | Recursive merge, keys from `for…in` (the shape stage 1 covers) | 1 |
| `p1` | Keys from `Object.getOwnPropertyNames(source)`, recursion behind `options.deep` | 0 |
| `p2` | Recursion through a local alias of `target[key]` | 0 |
| `p3` | Keys from `Reflect.ownKeys(source).forEach(…)` | 0 |
| `p4` | Path passed as an array and walked directly | 0 |
| `p5` | Path split by a regular expression | 0 |
| `p6` | Unflatten: each source key is split and walked | 0 |
| `p7` | Path walk written with `reduce` | 0 |

Seven of seven shapes are missed, and each is missed silently: no candidate and no Review record.
After this contract each probe yields one candidate. [Results](../evaluation/pollution-write-shapes-results.md#probes).

## 2. Required reading

- [Prototype pollution analyzer](prototype-pollution.md), D-4 to D-9 and AC2 to AC5. This contract
  extends D-4 and changes no other decision there.
- [Analysis guide](../../docs/scan/analysis/prototype-pollution.md), the bounded shapes and guard limits.
- Code: `pollutionKeyLoop`, `pollutionObjectKeyLoop` and `pollutionMergeLoop` in
  `internal/langjs/pollution_writes.go`; `pollutionPathLoop`, `pollutionPathParts` and
  `pollutionSplitSource` in `internal/langjs/pollution_path_walk.go`; the key-guard reading in
  `internal/langjs/pollution_guard.go`.
- The paper's sections II-B (motivating example), III-B with Table I (seed inputs), IV-B (past
  vulnerabilities) and Appendix B (why known cases are missed).

## 3. Invariants

- Recognition stays syntactic and bounded: one function body, one helper hop, as stage 1. No new
  flow engine, heap model or abstract interpreter.
- The scanner never installs or runs target code. No fixture needs `node` to pass.
- A shape that is not recognised produces no record. The guide lists it as a limit (OQ-1).
- Every new shape goes through the existing key-guard listing. A deny-list that leaves a name is
  `key_guard_incomplete` and can never be Protected.
- A write that can change only its own target is never a candidate, as in stage 1.
- Only request data counts as a payload. A value that must be a function, and a route that needs
  a builtin replaced beforehand, are not request-controlled.
- Existing pollution tests pass unchanged. Request digests of every other family are unchanged,
  and `TestArchitectureBaseline` changes only by new fixture rows.
- No paid call is made by this contract.

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/langjs/pollution_writes.go` | Modified | Key enumerators and the alias recursion |
| `internal/langjs/pollution_path_walk.go` | Modified | Array paths, regular-expression splits, unflatten, `reduce` walks |
| `internal/langjs/pollution_alias.go`, `internal/langjs/pollution_path_parts.go` | New | Contextual splits of the two files above: slot and value locals; where the parts of a path come from |
| `internal/langjs/pollution_guard.go` | Modified | Whole-path deny-lists, and guards united across the names of one object |
| `internal/langjs/pollution_gate.go` | New | Path tests that depend on a call taking the key operand (D-10) |
| `internal/langjs/modules.go` | Modified | ESM default exports in the module index (D-10) |
| `internal/langjs/pollution_walk_forms.go` | New | The `forEach` walk and the recursive walk (D-11) |
| `docs/samples/nodejs-goof/`, `vulnerable-typescript-app/`, `vuln-nextjs/reports/prototype-pollution/` | Modified, new | The reports of the AC8 live check |
| `.zazz/evaluation/recall-gap-inventory/cases.json` | Modified | Key row `JS-PP-R01`, expectation `review` |
| `docs/detection-capabilities.md` | Modified | The family row and the known gaps, at the owner's request |
| `internal/langjs/pollution.go` | Modified | Branch evidence, local walk roots, the `source_keys` operand, local declarations that shadow a built-in, and the result-consumer gap |
| `internal/langjs/pollution_shapes_test.go`, `internal/langjs/testdata/pollution/probes/`, `shapes-*/`, `explore-*/` | New | The eight probes, one fixture set per shape and per exploration item. `pollution_test.go` is unchanged |
| `internal/judge/pollution_shapes_test.go` | New | Stub-answer policy cases for every fixture set (AC9) |
| `internal/analysis/pollution.go` | Unchanged | Unflatten reports as `path_walk` (OQ-2) |
| `docs/analysis/prototype-pollution.md` | Modified | The shapes and the limits found |
| `.zazz/evaluation/pollution-write-shapes-results.md` | New | Per-shape outcome, noise check, limits |
| `prototype-pollution.md`, `.zazz/specifications/README.md`, `.zazz/project/implementation-plan.md` | Modified | D-4 reference, index, status |
| `cmd/scan/architecture_baseline_test.go`, `cmd/scan/testdata/architecture-baseline.json` | Modified | Fixture registration; new fixture rows only |

Out of scope:

- Dynamic validation, proof-of-concept generation and package installation.
- Library entry-point enumeration and the corpus. Section 9 records what the paper says about
  both for [phase 7](architecture-phase-7-npm-corpus.md) and
  [phase 8](architecture-phase-8-npm-library-mode.md); nothing here implements them.
- The access and gadget claims, new library contracts, and the lodash open questions of the
  parent contract.

## 5. Decisions

- **D-1. Static shapes only.** The paper's detection rate comes from execution. This contract
  uses its findings as a shape inventory and as ground truth, not as a method.
  **Why.** Running third-party package code is against the corpus rules and outside what a
  source scanner promises.
- **D-2. One table of key enumerators.** A key loop is recognised when the keys of a parameter
  come from `for…in`, `Object.keys`, `Object.entries`, `Object.getOwnPropertyNames` or
  `Reflect.ownKeys`, iterated by `for…of` or `.forEach`. Each built-in is verified unshadowed, as
  `Object.keys` is today.
  **Why.** The paper's motivating example (`putil-merge`, CVE-2021-25953) differs from the
  stage 1 shape only in the enumerator.
- **D-3. Recursion may go through one local alias.** `let t = target[key]`, including the chained
  `t = target[key] = {}`, followed by a recursive call on `t`, is the same recursion as a call on
  `target[key]`. An alias reassigned to anything else does not match.
- **D-4. A gating option is a condition, not a control.** Recursion behind `options.deep` is
  still a candidate. The option test is recorded as branch evidence on the path.
  **Why.** The caller sets the option; it does not constrain the key.
- **D-5. Three more ways to supply a path.** Besides `param.split('<literal>')`:
  - the parameter is itself the array of parts and is walked directly;
  - the split separator is a regular-expression literal;
  - the walk is `parts.reduce((cursor, part) => cursor[part], target)` and a later assignment
    writes through its result.

  The final write must still follow the walk in the same function.
- **D-6. Unflatten is a key loop whose key is a path.** A loop over the keys of a parameter that
  splits each key and walks the parts is one write whose key operand is the source's keys. It
  reports as a path walk unless a distinct operation name proves clearer in the report (OQ-2).
- **D-7. Read-only walks are controls.** A `get` or `has` that walks a path and returns or tests
  the value writes nothing and has no record. Each path shape in D-5 gets that control.
  **Why.** The paper found the `deephas@1.0.5` advisory (CVE-2020-28271) changes only the target
  object and the flagged `dot-object@2.1.2` sinks (CVE-2019-10793) are not exploitable. Those are
  the false positives a path-shape rule invites.
- **D-8. Exploration items are time-boxed.** Four further shapes are tried after D-2 to D-6 are
  green. Each gets one failing fixture and one attempt. If it needs more than a bounded
  recogniser, it is recorded as a limit:
  - a `while` loop that consumes the parts with `shift()` or `pop()`;
  - a whole-path deny-list, `if (path.includes('__proto__'))`, read as a key guard;
  - key enumeration through `Object.keys(x).reduce` or `.map`;
  - bracket-flattened keys, `a[b][c]`, parsed by a regular-expression loop.

  **Outcome.** All four are implemented, each by one recogniser inside one function body.
  [Results](../evaluation/pollution-write-shapes-results.md#exploration-items).
- **D-9. Decisions taken during implementation.** Each is open to owner review.
  - **A path parameter may be split in place.** `path = path.split('.')` keeps the caller's
    content, so the array-path shape still matches. Any other write to the parameter ends it.
    Accepted by the owner on 2026-11-21 (section 11.1).
  - **A non-parameter start is read only for unflatten.** `p6` builds its result in a local
    object. A walk from a path parameter still needs a parameter target, as in stage 1.
    Accepted by the owner on 2026-11-21 for this PR, with a follow-on contract (section 11.1).
  - **A local function or class shadows a built-in.** AC4 needs it for `Reflect` and `Object`.
    The check now applies to every built-in the pollution family verifies. Accepted by the
    owner on 2026-11-21 (section 11.1). The review found that a class declared at the top of
    the module was not seen; it is now.
  - **A call that encloses the write consumes its result.** `res.json(unflatten(req.body))`
    carried an unresolved-helper blocker. The enclosing call runs after the write, so the
    pollution claim no longer counts it. This also applies to stage 1 shapes. Accepted by the
    owner on 2026-11-21 (section 11.1).
  - **A whole-path deny-list needs an unchanged path.** A test followed by a decode or any other
    write to the path before the walk is not read as a guard. Accepted by the owner on
    2026-11-21 (section 11.1).
  - **A caller's array has untyped parts.** The verifier showed that `[["__proto__"], "x"]`
    passes a comparison with `'__proto__'` and still names the key. On the array-path shape a
    literal comparison counts only after a `typeof part !== 'string'` test that exits, and a
    deny-list on the whole array is not read. AC9 holds for AC5 with that type test in the
    guarded fixture. A comparison alone is Review with `key_guard_coverage_unknown`. Accepted
    by the owner on 2026-11-21 (section 11.1).

- **D-10. Two rules added at the owner's request after the first review.** Both apply to every
  pollution record and are outside the paper's shapes.
  - **Filling an absent slot keeps an inherited one.** A nested write was dropped whenever its
    slot had an earlier conditional write. `if (!store[k]) store[k] = {}`, its `undefined`,
    `typeof` and `in` forms, `store[k] = store[k] || {}`, `||=` and `??=` no longer drop it. A
    slot that is always replaced, or replaced after an own-property test, has no record. Stage 1
    recorded the always-replaced form, which is safe. Accepted by the owner on 2026-11-21
    (section 11.1).
  - **A call that takes the key is an unread guard.** A path test whose outcome depends on such a
    call marks the path `key_guard_coverage_unknown`, Review. A test on the operand itself or a
    plain `store[key]` existence test does not. Accepted by the owner on 2026-11-21 (section
    11.1). The review found that the same test written with `&&` or a conditional expression
    was not seen, which left a safe write confirmable; it is seen now.

  - **Default exports are indexed.** `export default function`, `export default name` and
    `export default { fn }` resolve like the CommonJS forms, so library source kept in the
    repository is followed through a default import. The index is shared by every family. The
    architecture baseline and all six sample reports are unchanged by it. Accepted by the owner
    on 2026-11-21 (section 11.1).

  **Why.** Juice Shop `lib/accuracy.ts:71` is the first form and was silent. With only the first
  rule it became a confirmable candidate, although both routes reject a prototype key before the
  write. [Review](../evaluation/pollution-write-shapes-results.md#juice-shop-libaccuracyts71).

- **D-11. Three forms taken from published libraries.** Added after the library check, each
  with one attempt and tests written in the shape of the library code:
  - a walk whose step is the body of a `forEach` over the parts. Accepted by the owner on
    2026-11-21 (section 11.1);
  - a walk that recurses on `obj[key]` with the next index or `path.slice(1)`, with the write in
    the function or in a helper it calls. A call that takes the key before the recursion is an
    unread guard, so an asserted key is Review and not raw. Accepted by the owner on 2026-11-21
    (section 11.1);
  - key tests written as one-line helpers of the module, and `object.hasOwnProperty(key)`.
    Accepted by the owner on 2026-11-21 (section 11.1).

  **Why.** They are what `minimist`, `set-in`, `object-path` and `merge-deep` use. Reaching
  those functions through each library's public API stays with phases 7 and 8.

## 6. Agent implementation rules

Follow [execution discipline](../docs/agent-execution-discipline.md). Work one shape at a time:
fixture and failing test, then the recogniser, then its guarded, bypass-sibling and control
fixtures. Stop and ask when a shape cannot be recognised without tracking values across more than
one helper, when an existing pollution test would have to change, or when the noise check in AC10
shows a new record on a keyed control.

## 7. Acceptance criteria

1. **AC1 (baseline).** The eight probes are committed as fixtures. Before any recogniser change,
   a test records one pollution record for `p0` and none for `p1` to `p7`.
2. **AC2 (`getOwnPropertyNames`).** The `p1` shape yields one `recursive_merge` candidate whose
   key operand is the source parameter, with the `options.deep` test as branch evidence.
3. **AC3 (alias).** The `p2` shape yields one candidate. The same function with the alias
   reassigned to a fresh object before the recursive call yields none.
4. **AC4 (`Reflect.ownKeys`).** The `p3` shape yields one candidate. A local function named
   `Reflect` or `Object` that shadows the built-in yields none.
5. **AC5 (array path).** The `p4` shape yields one `path_walk` candidate whose key operand is the
   path parameter. The same walk over a constant array yields none.
6. **AC6 (regular-expression split).** The `p5` shape yields one candidate.
7. **AC7 (unflatten).** The `p6` shape yields one candidate whose key operand is the source's keys.
8. **AC8 (`reduce` walk).** The `p7` shape yields one candidate. A `reduce` walk whose result is
   only returned yields none.
9. **AC9 (guards on every shape).** For each of AC2 to AC8: with all of `__proto__`,
   `constructor` and `prototype` skipped, stub answers `protected`, `no_bypass` and `complete`
   give Protected. With only `__proto__` skipped, the record carries `key_guard_incomplete` naming
   `constructor` and the same stub answers do not give Protected.
10. **AC10 (noise check).** Every JS/TS sample is scanned offline before and after. The results
    list each new pollution record with its location and a source-reviewed verdict: true write,
    false, or unclear. No keyed control gains a record, and `GOOF-PP-01` and `TS-PP-01` keep
    exactly one candidate each.
11. **AC11 (exploration).** Each D-8 item has a fixture and a recorded outcome: implemented with
    its tests, or a limit with the reason, stated in the guide.
12. **AC12 (isolation and gate).** Existing pollution tests pass unchanged. Other families'
    request digests are unchanged. `gofmt -l cmd internal` prints nothing; `go vet ./...`,
    `go build ./...` and `go test -race ./... -count=1` pass.

## 8. Test strategy

- One table test over `testdata/pollution/shapes-*`: per shape a vulnerable, guarded,
  bypass-sibling and control function in one small application, as `source-writes` does today.
- The AC1 baseline test is written first and inverted shape by shape, so the history shows each
  shape going from missed to found.
- Policy cases (AC9) reuse the stub-answer tests of stage 1.
- The noise check (AC10) is a recorded run against the pinned sample checkouts, not a committed
  test.

## 9. What the paper says for the library phases

Recorded so the corpus and library-mode contracts can use it. Nothing here is implemented by this
contract.

- **Entry points decide recall.** With the earlier tool's module loading and export enumeration,
  the same pipeline found 193 vulnerable packages instead of 290 and reached 12,870 entry
  functions instead of 154,889. Phase 8 lists `exports`, `main`, `module` and `bin`. The paper adds:
  - `jsnext:main`, and both the `import` and `require` conditions of one export;
  - modules the manifest does not index but a caller can load by relative path. Node blocks
    these when the package declares an `exports` map, so they are entries only without one;
  - functions stored as properties of an exported function, and class methods reached through
    the exported class's prototype.
- **Tests show how an export is called.** The paper reads each package's test files to learn
  argument shapes, including the option object that opens the vulnerable branch. For the
  library judge contract this is evidence for a parameter's role, alongside types and the README.
- **Ground truth beyond the eleven corpus rows.** The *Silent Spring* dataset has 100 packages
  with 134 known sink lines and a proof for each. The paper's Table VI lists its critical and
  high-severity CVEs with the affected package versions. Both suit a stage 2 recall measurement,
  with two cautions: the four ground-truth sinks named in D-7 are not real, and seven more need a
  prototype property that is already set.
- **Two lodash entry points.** The paper reports `pick` and `updateWith` as vulnerable in
  `lodash@4.17.4`. That bears on OQ-4 of the parent contract.

## 10. Definition of done

- [x] AC1 to AC12 verified, with evidence in the run log and the results record.
- [x] The guide states every shape recognised and every limit found.
- [x] `prototype-pollution.md` D-4 points to this contract for the added shapes.
- [x] Owner review of D-9, D-10 and D-11, 2026-11-21. All twelve choices accepted (section 11.1).

## 11. Open questions

- **OQ-1. Unrecognised dynamic writes.** A nested write through a non-constant key that matches
  no shape is silent today. Keep it silent with the limit documented, or emit a Review record?
  Recommendation: silent. Decide again from the AC10 counts if the shapes here still miss sample
  code that source review calls a write.
  **Applied: silent.** AC10 found no added shape in sample server code. Source review found one
  stage 1 nested write behind two helpers, Juice Shop `lib/accuracy.ts:71`. D-10 now records it
  and keeps it in Review.
- **OQ-2. Reporting unflatten.** Report it as `path_walk`, or add an `unflatten` operation name?
  Recommendation: `path_walk` with the key operand naming the source keys, unless the report
  reads wrongly in review.
  **Applied: `path_walk` with key operand `source_keys`.**
- **OQ-3. One contract or two.** Fold these shapes into `prototype-pollution.md` D-4 once they
  are implemented and retire this file, or keep it as the record of the exploration?
  Recommendation: keep it; the parent contract links here.
- **OQ-4. A larger measurement corpus.** Should the *Silent Spring* dataset be pinned for stage 2?
  It needs clone approval for 100 repositories and belongs to phase 7's rules.

## 11.1 Owner review and future exploration

The owner reviews D-9 to D-11 one choice at a time. Each accepted choice is listed with the
limit it leaves, so the limit is known and can be taken up as a later capability. The
identifiers refer to the user-facing list of every gap,
[prototype pollution coverage](../../docs/scan/detection-capabilities/prototype-pollution.md).

| Choice | Owner decision | Limit accepted | To explore later |
|---|---|---|---|
| D-9, split in place (`PP-N03`) | Accepted 2026-11-21 | Only `path = path.split(…)` keeps the match. A path normalised any other way has no record: `path = String(path).split('.')`, `path = toPath(path)`, a ternary such as `Array.isArray(path) ? path : path.split('.')`, or a helper result held in a new local. Checked with the scanner at `6006eaa` | Read a path normaliser: a string conversion before the split, a conditional that yields the path or its split, and a one-line helper that returns one of those. Each keeps the caller's content, so the walk stays a candidate |
| D-9, non-parameter start (`PP-N01`, `PP-N02`) | Closed by the [walk start contract](pollution-walk-start.md) | Stable module, local, imported and fixed-property starts are recorded. Handler walks are anchored at the final assignment | Instance fields remain an explicit limit (`PP-N15`) |
| D-9, shadowed built-ins (`PP-A01`) | Accepted 2026-11-21 | A function or class declared under a built-in's name, in an enclosing block or at the top of the module, ends the match, as a variable, a parameter or a write to the method already did. Three replacements are not seen and the function keeps its record: `globalThis.Reflect = …` in the same module, the same in another module, and a method patched in another module (`Reflect.ownKeys = …`). Checked with the scanner | Track writes to `globalThis` members and to built-in methods across the modules a scan reads, and treat a replaced built-in as unknown for every module |
| D-9, enclosing call (`PP-R06`) | Closed by the [walk start contract](pollution-walk-start.md) | Calls enclosing the write, verified logger calls, and later calls in the same function do not contribute an unresolved-input blocker | Unresolved calls before the write still need evidence |
| D-9, whole-path deny-list (`PP-N04`, `PP-R05`) | Accepted 2026-11-21 | `includes` and `indexOf` tests on the path or the parts are credited while the path is unchanged; a decode into the same variable withholds the credit and the walk is raw. Two things remain. First, a decode at the point of use, `decodeURIComponent(path).split('.')`, or into a new variable is not a walk the scanner reads, so that check-then-decode bypass has no record. Second, four complete guards are unread and their walks are recorded raw: a regular-expression test, `parts.some(…)` with comparisons, a deny array checked with `some` and `includes`, and a test on `path.toLowerCase()`. A raw record with a model answer of protected is Review, so these cost a review and risk a false finding only if the model misreads the guard. Checked with the scanner at `f8475b7` | Follow the path through a decode or another string transform into the split, so a check before the transform is seen as bypassed. Read regular-expression alternations of the three names, `some` over the parts, and a deny array, as key guards |
| D-9, untyped array parts (`PP-R03`, `PP-R04`, `PP-N11`) | Accepted 2026-11-21 | On an array path a comparison is credited only after an exit on `typeof part !== 'string'`. The bypassable comparison alone is Review, not Confirmed: the scanner does not claim the nested-array bypass. Two other type checks are not credited and are Review: `path.every(p => typeof p === 'string')` and a `typeof part === 'string'` test with the exit in its `else`. A part converted before use, `String(path[i])` or `'' + path[i]`, is not read as a walk at all, so that form has no record whether or not a deny-list follows. Checked with the scanner at `5e19706` | Claim the nested-array bypass so the comparison-only form can be Confirmed. Credit an up-front `every` type check and the positive `typeof` form. Read a converted part as a string part of the same path, which records the unguarded conversion and credits `dset`'s actual fix |
| D-10, absent-slot fill (`PP-N06`) | Accepted 2026-11-21 | A nested write is recorded when the slot is unchanged or only filled while absent, in these forms: an `if` whose whole body is the assignment and whose test is `!slot`, a comparison with `undefined` or `null`, `typeof slot === 'undefined'` or `!(key in obj)`; `slot = slot \|\| x`; `slot = slot ?? x`; `\|\|=`; `??=`. A slot always replaced, or replaced after an own-property test, correctly has no record. Five fills that also leave an inherited slot in place are not read, so their exploitable writes have no record: a ternary default, a branch with a second statement, a compound condition, a `typeof slot !== 'object'` test, and an `if` with an `else`. Checked with the scanner at `7903b26` | Read those five fills. The general rule is that a slot write leaves an inherited value in place whenever its condition is false for an object, which a small truthiness model of the condition can decide |
| D-10, call that takes the key (`PP-R01`, `PP-R10`) | Accepted 2026-11-21 | A test on the request path that depends on a call taking the key keeps the record in Review, whether written as an `if`, inside a `try`, with `&&` or `\|\|`, or as a conditional expression. This trades recall for precision in both directions: a `Map` or `Set` lookup that makes the write unreachable is not Protected, and a helper around a plain object lookup, which a prototype key passes, is not Confirmed. A plain `store[key]` existence test, a test on the key itself, a call whose result is unused and a test after the write are not guards, and those writes stay confirmable. A check in route middleware is not read as a guard of the handler's write. Checked with the scanner | Read the lookup: credit `Map.has`, `Set.has`, `Map.get` and an allow-list `includes` as complete guards, and treat a one-line helper around a plain object lookup as no guard. Read a key test in route middleware as a guard on every handler behind it |
| D-10, default exports (`PP-N12`) | Accepted 2026-11-21 | A helper imported by default is followed when it is declared as `export default function`, as a function or arrow bound to a name that is then exported by default, or in a default-exported object, under any local import name. The change is in the module index every family shares; no fixture or sample record moved, though an application that imports helpers by default can gain records in any family. Four forms are still not followed and the function has no record: `export { merge as default }`, a re-export from a barrel file (named, `default as`, or `export *`), and a dynamic `import()`. Checked with the scanner at `583eb70` | Follow re-exports through barrel files and literal dynamic imports. Barrel files are common in applications, so this is likely to matter for every vulnerability class, and it needs its own cross-family noise check |
| D-11, `forEach` walk (`PP-N13`) | Accepted 2026-11-21 | A `forEach` over the parts or over `parts.slice(0, -1)`, with a function or arrow callback that steps a cursor or the target parameter itself, followed by the final write, is a path walk. Four neighbouring forms have no record: a `forEach` whose callback also makes the final write on the last index, `map` or `every` used for the step, and `for…of` over `parts.entries()`. An index loop with the final write inside it is recorded. Checked with the scanner at `28efcf9` | Read a final write guarded by the last index inside the callback, as the index loop already does, and treat `map`, `every`, `some` and `entries()` iteration as the same step |
| D-11, recursive walk (`PP-N14`) | Accepted 2026-11-21 | A function that calls itself on `obj[key]`, with `key` taken as `path[i]` or `path[0]` and the path passed on unchanged or as `path.slice(1)`, and that writes `obj[key]`, is a path walk, also behind a public wrapper function. A comparison guard counts after a type test, and a call that takes the key before the recursion keeps the record in Review. Four forms have no record: the path destructured as `[head, ...rest]`, the path consumed with `shift()`, a string path re-split at each level, and two functions that call each other. `set-in` 2.0.3 is recorded as raw against its advisory range; that reading rests on the source and a transcription, not on running the package. Checked with the scanner at `7644e10` | Read the destructured and `shift()` forms, which are common in functional code, and mutual recursion. Confirm the `set-in` 2.0.3 reading by running the package in isolation before relying on it |
| D-11, one-line helper key tests (`PP-R02`, `PP-R11`) | Literal collections closed by the [walk start contract](pollution-walk-start.md) | Same-module single-return helpers are read, including membership in a stable literal Set or array. An incomplete deny-list names the routes left open | Imported helpers and helpers with multiple statements remain in Review |

The review ended on 2026-11-21 with all twelve choices accepted. It found and fixed two holes in
the rules themselves: a class at the top of a module was not seen as shadowing a built-in, and a
lookup gate written with `&&` or a conditional expression was not read. It corrected several
limits that had been written without a check, and added identifiers `PP-N11` to `PP-N14`,
`PP-R10` and `PP-R11`. One follow-on contract came out of it,
[walk start](pollution-walk-start.md).

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, each shape's failing-first evidence, the
before and after sample counts for AC10 with the reviewed verdicts, and the outcome of each
exploration item.

## 13. Agent implementation prompt

> Work in the `prototype-polution-analyzer` sibling worktree on its existing branch. Read
> AGENTS.md, the orientation contents, `prototype-pollution.md` and this spec. Copy the probes
> from the container's `_test-findings/prototype-pollution-write-shapes/probes/` into
> `internal/langjs/testdata/pollution/` and write the AC1 baseline test first. Then take D-2 to
> D-6 one shape at a time, test-first, each with its guarded, bypass-sibling and control fixtures.
> Run the AC10 noise check before the exploration items. Make no paid call, install nothing, and
> commit only when the owner asks. The worktree's uncommitted change to `prototype-pollution.md`
> is intentional; keep it. Verifier: a fresh-context subagent reruns the eight probes, confirms
> no bypass-sibling fixture can be Protected, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-20 — Drafted

Requested by the owner after supplying the Bullseye paper. Written from the paper, from a reading
of the stage 1 recognisers, and from eight probe fixtures scanned with the analyzer at `31380d5`.
No code changed.

### 2026-11-20 — Implemented the seven shapes and the four exploration items

The eight probes are committed as fixtures and go from one record to eight. Each shape has a
vulnerable, guarded, bypass-sibling and control fixture, and stub answers confirm that no bypass
sibling can be Protected. The six-sample noise check is byte-identical before and after. All
four D-8 items fit a bounded recogniser. D-9 records six decisions taken on the way, one of
which, the result-consumer gap, also changes stage 1 records nested in a call. The architecture
baseline gains 11 rows and keeps the earlier 48. The gate passes.

The independent verifier reported PASS and one unsound guard on the array-path shape, a
comparison that a nested array passes. The recogniser and the fixture were corrected before
the final gate. [Results](../evaluation/pollution-write-shapes-results.md#independent-verification).

### 2026-11-20 — Owner review: known gaps, the Juice Shop write and lookup gates

The owner asked for the known gaps in the user documentation, for the unrecorded Juice Shop
nested write to be fixed, and for proof that the result is not a false positive. D-10 adds the
absent-slot rule and the lookup-gate rule. The Juice Shop write is application source, has no
advisory, and cannot be reached with a prototype key on either route, so its four records are
kept in Review and keyed as `JS-PP-R01`. The five other sample reports are byte-identical to the
baseline and the architecture baseline is unchanged. Committed and pushed at the owner's request.

### 2026-11-20 — Owner review: where a write is found

The owner asked for the user guide to state where a vulnerable write is detected and for writes
in repository source to be found. The guide and the capability page now distinguish application
source, library source kept in the repository, `vendor/` and `node_modules/`, installed
dependencies and a library repository scanned alone. A test pins the in-repository cases. ESM
default exports were not followed and now are (D-10). Scanning a package's own exports stays
with phases 7 and 8.

### 2026-11-20 — TypeScript spellings and the vuln-nextjs fixtures

The owner asked for more prototype pollution examples in the vuln-nextjs lab. Writing them in
TypeScript showed three spellings the recognisers missed: wrapped callback parameters, a cast
around the key enumerator, and a cast on the last path part. All three are read now and pinned
by `TestPollutionTypeScriptShapes`. The lab gained 21 fixtures, including Lodash `set`,
`defaultsDeep` and `zipObjectDeep` by version and two non-Lodash advisory libraries recorded as
known gaps.

### 2026-11-20 — Live judgment of the vuln-nextjs fixtures

On the owner's word, one judged scan of the lab's combined pollution project: 19 requests, 14
Confirmed, 2 Protected, 3 Review, no false positive and no false Protected against the lab's
labels. Published as a [fixture report in the vuln-nextjs sample](../../docs/samples/vuln-nextjs/README.md#prototype-pollution-fixture-scan).

### 2026-11-20 — Checked against published advisory libraries

On the owner's approval, 22 versions of 11 advisory packages were downloaded as source and
scanned. None is detected through its public API. Called directly, the core function of `merge`
is read correctly at both pins, `merge-deep` and patched `minimist` are Review, and four packages
have no record. The results record lists each reading and the forms that stand in the way. This
bounds what the contract claims: the shapes are found in application code written like the
fixtures, not yet in published library code. Three further recognisers were started and are not
in this change.

### 2026-11-21 — Library forms, AC8 and the published reports

D-11 adds three forms found in published libraries. With them the core functions of `merge`,
`merge-deep`, `minimist` and `set-in` are read correctly at their affected pins and `set-in` is
detected through its public API; ten of eleven packages are still not reached through theirs.
The check found that `set-in` 2.0.3, listed as patched, still writes before it checks. The AC8
live check of the parent contract passed with the vuln-nextjs fixtures added to it, and the three
reports are published.

### 2026-11-21 — Owner review of D-9 to D-11

The owner accepted all twelve choices, one at a time. Each was probed with the scanner first;
section 11.1 lists the limit each one leaves and what to explore later. Two rules were fixed
during the review, each with a failing-first test: module-level class shadowing and lookup gates
written as expressions. The user-facing gap list moved to its own page under
`docs/detection-capabilities/`, with an identifier per gap, and the capability page became an
index by vulnerability class.
