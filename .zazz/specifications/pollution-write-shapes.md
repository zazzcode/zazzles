# Prototype pollution write shapes (exploration and tests)

- **Status** Implemented and verified offline on 2026-11-20, committed on the assigned branch.
  AC1 to AC12 pass. Owner review is pending.
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
- [Analysis guide](../../docs/analysis/prototype-pollution.md), the bounded shapes and guard limits.
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
  - **A non-parameter start is read only for unflatten.** `p6` builds its result in a local
    object. A walk from a path parameter still needs a parameter target, as in stage 1.
  - **A local function or class shadows a built-in.** AC4 needs it for `Reflect` and `Object`.
    The check now applies to every built-in the pollution family verifies.
  - **A call that encloses the write consumes its result.** `res.json(unflatten(req.body))`
    carried an unresolved-helper blocker. The enclosing call runs after the write, so the
    pollution claim no longer counts it. This also applies to stage 1 shapes.
  - **A whole-path deny-list needs an unchanged path.** A test followed by a decode or any other
    write to the path before the walk is not read as a guard.
  - **A caller's array has untyped parts.** The verifier showed that `[["__proto__"], "x"]`
    passes a comparison with `'__proto__'` and still names the key. On the array-path shape a
    literal comparison counts only after a `typeof part !== 'string'` test that exits, and a
    deny-list on the whole array is not read. AC9 holds for AC5 with that type test in the
    guarded fixture. A comparison alone is Review with `key_guard_coverage_unknown`.

- **D-10. Two rules added at the owner's request after the first review.** Both apply to every
  pollution record and are outside the paper's shapes.
  - **Filling an absent slot keeps an inherited one.** A nested write was dropped whenever its
    slot had an earlier conditional write. `if (!store[k]) store[k] = {}`, its `undefined`,
    `typeof` and `in` forms, `store[k] = store[k] || {}`, `||=` and `??=` no longer drop it. A
    slot that is always replaced, or replaced after an own-property test, has no record. Stage 1
    recorded the always-replaced form, which is safe.
  - **A call that takes the key is an unread guard.** A path test whose outcome depends on such a
    call marks the path `key_guard_coverage_unknown`, Review. A test on the operand itself or a
    plain `store[key]` existence test does not.

  - **Default exports are indexed.** `export default function`, `export default name` and
    `export default { fn }` resolve like the CommonJS forms, so library source kept in the
    repository is followed through a default import. The index is shared by every family. The
    architecture baseline and all six sample reports are unchanged by it.

  **Why.** Juice Shop `lib/accuracy.ts:71` is the first form and was silent. With only the first
  rule it became a confirmable candidate, although both routes reject a prototype key before the
  write. [Review](../evaluation/pollution-write-shapes-results.md#juice-shop-libaccuracyts71).

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
- [ ] Owner review, including the D-9 and D-10 decisions.

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
