# Prototype pollution walk start (module-level, local and inline walks)

- **Status** Proposal, drafted 2026-11-21 at the owner's request. No code is written.
- **Worktree and branch** Assigned by the owner. The analyzer lives on
  `prototype-polution-analyzer` until it merges; start from `stage` after that.
- **Baseline** `prototype-polution-analyzer` at `ed94711`.
- **Prerequisite** [Prototype pollution write shapes](pollution-write-shapes.md), merged.
- **Delivery** One draft PR into `stage`.
- **Run log** `.zazz/ephemeral/pollution-walk-start-run-log.md`
- **Source** Owner review of write shapes D-9, the choice "a non-parameter start is read only
  for unflatten" ([section 11.1](pollution-write-shapes.md#111-owner-review-and-future-exploration)).

## 1. Capability

Record a path walk whatever object it starts from. Today a walk whose path is a parameter is a
candidate only when it starts from another parameter. An application more often keeps its state
in a module-level object and writes into it by a request path:

```js
const store = {};
function setPath(path, value) {
  let cursor = store;
  …
}
```

That function has no record, although a request path of `__proto__.polluted` writes to
`Object.prototype` exactly as it does through a parameter. The same holds for a walk into a
local object, into a property of an object, and for a walk written in the handler itself with no
helper function.

The write shapes contract accepted this limit for its own PR because widening it adds records to
existing scans. This contract makes the change with its own noise check.

### Baseline today

Probe fixtures, one Express application each, scanned with the analyzer at `ed94711`. They are
kept under the container's `_test-findings/pollution-walk-start/probes/`.

| Probe | Walk starts from | Pollution records |
|---|---|---|
| `p0` | A parameter (the shape read today) | 1 |
| `p1` | A module-level object | 0 |
| `p2` | A local object that is returned | 0 |
| `p3` | A property of a module-level object, `holder.state` | 0 |
| `p4` | A module-level object, walked with `reduce` | 0 |
| `p5` | A module-level object, with the walk written in the handler and no helper | 0 |
| `p6` | A field of a class instance, `this.state` | 0 |
| `p7` | A module-level object made by `Object.create(null)` | 0 |

`p1` to `p6` pollute `Object.prototype` and are missed without a record. `p7` cannot be polluted
through its first lookup and must not become a raw candidate.

## 2. Required reading

- [Prototype pollution write shapes](pollution-write-shapes.md): D-5, D-6, D-9 and D-10, and
  section 11.1. This contract changes the second choice of D-9 and nothing else there.
- [Prototype pollution analyzer](prototype-pollution.md): D-5 to D-9 and AC4, the rule for a
  null-prototype root.
- [Analysis guide](../../docs/analysis/prototype-pollution.md), the shapes and limits.
- Code: `pollutionPathWrite`, `pollutionCursorStart` and `pollutionRootGuard` in
  `internal/langjs/pollution_path_walk.go`; `pollutionCall` and `recordPollution` in
  `internal/langjs/pollution.go`; `sourcePollutionWrites` in
  `internal/langjs/pollution_writes.go`; `pollutionNullTarget` in
  `internal/langjs/pollution_lodash.go`.

## 3. Invariants

- Recognition stays syntactic and bounded to one function body, as in the write shapes contract.
- A walk is a candidate only when a request-derived value supplies its parts. A walk over a
  constant path into any object has no record.
- A start the scanner cannot identify produces no record. It is never recorded as raw on a guess.
- A null-prototype start covers only the first lookup: Review with `null_prototype_root`, as today.
- Every guard rule of the write shapes contract applies unchanged: the key-guard listing, the
  type test for untyped array parts, whole-path deny-lists and unread guards on the key.
- Existing pollution tests pass unchanged. Request digests of every other family are unchanged,
  and `TestArchitectureBaseline` changes only by new fixture rows.
- No paid call is made by this contract.

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/langjs/pollution_path_walk.go`, `pollution_walk_forms.go` | Modified | Accept a start that is not a parameter for every walk form |
| `internal/langjs/pollution.go`, `pollution_writes.go` | Modified | Record identity and evidence for the start object; walks written in the handler |
| `internal/langjs/pollution_shapes_test.go`, `internal/langjs/testdata/pollution/start-*/` | Modified, new | Baseline test and one fixture set per start |
| `internal/judge/pollution_shapes_test.go` | Modified | Stub-answer policy cases for the new fixture sets |
| `cmd/scan/architecture_baseline_test.go`, `cmd/scan/testdata/architecture-baseline.json` | Modified | Fixture registration; new fixture rows only |
| `docs/analysis/prototype-pollution.md`, `docs/detection-capabilities.md` | Modified | The accepted starts; the closed gap removed from the known gaps |
| `.zazz/evaluation/pollution-walk-start-results.md` | New | Per-probe outcome and the noise check |
| `pollution-write-shapes.md`, `.zazz/specifications/README.md`, `.zazz/evaluation/recall-gap-inventory/cases.json` | Modified | Section 11.1 row, index, key rows for new sample records |

Out of scope:

- A recursive merge whose target is not a parameter. Its recursion needs the target as an
  argument, so the shape does not arise.
- Reaching a library's core function through its public API (phases 7 and 8).
- The other limits in section 11.1 of the write shapes contract. Each has its own row there.
- New fixtures in the vuln-nextjs lab. The lab is a separate repository; add them only on the
  owner's word.

## 5. Decisions

- **D-1. A start is any object binding the scanner can name.** A walk may start from a
  parameter, a local declared in the function, a module-level `const`, `let` or `var`, or a
  member chain of fixed property names rooted at one of those (`holder.state`). The binding must
  never be reassigned.
  **Why.** Every ordinary object reaches `Object.prototype` through `__proto__`, whoever holds
  it. The parameter rule of stage 1 was a boundary of the first implementation, not a property
  of the weakness.
- **D-2. The start object is evidence.** The record carries the declaration of the start as
  context, so a reader and the model see which object is written. Two walks in one function that
  start from different objects are two candidates.
- **D-3. The null-prototype rule moves with the start.** A start declared as
  `Object.create(null)` is `null_prototype_root`, Review. Any other initializer, including a call
  result or an import, is treated as an ordinary object.
  **Why.** Only an explicit null prototype removes the first lookup. Guessing that an unknown
  call returns one would hide real writes.
- **D-4. A walk in the handler is a walk.** Today a walk is read only inside a function that the
  handler calls. A walk written in the handler body, with parts split from a request value, is
  the same write and gets one candidate at its final assignment.
  **Why.** `p5` is how a small application writes it, and the stage 1 nested-write rule already
  reads the handler body directly.
- **D-5. Class fields are an exploration item.** `this.state` in a method needs the method call
  on an instance to resolve to the class. It gets one failing fixture and one attempt. If it
  needs more than the existing call resolution, it is recorded as a limit.

## 6. Agent implementation rules

Follow [execution discipline](../docs/agent-execution-discipline.md). Work one start at a time:
fixture and failing test, then the change, then its guarded, bypass-sibling and control
fixtures. Stop and ask when an existing pollution test would have to change, when a start
cannot be named without tracking values across functions, or when the noise check in AC8 shows
a new record on a keyed control.

## 7. Acceptance criteria

1. **AC1 (baseline).** The eight probes are committed as fixtures. Before any recogniser change,
   a test records one pollution record for `p0` and none for `p1` to `p7`.
2. **AC2 (module-level start).** `p1` and `p4` each yield one `path_walk` candidate whose key
   operand is the path, with the declaration of the start object in its context.
3. **AC3 (local start).** `p2` yields one candidate. The same function walking a constant path
   yields none.
4. **AC4 (property start).** `p3` yields one candidate. A start reached through a computed
   property, `holder[name]`, yields none.
5. **AC5 (walk in the handler).** `p5` yields one candidate at the final assignment, with no
   completeness blocker. The same handler with a constant path yields none.
6. **AC6 (null prototype and reassignment).** `p7` yields one candidate in Review with
   `null_prototype_root`. A start that is reassigned anywhere in the module yields none.
7. **AC7 (guards).** For each of AC2 to AC5: with all of `__proto__`, `constructor` and
   `prototype` rejected, stub answers `protected`, `no_bypass` and `complete` give Protected.
   With only `__proto__` rejected, the record carries `key_guard_incomplete` naming
   `constructor` and the same answers do not give Protected.
8. **AC8 (noise check).** Every JS/TS sample is scanned offline before and after. The results
   list each new pollution record with its location and a source-reviewed verdict: true write,
   false, or unclear. Each true or unclear record gets a key row. No keyed control gains a
   record, and `GOOF-PP-01` and `TS-PP-01` keep exactly one candidate each.
9. **AC9 (class field).** `p6` has a fixture and a recorded outcome: implemented with its tests,
   or a limit with the reason, stated in the guide.
10. **AC10 (isolation and gate).** Existing pollution tests pass unchanged. Other families'
    request digests are unchanged. `gofmt -l cmd internal` prints nothing; `go vet ./...`,
    `go build ./...` and `go test -race ./... -count=1` pass.

## 8. Test strategy

- The AC1 baseline test is written first and inverted start by start.
- One table test over `testdata/pollution/start-*`: per start a vulnerable, guarded,
  bypass-sibling and control function in one small application.
- Policy cases (AC7) extend the stub-answer test that already covers every shape fixture.
- The noise check (AC8) is a recorded run against the pinned sample checkouts, not a committed
  test. It is the main evidence for this contract, because the change adds records by design.

## 9. Execution sequence

1. Copy the probes into `internal/langjs/testdata/pollution/` and write the AC1 test.
2. Module-level and local starts for the loop walks, then the `reduce`, `forEach`, `while` and
   recursive forms (AC2, AC3). The start resolution is shared, so the forms should follow from
   one change. Confirm each with a fixture.
3. Property starts (AC4), then the null-prototype and reassignment rules (AC6).
4. Walks in the handler (AC5).
5. Guards and policy (AC7). Run the noise check (AC8) and review every new record.
6. The class-field attempt (AC9). Docs, results and gate (AC10). Draft PR.

## 10. Definition of done

- [ ] AC1 to AC10 verified, with evidence in the run log and the results record.
- [ ] The guide lists the accepted starts, and the capability page drops the closed gap.
- [ ] Section 11.1 of the write shapes contract marks the D-9 row as closed by this contract.
- [ ] Owner review.

## 11. Open questions

- **OQ-1. A start returned by a call.** `const store = getStore()` or an imported object is
  treated as an ordinary object under D-3. Keep that, or record it as Review because the object
  is not visible? Recommendation: keep it raw. A null-prototype object is the rare case and is
  explicit where it is used.
- **OQ-2. How many new sample records are acceptable.** AC8 reviews each one. Should a number
  above some bound stop the change for a second look at D-1? Recommendation: stop and ask the
  owner above ten new records across the six samples.
- **OQ-3. Lab fixtures.** Add module-level and handler walks to the vuln-nextjs lab's pollution
  fixtures and to its published sample? Recommendation: yes, after this contract passes its
  noise check, in a separate change to the lab.

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, each start's failing-first evidence, the
before and after sample counts for AC8 with the reviewed verdicts, and the outcome of the
class-field attempt.

## 13. Agent implementation prompt

> Work in the worktree and on the branch the owner assigns. Read AGENTS.md, the orientation
> contents, `prototype-pollution.md`, `pollution-write-shapes.md` and this spec. Copy the probes
> from the container's `_test-findings/pollution-walk-start/probes/` into
> `internal/langjs/testdata/pollution/` and write the AC1 baseline test first. Then follow
> section 9 one start at a time, test-first, each with its guarded, bypass-sibling and control
> fixtures. Run the AC8 noise check before the class-field attempt and review every new record
> against its source. Make no paid call, install nothing, and commit only when the owner asks.
> Verifier: a fresh-context subagent reruns the eight probes, runs each vulnerable fixture in
> Node with a prototype payload, confirms no bypass-sibling fixture can be Protected, and
> reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-21 — Drafted

Requested by the owner while reviewing the write shapes decisions. Written from that review,
from the walk recognisers at `ed94711`, and from eight probe fixtures scanned at that revision.
The handler-walk probe showed a second limit, recorded as D-4. No code changed.
