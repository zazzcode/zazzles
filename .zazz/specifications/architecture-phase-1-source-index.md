# Architecture phase 1 — Source index and callable summaries

**Worktree / branch:** `arch-review-clean-up` (owner decision 2026-11-17; phases 0–3 share it)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 1. Objective: **speed and accuracy**
**Replaces:** [registration graph](architecture-phase-1-registration-graph.md) (superseded 2026-11-17, owner decision)
**Depends on:** phase 0 (`TestArchitectureBaseline`) committed on `arch-review-clean-up` with green gates
**Delivery topology:** this spec holds the design for all languages and the contract for step 1A. Steps 1B–1E each get
a short contract section here, filled in before they start. Their commits join the milestone draft PR into `stage`.
**Coordination:** Lead Agent. Contributor Agents may own disjoint per-language files within one step.
**Run log:** `.zazz/ephemeral/architecture-phase-1-source-index-run-log.md`
**Drafted:** 2026-11-17

## 1. Why the registration graph was replaced

The owner asked for structures that improve **accuracy or speed**, and reliability, for every
supported language (JS/TS, Python, PHP) and for the planned library mode, Symfony and Drupal work.
The registration graph indexed the entry catalog: entries, registrations, dispatch bindings and
callables. That catalog is small (at most about 11k records on vulnpy) and never on the hot path.
It is also not where recall is lost. The graph changed neither speed nor findings, so it was backed
out. Its uncommitted work is kept only as a local patch in `.zazz/ephemeral/`.

### Measured cost (offline, phase 0 binary, 2026-11-17)

CPU and heap profiles of the full `--analyze --output-dir` path (`go test -cpuprofile/-memprofile`
on a temporary harness, not committed):

| Sample | Wall | Dominant CPU | Dominant allocation |
|---|---|---|---|
| juice-shop | 63 s | `bindingReassigned` **59%** (36.5 s), reached from browser flow (`templateCall` → `libraryObject`, `modelIdentity`, `contractBindingStable`, `nodeReceiver`). Tree-sitter CGo node access (`NamedChild`, `Kind`, `NamedChildCount`) makes up most of it. | `Kind()` string conversion **11.0 GB**, node wrappers **10.0 GB**, branch joins (`combine`, `uniqueGaps`, `tagBranch`, `copyValues`) about **7 GB** |
| vulnpy | 8.1 s | Bundle writing **43%** (HTML 31%); analysis is 2.3 s | JSON re-encoding while writing the bundle (`reformatValue`, `AppendIndent`, `slices.Grow`), about **4 GB**; peak RSS 2.1 GiB |

`bindingReassigned` (`internal/parse/commonjs.go`) answers "is this name reassigned in this
module?" by walking the whole module tree through CGo on every call. It has 78 call sites, many
of them inside per-call and per-branch evaluation. The cost is quadratic in file size times
evaluation count. Python and PHP have the same pattern in smaller form: `pyWalk` is 13% of vulnpy
analysis.

### Measured recall loss (phase 0 bundles)

| Sample | Largest gap kinds on candidate flows |
|---|---|
| juice-shop | `unknown_value` 1,457 · `unknown_call_result` 1,272 · `async_response_unresolved` 433 · `middleware_unresolved` 205 (+113 on entries) · `path_unrelated_helper_limit` 201 · `parse_error` 39 files |
| DVWA | `php_value_unresolved` 620 · `php_call_unresolved` 210 · `php_dynamic_include` 197 · `transfer_limit` 151 |
| vulnpy | `python_value_unresolved` 634 · `python_dispatch_unresolved` 389 · `python_call_unresolved` 131 · `python_comprehension_unresolved` 128 · `work_limit` 64 |

All three languages follow calls the same way. Each call site re-analyzes the callee body inline
for every entry that reaches it, under a depth limit of 3 and a per-entry budget: `helperExpansion{budget: 24}`
in JS, `depth >= 3 || work >= 24` in Python, and `phpHelperDepthLimit`/`phpHelperWorkLimit` in PHP.
The same helper is therefore analyzed once per route per call site. Calls past the limit, and calls
the per-language resolver cannot bind, become gaps. Those gaps are the misses above, and the
repeated walks are part of the cost.

## 2. Design

One layered source index, built once per scan. Each layer has one owner and one consumer, and
each layer's output is immutable after it is built.

```text
L0 inventory      one directory walk: files, language, hash                  (exists: internal/walk)
L1 syntax index   per file: flat node arrays, integer kinds, spans           NEW  (speed)
L2 binding index  per file: scopes, declarations, writes, imports, exports   NEW  (speed, correctness)
L3 call index     repository: modules, callables, call sites -> callees     NEW  (accuracy)
L4 summaries      per callable: parameter -> return / sink / store facts    NEW  (accuracy, speed)
L5 entry adapters frameworks and library exports produce entries -> callables (exists; extended)
L6 claims, judge, reports                                                   (exists; request bytes stable)
```

### L1 Syntax index (per file)

Parse once with Tree-sitter, then copy the tree into Go-native arrays: `kind uint16` (from
`Node.KindId()`), `field uint16`, `parent`, `firstChild`/`childCount` into a child array, byte and
line spans, and a `named` bit. Each language's kind names are interned once into a small table, so
a check is `n.Kind == js.Identifier`, an integer compare with no CGo call and no string allocation.
Evaluation code walks the arrays. The Tree-sitter tree stays available for `.scm` queries until
each caller migrates. Text is a byte slice of the shared source, never a copy.

Reason: CGo node access and `Kind()` string conversion account for most of the 21 GB that
juice-shop allocates. A flat array walk is roughly an order of magnitude cheaper per node, and it
is deterministic.

### L2 Binding index (per file)

One pass over L1 records lexical scopes; declarations (`const`/`let`/`var`/function/class/param/
import, Python assignment/def/class/import/global/nonlocal, PHP variable/function/class/use/
global/static); every write to a binding (assignment, augmented assignment, destructuring,
`for`-binding, `catch`); reads resolved to their declaration; imports and exports, including
re-exports, `export *` and CommonJS `module.exports`/`exports.x`; and PHP namespace and `use` aliases.

Queries are O(1) or O(log n): `Reassigned(binding)`, `Writes(binding)`, `Resolve(name, at)`,
`Shadowed(name, at)`, `Exports()`, `Import(name)`. They replace whole-module walks such as
`bindingReassigned`, `shadowed`, and ad hoc `funcs`/`exports`/`imports` maps where those are rebuilt per query.

Reliability rule: L2 answers only what the syntax states. A binding written through `eval`,
`with`, `globals()`, `$$var`, `extract()` or reflection is marked **dynamically writable**, and every query on
it answers "unknown", which existing callers already turn into gaps. The index never guesses that a
binding is stable.

### L3 Call index (repository)

- **Module graph.** JS/TS: ESM, CommonJS, re-exports and barrels, `tsconfig` `paths`/`baseUrl`,
  and `package.json` `exports`/`main` for in-repository packages. Python: package-relative and
  absolute imports under the scan root. PHP: `include`/`require` with literal or constant paths,
  plus PSR-4 autoload from `composer.json`, which Symfony and Drupal need.
- **Callable table.** Every function, method, arrow function and closure, keyed by the existing
  `SnapshotRecordID("callable", …)` so report IDs do not change.
- **Call sites.** Each site gets zero or more callee callables and a **resolution**:
  `direct`, `imported`, `method_on_known_class` (receiver type from a constructor, an annotation or a
  typed property), `container_service` (Symfony/Drupal service ID to class), or `unresolved` with a
  reason. Unresolved sites are explicit records, never dropped.
- Dispatch tables, factories and middleware chains that entry adapters already model are expressed
  as call sites with `resolution = table|factory|middleware`. The flow then sees them the same way
  as any other call.

### L4 Callable summaries

A summary is a context-insensitive, parameter-indexed description of what a callable does with
its inputs. It is computed **once per callable**, bottom-up over strongly connected components of
the L3 call graph, in deterministic key order:

- `param[i] -> return`, with the ordered transform chain and evidence spans;
- `param[i] -> sink(family, argument position)`, with the sink binding evidence;
- `param[i] -> store(key)`: server-held stores, model fields and session;
- source acquisitions inside the callable, such as `request.args` in a helper that reads the ambient request;
- controls observed on `param[i]` (validator, cast, encoder, allowlist test), as **facts with
  evidence**, never a "safe" bit. Protection stays per value, use and path;
- unresolved effects: calls with `unresolved` resolution, dynamic writes and size limits, as gaps
  with evidence.

At a call site, the flow substitutes the caller's argument values into the summary instead of
re-entering the callee body. The depth-3 and budget-24 limits are replaced by per-summary size
limits. An oversized summary keeps its facts and adds a `summary_limit` gap; it does not stop
the caller's analysis. A recursive SCC iterates to a fixpoint over a finite lattice (sets of
parameter indexes and transform IDs), capped at a fixed iteration count. Hitting the cap adds
`summary_fixpoint_limit`.

**Witness reconstruction.** A candidate still needs one concrete, source-backed path for its judge
request. Summaries keep span references, and witness assembly expands the path
(caller argument → callee parameter → … → sink) into the same `analysis.Evidence` records the
inline engine produces today. For a path the inline engine already handled, the resulting
evidence and request bytes are identical; the phase 0 golden checks this.

### L5 Entry adapters (frameworks and library mode)

Adapters stop doing flow. They produce entries and bind each entry's sources to a callable's
parameters or ambient acquisitions. Analysis of every entry is then "apply this callable's summary
with these source bindings".

- **Existing:** Express/Fastify/Hapi/Next.js, Flask/FastAPI/Django/Pyramid/…, PHP file entries.
- **Library mode (npm, later PyPI and Packagist):** `package.json` `exports`/`main` become entries
  whose callable is the exported function. Each parameter is a `caller_argument` source. A summary
  fact `param[k] -> sink` is the library finding, with no route needed. This is why summaries come
  before library mode.
- **Symfony:** `#[Route]` attributes, YAML/XML/PHP route files, controllers as services, and
  `Request` and argument-resolver parameters as sources. `services.yaml` and autowiring feed L3
  `container_service` resolution.
- **Drupal:** `*.routing.yml` `_controller`/`_form` callbacks, `hook_*` implementations, Form API
  `submitForm`/`validateForm`, and `\Drupal::service()` and constructor injection resolved through
  `*.services.yml`.

Framework knowledge is **data** (versioned model tables for sources, sinks, controls, route
syntax and service wiring), so a framework is mostly added as tables plus a thin adapter, never a
new analyzer. Source, sink and control models stay in `internal/analysispacks`.

### Efficiency rules

- Parse each file once. L1 and L2 are built per file in parallel. L3 and L4 merge results in
  sorted key order, so the output does not depend on scheduling.
- Branch joins use interned dependency and gap IDs with sorted small slices or bitsets instead of
  copying `[]analysis.Dependency` and `[]analysis.Gap` per branch (the 7 GB above).
- Evidence is a span reference until a report or request needs the text.
- A bundle encodes the report once and reuses the bytes for JSON, HTML and SARIF inputs, which is
  vulnpy's 43%.
- Phase 2 concurrent runners and phase 4 parallel judge stay as planned. They are independent of
  this design and compose with it.

### Reliability rules

- Determinism: every index is built in sorted key order, and parallel builds merge by key. The
  phase 0 golden must match byte for byte unless a step lists a delta.
- **Shadow mode before switch-over.** Each new layer first runs beside the code it replaces and
  asserts equal answers on every fixture and sample (the differential tests in §7). The old path is
  deleted only after parity.
- Recall deltas are reviewed, never blind `-update`s. A new candidate or a resolved gap is checked
  against the sample answer keys (`docs/samples/*`, detection guides) and recorded in the
  evaluation file. Changed evidence gets new judgments.
- Every limit produces a named gap with evidence. Nothing is silently truncated.

## 3. Delivery steps

| Step | Scope | Objective | Golden |
|---|---|---|---|
| **1A** | L1 + L2 for JS/TS; replace `bindingReassigned` and the other whole-module walks on the browser/flow hot path | Speed (juice-shop) | Byte-identical |
| 1B | L1 + L2 for Python and PHP; replace `pyWalk` and PHP equivalents on hot paths; bundle encode-once | Speed (vulnpy, DVWA) | Byte-identical |
| 1C | L3 call index for all three languages, in measurement mode: report call-site resolution rates per sample; no flow change | Accuracy baseline | Byte-identical |
| 1D | Production L3 call index for JS/TS and Python, with receiver typing and a typed-method effect table that flow reads at its unresolved-call points | Accuracy | Listed deltas only |
| 1E | L4 summaries for JS/TS: shadow mode, then switch-over; remove inline helper expansion | Accuracy + speed | Listed recall deltas only |
| 1F | L4 summaries for Python and PHP; PHP builtin effect tables; Symfony/Drupal L3 inputs (PSR-4, service maps) | Accuracy + speed | Listed recall deltas only |

Later plan phases: library mode (phase 8) needs 1E. Symfony (6) and Drupal (9) need 1F and
phase 3. Phase 5 (recall gaps) uses the 1C resolution report as its inventory. Express middleware
chain composition (juice-shop `middleware_unresolved`, 318) is an L5 adapter item for phase 5, not
call resolution.

## 4. Step 1A scope (the current contract)

| Path | New / modified | Purpose |
|---|---|---|
| `internal/parse/syntax_index.go`, `syntax_index_test.go` | new | L1 flat node arrays from a Tree-sitter tree; interned JS/TS kinds |
| `internal/parse/binding_index.go`, `binding_index_test.go` | new | L2 scopes, declarations, writes, imports/exports, dynamic-write marking for JS/TS |
| `internal/parse/modules.go` | modified | Build L1/L2 once per loaded module |
| `internal/parse/commonjs.go` and the hot-path callers of `bindingReassigned`, `shadowed`, `walkCalls` | modified | Query L2/L1 instead of re-walking; listed per file in the run log before editing |
| `internal/parse/binding_parity_test.go` | new | Differential test: old walk and L2 answers agree on every JS/TS fixture and on juice-shop when `ZAZZLES_JUICE_SHOP` is set |
| `.zazz/evaluation/architecture-baseline.md` | modified | After measurements |
| `.zazz/architecture/README.md` §3 and §11, `.zazz/architecture/repository-graph.md` | modified | Source index layers; implemented versus planned |

Out of scope for 1A: Python and PHP indexes, the call index, summaries, flow semantics, report fields and judge requests.

## 5. Decisions

- **D-1 Index in `internal/parse` first.** L1 and L2 are parser-adjacent and consumed only by
  `parse`. When phase 3 splits languages into packages, the shared index types move to a leaf
  `internal/source` package. A package with no second consumer now would be the "no machinery
  without a consumer" mistake.
- **D-2 Integer kinds from `KindId()`, interned per grammar.** This removes the CGo and string cost.
  Kind constants are generated from each grammar's node-type list at init, and a missing name fails
  at init, not at query time.
- **D-3 L2 is syntactic and conservative.** It never claims a binding is stable when dynamic writes
  are possible. Unknown stays unknown.
- **D-4 Shadow mode, then delete.** Each replaced walk keeps its old implementation in test code
  until the parity test passes on every fixture and on juice-shop. After that the old code is removed.
- **D-5 Summaries are context-insensitive and parameter-indexed.** They are applied with
  caller-specific arguments. This keeps one summary per callable (speed), and the per-use witness
  keeps evidence specific to each path (accuracy). Context-sensitive cloning is rejected because it
  brings back per-route cost.
- **D-6 No graph database, no third-party graph library, no general heap engine.** These carry
  over from the plan's shared rules.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Any phase 0 golden change in 1A–1C.
- A parity test disagreement that is not a bug in the old walk. If it is an old-walk bug, record it
  and ask before fixing, because fixing it changes output.
- A new recall delta in 1D or 1E that the answer keys or detection guides do not support.

## 7. Acceptance criteria (step 1A)

1. **AC1 L1.** For every JS/TS fixture file, the flat index yields the same node sequence, kinds,
   fields and spans as a Tree-sitter walk. Table-driven test over the fixtures.
2. **AC2 L2.** Hand-written cases cover declarations, shadowing, reassignment through every write
   form, re-exports, CommonJS exports, and dynamic writes (`eval`/`with`), where the answer must be unknown.
3. **AC3 Parity.** `binding_parity_test.go` shows that `Reassigned`, `Shadowed` and `Resolve` agree with
   the old walks for every binding in every JS/TS fixture. With `ZAZZLES_JUICE_SHOP` set, the same
   holds on juice-shop.
4. **AC4 Golden.** `TestArchitectureBaseline` passes with no update.
5. **AC5 Speed.** The juice-shop offline median of 3 runs (phase 0 method) is at most 25 s, against
   64.16 s before. Peak RSS does not increase. vulnpy and DVWA do not regress by more than 5%.
6. **AC6 Gate.** The contributor gate passes, and the docs list L1/L2 as implemented and L3/L4 as planned.

AC5's target comes from the profile: the replaced walk is 59% of CPU, and CGo/`Kind()` cost spans
most of the rest. If the measured gain is smaller, record the new profile and ask before changing scope.

## 8. Step contracts 1B–1F (outline; complete before each starts)

- **1B:** the same ACs for Python and PHP (vulnpy target ≤ 5 s, DVWA no regression). Bundle encode-once
  keeps bundle bytes identical.
- **1C (contract):** measurement only, with no production change. An env-gated test harness,
  `internal/parse/call_resolution_measure_test.go` (`ZAZZLES_MEASURE_ROOT`, optional
  `ZAZZLES_MEASURE_OUT`), loads every JS/TS, Python and PHP module of a target with the analyzers'
  own module sets. It classifies every call site with the analyzers' own resolvers
  (`moduleSet.resolveCall`; `pythonSet.resolve`/`funcs`; PHP `funcs`, unique cross-module functions
  and classes) into: `in_repo` (a definition is found); `in_repo_member_unresolved` (the callee
  root is an in-repository module or class, but the member is not found); `package` (the callee root
  is an import from outside the repository, or a PHP class not defined in it); `builtin` (an unbound
  global or builtin name); `member_on_value` (a method on a local value whose type is unknown); and
  `dynamic` (any other callee expression). It also attributes every call-related gap on candidate
  flows (the gap's span is a call node) to the same classes. ACs: (1) the harness runs on
  juice-shop, vulnpy and DVWA and writes `_test-findings/<app>/run-arch-1c/call-resolution.json`;
  (2) the evaluation record gets, per sample, the call-site class counts and the gap-kind × class
  table; (3) the golden is unchanged and there is no production diff. The production call index is
  promoted in 1D, where summaries consume it.
- **1D:** see [§8a](#8a-step-1d-contract-call-index-and-receiver-typing).
- **1E:** a shadow run on every JS/TS fixture and juice-shop proves that summary-applied flow
  reproduces the inline results wherever inline resolved the call. Each new candidate or removed
  gap is listed, with answer-key evidence. `helper_call_limit` and `path_unrelated_helper_limit`
  no longer occur on fixtures. Target: juice-shop's 559 limit-induced in-repository gaps (1C).
- **1F:** the same for Python and PHP, plus PHP builtin effect tables (DVWA's 210
  `php_call_unresolved`) and PSR-4 and service-map resolution. Symfony and Drupal fixtures are added
  under `internal/parse/testdata/php/`.

## 8a. Step 1D contract: call index and receiver typing

### Evidence

The 1C measurement attributes the largest class of call gaps to methods on values of unknown type:
713 on juice-shop and 582 on vulnpy, plus 313 vulnpy `input_validation_unresolved`. By callee
(phase 1B bundles), the gaps concentrate on a few typed receivers:

| Sample | Gap | Top callees |
|---|---|---|
| juice-shop | `unknown_call_result` 1,272 | `challenge.save` 280 (Sequelize instance), `HintModel.count` 140 (Sequelize model), `os.hostname`/`type`/`release` 210 (Node builtin), `config.get` 108 (package), `new Date` 74, `JSON.stringify` 70 (builtins), `req.header` 64 (framework request) |
| vulnpy | `python_dispatch_unresolved` 523 | `response.append` 314 (local `list`), `trigger_name.replace` 64 (local `str`) |
| vulnpy | `python_call_unresolved` 131 | `trigger_name.replace` 64 (`str`), `getattr` 64 (dynamic) |

### Scope

| Path | New / modified | Purpose |
|---|---|---|
| `internal/parse/call_index.go`, `call_index_test.go` | new | Per-module JS/TS and Python call index, built once per module: call site → resolution `{kind, target, receiver type, reason}` |
| `internal/parse/receiver_types.go`, `receiver_types_test.go` | new | Receiver type facts from binding-stable declarations: literals, imports, `new`/constructor calls, Sequelize model identity and finder results, framework request and response parameters |
| `internal/parse/call_effects.go` | new | Closed effect table keyed by (receiver type, method): `independent_result`, `receiver_transfer`, `argument_transfer(i)`, `container_write(i)`, `unknown` |
| `internal/parse/flow.go`, `python_calls.go` | modified | At the existing `unknown_call_result`, `python_call_unresolved` and `python_dispatch_unresolved` emission points only: apply the indexed effect when one exists; otherwise keep the gap exactly as today |
| `internal/parse/call_resolution_measure_test.go` | modified | Classify from the production index; add the typed classes |
| `cmd/scan/testdata/architecture-baseline.json`, affected parse goldens | modified | Listed deltas only (AC3) |
| `.zazz/evaluation/architecture-baseline.md`, `.zazz/architecture/README.md`, `repository-graph.md` | modified | Results; implemented L3 subset |

Out of scope: summaries (1E), PHP (1F), middleware chains (phase 5), judge request wire changes,
and new candidate families.

### Decisions

- **D-7 Resolution kinds:** `direct`, `imported`, `method_on_known_class(type)`, `builtin_method(type)`,
  `package_member(module)`, and `unresolved(reason)`, where the reason is `dynamic_callee`,
  `unknown_receiver`, `unknown_import_member`, `ambiguous` or `dynamic_write`.
  `in_repo` parity: wherever `resolveCall` or `pythonSet.resolve` finds a definition today, the
  index gives the same target.
- **D-8 Receiver typing is conservative.** A type comes only from a declaration that the binding
  index shows is never reassigned, written through or dynamically writable. Anything else is
  `unknown_receiver`. Types are never inferred from method names.
- **D-9 Effects are flow facts, never protection.** No effect marks a value safe or validated.
  `independent_result` means only "the result carries none of the receiver's or arguments'
  dependencies, and no request source" (for example `os.hostname()`). It never removes a dependency
  that a caller already holds. `container_write(i)` adds argument i's dependencies to the receiver
  value. The table is closed, and a method missing from it stays `unknown`.
- **D-10 Framework request objects keep their acquisition models.** `req.header` and similar stay
  owned by the Node input models. The index only routes the call to them.

### Acceptance criteria

1. **AC1 Index.** `call_index_test.go` has table cases for each kind and reason: reassigned and
   dynamically written receivers resolve to `unresolved`; shadowed names; re-exports; and Python
   `from x import y`. Parity: the index target equals `resolveCall`/`pythonSet.resolve` on every
   fixture call site where those resolve (and on juice-shop and vulnpy with their env vars).
2. **AC2 Effects reach flow.** On juice-shop, `unknown_call_result` is at most 800 (1,272 before).
   On vulnpy, `python_dispatch_unresolved` is at most 250 (523 before). Every removed gap is replaced
   by an effect from the table, and the 1D harness lists the effect counts.
3. **AC3 Listed deltas only.** The architecture golden and parse goldens change only for uses whose
   gaps, dependencies or evidence changed through an AC2 effect. The run log lists each changed
   fixture, with a JSON diff excerpt. No candidate is removed. Each new candidate is checked against
   the sample answer keys and detection guides before commit. An unsupported new candidate is a halt.
4. **AC4 No speed regression.** The 3-run medians on juice-shop, vulnpy and DVWA are within 5% of
   step 1B, or faster.
5. **AC5 Gate and docs.** The contributor gate passes. The architecture README and repository-graph
   document list L3 as implemented for JS/TS and Python.

### Halts (in addition to §6)

- A removed candidate, or a new candidate that the answer keys or detection guides do not support.
- A type assigned to a binding that the binding index shows can be written.
- An effect that would need a new judge request field.

### Execution sequence

1. Red: AC1 table cases. Then implement `receiver_types.go` and `call_index.go`, with no flow change,
   and run the parity test plus the golden (byte-identical at this point).
2. Switch the measurement harness to the index, and record the typed-class tables.
3. Red: effect cases per table row. Implement `call_effects.go`, and wire the three emission points.
4. Regenerate goldens, review each delta (AC3), and check new candidates against the answer keys.
5. Measure AC2 and AC4. Write docs, run the gate and verifier, then commit and push.

## 9. TDD entry point and execution sequence (step 1A)

1. Red: AC1 test over fixtures against an empty `syntax_index.go`.
2. Implement L1 and the interned kinds. AC1 green.
3. Red: AC2 cases. Implement L2 for JS/TS. AC2 green.
4. List every hot-path caller of `bindingReassigned`, `shadowed` and similar whole-module walks (profile
   plus grep) in the run log. Add `binding_parity_test.go` (AC3).
5. Switch callers one file at a time. After each, run `TestArchitectureBaseline` and the parse tests.
6. Remove the old walks once AC3 is green. Re-profile juice-shop and measure AC5.
7. Docs, gate, commit, push.

## 10. Definition of done (step 1A)

- [ ] AC1–AC6, with evidence in the run log.
- [ ] `git diff <step start> --stat` matches §4.
- [ ] The run log lists replaced call sites, before and after profiles, and the golden unchanged.

## 11. Open questions

1. Does the owner want 1B's bundle encode-once in this phase, or kept with phase 2's output work? Default: 1B.
2. Library mode scope beyond npm (PyPI, Packagist) after phase 8: not needed for 1A–1E.

## 12. Run log protocol

Use the plan's common rules. Record the profiles, the replaced call-site list, parity results and
measurements.

## 13. Agent implementation prompt (step 1A)

> Work in the `arch-review-clean-up` worktree. Confirm the phase 0 commits are on the branch and its run log shows
> green gates, and record the starting HEAD. Read AGENTS.md, the orientation contents, the plan,
> and this spec (§1–§7 and §9). Execute §9 in order, TDD first. Keep `TestArchitectureBaseline` green after
> every caller switch. Stop on any §6 halt. Finish with the gate, measurements, commit and push.
> Verifier: a fresh-context subagent re-runs `go test -race ./internal/parse ./cmd/scan -count=1`,
> confirms the golden is unchanged since phase 0, checks AC5 numbers against the evaluation
> record, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-17 — Replaces the registration graph

Source: owner, in the phase 0–1 session ("I only want what improves accuracy or speed"; "back out
the graph idea and build something better"). The registration-graph spec is superseded. Its
classification fields, `internal/graph` package and PHP callable-language fix were not committed.
The PHP label fix can be filed as a separate one-line correctness change. Profiles and gap counts
in §1 come from phase 0 binaries and bundles on the pinned samples. Specs that cite registration-graph D-5/D-7
(phases 5, 6, 8, 9) are repointed to this spec's L3 resolution kinds and L5 model tables when each of
them starts.

### 2026-11-17 — Step 1A implemented

Source: implementation. Changed against §4, §7 and §9:

- **L2 shipped as the binding write index** (`internal/parse/binding_index.go`). It records
  identifier assignment targets, written member paths (with `.`/`[` prefixes), aliasing
  declarators and escaping uses. `bindingReassigned` and `contractBindingStable` read it. Scope
  resolution and declarations were not built: they have no consumer before 1C, and a scope-aware
  answer would change output, because both functions are name-based and module-wide by contract.
- **L1 (flat syntax index) was not built in 1A.** The write index alone met AC5's wall-clock target
  (64.16 s → 10.19 s on juice-shop), and the remaining profile is flow evaluation, not whole-module
  walks. L1 moves to the step that converts flow evaluation, and AC1 moves with it.
- AC2 and AC3 are covered by `binding_parity_test.go`, with the old walks as oracles: 531 names in
  47 fixture files, and 17,479 names in 704 juice-shop files with `ZAZZLES_JUICE_SHOP`.
  Single-use escape checks are capped at 4 uses per name, because the oracle walks the module once per call.
- AC5's RSS clause is a near miss: juice-shop max RSS 255 → 276 MiB (median 238 → 251 MiB).
  The owner decides whether to accept it or to compact the index.
- The `contractBindings` per-module cache was removed; the index replaces it.

Verification impact: `TestArchitectureBaseline` is unchanged, and juice-shop JSON and SARIF are
byte-identical. Measurements are in `.zazz/evaluation/architecture-baseline.md`.


### 2026-11-17 — PHP callable language (owner request)

Source: owner ("make sure to fix … the PHP callable-language fix"). `registerInvocation` takes the
callable language from `internal/lang` detection instead of an extension `if` chain that labelled PHP
callables `javascript`. Unknown extensions keep `javascript`. Listed golden delta: `report_sha256`
only, for `php/{code,command,includes,path,routes,sql,xss}` and `mixed/three-language`. Request
digests, signatures, use rows, counts and SARIF hashes are unchanged; the judge does not read
callables. Report diff: `"language": "javascript"` → `"php"` on PHP callables only.

### 2026-11-17 — Step 1B implemented

Source: implementation, after a profile of the step 1A binary. Changed against §3 and §8 (1B):

- **The bundle cost was syscalls, not encoding.** `WriteBundle` now buffers each output file
  (`internal/report/bundle.go`). No encode-once change was needed. All bundle bytes are identical.
- **Python hot walk:** `mountPrefix` and `dynamicMounts` re-walked every Python module for each
  route. A per-module `mountCalls` index (`python_modules.go`) replaces that. Parity:
  `python_index_parity_test.go` checks the index against the old walk, under both callers' filters,
  on 19 fixture modules and on 113 vulnpy modules with `ZAZZLES_VULNPY`.
- **PHP:** the DVWA scan is 0.61 s, and no PHP whole-module walk is hot, so no PHP index was added.
  The PHP binding index moves to the step that first needs PHP binding queries (1C/1E).
- Results: vulnpy 3.49 s (target at most 5 s), DVWA 0.61 s, juice-shop 9.89 s. The golden is unchanged
  after the PHP-fix commit. File scope: `internal/report/bundle.go`, `internal/parse/python_modules.go`,
  `python_routes.go`, `python_dynamic_registrations.go`, `python_index_parity_test.go`, and docs.


### 2026-11-18 — Step 1C measured; 1D reprioritized

Source: step 1C measurement
([evaluation](../evaluation/architecture-baseline.md#phase-1-step-1c-call-site-resolution-2026-11-18)).
`call_resolution_measure_test.go` was added. It is test-only, there is no production diff, and the
golden is unchanged. Findings:

- Summaries close the limit-induced gaps on in-repository callables: juice-shop 559 and vulnpy 64.
- The largest class is methods on values of unknown type: juice-shop 713 (including all 318
  `middleware_unresolved`), and vulnpy 582 (515 `python_dispatch_unresolved`).
- Package and builtin calls need model tables: juice-shop 337 package and 150 builtin; all 210 DVWA
  `php_call_unresolved` gaps are PHP builtins.

Impact on 1D: build the production call index first, with `method_on_known_class` receiver typing
(constructor, import and annotation facts) as its first resolution kind beyond direct and imported
calls. Then build summaries for JS/TS in shadow mode. Builtin and package model-table growth is a
parallel accuracy track, owned per language in `internal/analysispacks`. The 1D contract is
written against these numbers before it starts.

Docs updated: `.zazz/architecture/repository-graph.md` (abandoned graph data model, and why the source
index is better), `.zazz/architecture/README.md` §3 and the graph storage decision, and
`docs/technical-approach.md` (engine structure and performance).

### 2026-11-18 — Step 1D contract written; steps renumbered

Source: owner ("Write 1D contract") and the 1C measurement. 1D is now the production call index with
receiver typing and a closed effect table (§8a). The JS/TS summaries move to 1E. Python and PHP
summaries, PHP builtin effect tables and Symfony/Drupal resolution move to 1F. Library mode now
depends on 1E, and Symfony and Drupal on 1F.

### 2026-11-18 — Step 1D implemented

Source: implementation of §8a. Files: `internal/parse/call_index.go`, `call_effects.go`,
`python_binding_index.go`, `call_index_test.go`, one-line hooks in `flow.go` (the
`unknown_call_result` point) and `python_calls.go` (before the generic method fallback), caches
in `modules.go`/`python_modules.go`, and the harness's index counts.

Deviations from §8a:
- Receiver types come from the existing binding facts, not a separate `receiver_types.go`. JS uses
  `bindingWrites` plus `modelIdentity` and import bindings. Python uses a new name-based
  `pythonBindingIndex` (single write, list literal, not aliased, no `global`/`nonlocal`, no dynamic writes).
- The effect table holds two effects: `independent_result` (JS, applied only where a call already
  has no dependencies) and `container_write` (Python `append`/`extend`/`insert` on a local list).
  The other effect kinds in §8a are deferred to the steps that need them.
- AC1 parity holds by construction: the index calls `resolveCall` first and keeps its result.

Results: juice-shop `unknown_call_result` 1,272 → 668; vulnpy `python_dispatch_unresolved` 523 → 81.
Gaps were only removed. No candidate was added or removed by (kind, entry, sink). 125 vulnpy
input-validation candidates were re-keyed by changed evidence. Speed is within 5% of 1B. A new
fixture shows a recall gain. Details are in the evaluation record.

Verifier notes, accepted as known limits for later tightening:
- **Shadowing forms:** `shadowed()` does not see single-parameter arrows, destructured parameters,
  `catch` bindings or `for…of` names. A shadowing local with request dependencies is unaffected,
  because the effect applies only to calls with no dependencies.
- **`module:config`:** an in-repository `config` module reached only through a tsconfig path alias
  would be typed as the `config` package.
- **`sequelize_model.count`:** returns a stored aggregate (a number). This is accepted for gap suppression.
- **Python aliases:** aliasing through call arguments, returns or containers is missed. A missed alias
  is a missed dependency, never a false finding, which matches the previous behavior.

