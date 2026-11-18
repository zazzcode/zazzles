# Architecture phase 1 — Registration graph (superseded)

**Status:** Superseded 2026-11-17 by [source index and callable summaries](architecture-phase-1-source-index.md).
Not implemented. Kept as the record of the rejected design; do not execute.

**Worktree / branch:** `arch-review-clean-up` (owner decision 2026-11-17; phases 0–3 share it)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 1. Objective: maintainability, with registration facts made visible
**Depends on:** phase 0 committed on `arch-review-clean-up` with green gates
**Delivery topology:** one deliverable; its commits join the phases 0–3 milestone draft PR into `stage`
**Coordination:** Lead Agent. One Contributor Agent may own `internal/graph` and its tests while the lead does the integration
**Run log:** `.zazz/ephemeral/architecture-phase-1-registration-graph-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

This is a representation migration with no new route recall. A new leaf package,
`internal/graph`, holds an immutable, indexed, deterministic store of the finalized entry catalog:
entries, registrations, dispatch bindings, callables, and invocation contexts. Its typed relations
are validated at build time. The catalog's canonical order, reference validation, entry gap
projection, handler lookup, and entry selection read from it, replacing ad hoc maps and linear scans.

Each registration gains a separate **origin** (static/dynamic/unknown), **path shape**
(literal/framework pattern/symbolic/unknown/not applicable), and **resolution**
(resolved/partial/unresolved) in JSON and SARIF. The PHP callable language label is corrected.
Request bytes and candidate IDs do not change.

## 2. Required reading

- Plan [what already exists](architecture-update-plan.md#what-already-exists),
  [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).
- [Repository graph](../architecture/repository-graph.md#canonical-records-and-views),
  [identity and provenance](../architecture/repository-graph.md#source-locations-identity-and-provenance).
- [Architecture §4](../architecture.md#4-normalized-representation-and-graph-views),
  [graph storage decision](../architecture.md#graph-storage-decision),
  [entry/dispatch decision](../architecture.md#multiple-entry-and-dispatch-mechanisms).
- Code: `internal/analysis/entries.go`, `entry_ids.go`, `entry_validation.go` (`index()`),
  `report_entries.go` (`Handler`, `EntryGaps`, `SelectEntries`, `validateReferences`);
  `internal/parse/entry_context.go` (`registerInvocation`, `finalizeEntries`).
- [Testing: graph fixtures](../standards/testing.md#5-graph-fixtures), [code structure](../standards/code-structure.md#1-package-layout).
- Container-root `dynamic-route-graph-design.md`, sections "Route origin, path shape and resolution"
  and "Proposed internal representation". These are design input; this spec owns the schema.

## 3. Invariants

- **Byte compatibility.** `TestArchitectureBaseline` matches, except for the AC8 deltas: report and
  SARIF hashes, for every fixture with registrations and for PHP callables. Request digests,
  signatures, use IDs, and counts are unchanged for every fixture.
- **Leaf package.** `internal/graph` imports only the standard library. `internal/analysis` may
  import `internal/graph`. Nothing in `graph` knows about Tree-sitter, HTTP, or judgments.
- **Dense IDs stay internal.** Dense `NodeID`s are process-local. They never appear in JSON,
  SARIF, requests, traces, or record IDs.
- **No fabricated targets.** An unresolved dispatch has no `DISPATCHES_TO` edge and never gets a
  placeholder callable node.
- **Immutability.** A `Snapshot` is immutable after `Freeze`. Catalog mutation after a build means
  building a new snapshot, never patching one in place. `AnalysisReport` holds no hidden cached index.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/graph/graph.go`, `graph_test.go` | new | Kinds, relations, records, `Builder`, `Snapshot`, `Freeze` |
| `internal/analysis/entry_graph.go`, `entry_graph_test.go` | new | `EntryCatalog.Graph()`, `EntryGraph` lookups, registration classification |
| `internal/analysis/entries.go` | modified | `RegistrationClassification` and the `Classification` field; `Canonical` ordered by the graph |
| `internal/analysis/entry_validation.go`, `report_entries.go` | modified | `index()` replaced by graph lookups; `Handler`, `EntryGaps`, `SelectEntries` use `EntryGraph` |
| `internal/report/entries.go`, `sarif.go` | modified only if needed | Build one `EntryGraph` per report instead of per entry |
| `internal/parse/entry_context.go` | modified | Callable language from `internal/lang`; classify after canonicalization |
| `cmd/scan/architecture_baseline_test.go`, `cmd/scan/testdata/architecture-baseline.json` | modified | Regenerated golden with the AC8 deltas; optional `-graph-sample` stats test |
| `internal/parse/python_input_baseline_test.go` golden (`testdata/python/input-baseline.json`) | modified | Regenerated for the additive registration field |
| `.zazz/architecture/repository-graph.md`, `.zazz/architecture.md` (§4, graph storage decision, §11) | modified | Implemented subset versus proposed |
| `docs/interpreting-results.md` | modified only if it lists registration fields | Classification meaning |
| `.zazz/evaluation/architecture-baseline.md` | modified | Graph node/edge counts, build time, and heap delta on samples |

Out of scope:

- candidate nodes;
- value, control, or call edges;
- language packages and concurrency;
- HTML presentation of classification;
- new registration producers;
- judge request changes.

Review shape: one PR.

## 5. Decisions

- **D-1 Persistent identity is the existing `SnapshotRecordID` string.** These IDs are already
  namespaced, versioned, and content-addressed. A second identity scheme would need a mapping
  table and would invite drift.
- **D-2 Dense IDs are assigned once, in `Freeze`.** `Freeze` sorts nodes by (kind, key). Builders
  and fragments hold only persistent keys, so merging fragments needs no ID remapping. Dense IDs are
  then deterministic by construction. Rejected alternative: per-fragment dense IDs with an offset
  remap, which is error-prone and order-dependent.
- **D-3 The graph indexes the catalog; it does not own records.** `NodeRecord{Kind, Key, Ref}`
  points at the record's index in the canonical catalog slice. Edge evidence is a `SpanRef` (file,
  hash, byte range), not a copy of `analysis.Evidence`. The catalog keeps sole ownership of source
  text, so memory does not double. Rejected alternative: copying records into the graph, which
  leaves two sources of truth.
- **D-4 Finalization stays in `parse.finalizeEntries`.** Dedup, use binding, and rekeying run there
  as they do today. The graph is built from the canonical catalog at the end. Classification
  happens after the build, and validation runs as part of it. This puts one finalization point
  ahead of the phase 2 merge seam.
- **D-5 Phase 1 relation set and endpoint table.**

| Relation | From → To | Source field | Resolution | Slot |
|---|---|---|---|---|
| `EXPOSES` | registration → entry | `EntryRegistration.EntryID` | observed | — |
| `HAS_BINDING` | registration → dispatch | `DispatchBinding.RegistrationID` | observed | `stage=<n>;alt=<alternative>` |
| `DISPATCHES_TO` | dispatch → callable | `DispatchBinding.CallableID` when non-empty | resolved | `stage=<n>;alt=<alternative>` |
| `INSTANTIATES` | invocation → dispatch | `InvocationContext.DispatchBindingID` | observed | — |
| `INPUT_FROM_ENTRY` | invocation → entry | `InputBinding.Origin.RelatedEntryID` (inputs, closures, receiver) | observed | `<role>:<parameter>` |

  `Rule` is `catalog@1` for structural relations and `<mechanism>@1` for `DISPATCHES_TO`. The
  names follow the repository-graph relation vocabulary. `HAS_BINDING`, `INSTANTIATES`, and
  `INPUT_FROM_ENTRY` are recorded there as implemented additions.
- **D-6 Duplicates, parallel edges, self-edges, and cycles.**
  - A duplicate node key is an error. Callable dedup already ran in D-4, so a duplicate is a real
    collision.
  - An edge with the same (relation, from, to, slot) and identical attributes collapses to one.
    The same tuple with a different resolution or rule is a conflict error.
  - Edges that differ in relation or slot are kept as parallel edges.
  - Self-edges are allowed only for relations whose table entry sets `AllowSelf`. No phase 1 relation sets it.
  - Cycles are allowed. Phase 1 provides one-hop neighbor queries only, with no traversal.
- **D-7 The classification derivation is a fixed table in `analysis`, computed per registration.**
  - **Origin:** `dynamic` if any binding's mechanism is `table_expansion` or `factory_expansion`.
    Otherwise `static` if every mechanism is one of the known static mechanisms (§9 step 4).
    Otherwise `unknown`.
  - **Path shape:** HTTP entries only. `framework_pattern` if the path contains a `:name`, `{…}`,
    `<…>`, `[…]`, or `*` segment. `literal` if it is non-empty with none of those. `unknown` if it
    is empty. Non-HTTP entries are `not_applicable`. No producer emits a symbolic path today; that
    is recorded as a gap in the docs, not invented.
  - **Resolution:** `unresolved` if no binding has a callable. `resolved` if every binding has a
    callable and neither the registration nor its bindings carry gaps. Otherwise `partial`.

  A table was chosen over producer-set fields so existing adapters need no edits. New producers
  extend the mechanism table.
- **D-8 Expose the classification in JSON and SARIF (additive, `omitempty`), with no schema bump.**
  The field is optional and readers of schema 1–4 ignore it. HTML is deferred because the owner
  has not chosen a presentation. Classification is not added to judge requests: the request wire
  already carries `mechanism` and `resolution`.
- **D-9 Callable language comes from `internal/lang` detection.** This fixes PHP and keeps the
  JS/TS/Python labels as they are. It is a listed report delta, not hidden cleanup.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Any request digest or use ID changes.
- Any fixture produces a D-6 conflict or duplicate-key error. That is an existing data defect;
  report it with the IDs.
- A mechanism literal used in `internal/parse` is missing from the D-7 table and its origin is not
  obvious from source. Ask rather than guess.

## 7. Acceptance criteria

1. **AC1 Schema.** `internal/graph` tests build graphs by hand ([graph fixtures](../standards/testing.md#5-graph-fixtures)). They show:
   - `Freeze` assigns the same dense order regardless of insertion order (shuffled input, 20 seeds);
   - exact duplicate edges collapse;
   - conflicting duplicates and duplicate node keys are errors naming both keys;
   - a dangling endpoint and a wrong endpoint kind are errors;
   - a self-edge is rejected unless `AllowSelf` is set;
   - a two-node cycle is stored and queryable in both directions;
   - parallel edges with different slots are both returned in (relation, to key, slot) order.
2. **AC2 Immutability.** `Snapshot` exposes no exported mutable fields and no mutating methods. Accessors return
   values or iterators. A test that mutates a returned slice or record shows the snapshot is unchanged.
3. **AC3 Unresolved dispatch.** For a catalog whose dispatch binding has no callable, the snapshot
   has no `DISPATCHES_TO` edge from that dispatch and no extra callable node. `EntryGraph` lists the
   dispatch under unresolved bindings.
4. **AC4 Catalog parity.** On every phase 0 fixture, `EntryCatalog.Canonical()` built through the
   graph equals the pre-change sort record-for-record. `Validate` errors keep their current text for
   the existing invalid-catalog tests in `entries_test.go`.
5. **AC5 Consumers.** `Handler`, `EntryGaps`, `SelectEntries`, and `validateReferences` produce
   results identical to their pre-change versions on every phase 0 fixture. This is a table-driven
   comparison against a test-local copy of the old function. The report renderer builds one
   `EntryGraph` per report, not one per entry.
6. **AC6 Classification.**
   - `javascript/dynamic-dispatch` and `python/dynamic-vulnpy` have registrations with
     `origin=dynamic`, and factory instances keep distinct registration IDs.
   - A direct Express route is `origin=static`, `path_shape=framework_pattern` for `/users/:id`,
     and `literal` for `/health`.
   - `php/routes` entries are `static`.
   - A registration with a gap-bearing resolved binding is `partial`.
   - A registration with no callable is `unresolved`.
7. **AC7 Request stability.** `TestArchitectureBaseline` request digests, signatures, use rows, and
   counts are identical to the phase 0 golden for every fixture.
8. **AC8 Listed report deltas only.** The regenerated golden differs from phase 0 only in
   `report_sha256` and `sarif_sha256`. The run log shows a JSON diff on one fixture per language,
   and that diff contains only added `classification` objects and, for PHP, `"language": "php"`.
9. **AC9 Measurement.** The evaluation record adds node and edge counts per kind and relation,
   `Freeze` time, and heap delta for juice-shop, vulnpy, and DVWA, measured offline.
10. **AC10 Docs.** `repository-graph.md` has an "Implemented subset (phase 1)" section with the D-5
    table. Architecture §4 and §11 list `internal/graph` and what stays proposed. The contributor gate passes.

## 8. Test strategy

- `internal/graph/graph_test.go`: AC1–AC3, with hand-built graphs and table-driven error cases.
- `internal/analysis/entry_graph_test.go`: AC4 and AC5 parity tables over phase 0 fixtures (through
  `parse.Analyze`, test-only), plus the AC6 derivation table on small synthetic catalogs.
- `TestArchitectureBaseline`: AC7 and AC8. There are no new parse fixtures; AC6 reuses existing ones.
- Omitted: traversal tests, since there is no traversal, and per-relation tests duplicating AC1.

## 9. TDD entry point and execution sequence

1. **Red:** write `graph_test.go` AC1 cases against the skeleton below.
2. Implement `internal/graph`:

```go
package graph

type Kind uint8     // Entry, Registration, Dispatch, Callable, Invocation (ordered)
type Relation uint8 // Exposes, HasBinding, DispatchesTo, Instantiates, InputFromEntry
type Resolution uint8 // Observed, Resolved, Approximate, Unresolved (repository-graph certainty)

type SpanRef struct{ File, SHA256 string; StartByte, EndByte int }
type NodeRecord struct{ Kind Kind; Key string; Ref int } // Ref: index in the owning catalog slice
type EdgeRecord struct {
	Relation   Relation
	From, To   string // persistent keys
	Slot       string
	Resolution Resolution
	Rule       string // "<rule>@<version>"
	Evidence   []SpanRef
}
type Endpoints struct{ From, To Kind; AllowSelf bool }

type Builder struct{ /* nodes, edges, table map[Relation]Endpoints */ }
func NewBuilder(table map[Relation]Endpoints) *Builder
func (b *Builder) AddNode(NodeRecord)
func (b *Builder) AddEdge(EdgeRecord)
func (b *Builder) Freeze() (*Snapshot, error) // sort, dedupe/conflict, validate, CSR indexes

type NodeID uint32
type Snapshot struct{ /* unexported: nodes, edges, outOffsets/outEdges, inOffsets/inEdges, byKey */ }
func (s *Snapshot) Lookup(key string) (NodeID, bool)
func (s *Snapshot) Node(id NodeID) NodeRecord
func (s *Snapshot) Nodes(k Kind) iter.Seq[NodeID]                // key order
func (s *Snapshot) Out(id NodeID, r Relation) iter.Seq[EdgeRecord] // (relation, to key, slot) order
func (s *Snapshot) In(id NodeID, r Relation) iter.Seq[EdgeRecord]
func (s *Snapshot) Stats() Stats // node counts per kind, edge counts per relation
```

3. **Red, then green:** AC4 and AC5 parity tests. Add `internal/analysis/entry_graph.go`:

```go
type EntryGraph struct{ cat EntryCatalog; g *graph.Snapshot }
func (c EntryCatalog) Graph() (*EntryGraph, error)
func (e *EntryGraph) Handler(entryID string) *Evidence
func (e *EntryGraph) EntryGaps(entryID string) []Gap
func (e *EntryGraph) UnresolvedDispatch() []string
func (e *EntryGraph) Classify(registrationID string) RegistrationClassification
```

   Reimplement `Canonical`, `Validate`'s index, and the four `AnalysisReport` methods on top of it.
   Keep their signatures; the methods build an `EntryGraph` once per call.
4. Classification: enumerate the mechanism literals with
   `grep -rhoE '"[a-z_]+_(registration|expansion|route|mapping|resolver|handler)"|"addEventListener"|"browser_source_slice"' internal/parse`.
   Record the list in the run log and the D-7 table. Add the field and classify at the end of
   `finalizeEntries`. AC6 goes green.
5. D-9 language fix. Regenerate the phase 0 golden and the Python input-baseline golden. Verify the
   AC7 and AC8 diff by inspection.
6. Measurements for AC9, then docs for AC10, then the gate. Commit and push.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC10 verified, with evidence for each AC in the run log.
- [ ] `git diff <phase start HEAD> --stat` matches §4.
- [ ] The run log's PR summary lists the AC8 deltas and states that request bytes are unchanged.

## 11. Open questions

None blocking. The owner may veto D-8; the fallback is to keep classification graph-internal and
skip AC8's report delta.

## 12. Run log protocol

Use the plan's common rules. Record the mechanism enumeration, the golden diff excerpts, and the sample measurements.

## 13. Agent implementation prompt

> Work in the `arch-review-clean-up` worktree (`<DEV_ROOT>/zazzcode/zazzles/arch-review-clean-up`).
> Confirm the phase 0 commits are on the branch and its run log shows green gates; record the starting HEAD. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md), and this
> spec. Follow the plan's session start and common rules. Execute §9 in order, TDD first. You may
> delegate `internal/graph` and its tests (§9 steps 1–2) to one Sonnet Contributor Agent. It owns only
> those files; you integrate and run the gates. Stop on any §6 halt. Finish by committing and
> pushing, with AC1–AC10 evidence in the run log; the phase 3 session opens the milestone draft PR. Verifier: a fresh-context subagent compares the phase 0 and
> phase 1 goldens and confirms that only `report_sha256` and `sarif_sha256` changed. It re-runs
> `go test -race ./internal/graph ./internal/analysis ./cmd/scan -count=1` and checks that no
> `NodeID` appears in any JSON tag or request builder. It reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-17 — Owner topology decision

Source: owner, in the planning session. Runs in the `arch-review-clean-up` worktree as one fresh
session, after the previous phase's commits, with no new worktree. Changed: header, §10 scope diff
base, §13 prompt. Verification impact: the scope diff is taken from this phase's recorded starting
HEAD, not `origin/stage`. The PR is the shared milestone draft PR into `stage`.
