# Cross-Analyzer Engine Hardening — Milestone Specification Index & Slice 1 Contract

**Worktree / branch:** `analyzer-engine-hardening` (future branch from `stage` after `path-traversal` merges; authored as a planning/contract artifact on `path-traversal`)  
**Feature:** Shared Analysis Engine — Scheduling, Context Deduplication, AST Guards, and Wire Bundle v7  
**Milestone:** Native Scan — Engine Hardening (`N/A` calendar milestone)  
**Deliverable:** Milestone Index + Slice 1 (`scan-scheduling-and-context-dedupe`) Executable Contract  
**Project Owner:** Human Project Owner  
**Deliverable Owner:** Human Deliverable Owner  
**Delivery topology:** Milestone branch `analyzer-engine-hardening` with four ordered, independently checkpointed slices (or sibling branches if the Deliverable Owner prefers separate PRs per slice)  
**Review artifact:** One draft PR per approved topology targeting `stage`  
**Approved review shape:** Sequenced milestone slices (`E1` Scheduling & Dedupe -> `E2` Shared AST Guard & Workspace Manifests -> `E3` Wire Bundle v7 -> `E4` Node Chain/URL Promotion & Phase-2 File Contracts)  
**Decomposition rationale:** Grouping `E1`–`E4` in strict dependency order prevents invalidating saved decision traces more than once: `E1` cuts multi-adapter live call counts by up to 96.9% *without* changing any candidate's `request_digest`; `E2` upgrades static guard/manifest facts; `E3` performs a single coordinated `-v2`/`evidence_version: 7` wire-format bump across all families; `E4` widens cross-analyzer entry reachability once per-call cost and deduplication are in place.  
**Integration branch:** `stage`  
**Merge policy:** PR review required — agents commit/push feature branches only; never merge to `stage`  
**Drafted:** 2026-11-14  
**Shared run log:** `.zazz/ephemeral/analyzer-engine-hardening-run-log.md`  
**Execution tracking:** Local run log only (Zazz Board is not used)  
**Implementation coordination:** Lead Agent working alone in the assigned feature worktree  
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability & Milestone Roadmap

Eliminate cross-analyzer scheduling bugs, redundant multi-context model calls, asymmetric JS/Python guard gaps, monorepo manifest misses, and wire-payload token bloat documented in the [hardening and wire-efficiency proposal](../project/analyzer-hardening-and-wire-efficiency-proposal.md).

### Ordered Milestone Slices

| Slice | Contract Status | Analyzer Scope | Observable Outcome | Wire-Digest Impact |
| --- | --- | --- | --- | --- |
| **E1: Scheduling, Family Filters & Context Dedupe** | **Full executable spec in §§1–12 below** | `[All Analyzers]` | Eligibility-aware `--judge-limit` (never burned by zero-call observations), `xss`/`logging` prioritized ahead of standalone `input-validation`, general `--skip-family` / `--only-family`, and default-on **Canonical Payload-Digest Context Deduplication** (`derived_from` provenance, cutting VulnPy 260 -> 8 calls) | **Zero** (`request_digest` unchanged for every candidate) |
| **E2: Shared AST Guard & Workspace Manifest Engine** | Scoped blueprint; author dedicated spec slice before coding | **Command**, **Path**, **Validation**, **XSS**, **NoSQL** | Extract `internal/parse/guard_climb.go` from Path's polarity/conjunction/terminator engine to fix JS Command `else`-branch guards and Python Command `abort()`/`HTTPException` guards; upgrade `packageVersion` (`xss_versions.go`) to walk nearest ancestor `package.json` + workspace lockfiles | Changes only candidates whose static guard or version facts actually change |
| **E3: Wire Bundle v7 & Catalog Sync** | Scoped blueprint; author dedicated spec slice before coding | `[All Analyzers]` | Single coordinated bump (`evidence_version: 7`, family `-v2`/`-v3` protocols): always-on `compact_wire`, drop duplicate `evidence_roles`, omit 64-hex component digests from prompt, project `CommandFacts`/`PathFacts` offsets to `eN` refs, sync `NodeFSContract`/`path_*.md` prose, migrate `log-use-v1` to `analysispacks` (`-25–35%` input tokens/call); update `TestOutboundPredecessorRequests` & `TestCommandPredecessorRequests` | Intentional one-time protocol bump; old traces remain readable on historical exports |
| **E4: Shared Node Chain/URL Inputs & Phase-2 File APIs** | Scoped blueprint; author dedicated spec slice before coding | `[All Node Analyzers]` + **Path** | Promote Express non-final chain handlers & `req.path`/`url`/`files` into `source.node-input-v2` (removing Path's double handler pass and exposing middleware/URL sinks to XSS, Command, SQL, NoSQL); add Starlette/FastAPI `FileResponse` + `UploadFile`, `fs.open/copyFile/rename`, `shutil`, and `tarfile.extractall` (`filter='data'`) | Additive new candidates + `source.node-input-v2` |

---

## 1. Required Reading For Implementor (Slice E1)

### 1.a This Specification & Proposal

- Read this specification end to end and [.zazz/project/analyzer-hardening-and-wire-efficiency-proposal.md §2–§4](../project/analyzer-hardening-and-wire-efficiency-proposal.md#2-cross-analyzer-architectural-audit-where-analyzer-silos-are-hurting-accuracy--cost).

### 1.b Prior Contracts Establishing Explicit Baselines Being Updated

- [.zazz/specifications/components-03-outbound.md §4 Decisions](components-03-outbound.md#4-decisions-and-explicit-behavior-boundary) and [§6 Acceptance O4](components-03-outbound.md#6-acceptance-criteria) — **CRITICAL:** `O4` (`cmd/scan/outbound_test.go:157`) intentionally froze conservative candidate-index `--judge-limit` counting where `outbound_http_candidate` occupied capped slots. Slice E1 explicitly supersedes that rule so zero-call observations never consume `--judge-limit` HTTP request budget while still keeping requested scans with unassessed outbound observations incomplete (`exit 1`)!
- [.zazz/specifications/decision-model-limits.md](decision-model-limits.md) — shared `requestLimiter` accounting (`JUDGE_LIMIT`, `JUDGE_BUDGET_USD`, `JUDGE_RPM`, `JUDGE_TPM`).
- [.zazz/architecture/reporting-and-sarif.md](../architecture/reporting-and-sarif.md) — schema-4 compatibility and `Enrich()` invariants.

### 1.c Standards

Per `.zazz/standards/index.yaml`:

| Standard | What it governs here |
| --- | --- |
| [.zazz/standards/code-structure.md](../standards/code-structure.md) | Thin `cmd/scan` wiring (move scheduling/dedupe mechanics into `internal/judge`), deterministic sorting, <= 400/700-line files |
| [.zazz/standards/testing.md](../standards/testing.md) | Table-driven CLI/judge `httptest` stub suites, deterministic fake-clock/offline replay tests |
| [.zazz/standards/docs-hygiene.md](../standards/docs-hygiene.md) | Zero `AC-`/`D-`/`OQ-`/`SPEC`/`INVARIANT` tokens in Go code/tests; relative links |
| [.zazz/standards/spec-hygiene.md](../standards/spec-hygiene.md) | Explicit baseline deltas, TDD-grade ACs, strict scope |

### 1.d Existing Code References

- `cmd/scan/main.go:40-65`, `cmd/scan/analysis.go:67-180`, `cmd/scan/outbound_test.go:65-180`
- `internal/analysis/analysis.go:55-96` (`Assessment`, `AnalysisReport`)
- `internal/analysispacks/families.go:93-155` (`Families()`, `ObservationOnly()`)
- `internal/judge/client.go:72-145`, `internal/judge/trace.go:28-70` (`Preview`, `Replay`, `requestDigest`)
- `internal/report/findings.go:105-140` (`Enrich`, `describe`, skipped-family & assessment uncertainty text)

---

## 2. Invariants (Slice E1)

1. **Zero `request_digest` or wire-payload byte changes.** `TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests`, and all 360 saved `path-traversal` exact replays MUST pass without changing a single byte of any provider request body.
2. **Sound equivalence key (`NormalizedContextDigest`) — never conflate distinct entry controls.** Two candidates may share one model call ONLY when their exact provider request payloads are byte-identical **after** normalizing invocation/entry/candidate IDs and entry registration coordinates, proving identical `(model, protocol, selected_components, guidelines, questions, callable_id, sink, api_model, claim_facts, dependency_source_expressions_and_transfers, applicable_entry_controls_and_stages, blocking_gaps, coverage_gaps)`. If one route has an auth/validator middleware, a Flask `<int:id>` vs `<path:p>` converter, a different `InputFacts` stage, or VulnPy WSGI `PATH_INFO` comprehension vs Flask `request.args`, their normalized payloads differ and they MUST be judged independently!
3. **Deduplicated siblings preserve distinct candidate/entry findings and explicit provenance.** Every sibling `CandidateUse` keeps its own `ID`, `EntryID`, `InvocationContextID`, and `RequestDigest` (its own exact request digest), plus `Assessment.DeduplicatedFrom = canonicalUse.ID` (`Status: "completed"`). `report.Enrich()` emits per-entry findings for all siblings while stating in `Assessment` / report `Limitations` how many distinct signatures were judged vs. derived.
4. **Unassessed observations never consume `--judge-limit`, yet requested-scan incompleteness (`exit 1`) still holds.** Skipping zero-call candidates (`outbound_http_candidate`, `xss_data_candidate`) before incrementing `requestIndex` frees `--judge-limit` for real HTTP calls, while `outbound_http_candidate` still records `Status: "not_run"` (`Reason: OutboundNotAssessed`) and still causes a `--judge` scan containing outbound observations to exit `1` unless `outbound` is explicitly skipped via `--skip-family outbound`.
5. **Mutual exclusion & canonical naming on family filters.** `--only-family` and `--skip-family` accept canonical family names (`sql`, `nosql`, `xss`, `command`, `path`, `logging`, `input-validation`, `outbound`); specifying both `--only-family` and `--skip-family` (or an unknown family name) exits `2` (`exitUsage`) before scanning.

---

## 3. Scope (Slice E1)

### Approved Review Shape

Single coherent slice (`[CLI+JUDGE+ANALYSIS+REPORT+DOC]`) on branch `analyzer-engine-hardening` targeting `stage` as a draft PR after `path-traversal` lands.

### Strict Scope Constraint

Only `cmd/scan/`, `internal/analysis/`, `internal/analysispacks/`, `internal/judge/`, `internal/report/`, `docs/`, `README.md`, and `.zazz/` may be modified. Do NOT touch `internal/parse/` or embedded guideline/contract prose in Slice E1.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `internal/analysis/analysis.go` | Modified | Add `DeduplicatedFrom string` (`json:"deduplicated_from,omitempty"`) on `Assessment` and `OnlyFamilies []string` (`json:"only_families,omitempty"`) on `AnalysisReport` |
| `internal/analysispacks/families.go` | Modified | Export canonical CLI family-name lookup (`FamilySlugForKind`, `ValidCLIFamily`) covering registered packs plus `logging` (`log_sink_candidate`) and `input-validation` |
| `internal/judge/schedule.go` | New | Priority ordering (`securitySinkPriority`), assessability predicate (`AssessableUse`), deterministic `EquivalenceSignature(client, use)` over normalized wire bundle, and batch/replay deduplication coordinator |
| `internal/judge/schedule_test.go` | New | Unit & `httptest` stub tests for equivalence soundness (shared callable with identical controls merges; route-specific middleware/converter/input-stage splits), trace-dir writing, and replay compatibility |
| `cmd/scan/main.go`, `cmd/scan/analysis.go` | Modified | Add `--only-family` / `JUDGE_ONLY_FAMILY`, generalize `--skip-family` / `JUDGE_SKIP_FAMILY`, wire `judge.ScheduleAndAssess`, and emit accurate skipped/only/deduplicated `Limitations` accounting |
| `cmd/scan/outbound_test.go`, `cmd/scan/schedule_cli_test.go` | Modified / New | Update `TestMixedAssessmentWithOutboundObservations` to assert the intentional eligibility-cap delta (outbound uses 0 `--judge-limit` slots while preserving `exit 1`), plus CLI tests for `--only-family`, `--skip-family`, and XSS/Logging priority |
| `internal/report/findings.go`, `internal/report/findings_test.go` | Modified | Generalized `analyzer not used for this run` uncertainty copy for any skipped/excluded family, and provenance note when `Assessment.DeduplicatedFrom != ""` |
| `README.md`, `docs/running-scans.md`, `docs/decision-models.md`, `.zazz/project/implementation-plan.md` | Modified | Document `--only-family`, expanded `--skip-family`, priority order, and equivalent-context deduplication provenance |

### Out Of Scope (Deferred to Slices E2–E4 or Tier-3 Non-Goals)

- Changing wire bundle format, `compact_wire` threshold, `evidence_roles`, or component/guideline prose (`Slice E3`).
- Modifying `internal/parse/` guard climbing, `packageVersion`, Express chain handlers, or adding new sink contracts (`Slices E2 & E4`).
- Cross-process persistent disk caching of model answers (deduplication in `E1` is strictly within one scan + explicit `--trace-dir` replay).
- Tier-3 non-goals: Windows path/shell semantics, runtime symlink/TOCTOU state, >1-hop whole-program interprocedural summaries, full `flow.go` SSA rewrite, and second-order DB-to-path/command flows.

---

## 4. Decisions (Slice E1)

### D-1 — Normalized Wire-Payload Signature vs. Ad Hoc Struct Hashing for Context Deduplication

**Decision.** Compute the context-equivalence signature in `internal/judge/schedule.go` directly from `wireBundle(use)` + selected `analysispacks.ForUse(use)` material after stripping only candidate-identity / entry-coordinate fields (`candidate_id`, `entry`, `entry_id`, `invocation_context_id`, `registration_id`, `dispatch_binding_id`, `instance_id`, `http.path`, `http.source_path`, `http.method`, and `entry_registration` / `route_registration` excerpt spans when no entry-level `controls`/`stages`/`entry_gaps`/`dispatch_gaps` reference them) while **retaining** `callable_id`, all `sink` / `dependencies` / `transfers` / `guard` / `control_flow` / `input_facts.controls` / `input_facts.stages` / `blocking_gaps` / `coverage_gaps` / `path` / `command` / `xss` / `api_model` bytes!  
**Why.** Hand-picking Go struct fields per analyzer risks forgetting a family-specific field (e.g., `XSS.OutputContext`, `InputFacts.Values[i].InitialType`, or SQL `Check.Fields`) and falsely merging two non-equivalent contexts. Normalizing the actual `wireBundle` guarantees that **anything visible to the model about the callable, input types/stages, guards, transfers, or sink** is automatically part of the hash across all 7 analyzers!  
**Rejected alternative.** Deduplicating by `(callable_id, sink.span)` alone — rejected because one route mounted with auth/validator middleware or `<int:id>` conversion and another mounted raw share `(callable_id, sink.span)` while having different security outcomes.

### D-2 — Keep Exact Per-Candidate `DecisionTrace` Compatibility via `--trace-dir`

**Decision.** For the canonical candidate of an equivalence group, execute `AssessTrace` normally (consuming 1 `--judge-limit` slot and 1 HTTP request) and write its exact `DecisionTrace`. For equivalent sibling candidates, copy `Answers`, `AnswerDetails`, and `Model` (`Usage` set to `0` so token/spend totals are never double-counted!), set `DeduplicatedFrom = canonical.ID`, compute the sibling's own `RequestDigest`, and run `applyPolicy(siblingUse, &siblingAssessment)` independently in Go!  
**Why.** Running `applyPolicy` independently on every sibling guarantees Go's deterministic evidence gates validate each sibling's own `CandidateUse` invariants, and setting sibling `Usage = 0` keeps `LimitSummary()` token/dollar accounting 100% honest.

### D-3 — Three-Tier Assessment Priority Queue & Zero-Slot Observation Skipping

**Decision.** Order eligible candidates stably in three tiers:
1. Primary security sinks: `sql_query_candidate`, `nosql_query_candidate`, `command_execution_candidate`, `path_traversal_candidate`, `xss_candidate`, `log_sink_candidate`.
2. Standalone field-policy checks: `input_validation_candidate`.
3. Non-assessable / observation-only records (`outbound_http_candidate`, `xss_data_candidate`): handled immediately with `0` `--judge-limit` slots consumed (`not_run`).  
**Why.** Fixes `A-1` where `xss_candidate` and `log_sink_candidate` sat behind `outbound_http_candidate` and `input_validation_candidate` under small `--judge-limit` caps.

---

## 5. Agent Implementation Rules & Halt Conditions

- **Precondition:** Start in a fresh worktree `analyzer-engine-hardening` branched from `stage` **after** `path-traversal` merges (or on top of `path-traversal` only if explicitly instructed by the Deliverable Owner).
- **Toolchain & offline discipline:** `GOFLAGS=-buildvcs=false`; zero live paid model calls are needed for Slice E1 (100% verifiable via `httptest` stubs and saved VulnPy traces). Never read or print `.env`.
- **Code comment hygiene:** Never include `AC1`, `D-1`, `OQ-1`, `SPEC`, or `INVARIANT` in Go source or test files.
- **Halt conditions:** Stop and surface to the Deliverable Owner if (1) any predecessor request-digest test (`TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests`) changes bytes, (2) two contexts with different entry controls/converters produce the same `EquivalenceSignature`, or (3) diff touches files outside §3.

---

## 6. Acceptance Criteria (Slice E1)

- **AC1 — Zero-call observations consume zero `--judge-limit` slots while preserving incomplete-scan `exit 1`.** On a mixed fixture with 5 `outbound_http_candidate` uses, 1 `xss_data_candidate` use, 1 `sql_query_candidate`, and 1 `xss_candidate`, running `scan --analyze --judge openai --judge-limit 2` makes exactly **2 HTTP calls** (judging both SQL and XSS to `completed`), marks the 5 outbound and 1 data-only uses `not_run` without `"judge request limit reached"`, and exits `1` because requested outbound assessment is unimplemented (`exit 0` when `--skip-family outbound` is passed and no `xss_data_candidate` fails completeness). Verified by updated `TestMixedAssessmentWithOutboundObservations` and `TestSchedulePriorityAndObservationSlots` in `cmd/scan/`.
- **AC2 — General `--only-family` and `--skip-family` CLI & env filtering.** `--only-family path,command` judges only path and command candidates and marks other families `not_run` with `"<family> analyzer not used for this run (--only-family ...)"` (without setting `failed = true` for excluded families); `--skip-family input-validation,outbound,xss` skips all named families; combining `--only-family` and `--skip-family` or passing an unknown family exits `2`. Verified by `TestCLIFamilySelection` in `cmd/scan/schedule_cli_test.go`.
- **AC3 — Equivalent multi-context callables deduplicate HTTP calls; distinct entry controls do NOT.**
  1. A shared handler registered across 5 HTTP routes with identical input bindings and zero route-specific controls makes **1 HTTP call** (`--judge-limit 1` succeeds with `exit 0`!), marks 1 canonical use (`Usage["input_tokens"] > 0`, `DeduplicatedFrom == ""`) and 4 derived siblings (`DeduplicatedFrom == canonical.ID`, `Usage == nil`, independent `applyPolicy` verdict), and emits all 5 route findings in JSON, HTML, and SARIF.
  2. When 1 of the 5 routes attaches a route-specific validator/auth middleware, a different Flask route converter (`<int:id>` vs `<path:id>`), or a distinct input transfer (such as VulnPy WSGI `PATH_INFO` comprehension vs Flask `request.args`), `EquivalenceSignature` produces **2 distinct signatures** and makes **2 HTTP calls**.
  3. Across parsed VulnPy (`260` path candidates), `EquivalenceSignature` partitions into `<= 15` distinct signatures while keeping WSGI `templating.py:27` strictly separate from `pt.py` sinks.
  Verified by `TestEquivalenceSignatureSoundness` and `TestVulnPySignaturePartition` in `internal/judge/schedule_test.go`.
- **AC4 — Predecessor request bytes, build, vet, format, docs, and full `-race` pass.** `TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests`, `go build ./...`, `go vet ./...`, `gofmt -l cmd internal`, `go test -race ./... -count=1`, and `check-docs.py` all pass with zero errors.

---

## 7. Test Strategy

- `TestEquivalenceSignatureSoundness` (`internal/judge/schedule_test.go`) — table-driven matrix testing identical Express/Flask multi-route registrations (merge) vs. route middleware, parameter destructuring vs. query, Flask converter differences, and GraphQL vs. HTTP exposure of the same function (split).
- `TestScheduleDeduplicationAccounting` (`internal/judge/schedule_test.go`) — `httptest` server asserting exact HTTP call count, single-counted token/USD budget reservation in `requestLimiter`, independent `applyPolicy` execution per sibling, and `LimitSummary()` reporting `"judged M distinct signatures (K derived across equivalent entry contexts)"`.
- `TestCLIFamilySelection` & `TestSchedulePriorityAndObservationSlots` (`cmd/scan/schedule_cli_test.go`) — end-to-end CLI flag/env precedence, exit codes (`0`, `1`, `2`), XSS/Logging priority ahead of `input_validation_candidate`, and JSON/HTML/SARIF `Limitations` parity.

---

## 8. TDD Entry Point & Prescriptive Execution Sequence

### TDD Entry Point

Add `TestEquivalenceSignatureSoundness` in `internal/judge/schedule_test.go` and `TestCLIFamilySelection` in `cmd/scan/schedule_cli_test.go`; run:
```bash
GOFLAGS=-buildvcs=false go test ./internal/judge ./cmd/scan -run 'Test(EquivalenceSignatureSoundness|CLIFamilySelection)' -count=1
```

### Execution Phases

1. **Phase 1 (`internal/analysis` + `internal/analysispacks`):** Add `Assessment.DeduplicatedFrom` and `AnalysisReport.OnlyFamilies`; add `FamilySlugForKind` / `ValidCLIFamily` in `internal/analysispacks/families.go`.
2. **Phase 2 (`internal/judge/schedule.go`):** Implement `AssessableUse`, `securitySinkPriority`, `EquivalenceSignature`, and `Client.AssessScheduled` (integrating cleanly with `c.limiter` and `--trace-dir`). Verify `internal/judge` tests pass.
3. **Phase 3 (`cmd/scan` + `internal/report`):** Wire `--only-family` / generalized `--skip-family` and `AssessScheduled` in `cmd/scan/main.go` + `cmd/scan/analysis.go`; update `internal/report/findings.go` for generalized skipped-family reasons and `DeduplicatedFrom` provenance; update `cmd/scan/outbound_test.go` for the documented `O4` slot delta.
4. **Phase 4 (Full Verification & Docs):** Update `README.md`, `docs/running-scans.md`, `docs/decision-models.md`, and `.zazz/project/implementation-plan.md`; run `go build ./...`, `go vet ./...`, `gofmt`, `go test -race ./... -count=1`, and `check-docs.py`.

### Skeleton: `internal/judge/schedule.go`

```go
package judge

import "github.com/zazzcode/zazzles/internal/analysis"

// AssessableUse reports whether a candidate makes a model decision request when not skipped.
func AssessableUse(u analysis.CandidateUse) bool {
	return !analysispacks.ObservationOnly(u.Kind) && u.Kind != "xss_data_candidate"
}

// EquivalenceSignature returns a deterministic SHA-256 over the candidate's selected
// pack/protocol/questions and normalized wire bundle (retaining callable, sink, input
// stages/controls, transfers, guards and gaps while stripping per-entry registration IDs).
func (c *Client) EquivalenceSignature(u analysis.CandidateUse) (string, error) {
	// Returns ("", err) if payload construction fails, forcing normal per-use error handling.
	return "", nil
}
```

---

## 9. Definition Of Done (Slice E1)

- [ ] All §1 required reading and `.zazz/standards/index.yaml` verified.
- [ ] `TestOutboundPredecessorRequests` and `TestCommandPredecessorRequests` pass unchanged.
- [ ] AC1–AC4 tests green under `GOFLAGS=-buildvcs=false go test -race ./... -count=1`.
- [ ] `go build ./...`, `go vet ./...`, `gofmt -l cmd internal` (empty), and `check-docs.py` exit 0.
- [ ] Zero working-doc tokens (`AC-`, `D-`, `OQ-`, `SPEC`, `INVARIANT`) in Go source or tests.
- [ ] Independent fresh-context Verifier sub-agent returns PASS on AC1–AC4.

---

## 10. Open Questions

None for Slice E1 — Deliverable Owner confirmed default-on equivalence deduplication with explicit `derived_from` (`deduplicated_from`) provenance on 2026-11-14.

---

## 11. Run Log Protocol

Record execution history append-only in `.zazz/ephemeral/analyzer-engine-hardening-run-log.md`.

---

## 12. Agent Implementation Prompt (Slice E1)

```text
Create or switch to the assigned `analyzer-engine-hardening` worktree branched from `stage` (after `path-traversal` merges, or from the base confirmed by the user).
Implement Slice E1 of `.zazz/specifications/analyzer-engine-hardening.md`.
Shared run log: `.zazz/ephemeral/analyzer-engine-hardening-run-log.md` (local run log only; no Zazz Board).
Skills: `spec-driven`, `doc-check`. Never read or print `.env`; zero paid live API calls are needed.

1. Verify `pwd`, `git branch --show-current`, `git status --short --branch`, and `.zazz/standards/index.yaml`.
2. Start with the TDD entry point in §8 (`TestEquivalenceSignatureSoundness` and `TestCLIFamilySelection`), confirm red failure, then implement Phases 1–4 strictly within §3 scope.
3. Verify `TestOutboundPredecessorRequests` and `TestCommandPredecessorRequests` remain byte-identical, and verify the intentional `components-03-outbound.md` O4 slot-consumption improvement is cleanly asserted in `cmd/scan/outbound_test.go`.
4. Run `GOFLAGS=-buildvcs=false` for `go build ./...`, `go vet ./...`, `go test -race ./... -count=1`, `gofmt -l cmd internal`, and `check-docs.py`.
5. Dispatch a read-only Verifier sub-agent to independently run AC1–AC4 checks and audit diff scope before reporting completion. Do not merge to `stage`.
```

---

## 13. Implementation And Review Change Log

No changes recorded.
