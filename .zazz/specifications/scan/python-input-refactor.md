# Shared Python input acquisition — implementation contract

**Worktree / branch:** `python-input-refactor`
**Feature:** shared acquisition and flow; Python parity with the Node design
**Milestone:** behavior-preserving acquisition migration; no new analyzer capability
**Project Owner / Deliverable Owner:** requesting human user
**Delivery topology:** single deliverable, one branch and one reviewable PR into `stage`
**Coordination:** Lead Agent working alone; local run log only
**Run log:** `.zazz/ephemeral/python-input-refactor-run-log.md`

## 1. Capability

Migrate existing Python HTTP acquisition onto the same optional `InputFacts` schema used
by Node. Separate Python framework parameter/context acquisition from shared Python value
flow and from existing DB-API, process, rendering, logging, path and outbound contracts.
Preserve supported functionality, candidate/dispatch identity, source paths, gaps, questions,
and classification rules. The user's implementation request authorizes this contract and
execution in the assigned worktree; no separate greenlight ceremony is required.

The source proposal is `PYTHON-INPUT-REFACTOR-PROPOSAL.md` in the workspace container.
This contract captures its behavior-preserving migration. Proposed new lifecycle discovery,
framework features and model-assisted Python registration discovery are deferred because
they add functionality rather than refactor existing acquisition.

## 2. Required reading

- [Agent orientation: working protocol](../../docs/zazzles-agent-orientation.md#working-protocol).
- [Capability checklist](../../project/implementation-plan.md#supported-capability-checklist).
- [Node acquisition contract: bounded scope](node-http-input-refactor.md#bounded-scope).
- [Evidence and claims](../../architecture/evidence-and-claims.md): transport-neutral input/value evidence.
- [Input validation: enforcement](../../../docs/scan/analysis/input-validation.md#establish-enforcement).
- [Execution discipline: verification](../../docs/agent-execution-discipline.md#verification-discipline).
- [Contributor verification](../../../docs/contributing.md#verification).
- Standards selected through [index](../../standards/index.yaml):
  [code structure](../../standards/code-structure.md), [testing](../../standards/testing.md),
  [spec hygiene](../../standards/spec-hygiene.md), [docs hygiene](../../standards/docs-hygiene.md).
- Existing code: `internal/parse/node_input_facts.go`, `python_flow.go`, `python_values.go`,
  `python_modules.go`; `internal/analysis/input_facts.go`; `internal/analysispacks/select.go`;
  `internal/judge/input_facts.go`, `sql_python_components_test.go`, `command_predecessor_test.go`.

## 3. Invariants

- Existing routes, invocation identities, candidates, dependency source/transfer evidence,
  sink slots, API contracts, questions, gaps and historical assessments MUST be preserved.
- Framework acquisition MUST NOT create security verdicts or infer protection from names,
  Python annotations, missing dependency implementations, or initial transport type.
- Initial runtime type and sink type MUST remain independent; unknowns stay explicit.
- Existing conditional, upload, async/thread and finite-registry witnesses MUST be retained.
- Python NoSQL and general Python-to-browser linkage remain outside implemented support.
- Saved reports and raw answers MUST NOT be rewritten. Changed requests MUST reject exact
  historical replay. Optional facts remain absent when reading historical reports.
- No live model calls are part of automated tests. Paid Python assessment requires a
  selected provider/model and bounded cap; non-Python paid runs are outside this task.

## 4. Scope and review shape

One PR keeps acquisition extraction, schema adoption and parity evidence reviewable together.
All edits MUST stay in this assigned checkout under `internal/`, `cmd/scan/export.go`, `.zazz/`, and the
explicitly requested Python sample surfaces in `docs/samples/`.
Unrelated formatting and cleanup are excluded.

| Path | Change | Purpose |
| --- | --- | --- |
| `internal/parse/python_input*.go` | New | Acquisition adapter boundary, source metadata, final shared facts and regression tests |
| `internal/parse/python_flow.go` | Modified | Delegate acquisition while retaining shared flow and use construction |
| `internal/parse/python_values.go`, `python_calls.go`, `python_frameworks.go` | Modified if needed | Delegate existing context and framework acquisition without semantic changes |
| `internal/parse/python_modules.go` | Modified | Snapshot-local acquisition index and final assembly |
| `internal/parse/testdata/python/` | New baseline data if needed | Frozen predecessor structural evidence |
| `internal/analysispacks/python_inputs.go`, `select.go`, `descriptors.go` | New/modified | Separate versioned Python input interpretation; keep existing Node component bytes |
| `internal/analysispacks/*test.go` | Modified/new if needed | Valid selection, malformed facts and unsupported Python NoSQL |
| `internal/judge/*input*test.go`, `*predecessor*test.go`, `*python*test.go` | New/modified | Exact requests/replay and stubbed classification parity |
| `.zazz/specifications/scan/python-input-refactor.md`, `README.md` | New/modified | Contract and index |
| `.zazz/evaluation/python-input-refactor-results.md` | New | Durable acceptance evidence and limits |
| `.zazz/evaluation/vulnpy-detection-guide.md` | Modified | Reconcile historical source anchors/dispositions with the current source reference |
| `.zazz/project/implementation-plan.md` | Modified | Accurate acquisition status |
| `docs/samples/{vulnpy,ThreatByte,python-insecure-app,vulnerable-flask-app}/` | Modified | Fresh canonical JSON, HTML, SARIF, metadata and report README notes |
| `README.md`, `docs/samples/README.md`, `index.html` | Modified | Correct VulnPy/ThreatByte and other Python example links, full-artifact downloads and provenance |
| `.zazz/project/vulnerable-sample-apps.md` | Modified | Updated Python app metrics from full assessments, with existing Node metrics retained |
| `docs/samples/refresh.py`, `evaluate-python.py` | Modified | Lossless compressed JSON/SARIF publication and offline evaluation for oversized full reports |
| `cmd/scan/export.go` | Modified | Bound saved-report reads at 512 MiB so the exporter accepts the scanner’s own full Python report |

New framework behavior, dependency resolution, hook ordering, runtime execution, Python
discovery activation, new sink models, paid Node reruns, target edits, release/integration merge
operations and rewriting retained sample reports are out of scope.

## 5. Decisions

**Shared optional schema.** Use `analysis.InputFacts` version 1 because Node and Python
need the same origin/type/transfer boundary, without a new historical report schema.

**Acquisition index.** Record source-backed metadata within the originating invocation;
assemble facts after storage linking, claim/check construction and final dependency edits.
This preserves exact final source/transfer paths and avoids stale facts attached to early uses.
Unindexed storage, response or browser sources retain explicit non-HTTP/unknown origins.

**Conservative types.** Initial and sink types default to unknown. Only independently
established acquisition semantics may narrow initial types; no annotation-only guarantee.
This refactor does not introduce a new type solver or weaken evidence gates.

**Separate component.** Add `source.python-input-v1` with Python-specific interpretation,
including annotation/dependency/lifecycle caveats, while reusing existing sink contracts.
Keep existing Node component material unchanged so Node requests remain unchanged.

**Compatibility evidence.** Freeze predecessor report and effective-request digests before
implementation. New Python requests intentionally add shared facts and component provenance;
strip only those additions when proving predecessor equivalence. Old traces must fail replay
against the changed requests, while fresh local-stub traces must replay exactly.

## 6. Agent implementation rules

Work from the checkout containing `go.mod` on `python-input-refactor`. Verify path/branch,
status and the `stage` diff before edits. Use the native declared Go toolchain and C compiler.
Follow `spec-driven` during execution and `doc-check` for modified documents.
The user subsequently requested committing/publishing the implementation and refreshed
Python sample reports to GitHub. Verify zazzcode identity/authentication before committing
and pushing this feature branch; prepare one draft PR into stage. Human review owns merge.
Keep an append-only ignored run log; record baselines, commands, outcomes and deviations.
Stop on behavior drift, unavailable required baseline evidence, destructive recovery, or a
material expansion of the approved functionality. Routine helper/file organization is adaptive.

## 7. Acceptance criteria

1. Existing Python fixture reports are byte-equivalent after removing only new facts and
   their selected component provenance. Verify `TestPythonInputPredecessorBaseline` and
   unchanged existing `TestSQLDiscoveryBaseline` hashes.
2. Flask/Quart, FastAPI/Starlette-backed existing registrations, Django sync/ASGI, Falcon
   sync/ASGI, Bottle, Pyramid, aiohttp and WSGI keep their existing dispatch coverage.
   Shared facts validate every final dependency source/transfer, with invocation-local
   registration, framework, origins and gaps. Verify `TestPythonInputFacts` and existing
   Python dynamic/generalization/command/path tests; do not claim unsupported standalone
   Starlette registration coverage.
3. Query/form/JSON/path/files/session sources remain distinct. Annotation-only values,
   custom transformations, missing hooks, conditions and thread continuations cannot gain
   new sink-type safety. Verify the input-fact matrix plus existing policy controls.
4. Existing Python API contracts, question sets and Protected/vulnerable/Review status
   outcomes remain unchanged under identical stub answers. Verify Python SQL pipeline,
   command/path/SSRF policies and report parity tests.
5. Old effective request bytes are frozen; new requests carry only the intended input-fact
   interpretation extension. Historical traces cannot be replayed against changed requests;
   new stub traces replay exactly. Verify `TestPythonInputRequestCompatibility` and the
   existing predecessor request digests without replacing their expected hashes.
6. `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, `go build ./...`,
   changed-file formatting, `git diff --check` and scoped document checks pass.
7. Results document exact evidence, adapter limits, intentionally changed Python requests,
   deferred discovery/lifecycle extensions, and whether paid Python evaluation was performed.

## 8. Test strategy

Freeze all retained Python fixture structural output before changing product code. Cover
routes, dynamic VulnPy, command injection, path traversal and outbound fixtures, with stable
root normalization and only the documented extension projected out.
Use a compact acquisition matrix for framework origins, plain/typed path binding, raw JSON,
uploads, annotations, mutation and conditional sources. Validate final facts against dependencies.
Reuse existing eleven-adapter, thread/upload, conditional, shadowing, SQL driver and renderer
tests for behavioral parity rather than duplicating them. Add one request compatibility
integration test over all Python fixture families and local-stub replay/policy cases.
Existing report tests cover JSON/HTML/SARIF and historical readers. No live service is needed.

## 9. TDD entry point and execution sequence

1. Capture untouched full-suite evidence and predecessor fixture/request hashes. Add the
   structural freeze test first; then add a shared-fact assertion that fails on missing facts.
2. Extract existing `source`, parameter and ambient request acquisition into Python input
   adapter helpers. Preserve expression evaluation order and protection logic exactly.
3. Record acquisition metadata per invocation/source, then construct `InputFacts` from final
   dependencies in `pythonSet.report`. Skeleton:

   ```go
   func (s *pythonSet) assemblePythonInputs(out *analysis.AnalysisReport)
   func (f *pythonFlow) source(n *sitter.Node, container, key string) pythonValue
   ```

4. Select the separate Python input component for valid HTTP facts; retain historical nil
   facts and unchanged Node selection. Reject malformed provenance and preserve NoSQL limits.
5. Run targeted parity/replay/stub tests, then full checks. Update index, capability status
   and results with exact evidence. Review all scoped changes and limits.

## 10. Definition of done

- Implementation and all acceptance checks have recorded evidence.
- Spec, index, capability status and durable results agree with the final code.
- Working tree contains only scoped changes; historical answers and sample sources are untouched.
- Human review and merge remain pending; technical completion does not imply approval.

## 11. Open questions

No question blocks offline implementation. The user explicitly authorized all paid Python sample assessments, with as much paid
validation as needed. Use configured OpenAI `gpt-6-luna`; all families are included.
The first complete pass is capped at the 3,354 discovered assessable contexts across the
four Python samples, with no fallback or automatic retries and existing RPM/TPM pacing.

## 12. Run log protocol and implementation prompt

Read this contract, `AGENTS.md`, orientation and the entire ignored run log on resume.
Verify the standards index, current branch/diff and last completed phase. Work alone in
this checkout, preserve concurrent changes, implement the phases above, run each named
acceptance check and append evidence/recovery notes to the run log. Use no external tracker.
Prepare reviewed changes, commit and push the feature branch with one draft PR into
stage, and provide the evidence/report links. Do not merge.

## 13. Implementation and review change log

### 2026-11-15 — Full paid Python validation authorized

**Source.** The user explicitly requested all paid Python assessments and then authorized
as much paid Python evaluation as needed to confirm refactor behavior.

**Changed sections.** Section 11 resolves the pending evaluation scope.

**Rationale and summary.** Assess every existing family on all four available Python
samples with configured `gpt-6-luna`, retaining request/response traces and three-format
reports. The initial pass has an explicit 3,354-context cap, without provider fallback
or automatic retries; this replaces the historical VulnPy input-validation skip.

**Verification impact.** Check completion and source-backed controls, then replay every
completed assessment against fresh source and compare report formats. Preserve original
historical reports and source checkouts.


### 2026-11-15 — Publish refreshed Python sample reports

**Source.** The user requested updated HTML and SARIF from the complete paid scan,
including ThreatByte, committed to GitHub; no Node.js/TypeScript paid reruns.

**Changed sections.** Sections 4, 6 and 12 authorize the four Python sample surfaces
and feature-branch commit/push with a draft PR into stage.

**Summary and verification impact.** Publish matching fresh JSON/HTML/SARIF and accurate
metadata/coverage notes; preserve source attribution and check format/status parity.
Document that this run includes every input-validation context. Future routine Python
comparisons use `--skip-family input-validation` per the user's follow-up preference.
Validate GitHub file-size constraints before staging generated artifacts; any necessary
partitioning must retain every assessed record and clearly link all parts.


### 2026-11-15 — Preserve full oversized report artifacts

**Source.** The user's full-report publication request plus measured VulnPy export sizes.

**Changed sections.** Section 4 includes the sample refresh/evaluation utilities.

**Rationale and summary.** Full VulnPy JSON and SARIF exceed the regular GitHub file-size
limit. Store lossless deterministic gzip versions, retain the full normal HTML report,
and update download links and offline refresh/evaluation support. Every assessed record
remains available; compression is publication packaging, not report schema or verdict change.
The existing ThreatByte case inventory's old outbound kind is reconciled to the already
implemented request-destination SSRF contract after direct pinned-source review.

**Verification impact.** Check decompressed canonical equality, format/status parity,
refresh repeatability, source-case results and per-file GitHub size limits before commit.


### 2026-11-15 — Export the scanner's full report

**Source.** Full-sized offline publication trial failed at the existing exporter 64 MiB
read ceiling, although the scanner itself generated a valid 206 MiB canonical report.

**Changed sections.** Section 4 includes the narrow saved-report reader limit change.

**Rationale and summary.** Keep the reader bounded at 512 MiB, sufficient for this full
report, and preserve its schema/decoding/rendering behavior. This is needed to publish
and subsequently refresh the complete authorized results; it changes no acquisition,
model request, assessment or finding behavior.

**Verification impact.** Export the actual full-sized report to both formats, compare
record counts/statuses, and run the existing CLI export/race tests. No additional paid
assessment is needed because only offline saved-report reading changes.


### 2026-11-15 — Delivery-list and Python metrics reconciliation

**Source.** The user explicitly requested the project implementation-plan delivery list
and vulnerable-Python-app metrics be updated before commit/push/draft PR creation.

**Changed sections.** Section 4 adds the sample-app metrics catalog.

**Summary and verification impact.** Record this refactor as an implemented deliverable
in the sequenced delivery list, with contract/results links and human merge status. Update
all four Python app metrics from their actual fresh reports, including scope, requests,
tokens, completion/outcomes and replay counts. Preserve existing Node/TypeScript metrics
and artifacts. Do not commit or push until the complete paid run and exports are verified.


### 2026-11-15 — Reconcile independent source-case references

**Source.** Direct pinned-source review during final report/metric reconciliation.

**Summary.** Retain all six VulnPy positive expectations, correcting the Jinja locator from
its render call to the actual raw template output (already recognized before this refactor).
Keep the four coverage controls and their historical gap expectations; require either
source-backed resolved registration/dispatch/invocation or an explicit warning, and fail
when both are absent. Source references document the corrections. No positive was dropped,
reclassified safe, or fed back into detector/model inputs.

**Verification impact.** All 39 current Python source checks pass; explicit negative tests
verify that missing bindings without a warning fail. Final full paid replay and all-format
parity pass for every candidate. No Node/TypeScript paid reruns or artifact changes.


### 2026-11-15 — Verify root example-report links

**Source.** The user explicitly requested README references to the correct VulnPy and
ThreatByte examples. The root table now includes all four refreshed Python samples;
VulnPy notes link its full gzip JSON/SARIF. Hosted preview paths preserve correct casing
and the existing stage-based Pages layout. Relative files and all generated links are
verified before commit; hosted content updates after human merge into stage.
