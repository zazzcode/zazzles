# Analysis pack MVP — SQL-first component migration

## 0. Capability

Organize existing scanner knowledge into an internal, embedded, versioned component catalog and
make SQL injection its first working consumer across supported JavaScript, TypeScript and Python.
Static evidence assembly and semantic judgment MUST use one explicit component selection; judgment
and reports MUST preserve its provenance. This changes knowledge ownership and composition while
preserving supported discovery, evidence, outcomes and coverage limits.

This contract derives from the user-supplied `analysis-pack-mvp-proposal.md` review copy dated
2026-11-05, including Scan/Inspect/Audit/Fix and standards-workflow additions. The [tracked proposal](../project/analysis-pack-mvp.md) is available on the merged foundation.
The user authorized implementation, applicable SQL tests, scoped cleanup, and updates to the plan
and root README on 2026-11-05. A different Contributor Agent implements runtime code and tests;
the specification author integrates documentation and verification.

## 1. Required reading for the implementor

Load these in order, then only their task-relevant references:

- [AGENTS.md](../../AGENTS.md#start-here) and
  [agent orientation](../docs/zazzles-agent-orientation.md#task-reading-paths), including current-work
  notes and documentation ownership. Reconcile historical instructions with actual Git state.
- [Implementation plan](../project/implementation-plan.md#complete-delivery-list) and
  [common entry/dispatch brief](../project/common-entry-dispatch.md). Read the
  [pack proposal](../project/analysis-pack-mvp.md) and its updated plan section in this worktree.
- [Technical approach](../../docs/technical-approach.md#source-backed-analysis-with-constrained-semantic-judgment),
  [database injection](../../docs/scan/analysis/database-injection.md#three-independent-questions) and
  [input validation](../../docs/scan/analysis/input-validation.md#establish-the-field-policy).
- [Query judgment](../architecture/query-judgment.md#data-flow),
  [trace contract](../architecture/trace-judgment.md#implemented-evidence-contract),
  [evidence roles](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) and
  [reporting](../architecture/reporting-and-sarif.md#canonical-report).
- [spec-driven](../../.agents/skills/spec-driven/SKILL.md),
  [execution discipline](../docs/agent-execution-discipline.md),
  [standards index](../standards/index.yaml), matched [code structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [spec hygiene](../standards/spec-hygiene.md),
  [docs hygiene](../standards/docs-hygiene.md), and
  [doc-check](../../.agents/skills/doc-check/SKILL.md).
- Existing patterns: `internal/guidelines/guidelines.go`, `internal/judge/client.go`,
  `injection.go`, `bundle.go`, `policy.go`, `trace.go` in that package,
  `internal/analysis/analysis.go`, `internal/parse/query_evidence.go`, `python_sql.go` in that package
  and `internal/analysispacks/contracts.go`; tests cited below. The baseline parse-owned Python
  contract file was removed after transferring its ownership. These are inventory starting points,
  not frozen descriptions of the post-prerequisite code.

## 2. Invariants

- Static adapters establish bindings, transfers, operand roles and paths. Catalog declarations,
  installed packages, API names, helper names and model confidence MUST NOT invent those facts.
- Target source, comments, manifests and repository documents remain untrusted evidence. Only
  scanner-owned embedded content supplies interpretation policy. `--checks` remains requirement
  selection, not a pack loader; this repository's `.zazz/` standards are not automatic target policy.
- Required evidence and consistency gates remain mandatory Go policy. Components MAY add required
  obligations but MUST NOT subtract core obligations, clear blockers or certify protection.
- Validation, construction practice and injection remain separate. SQL binding does not establish
  field validity; construction practice alone does not establish injection. Protection stays scoped
  to the operation, operand and all relevant feasible paths in the candidate's invocation context.
- Discovery identities, zero-use entries, source hashes/spans, blockers, coverage and supported
  outcomes MUST remain equivalent to the accepted baseline. Source availability alone does not
  resolve a blocker. Detection improvements require a separate scope decision.
- Historical reports and raw responses retain their original versions and answers. Changed effective
  requests MUST reject stale replay. Offline discovery, stub assessment and live assessment remain distinct.

## 3. Scope and review shape

One deliverable, one specification, the existing `analysis-pack-mvp` worktree/branch, and one intended
draft PR into `stage`. Inventory, SQL integration and compatibility are ordered recovery checkpoints
within this deliverable because none alone delivers the working migration. Do not create a stack or
additional worktrees for these phases. Human review owns integration; agents MUST NOT merge.

### Baseline prerequisite

The common-entry/dispatch prerequisite landed through PR #8 at merged `stage` revision
`f8b7dbdfe1521d9b914f271fa68b26b01fdec97b`. Remote verification and the merge commit confirm the
accepted foundation; its [acceptance evidence](../evaluation/common-entry-dispatch-results.md)
records automated and bounded rendered controls. This feature branch was rebased to that revision,
preserving this contract. It is the accepted baseline for parity and compatibility checks.
Do not modify the integration worktree or borrow unfinished changes from sibling worktrees.

### Files and ownership

All paths below are repository-relative; new filenames are the intended layout. Existing owners
MAY acquire narrowly scoped companion files after baseline inventory, recorded in the run log.

| Path | Change | Purpose |
| --- | --- | --- |
| `internal/analysispacks/{catalog,select,material}.go` and tests | New | Embedded catalog validation, deterministic selection, bounded effective material |
| `internal/analysispacks/content/` | New, if needed | Scanner-authored SQL/shared guidance and contract content actually consumed at runtime |
| `internal/analysis/{components.go,analysis.go,json.go}` and tests | New/modify | Dependency-neutral selection/provenance records and report compatibility |
| `internal/parse/` SQL evidence/API-model owners and tests | Modify | Associate verified compiled capabilities/contracts with selected obligations; preserve extraction |
| `internal/guidelines/` SQL/shared content and tests | Modify as needed | Explicit component ownership, preserving meaning and unmigrated consumers |
| `internal/judge/{client,injection,bundle,trace}.go` and companion tests | Modify | SQL composition, question material, trace provenance and replay |
| `internal/judge/policy.go` and evidence gates | Narrow modify/test | Consume additional obligations; preserve mandatory gates and outcome rules |
| `internal/report/` and `cmd/scan/` wiring/tests | Narrow modify/test | Carry provenance, read saved reports, preserve all three output formats |
| `internal/parse/testdata/` | Narrow add | Small synthetic cases only where existing fixtures do not cover the matrix |
| `.zazz/architecture/analysis-packs.md` | New | Catalog inventory, ownership, supported limits, migration ledger and compatibility decision |
| `.zazz/architecture/README.md`, `.zazz/project/implementation-plan.md` | Narrow modify | Link implemented boundary and explicit follow-on migration tasks |
| `docs/technical-approach.md`, `docs/analysis/database-injection.md`, `docs/decision-models.md` | Narrow modify if behavior described changes | Explain embedded selection/provenance and replay limits without claiming broader detection |
| `.zazz/specifications/analysis-pack-mvp.md`, `README.md` in that directory | Modify | Contract refinements and discoverability |
| `README.md` | Modify | Explain implemented SQL component capabilities and their limits |

The implementation diff MUST stay within `internal/analysispacks/`, `internal/analysis/`,
`internal/parse/`, `internal/guidelines/`, `internal/judge/`, `internal/report/`, `cmd/scan/`, and the
specific documentation paths above, including root `README.md`. Tests belong with their owning package. No module/dependency,
CLI flag, external service or target application changes are required. Any broader change requires
an in-place contract update and user direction. Unrelated cleanup belongs in separate work.

### Exclusions and follow-on ledger

Command injection is the next new family **after** MVP acceptance and requires its own contract.
XSS, standalone validation, logging, JS/TS NoSQL and outbound requests remain on their existing runtime paths in this
MVP; inventory them and preserve regression coverage. Record each in the architecture migration
ledger as `inventoried / not migrated`, with current owner, destination components, bounded next
migration task and acceptance controls. SQL is marked migrated only after pipeline acceptance.
Schedule the remaining migrations explicitly in the plan; they need not all precede command injection.
Do not introduce a second permanent policy path or an old/new SQL runtime switch.

General Inspect coverage, Audit, automated Fix, new report domains/statuses, standards ingestion,
architecture-quality detectors, independent Findings Review, whole-program IR, broader helper/heap/
async support, new languages/frameworks/APIs, automatic judgment caching, external registries,
downloads, executable plugins, custom safety contracts and Semgrep compatibility are excluded.
No paid calibration, live target execution or sample-application modifications are authorized.

## 4. Decisions and internal contract

### Embedded composition with one owner per material item

Use `internal/analysispacks` for scanner-owned metadata, material lookup and selection because both
static assembly and judgment need the same versioned knowledge without importing each other.
It MAY depend on shared analysis/language records; it MUST NOT import parse, judge or report.
Shared provenance types live in `internal/analysis`. Keep transport/decoding and mandatory gates in
judge, discovery in parse, presentation in report. Do not scaffold a generic execution/plugin engine.

Each manifest component MUST identify a stable ID, explicit version, content/descriptor SHA-256,
kind, supported claim domains, applicability, compatibility references, dependencies, compiled-owner
reference where applicable, required evidence roles, limits and regression test references.
Kinds cover language guidance, entry/binding/flow capability references, API contracts, claim questions
and evidence obligations. An embedded pack identifies a versioned composition of those components.
Content is embedded text or typed Go data; choose the smaller representation with real consumers.
Changing content MUST change its digest even when a human forgets to bump its version.

Language, entry framework, library operation and claim remain independent dimensions because supported
combinations share knowledge. No monolithic pack per cross-product. Domain metadata can describe
security, existing validation/construction practice or shared capabilities without implementing a
quality engine or forcing future quality claims into source/sink records. Scan, Inspect, Audit and Fix
remain independently usable product goals; no mandatory pipeline or new command shape is introduced.

### Evidence-driven selection shared by two consumers

Parse-side integration MUST associate existing verified bindings and compiled capability IDs with SQL
candidates and obtain a stable selection and effective obligations. Judge MUST consume/validate that
same selection rather than infer a second one from prose. Selection MUST use supported source facts
and trusted scanner configuration, never installed-package declarations alone. Unknown library versions
MUST retain their known contract assumptions/limits; do not fabricate a version or widen applicability.

Resolve dependency closure, reject duplicate IDs, incompatible versions, cycles and conflicting
required choices; sort by stable IDs for serialization and digests. Missing required components in the
embedded catalog are configuration errors before model calls. Candidate-specific unsupported or
ambiguous applicability preserves the candidate and original gaps, records explicit coverage failure
in `analysis_components.failure`, fails assessment explicitly and
makes no model call; it MUST NOT drop the candidate or silently use generic guidance. Do not convert
an unsupported case into a definite result merely to satisfy the selector.

Compiled capability references describe existing support; they cannot enable an unimplemented adapter.
Effective required roles are the union of mandatory core and selected component obligations.
Record selected roles under candidate `analysis_components.required`; preserve the original
`completeness.required` and source gaps, and check their union against actual evidence in Go judgment. A shared callable MUST keep selections/effects scoped to each
invocation context; one caller's guard or API binding cannot protect another caller.

### Bounded candidate material, unchanged claim meaning

For SQL, compose only applicable language/shared guidance, verified operation contracts, SQL claim
questions/choices and interpretation material. Migrate existing question semantics and API content;
retain validation and construction facets. Separate SQL-relevant guidance from unrelated XSS/logging/
NoSQL guidance without rewriting its security meaning. Inventory each moved item and original owner.
The old SQL definitions MUST delegate to or be replaced by the new owner, not remain duplicate sources.

The judge receives source trace plus selected interpretation content. It MUST NOT receive executable
adapters, catalog-wide listings, test labels, coverage-test names or unrelated claim text. Preserve
source deduplication and existing evidence bounds. Enforce 32 selected components, 16 KiB of selected
interpretation material and the existing 64 KiB final provider-body limit in Go. Record measured
baseline sizes and the headroom rationale in the architecture document. Oversize requests MUST fail
explicitly before HTTP, preserve an unresolved result and never truncate required material/evidence.

### Provenance and compatibility are observable contracts

Persist ordered pack/component IDs, versions, digests and selection digest per SQL candidate, including
offline selection; assessed SQL records/traces additionally identify the effective request digest and
protocol version. A report-level deduplicated catalog MAY reduce repetition only if each candidate's
selection is recoverable. Distinguish selected-for-analysis from actually assessed provenance.
Digests MUST use deterministic canonical serialized material/descriptors, including dependencies,
applicability, obligations and compatibility, not filenames or version strings alone.

Use SQL-specific question/envelope protocol identifier `sql-components-v1` because its request composition changes.
Leave unmigrated family protocols unchanged. Increment the fresh report schema to 4 from the accepted
baseline's version 3 because selection provenance changes the report contract; retain historical schema
read/export support, without adding invented component identities to old reports. Record the exact
new schema/protocol identifiers at the first implementation checkpoint before integration.

Keep exact effective provider-body matching in Replay, in addition to protocol checks. The request
MUST bind selected IDs/versions/digests and material, instructions, evidence, questions/choices and
model. A changed selection or any of these inputs rejects saved answers even if a version is unchanged.
Never rewrite historical responses or rebrand an exported saved report as a fresh assessment.
HTML/SARIF keep existing issue semantics/counts; canonical JSON owns detailed provenance. No report
layout redesign is required.

## 5. Agent implementation rules

The user requested a different implementing agent. A Contributor Agent owns runtime code and
its tests under `internal/` and `cmd/scan/`; the specification author owns documentation, the local
run log and final integration verification in the same worktree. File ownership is disjoint and
runtime changes are serialized by that Contributor Agent. No further agents are required.
The user's implementation request supplies authorization under
[AGENTS](../../AGENTS.md#authorization-and-delivery). Commits, pushes and PR creation are not
requested by this turn; verify identity/authentication before any subsequently assigned such action.

Run commands from the assigned worktree root using its declared toolchain; use the
[linked toolchain setup](../docs/worktree-setup.md#linked-computer-agent-toolchain) when applicable.
Record the accepted baseline in the local run log. Inspect scope with `git diff --stat`,
`git diff --name-only <accepted-base>...HEAD`, `git diff --name-only` and
`git ls-files --others --exclude-standard`; review committed, unstaged and untracked changes together.

Halt product changes for an unmet prerequisite, necessary detection expansion, unexplained outcome or
blocker drift, a required core-gate weakening, incompatible saved-report behavior, inability to keep
applicable material bounded, or changes outside scope. Preserve evidence, explain the specific issue,
and resolve the contract before continuing dependent work. Missing credentials are not a blocker for
this offline MVP. Do not infer paid-call permission from a configured key.

## 6. Acceptance criteria

The test names below are prescribed new tests unless explicitly identified as existing. Names MAY be
adapted to package conventions if the same observable assertions and coverage are retained in the log.

| ID | Required observable result | Verification |
| --- | --- | --- |
| A1 | Accepted prerequisite SHA/evidence recorded; inventory maps existing guidance, contracts, questions, obligations and tests across all families; SQL has one runtime owner | Architecture inventory, migration ledger, baseline log and scope diff review |
| A2 | Catalog detects duplicates, missing dependencies, cycles, incompatible/conflicting choices; changed bytes alter digest; identical input yields identical closure/order | `internal/analysispacks`: `TestCatalogValidation`, `TestSelectionDeterminism` |
| A3 | JS/TS/Python supported SQL selects the correct independent components from verified evidence; fake APIs/package-only declarations cannot select a trusted contract; unknown/unsupported bindings/versions retain limits; caller contexts do not borrow effects | `TestSQLApplicability` in analysispacks and parse integration; existing binding/context controls |
| A4 | SQL request has only applicable interpretation material and actual trace; facets/questions/choices retain meaning; no labels/catalog/adapter data; explicit limits reject oversized requests before HTTP | `internal/judge`: `TestSQLComponentPayload`, `TestSQLComponentLimits`; tests for both provider encoders with local stubs |
| A5 | Raw, bound, constrained, unresolved and mixed-path SQL preserve discovery, source/slot/context, blockers, coverage, raw answers and policy outcomes through parse → local judge stub → JSON/HTML/SARIF; optimistic answers cannot bypass gates | `TestSQLComponentPipelineParity`, `TestSQLPythonComponentPipeline`; existing `TestInjectionPolicySeparatesPracticeAndActualProtection`, `TestPythonEvidenceDecisionReportPipeline` |
| A6 | Missing/conflicting catalog material yields configuration failure; per-candidate unsupported/oversize selection yields explicit unresolved assessment, retained candidate/gap and zero HTTP calls; no generic fallback | `TestSQLSelectionFailurePipeline` and A2/A4 negative cases |
| A7 | Reports/traces expose exact selected provenance; unchanged requests replay; changed guidance, contract, question/choice, evidence, selection metadata, protocol or model reject replay; old report exports preserve original answers/versions | `TestSQLComponentReplay`, `TestComponentReportCompatibility`; existing `TestSavedDecisionReplayRequiresIdenticalEvidenceAndRetainsScores` |
| A8 | Unmigrated families retain behavior/protocol and regression coverage; zero-use/unsupported entries persist; no live/stub/discovery conflation; scoped and full offline checks pass | `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...`; changed-file format and doc checks |
| A9 | Measured selection cost/allocations, selected-material bytes and final provider-body bytes are recorded versus the accepted baseline; all baseline controls fit declared limits without dropped obligations | `BenchmarkSQLComponentSelection` with `-benchmem`; payload measurements from A4/A5; architecture evidence summary |

## 7. Test strategy

Capture the accepted baseline before moving content. Reuse existing fixture evidence and fixed
responses; compare normalized observable records, allowing only enumerated schema/provenance/envelope
changes. Never normalize away IDs, bindings, blockers, coverage, finding types/counts, facet outcomes
or source hashes. Preserve the baseline projection so tests cannot approve drift by regenerating goldens.

Use a compact table-driven SQL pipeline matrix: raw executable interpolation; separately bound values;
syntax-constrained construction that retains a practice concern; missing helper/API/path evidence;
dynamic identifiers with bound values; unsafe and safe alternatives; shared callable contexts with
unequal guards; and unrelated bound-value transformations. Exercise JS and TS separately, Python sqlite3
and the existing Psycopg 2/3, PyMySQL and MySQL Connector contracts. Parameterize nearby forms and reuse
`TestPythonDBAPIBindings`, `TestConditionalQueryOutputConstraints` and
`TestAutomaticQueryEvidenceControls`; do not duplicate all parser tests in the catalog package.
After prerequisite merge, include its supported HTTP/dynamic/GraphQL/gRPC SQL controls where present,
and unsupported cases, without adding adapters or extending that milestone's supported subsets.

Local `httptest` responses MUST include vulnerable, protected, unknown and not-applicable answers and
optimistic protected/vulnerable answers on incomplete evidence. Expected outcomes stay in assertions
and stub configuration, outside requests. Reuse strict-decoder, timeout/non-200 and cancellation tests.
Run existing XSS, NoSQL, validation and logging tests as regression coverage. Verify legacy export with
saved schema-1/schema-2 fixtures plus the accepted baseline schema if different; absence of provenance
must remain absence. Replay mutation tests change one effective dependency at a time, including bytes
without version bumps. Size measurements and benchmarks are offline; no latency threshold dependent
on host timing is a unit-test assertion. Offline parity is not proof of live-model accuracy.

## 8. TDD entry point and execution sequence

1. **Inventory/recovery checkpoint.** Verify prerequisite, preserve this spec, record accepted base,
   run baseline checks and capture normalized fixtures, payload sizes and actual current identifiers.
   Write the architecture inventory, migration ledger, exact compatibility identifiers and size limits.
2. **First failing test.** Add `TestCatalogValidation` and the missing-required-contract case of
   `TestSQLSelectionFailurePipeline`: a SQL candidate must remain unresolved with zero HTTP calls.
   Implement embedded catalog and dependency validation; prove existing behavior unchanged before wiring SQL.
3. **Selection checkpoint.** Add applicability/determinism tests, then wire verified capability/API
   references and effective obligations into SQL assembly. Retain actual parse evidence and limits.
4. **Working SQL checkpoint.** Add payload and pipeline parity tests; move SQL/shared interpretation
   content to its single owner. Connect both provider encoders, selected questions and mandatory gates.
   Explicitly account for SQL validation/construction facets and unmigrated-family consumers.
5. **Compatibility checkpoint.** Add provenance, schema migration/read-export tests, replay mutations
   and limit failures. Update report wiring and confirm JSON/HTML/SARIF parity against captured baselines.
6. **Closeout.** Measure overhead, complete the migration ledger and public/internal documentation,
   run scoped checks then contributor full checks, and review diff/scope. Report remaining limits and
   any unmet criterion; do not describe inventory-only delivery as a completed MVP.

Minimal responsibility skeleton (internal names may adapt to the merged baseline):

```go
// internal/analysis/components.go: shared, serializable value records only.
type ComponentRef struct { ID, Version, Digest string }
type ComponentSelection struct { Pack ComponentRef; Components []ComponentRef; Digest string }

// internal/analysispacks/catalog.go: validate embedded descriptors/dependencies once.
// internal/analysispacks/select.go: source-backed facts -> deterministic selection or explicit error.
// internal/analysispacks/material.go: selection -> bounded interpretation material/obligations.
// internal/parse/: existing SQL assembly -> verified facts -> selection + effective evidence roles.
// internal/judge/: selection + trace -> provider body -> existing decoder and mandatory Go policy.
```

Do not add public extension interfaces or speculative execution hooks to realize this skeleton.

## 9. Definition of done

- [x] Every acceptance criterion has evidence; SQL is a working migrated runtime consumer.
- [x] Baseline source relationships, claim outcomes, gaps and report counts remain equivalent.
- [x] Selection failures/limits cannot produce protection, silent omission or model requests.
- [x] Provenance, protocol/schema compatibility and stale-replay rejection are verified.
- [x] Scoped tests and contributor build/vet/race checks pass; changed Go files are formatted.
- [x] Documentation links/checks pass; inventory and follow-on tasks are durable and current.
- [x] Final report identifies exact commands, measurements, accepted base, remaining limits and deviations.

Human acceptance/review remains separate from agent verification. Any unchecked item is reported as incomplete.

## 10. Open questions

No product-scope question blocks specification delivery. Implementation was assigned by the user and the prerequisite merge was verified against remote
`stage`. No prerequisite approval remains pending.
Precise post-merge symbols, schema numbers and measured bounds are checkpoint outputs constrained
above; they are not permission to redesign detection or reporting. Conflicts require user resolution.

## 11. Run log protocol

Use one ignored local log under `.zazz/ephemeral/`, following its
[storage policy](../ephemeral/README.md); reuse an existing effort log or create
`analysis-pack-mvp-run-log.md` there on implementation assignment. Track standards verification,
baseline/phase evidence, resolutions, deviations, QA/rework and recovery notes append-only.
Scan/test result artifacts belong in the prescribed external `_test-findings/` location; the log
links them. Durable inventory, compatibility decisions and acceptance summaries remain tracked.
Resume by reading this contract, the local log if present, actual Git state and relevant diffs.

## 12. Agent implementation prompt

> Implement `.zazz/specifications/analysis-pack-mvp.md` in the existing `analysis-pack-mvp`
> worktree/branch when explicitly assigned. First read `AGENTS.md`, the referenced agent orientation,
> this contract and the relevant required reading/skills/standards. Verify actual path, branch and
> changes. Confirm common-entry/dispatch acceptance and merge into `stage` before product changes;
> preserve this contract when updating the feature baseline. If the dependency is unmet, report it.
> Own runtime code and tests as the Contributor Agent, independently of the specification author
> who integrates documentation and final verification. Use the local ignored run log; no external
> tracker or further delegated agents are required. Execute the ordered checkpoints,
> starting with baseline inventory and failing boundary tests. Deliver a real SQL component migration
> across existing JS/TS/Python pipelines, preserving independent validation/construction/injection
> semantics, mandatory Go gates, coverage limits and historical reports. Verify both provider encoders
> with local stubs, exact-request replay and JSON/HTML/SARIF parity. No paid calls, sample edits,
> new detection families or broad cleanup. Update the contract in place for accepted scope changes
> and record their rationale below. Run scoped and full required checks; report evidence and unmet
> criteria candidly. Do not merge or push integration branches; follow the user's assignment for
> commits, feature pushes and draft PR creation.

## 13. Implementation and review change log

### 2026-11-05 — Implementation assignment and merged baseline

**Source.** User requested implementation, applicable SQL injection tests, scoped cleanup, plan and README updates.

**Changed sections.** Capability, baseline, scope, compatibility, implementation rules, open questions and prompt.

**Rationale.** PR #8 has landed; the remote `stage` revision is now the accepted baseline. The user's
request assigns implementation and extends documentation scope to the root README.

**Summary.** Recorded the merged base, schema 4 and `sql-components-v1`, runtime/documentation ownership,
and the authorized documentation updates. No detection expansion or paid evaluation is included.

**Verification impact.** Compare SQL behavior against the merged foundation and include root README in doc checks.
Selected evidence obligations and selection failures use separate component provenance fields so the
original source-required roles, blockers and coverage records remain comparable without normalization.

### 2026-11-05 — Follow-on session recommendations

**Source.** User requested advice after SQL acceptance on NoSQL, validation, logging, all XSS types
and outbound requests, including whether to use separate sessions.

**Changed sections.** Follow-on ledger; implementation plan and architecture migration ledger.

**Rationale.** Preserve attributable behavior comparisons and keep new detector work separate from ownership migration.

**Summary.** Record separate bounded family sessions, staged XSS work and an outbound migration that
preserves existing destination evidence without claiming complete SSRF assessment. No other-family
implementation is assigned in this SQL refactor.

**Verification impact.** Existing other-family regression suites remain mandatory for SQL closeout;
future migrations require their own paired controls and compatibility evidence.

### 2026-11-05 — Implementation verification completed

**Source.** Contributor implementation evidence and independent author review/checks.

**Changed sections.** Required reading and definition of done; architecture evidence and plan status.

**Rationale.** SQL is a working consumer, including both transports and saved-report compatibility.

**Summary.** Removed the obsolete parse-owned Python contract file, fixed missing required catalog
roots as startup configuration errors, completed offline acceptance and documented the actual owners.

**Verification impact.** Final full race suite, vet, build, changed-Go formatting and documentation
checks pass. Frozen source/evidence hashes preserve the accepted foundation; no live accuracy claim
or other-family migration is inferred. Human review remains separate.
