# Python support — implementation contract

**Branch/worktree:** `python-support-base`. **Owner:** human user. **Date:** 2026-11-01.
**Topology:** one feature branch and one review unit for the Python adapter and evaluation.
The user authorized implementation, required downloads, `gpt-6-luna` decision requests without a user-imposed count cap, and commits/results. The user subsequently authorized pushing this feature branch and sustained general hardening; no merge.
Integration remains `stage`, through later human PR review. Local run log:
`.zazz/ephemeral/python-support-run-log.md`. The lead agent implements and reviews directly.

## Capability

Supply Python route, request, value-flow, SQL, logging, rendering and outbound evidence
through the existing language-neutral graph, judgment and JSON/HTML/SARIF reports.
Evaluate and iterate against all three pinned Python targets and independent source references.

## Required reading

- [Orientation](../docs/zazzles-agent-orientation.md), [execution discipline](../docs/agent-execution-discipline.md).
- [Plan, Python adapter](../project/implementation-plan.md#phase-11--python-adapter).
- [Graph](../architecture/repository-graph.md), [evidence](../architecture/evidence-and-claims.md).
- [Analysis guides](../../docs/scan/analysis/README.md): input validation, database injection, logging, XSS, calibration.
- [Sample reference policy](../../docs/samples/reference-policy.md).
- Standards: [structure](../standards/code-structure.md), [testing](../standards/testing.md),
  [spec hygiene](../standards/spec-hygiene.md), [docs hygiene](../standards/docs-hygiene.md).
- Existing `internal/parse/analysis.go`, `xss_claims.go`, graph records and report/judge adapters.

## Architecture and terminology closeout

The user authorized this closeout in the existing feature worktree before the draft PR.
It changes naming and documentation, not vulnerability coverage or security policy.

- Rename the embedded language documents and their Go types to **Analysis Guidelines**.
  Move `internal/rules/` to `internal/guidelines/`; distinguish embedded model guidance
  from executable detection rules, application requirements and Go policy gates.
- Rename `StringUse` to `CandidateUse`, `StringReport` to `AnalysisReport`, and
  `graph.Graph` to `analysis.RouteInventory`. Move shared records to `internal/analysis/`.
  Rename parser entry points to `Analyze` and `AnalyzeWithChecks` and document `--analyze`.
- Keep `--strings` as a working compatibility alias for existing user scripts. No old
  internal Go aliases remain. New analysis reports use schema 2 and `analysis_guidelines`;
  saved schema-1 reports with `practice` remain readable for HTML/SARIF export.
  Route inventory JSON remains schema 1. Candidate IDs, claim statuses and evidence stay intact.
- Rename the model-input key to `analysis_guidelines` and version changed embedded documents
  and generic questions. Existing claim-specific question versions retain their question semantics.
  Exact-request replay MUST reject old payloads after guideline text or envelope changes.
  Historical sample artifacts retain their original source, answers, versions and provenance.
- Rewrite the main architecture overview around implemented packages and pipeline. Label the
  full repository IR, independent Findings Review, caching and CI severity gates as planned.
  Keep existing architecture anchors working where practical.
- Document the technical approach and design strengths in `docs/technical-approach.md`, with
  official SAST/prior-art references, scoped evidence and explicit limits on novelty/superiority.
- Verify with the full Go race suite, vet and build; targeted compatibility tests MUST prove
  both CLI names work, old/new saved reports export, guidelines enter both provider payloads,
  changed guidance cannot inherit a saved decision, and current names serialize correctly.
  Run the built CLI offline on JS/TS and Python fixtures and export real saved sample reports.
  Check changed docs for links, formatting and stale names. No paid requests or sample edits.

## Invariants

Sample checkouts MUST remain clean at pinned revisions; analysis MUST NOT execute target code.
Expected labels MUST stay outside target source and model inputs; no target-name detector exceptions.
Unknown flows, bindings, guards and renderer settings MUST NOT become protection or proven paths.
Validation and sink protection remain separate. Claim questions and policy semantics remain unchanged except for the explicitly authorized terminology migration below.
Only the selected provider key reaches a live scanner child; never print secrets.
New evidence MUST NOT inherit decisions for an older request. Record cumulative live usage; use explicit per-run limits, no fallback.

## Scope and review shape

One branch keeps extraction, evidence and evaluation reviewable together; no extra worktrees.
All product changes stay in this worktree. Raw runs are outside it in `_test-findings/<app>/<run>/`.

| Paths | Change | Purpose |
| --- | --- | --- |
| `go.mod`, `go.sum` | modified | pinned Python grammar |
| `internal/parse/python_*.go`, Python testdata | new | separate Python adapter and paired fixtures |
| `internal/parse/parse.go`, `analysis.go`, `modules.go`, `flow.go`, `xss_client*.go` | modified | language dispatch, mixed repositories and reusing browser analysis for inline template scripts |
| `cmd/scan/` | modified | Python CLI acceptance, help and end-to-end tests |
| `internal/guidelines/python.md` | modified if needed | accurate Python Analysis Guidelines |
| `internal/analysis/`, `internal/report/`, `internal/judge/` | modified only if necessary | language-neutral compatibility; version changed generic questions and guideline documents |
| `docs/analysis/`, `docs/samples/`, `README.md`, `docs/` | modified/new | implemented subset, source keys, curated baselines and usage |
| `.zazz/specifications/`, `.zazz/evaluation/`, `.zazz/docs/zazzles-agent-orientation.md` | modified/new | tracked contract, durable evaluation and current resumption pointers |
| `.zazz/ephemeral/` | ignored | execution history, scripts and local results |

Paths reflect [architecture phase 3B](architecture-phase-3-js-ts-python-package.md): the adapter moved
from `internal/parse/python_*.go` to `internal/langpy` (prefix dropped) and its fixtures to
`internal/langpy/testdata`. It uses `parse`'s language core API and reaches browser analysis only
through `langjs.AnalyzeInlineScripts`.

Out of scope: new vulnerability families, SCA, other languages, edits/dependency installation
inside samples, deployment, integration pushes and merge. Draft PR publication into `stage` is
explicitly authorized for this branch closeout. NoSQL is out of corpus unless
source inspection finds actual PyMongo use. Outbound destinations are existing candidate evidence,
not an expanded SSRF verdict engine.

## Decisions

- Use pinned Tree-sitter Python with a separate adapter; reuse public graph/report/judge records.
  This avoids importing Express assumptions into Python semantics.
- Resolve verified Flask/Blueprint, RESTX Resource and FastAPI registrations and local Python imports.
  Static literal mounts are supported; dynamic mounts and decorators carry explicit gaps.
- Bound helper expansion to three calls, source files to 2 MiB, and preserve uncertainty on
  loops, mutation, custom wrappers and unresolved calls. Do not infer arbitrary whole-program flow.
- Parameterized SQL remains a negative for construction defects while validation is separate.
  A SQL-like name without driver binding cannot establish execution.
- Jinja autoescape applies only with verified Flask template configuration and matching context;
  raw filters, Markup and dynamic template construction retain provenance and path alternatives.
- Stored origins require a supported table/field write/read link. Otherwise record Review.
- Iterate accuracy using source-reviewed keys, app documentation and existing comparator output.
  Report comparator-only out-of-scope cases separately; never tune to benchmark names.

## Implementation rules

Run commands from this worktree using native Go 1.27.3, `GOTOOLCHAIN=local`,
`GOCACHE=$PWD/.zazz/ephemeral/go-cache`; verification uses `GOPROXY=off`.
Downloads are authorized only for required grammar/dependencies. Keep separate context-dependent
files within structure limits. Preserve existing JS/TS behavior and unrelated changes.
Commit coherent green work locally after checking path, branch, identity and auth profile.
Stop an affected operation on dirty samples, provider/account exhaustion or destructive recovery needs;
continue independent safe work. Record unresolved requirements and implementation limits honestly.

## Acceptance criteria

- Python Flask, Blueprint, RESTX and FastAPI entry inventories have deterministic source-backed
  routes; Python CLI entry works and mixed repositories retain JS/TS entries.
- Supported assignments, f-strings, percent/format/concatenation, direct helpers/imports and branches
  retain dependencies and transfers. Reassignment and unsupported transfers cannot imply safety.
- SQL text versus parameter arguments, request-sensitive logging and outbound destinations have
  verified bindings. Fake/shadowed APIs do not become definite sinks.
- Flask/Jinja and FastAPI HTML output carry context/protection facts; escaped, raw, stored and
  unresolved outputs are distinguished. Branch-only protection does not protect raw siblings.
- Python facts pass existing judgment and reports without language-specific report forks.
- All three samples have source-reviewed keys/hashes, comparator comparison, fresh reports and
  an accuracy ledger of matched/missed/false-positive/Review cases. Iterate to address actionable
  supported-family gaps and document residual limits without claiming parity.
- Offline scoped tests, full race tests, vet, build, changed-file formatting and doc checks pass.
- Baseline targets remain unchanged; live usage is recorded and respects provider restrictions.

## Test strategy

Use synthetic real Python fixtures with positive/protected/unknown siblings, binding shadowing,
parameterized controls, raw versus encoded outputs, aliases, branches, helpers/imports, typed
FastAPI inputs, fixed versus request-influenced destinations and unresolved stored origins.
`TestPythonRoutes` is the first failing test. `TestPythonEvidence` exercises use-level facts and
`TestPythonCLI` checks canonical output and entry selection. Existing JS/TS tests are regression
coverage. Tests use local/stubbed decisions; live calibration is separately capped and recorded.
Verify determinism by repeated normalized output and inspect source spans/hashes.

## Execution sequence and skeletons

1. Establish source-reviewed keys and hashes and curate comparator baselines before scanner code.
2. Add failing Python route fixture/test, pin grammar, load modules, bind receivers, extract routes.
3. Add bounded `pythonFlow` evaluation (`eval`, `block`, `call`) with independent environment states.
4. Add verified SQL/log/outbound models with explicit operand roles and gaps.
5. Add rendering/template bindings, contexts, protection paths and bounded storage correlation.
6. Integrate CLI/report/judge; run all three apps, compare keys, fix generic causes and rerun.
7. Calibrate with fresh Luna requests with recorded cumulative usage, rerun checks, review diff and commit locally.

Skeleton: `pythonSet` owns parsed module snapshots; `pythonModule` owns imports and declarations;
`pythonFlow` owns route-local values, gaps and uses; rendering and SQL models live in separate files.

## Generalization and guardrail hardening

User steering authorizes sustained iterations beyond the original three-app slice, on the same branch.
Keep the existing vulnerability families; broaden their source/binding/flow coverage using independently
specified synthetic cases. No sample-name shortcuts and no new vulnerability-family verdicts.

Additional acceptance evidence:

- Alternative dictionary fields and missing/unresolved values cannot borrow sibling protection.
- Local package imports, request aliases and supported helper argument binding retain source identity;
  unsupported parameters, mutation, loops and custom guards remain explicit rather than disappearing.
- Add verified DB-API connection models for PostgreSQL/MySQL alongside sqlite, with driver-specific
  contracts; fake/shadowed bindings remain negatives, and SQLite storage correlation stays scoped.
- Decision bundles include actual guard conditions/helpers and fact/assumption/blocker roles. Model
  interpretation cannot discharge unresolved source facts. Changed questions require a new version.
- Audit every README/upstream author vulnerability claim and local test/API-documentation claim into
  a separate covered/unsupported/out-of-scope inventory; do not put expected labels in model inputs.
- Add novel synthetic positive/protected/unknown controls, compare the pinned comparator tools on a
  compatible corpus where useful, and retain actual misses/overclaims instead of asserting broad parity.

New tests: `TestPythonGeneralizationBranches`, `TestPythonPackageImports`,
`TestPythonDBAPIBindings`, `TestPythonUnknownHelperParameters`, plus targeted policy/bundle tests.
The existing parser/CLI/race/vet/build and source-integrity checks remain required. Iterate in coherent
green commits and push `python-support-base`; the user subsequently authorized draft PR publication
into `stage`. No integration push or merge is authorized.

## Shared trace and reporting hardening

The user's source-graph-to-Luna design is implemented in the common judge, with versioned
trace evidence, operand roles, coverage ledger and separate validation policy. Required tests
cover evidence references, missing roles, unsafe/escaped/unknown alternatives and report gates.
Only Protected is green; inconclusive content cannot retain a protection title. Remediation
must identify the operation, field policy and exact supported repair or investigation blocker.
Architecture, evidence design, functionality and public analysis guides must match the code.

## Definition of done

Implementation, tests, source keys, all three reports, accuracy iterations, recorded limits and
local commit are complete. Final report links actual saved results and validation evidence.
Acceptance evidence is recorded by the agent; final acceptance remains with the human.

## Open questions

Resolved by the user: downloads allowed; `gpt-6-luna` only, count cap removed after increases from 25 to 100;
feature-branch push allowed; iterate accuracy against other SAST and app documentation.
No unresolved question blocks implementation.

## Run log protocol

Append authorization, standards check, source checks, phase evidence, failed attempts/recoveries,
accuracy deltas and live usage to `.zazz/ephemeral/python-support-run-log.md`. Keep raw artifacts
under the app-specific `_test-findings` directories. Durable conclusions belong in evaluation docs.

## Agent implementation prompt

Resume in `python-support-base`; read this contract and local run log, inspect branch/status,
verify sample pins, implement remaining steps directly, preserve invariants and record evidence.
No paid request without updating the persistent cumulative ledger. Push the assigned feature branch only; do not merge or push integration.

## Implementation and review change log

2026-11-01: Initial scope from handoff and user authorization. User added explicit accuracy
iteration and raised the live request cap to 100, then removed the count cap during implementation, emphasizing accuracy.

2026-11-01: User emphasized all sample XSS and PII logging. Source review found inline jQuery DOM XSS in ThreatByte; extend the existing browser adapter through snapshot-preserving template-script parsing and verified jQuery CDN bindings. Add source-backed form requirements and literal/database logging sources; retain shared judgment questions.

2026-11-01: Explicit sample-source transmission approved after auto-review requested clarity. Live calibration completed 78 calls across 77 current records; literal-address sensitivity now blocks model overclaims. Results, tests and 22-case evidence are linked from the evaluation and current orientation.

2026-11-01: User authorized branch push and several hours of unattended general algorithm, guardrail, decision-evidence and findings-interpretation hardening. User also requested deeper local/upstream vulnerability documentation review. Added the generalization acceptance matrix; existing family scope remains.

2026-11-02: User requested shared route/browser trace evidence, definite source-supported
validation/practice judgments, protection-color auditing and specific remediation. Added the
shared trace/reporting acceptance section and architecture documentation requirement.

2026-11-02: User added the read-only VulnPy sample and requested Zazzles/Semgrep/Bearer baselines,
living source-backed answer guides, and branch closeout. Preserve new sample misses as coverage
work, do not imply dynamic registration support. Add verified unsupported registration/path warnings
and literal keyword-path extraction controls. No new vulnerability family is included by this change.

Final route review identified contradictory generic protected-SQL titles and coarse missing-validator
wording. Shared presentation now names SQL syntax protection and defers field-policy adequacy to
its independent claim; source evidence and saved model answers remain unchanged.

### 2026-11-02 — Architecture and terminology closeout

**Source:** user requested Analysis Guidelines and correction of architecture/naming before merge.
**Changed sections:** Architecture and terminology closeout; invariants.
**Rationale:** names and the architecture overview must describe the implemented scanner.
**Verification impact:** naming migration, saved-report/CLI compatibility, payload identity,
offline end-to-end runs and full Go checks; no new live model calibration.

### 2026-11-02 — Follow-up handoff and draft PR publication

**Source:** user requested a separate common-entry/dispatch handoff with required reading, then
committing/pushing all worktree changes and creating a draft PR for human review/merge.
**Changed sections:** branch closeout authorization and out-of-scope publication wording.
**Summary:** publish the Python/terminology work as one draft PR into `stage`; the common model
remains a separately scoped foundation refactor documented in the tracked follow-up brief.
**Verification impact:** final documentation/link checks, clean committed/pushed branch and remote
verification of draft/head/base. No additional scanner behavior or live-model testing is introduced.

### 2026-11-18 — Adapter moved to internal/langpy (architecture phase 3B)

**Source:** [architecture phase 3B](architecture-phase-3-js-ts-python-package.md).
**Changed sections:** path table note.
**Summary:** package move only; Python behavior and report bytes are unchanged apart from the
embedded fixture root of moved fixtures.
