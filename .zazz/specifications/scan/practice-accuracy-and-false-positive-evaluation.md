# Practice accuracy and false-positive evaluation

**Assigned branch/worktree:** `accuracy-false-positive-eval`.
**Baseline:** `cb40f3705949` (`stage`, merged PR #20; includes PR #19).
**Project and Deliverable Owner:** human maintainer.
**Delivery topology:** one deliverable, one feature branch, one draft PR targeting `stage`.
**Review rationale:** practice corrections and their evaluation share the same source oracle and
before/after evidence. Splitting them would separate behavior changes from their accuracy claims.
**Execution record:** `.zazz/ephemeral/practice-accuracy-run-log.md` (ignored, append-only).
**Coordination:** lead owns parser changes and integration; lower-cost agents own disjoint
evaluation tooling and regression-test files. Overlapping source changes are sequential.

## 1. Capability and assignment

Measure and improve the eight shipped Next.js practice checks and evaluate the merged analyzer
baseline against source-established positives, genuine safe controls and a non-intentionally-
vulnerable reference. Practice observations MUST remain model-free and MUST NOT become vulnerability
verdicts. Security accuracy MUST be reported separately from practice accuracy.

The current assignment includes this researched contract, implementation of bounded corrections,
and evaluation. Unchecked acceptance criteria MUST NOT be represented as completed implementation.

The owner supplied proposal 2 outside the source checkout. This contract captures its operative
scope without depending on that machine-local path. Proposal 1 merged as PR #20 before this branch
was created. The source-reviewed [research record](../../evaluation/practice-accuracy/research.md)
owns the measured starting point and reproducible probes.

## 2. Required reading and standards

Read this contract, then only the relevant referenced sections:

- [AGENTS authorization and delivery](../../../AGENTS.md#authorization-and-delivery) and
  [orientation code structure](../../docs/zazzles-agent-orientation.md#code-structure).
- [Implementation plan: completed functionality](../../project/implementation-plan.md#completed-functionality).
- [Predecessor inventory: source-backed corrections](../../evaluation/analyzer-protection-and-flow-inventory.md#source-backed-answer-key-corrections)
  and [results: handed to proposal 2](../../evaluation/analyzer-protection-and-flow-results.md#not-delivered-and-handed-to-proposal-2).
- [Phase 2 Commerce measurement](../../evaluation/nextjs-phase-2-results.md#non-intentionally-vulnerable-reference-d).
- [Next.js rules](../../../docs/scan/analysis/nextjs.md),
  [calibration pairs](../../../docs/scan/analysis/calibration.md#regression-pairs),
  [claim completeness](../../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [judgment and gates](../../architecture/trace-judgment.md#separate-judgments-and-gates).
- [Contributor verification](../../../docs/contributing.md#verification) and
  [live-run scope](../../../docs/scan/decision-models.md#scope-a-live-run), only before paid evaluation.

| Applicable standard | Application and verification |
|---|---|
| [Spec hygiene](../../standards/spec-hygiene.md) | Portable contract; numbered observable acceptance |
| [Docs hygiene](../../standards/docs-hygiene.md) | Links, durable ownership, no machine-local paths |
| [Code structure §§1–6](../../standards/code-structure.md#1-package-layout) | Reuse parse boundaries; bounded helpers, deterministic output |
| [Testing §§2–9](../../standards/testing.md#2-test-kinds) | Paired regressions, offline stubs, race evidence |
| [PR process](../../standards/pr-process.md) | Load before publication; one draft into `stage`, human merge |

Recheck `.zazz/standards/index.yaml` against the actual changed paths before implementation.
Use local `spec-builder`, `spec-driven` and `doc-check` skills for their respective phases.

## 3. Scope and invariants

All changes MUST remain in the assigned checkout. The allowed tracked paths are below; filenames
for focused new helpers may vary within the named directory, with a reason recorded in the run log.

| Path | Change | Purpose |
|---|---|---|
| `.zazz/specifications/scan/practice-accuracy-and-false-positive-evaluation.md`, specification index | new/modified | Contract and discoverability |
| `.zazz/evaluation/practice-accuracy/` | new | Research, case matrix, metrics, evaluator and results |
| `internal/parse/next_practice_extended.go` | modified | Remove the demonstrated syntactic shortcuts |
| `internal/parse/next_practice_*.go` | new | Focused option/cache/message/authorization helpers and tests |
| `internal/parse/next_boundary.go` | modified | Per-value Action validation; preserve source-established sensitive projection behavior |
| `internal/parse/nextjs_lab_test.go`, `nextjs_sample_test.go` | conditional modified | Source-backed answer-key assertions; never weaken existing positives |
| `docs/analysis/nextjs.md`, `docs/analysis/calibration.md` | modified | Describe verified bounds and measurement semantics |
| `.zazz/project/vulnerable-sample-apps.md`, `docs/samples/` | conditional modified | Retained final evidence and provenance only |

Invariants:

1. Expected labels stay outside model bundles. No target names or answer-key exceptions in production.
2. Protection belongs to the exact claim, operand and path. Unknown writers, aliases, mutations,
   authorization helpers or trust contracts MUST NOT establish safety.
3. Practice absence is not a Protected verdict. Practice `review` is not a security false positive.
4. Immutable targets MUST NOT be edited, checked out, installed or executed. Hashes and Git status
   are checked before/after; raw reports and traces stay outside target/source checkouts.
5. Preserve the old reports, failed paid attempts and original oracle labels. Corrections require
   source rationale and explicit old/new label history. Never improve metrics by dropping hard cases.
6. Changed request bytes require a new assessment; unchanged requests may use exact replay only.

Out of scope: new analyzers, dependency scanning, runtime exploitation, exhaustive detection,
framework upgrades, broad flow-engine refactoring, blanket validation suppression, or promises to
remove all Review records. Cross-request writer tracking through objects/exports/aliases/`Map`
is explicitly excluded. Retain `storage_origin_unresolved`; a revised bounded owner contract is
required before implementing that new flow capability. Do not create another worktree for a phase.

## 4. Corpus and source oracle

Use the eight full revisions in [research pins](../../evaluation/practice-accuracy/research.md#pinned-corpus).
Reuse all 135 predecessor inventory rows as the reconciliation universe. Do not claim all were
reassessed: every row MUST be selected, carried unchanged with provenance, excluded with reason, or
recorded as missed/unresolved. The required implementation selection includes all eight practice
checks, all 23 Commerce records, predecessor protected controls, and security siblings affected by
any shared code change. Additional reference applications require a named uncovered boundary first.

Create `cases.json` with schema version 1 and deterministic ordering. One row represents one
claim/operand/context, with a separate `defect_id` for source-defect aggregation:

```text
id, predecessor_ids[], target, revision, family, entry, sink{file,start_byte,end_byte,sha256,operand},
defect_id, oracle{class,rationale,source_refs[],label_history[]},
selection{state,reason}, baseline{run,use_ids[],assessment_state,outcome,blockers[]},
after{run,use_ids[],assessment_state,outcome,blockers[]}, disposition, evidence_refs[]
```

Oracle classes are `known_positive`, `genuine_safe`, `unresolved_trust`, `practice_expected`,
`practice_absent`, and `unjudged_candidate`. These classes MUST NOT be inferred from scanner status.
Missing candidate is a measured disposition, not a new oracle. Match by family, entry/context,
sink and operand; IDs alone cannot match changed evidence. Ambiguous matches MUST fail validation.
Carried rows with unavailable source evidence may use a null hash, explicitly outside selected
metric denominators; they MUST NOT be described as freshly source-validated or reassessed.

Commerce's Shopify endpoint is API `2023-01`; its Next.js dependency is `15.6.0-canary.60`.
Current documentation is supporting context, not proof of the pinned implementation's behavior.
CMS authorship/sanitization contracts are absent from the source archive: retain that trust boundary
as unresolved. JSON serialization alone does not escape the HTML script delimiter. Do not mark
either HTML record safe because the application is non-intentionally vulnerable.

## 5. Decisions and bounded implementation requirements

**Use established value/control evidence.** Identifier spelling and mere call presence do not
establish identity or enforcement; seven probes demonstrate why this is necessary.

| Check | Required behavior and regression boundary |
|---|---|
| NX-BP-09 | Review the actual action argument reaching the sensitive use. Validation/auth evidence must apply before that use, on its path; authentication alone cannot prove field validation or an admin permission. Pair validated input with an ignored validation result and an unprotected sibling field. Do not invent a new auth model here. |
| NX-BP-11 | Resolve verified cookie receiver options through bounded immutable local literal objects and ordered spreads. Later writes win. Safe defaults suppress the observation; a later `secure:false` restores it. Unknown spreads/options produce an uncertainty observation, never a statement that a particular flag is definitely absent. Preserve environment-conditional behavior. |
| NX-BP-13 | Preserve wildcard-host and SVG-policy observations; pair explicit restrictive configuration with broad and unresolved configuration. Resolve only supported literal configuration and identify unsupported composition without calling it safe. |
| NX-BP-14 | Preserve wildcard Server Action origin observations and literal restrictive controls. Origins are an observation of configuration breadth, not proof of CSRF or a cross-origin exploit. |
| NX-BP-15 | Identity must be source-established in the effective cache key (`unstable_cache` arguments and explicit key parts), relevant to the same cached computation. Pair a verified identity passed through an alias/argument with a constant named `user` holding `'global'`. A public cached catalog fetched beside a cookie read is not user-specific cached data. Limit local value tracing to verified imports and immutable bindings; unknown closures retain Review. |
| NX-BP-18 | Keep schema-established whole sensitive row and selected sensitive fields visible; suppress only an explicit public projection. Pair arrays/nested rows/Server Action returns/client props with public-field siblings. Unknown/dynamic projection is unresolved, not a proven public projection. |
| NX-BP-21 | An origin predicate must enforce an exact trusted origin before the same listener's data use. Ignored booleans, comparisons after use, accepting branches and sibling/nested callbacks cannot suppress Review. Pair early-return rejection and accepting-branch-only use with bypass/after-use variants. Sender origin does not establish HTML encoding. |
| NX-BP-22 | Associate the client gate with its actual request and matched method/route. Ignoring `auth()` does not establish server enforcement. Pair an enforcing server role check with authenticated-but-unprivileged, ignored-result and after-operation variants. Suppress only when existing evidence proves the relevant permission/rejection path before the operation. An unresolved API is explicitly Review. Client gate + server checks remain separate evidence. |

**Use conservative bounded resolution.** Reuse existing binding, shadowing and guard helpers. New
practice-only resolution MUST have cycle/depth bounds and distinguish established, ineffective and
unresolved evidence. Do not modify shared flow semantics to make a practice fixture pass.

**Measure explicit populations.** A curated corpus supports bounded rates, not population-wide
false-positive claims. Always publish counts and denominators as well as percentages.

## 6. Acceptance criteria

1. **Corpus reconciliation:** `evaluate.py --validate cases.json` rejects duplicate identities,
   unknown oracle classes, stale source hashes, ambiguous record mapping and unaccounted predecessor
   rows; all 135 predecessor rows and all 23 Commerce records have a disposition.
2. **Practice regressions:** `go test ./internal/parse -run 'TestPracticeAccuracy' -count=1` passes
   the eight check matrices in §5. The seven [research probes](../../evaluation/practice-accuracy/research-probes.txt)
   must change from 0/7 to 7/7 correct expectations without weakening their source examples.
   Existing `TestNextPracticeExtended` and `TestNextCookieBindingAndSensitiveProjection` still pass.
3. **No invented safety:** ignored/after-use guards, false identity names, overwritten cookie
   defaults, unresolved projection/store origin and unchecked auth return values cannot suppress
   the relevant observation or establish Protected. Assert evidence location and reason, not just totals.
4. **Commerce audit:** every record has source-use and missing-policy rationale, including all
   repeated cart contexts. Both HTML cases retain explicit origin/encoding/trust analysis. Any status
   change has a source rationale. No blanket CMS, GraphQL, JSON or validation exemptions are allowed.
5. **Metrics:** `python3 -m unittest discover -s .zazz/evaluation/practice-accuracy -p 'test_*.py'`
   proves formulas below using mixed known labels, missing candidates, excluded controls, unjudged
   records, repeated contexts, failed assessments and zero denominators. Output is stable under row
   reordering. Unjudged/unknown cannot be treated as a correct safety judgment.
6. **Security accuracy:** zero false Protected on selected established positives and zero false
   Confirmed on selected genuine safe controls, with assessed numerator/denominator and coverage
   alongside each claim. Missing/unjudged cases remain in recall denominators. Offline-only runs
   MUST label semantic error rates unmeasured rather than reporting a successful zero-error study.
7. **Regression verification:** both real Next.js answer-key gates run without skips at the pins.
   Shared-code changes require four Express before/after comparisons and an explanation for every
   changed candidate. Contributor format, vet, build, full race and documentation gates pass.
8. **Retained assessment:** every final paid result exact-replays from fresh source using
   `TestReplaySavedRun`, with zero mismatches/missing traces. The reconciled ledger never exceeds
   the session's authorized cap. No paid calls are needed for practice-only fixes or spec research.

## 7. Measurement and test strategy

Report per family and overall, once per context and once per `defect_id`. A defect is recalled if
at least one established context is Confirmed; publish full context coverage alongside that count.
Mixed positive/safe oracle classes under one defect ID MUST be rejected.
Representative safe-defect recognition counts a source-safe defect when at least one context is
Protected; publish the context denominator alongside it. This metric never certifies an entire route.

| Metric | Numerator / denominator |
|---|---|
| Known-positive recall | Confirmed known positives / all selected known positives (including missing/unjudged) |
| Protected recognition | Protected genuine-safe candidates / all selected genuine-safe cases requiring a candidate |
| Safe exclusions | Justified excluded genuine-safe cases / all selected genuine-safe cases; reported separately |
| False Confirmed | Confirmed genuine-safe cases / assessed genuine-safe cases, plus assessed/all-safe coverage |
| False Protected | Protected known positives / assessed known positives, plus assessed/all-positive coverage |
| Missing candidates | Required cases with no record / selected cases requiring a record, by oracle class |
| Unresolved | Unresolved-trust or unresolved-evidence cases / selected cases, reasons separated |
| Review burden | Security Review records / all security analysis records; separate not-run, failed and judged-unresolved counts |
| Unjudged workload | Security records with no completed assessment / all security analysis records |
| Practice precision / recall | Correct emitted observations / all emitted; detected expected observations / all expected |

Zero denominators MUST render `null`/`not measured`, never 0% or 100%. `poor_practice` construction
records are not automatically Confirmed or Review; preserve their own counts. Security percentages
exclude practice observations. Report before/after absolute counts, denominator changes and causes.
For semantic error rates, `assessed` means a completed, retained model assessment; deterministic
offline protections are separately counted and checked against the oracle. A failed or absent model
assessment MUST NOT inflate the assessed denominator.

Use inline temporary Next repositories for paired semantic boundaries and existing real-app gates
for integration. Do not duplicate the whole preexisting suite or use live models in tests. Unit-test
the evaluator with a small hand-computable matrix, including a deletion that must reduce recall.
An observed reduction in Review burden is not acceptance evidence unless the source oracle supports it.

## 8. Prescriptive execution sequence and implementation shape

1. Verify branch/base, target pins/status/hashes; save fresh offline baseline before product edits.
2. Build the case matrix from the predecessor inventory; inspect all Commerce records and practice
   pairs, freeze labels and baseline evidence. Run evaluator validation before editing scanner code.
3. Promote the research probes to `TestPracticeAccuracy*` paired regressions; reproduce failures.
4. Implement cookie, cache, message and authorization corrections sequentially in focused helpers.
   Audit 09/13/14/18; change them only when realistic tests demonstrate a defect. Run narrow tests
   after each change, inspect reasons and source spans, then run both real sample gates.
5. Generate after reports, validate matches, explain every delta and compute metrics. Investigate
   errors rather than modifying oracle labels to fit output.
6. Judge only changed security evidence and representative safe controls if needed and authorized;
   retain exact-replay final reports. Run contributor gates and publish durable limitations/results.

Implementation skeletons (names adaptive, behavior binding):

```text
resolveCookieOptions(binding, orderedProperties, depth) -> flags + uncertainty + evidence
cacheIdentityForCall(entry, callback, keyParts, invocationArgs) -> relevant identity evidence
messageOriginEnforced(callback, dataUse) -> existing path/guard evidence or unresolved reason
serverAuthorizationForRequest(request, handler) -> enforcing context or unresolved reason
evaluate(cases, beforeReport, afterReport) -> validated matches + counts + metrics + deltas
```

The evaluator MUST read immutable reports; it MUST NOT supply decisions to the scanner. Store raw
reports/traces under an external evaluation directory, referenced by portable run IDs and hashes.

## 9. Paid-call discipline

The owner authorized at most **300 paid Decision API requests for this session**, not a spending
target or a transferable allowance. Spec research and all practice observations use zero calls.
For a live phase, record OpenAI `gpt-6-luna` (the repository primary) explicitly before launch;
honor any subsequent owner selection. No provider/model fallback or discovery calls.

Keep one append-only ledger across all runs: sequence, case, provider/model, request hash, reserved
count, actual attempt, timestamp, response/trace reference, outcome and final/superseded state.
Reserve the batch's maximum before launch and decrement remaining capacity globally; debit uncertain
sent/failed attempts conservatively. Reconcile reservations before another batch. Use explicit
`--judge-limit`, family and entry selectors, validate selection offline first, and send only the
selected provider key via environment. Use small diagnostic batches (at most 10), then batches of
at most 25; spend further calls only to answer a documented remaining question. Do not retry blindly.
Stop paid work at 300, on missing credentials or uncertain ledger state. Continue offline work.
A later session requires its own authorization; predecessor budgets do not carry over.

## 10. Execution rules, halt conditions and definition of done

Follow the [execution record policy](../../docs/agent-execution-discipline.md#execution-records).
Log commands, failures, source-oracle decisions and acceptance evidence after each phase.
The user authorized lower-cost implementation agents; the lead reviews their disjoint contributions.
Perform a separate review
pass of source expectations, changes and evidence after tests. Independent QA is not claimed when
the same lead performs it. If independent verification is later authorized, give a read-only verifier
this contract, matrix, diff and run log; request acceptance results with commands and source evidence.

Halt the affected slice for changed target pins, unexplained candidate deletion, a false definitive
verdict, material scope expansion, new cross-request tracking, unavailable source contracts or
unsafe repository recovery. Record unknowns; continue independent authorized work. Human approval
and merge remain the owner's responsibility. Do not publish or merge merely to finish unattended.

- [x] All selected cases reconciled; original evidence and label changes retained.
- [x] Every implemented practice correction has safe/unsafe/unresolved regressions.
- [x] Metrics satisfy §7 and disclose remaining unjudged/missing cases.
- [x] Scoped gates, both real answer keys, appropriate comparisons and contributor gates pass.
- [x] Paid ledger reconciles, final retained assessments replay exactly, cap respected.
- [x] Results/catalog/guides reflect actual delivered bounds; scope diff reviewed.
- [x] Human-review artifact is prepared; no integration merge performed.

## 11. Agent implementation prompt

Implement this contract in the existing `accuracy-false-positive-eval` checkout only when assigned
product implementation. Read §§2–7 and the local run log, verify branch and standards, then follow
§8 in order. Apply §10 throughout. Start with the frozen matrix and failing paired probes. Work
with the declared coordination model, serialize overlapping changes, and distinguish research
evidence from completed acceptance.
Use §9 only within its session authorization. Record evidence per criterion, conduct the separate
verification pass, and prepare one draft-review artifact for `stage`; do not merge. Stop affected
work at a halt condition and record the precise unresolved boundary. Do not claim completion while
any required criterion lacks evidence.

## 12. Implementation And Review Change Log

### 2026-11-16 — Implementation and delegation authorized

**Source:** owner clarified “Spec, implementation, and evaluation” and authorized lower-cost agents.
**Changed sections:** assignment, coordination and execution rules.
**Rationale:** extend researched contract into the requested unattended implementation/evaluation.
**Summary:** proceed through §8; tooling and paired tests have separate agent ownership.
**Verification impact:** all acceptance criteria now require completed evidence or an explicit
unresolved boundary before handoff; the 300-request ceiling remains unchanged.

### 2026-11-16 — Source-backed implementation boundaries

**Source:** paired regression and integration research during the authorized implementation.
**Changed sections:** schema, decisions and acceptance interpretation.
**Rationale:** preserve honest carried evidence and avoid treating authentication as validation.
**Summary:** carried unassessed rows may retain unavailable hashes; action validation follows
every request-derived value. Server role recognition is bounded to a verified `next-auth`
`getServerSession` binding and a rejecting 401/403 path; unknown local auth helpers remain Review.
**Verification impact:** paired ignored/sibling validation, cookie-derived role, successful rejection
response and unknown-auth cases must pass; no expansion into general authorization tracking.

### 2026-11-16 — Independent review corrections

**Source:** independent read-only verifier reproductions and evaluator review.
**Changed sections:** implementation requirements and acceptance interpretation.
**Rationale:** alias mutation invalidates a role check; direct ternary gates need the same request
association as `if`. Pending expected observations and incomplete report identities cannot improve metrics.
**Summary:** add those two authorization regressions; retain pending expectations in recall and
require full source identity for report-backed validation. Structural-only matrix validation is
explicitly distinct from report-verified results.
**Verification impact:** final paired suite, evaluator regressions, source comparison, retained exact
replay and final race checks cover the corrected boundaries.
