# Wire Bundle v7 and catalog synchronization

## Assignment and review

Implement E3 in the existing `analyzer-assessment-coverage` worktree and branch, as
requested by the owner on 2026-11-15. Related changes join the existing draft review
against `stage`; no new worktree, integration merge, or release action is authorized.
Execution record: `.zazz/ephemeral/analyzer-assessment-coverage-run-log.md`.
The lead implements serially; independent verification follows the repository skills.

## Required reading and governing design

- [Request size and evidence relevance](../architecture/request-size-and-evidence-relevance.md):
  principles, W1–W12, S3, ablation protocol, and evidence ledger.
- [Assessment coverage](analyzer-assessment-coverage.md): retained evidence and claim gates.
- [Hardening milestone](analyzer-engine-hardening.md): E3 boundary.
- [Analysis calibration](../../docs/analysis/calibration.md): source semantics and paired controls.
- Standards: [code structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [spec hygiene](../standards/spec-hygiene.md),
  [docs hygiene](../standards/docs-hygiene.md). Verify the standards index before edits.

## Scope and explicit deltas

Allowed paths: `internal/judge`, `internal/analysispacks`, `internal/guidelines`,
`internal/parse`, their tests and fixtures, `docs`, `.zazz`.
Only changes needed for the following deltas belong in this deliverable:

- Evidence version 7 and the next protocol version for every assessed family.
- Always compact evidence; retain one coverage ledger; omit prompt component digests
  and replay-only span metadata. Preserve complete provenance in reports and traces.
- Project family context indices to evidence IDs after budget remapping.
- Preserve static material before candidate evidence. Investigate provider caching
  before changing envelope semantics; JSON key order alone does not prove cache reuse.
- Merge excerpts using original coordinates, then trim masked trailing whitespace
  without deleting line separators or changing strings and template literals.
- Keep one complete dependency-path representation, including storage keys and order.
- Reference already supplied evidence; remove only provably duplicated metadata.
- Move fixed interpretation to selected static material; keep candidate-specific facts.
- Logging catalog migration and claim-specific guidance; Node filesystem/archive prose
  synchronization; correct the sql.js component owner.
- Prove transparent local/imported JS/TS wrapper forwarding before removing blockers;
  retain wrapper definition evidence. Reject mutation, multiple calls, argument reorder,
  reassignment and unsupported syntax. Python decorators remain separately modeled.
- Summarize middleware only when source or a verified contract proves it cannot
  mutate claim inputs, authorize, terminate or alter dispatch; otherwise retain it.

The owner deferred optional JS if modeling. Soft-tier helper/model
filtering and data-path slicing require separate contracts and paid ablation evidence;
no lossy omission is enabled by this contract. No new answer citations are invented.
Historical traces remain readable but cannot replay against changed requests. Never
relabel saved responses as fresh judgments.

## Acceptance criteria and test strategy

| Criterion | Verification |
|---|---|
| Baseline exact replay | Run all 360 historical replay decisions before implementation; report every mismatch and per-bundle counts |
| Evidence retention | Inspect saved raw responses for citations; if absent, explicitly mark citation acceptance uncheckable and verify required/gate/control/dependency evidence retention at 32 KiB as a proxy |
| Wire representation | Deterministic schema tests for evidence version, no duplicate role ledger/digests/byte hashes, complete references and static-first order |
| Family projection | Command, Path and SSRF references resolve to the same evidence before/after shedding; original CandidateUse is unchanged |
| Excerpt fidelity | Containing controls and line numbers survive comment masking/condensing; multiline string bytes survive |
| Dependency fidelity | Selected representation retains source, transfer order, sink slot, storage key and control edges |
| Dispatch | Positive arrow/function imported/local wrappers and negative mutation/reassignment/double-call/reorder fixtures; all affected families retain evidence |
| Catalog/prose | Logging selections and unknown/stale-selection failure tests; filesystem and archive-slot regressions; no weakened inconsistency gate |
| Sample measurement | Offline request digest and per-section app/family distribution across eight standard apps and parser fixtures, measured before and after; report actual savings against the 25–35% estimate, including regressions and residual shedding |
| Live checks | Owner-approved explicit gpt-6-luna cap, selected key only, no fallback; representative families/apps, archive and wrapped routes; inspect raw answers and gates and fix defects |
| Repository checks | `go test -race ./... -count=1`, `go vet ./...`, changed-file formatting, diff/doc checks |

Acceptance targets use measured distributions, not invented byte budgets. All assessed
requests intentionally change once; candidate additions/removals and semantic changes
must be explained separately. Re-record predecessor fixtures only after reviewing the
schema/prose delta. Preserve old traces and capture fresh paid traces under new labels.

## Execution sequence and implementation rules

1. Complete baseline replay, citation inspection and offline byte measurements.
2. Implement representation and catalog changes with narrow regression tests.
3. Implement conservative wrapper resolution and justified middleware treatment.
4. Run offline sample measurements; record per-family/app savings and affected records.
5. Re-record intentional predecessor expectations, run race/vet/doc checks, then capped
   live validation and offline replay of every new trace. Fix and rerun affected checks.
6. Update design statuses/evidence ledger and relevant user/architecture/spec indexes.

Use Go from `go.mod`, `GOFLAGS=-buildvcs=false`, and a C compiler. Treat sample
checkouts as read-only; verify revisions and cleanliness before/after. Do not print
credentials or commit scratch files. Paid request budget: at most 440 gpt-6-luna requests across focused checks and the
full standard-app rebuild, authorized by the owner; no provider/model fallback.
Stop dependent work for unavailable references, an unresolved scope decision, unsafe
recovery, or repeated failure without a clear fix; continue unaffected work. Keep
unrelated user changes. Record departures and residual limitations explicitly.

## Work checklist

- [x] Verify assigned worktree, branch and clean starting state.
- [x] Re-run 360 historical exact replays before implementation.
- [x] Inspect raw responses for citations and run 32 KiB retention proxy.
- [x] Capture pre-change offline sample/fixture byte distributions.
- [x] Record owner paid cap (440), core-first sequence and same-branch follow-ups.
- [x] Implement and test W1–W5 wire representation.
- [x] Evaluate and implement W6–W12 with fidelity evidence; document rejected approaches.
- [x] Migrate logging catalog and synchronize filesystem/archive prose.
- [x] Resolve transparent wrappers with conservative negative controls.
- [x] Evaluate middleware summaries without hiding mutation/authorization effects.
- [x] Measure post-change sample distributions and explain candidate deltas.
- [x] Refresh intentional protocol expectations and pass race/vet/doc checks.
- [x] Run capped paid checks and rebuild standard sample results; replay fresh traces.
- [x] Resolve test/live defects and update evidence ledger, docs and review evidence.

- [x] Commit the verified implementation and rebuilt samples locally.
- [ ] Push the feature commit and update existing draft PR #14. Automatic approval review
  rejected external publication pending explicit user confirmation; no push or PR update executed.

Follow-ups remain in this same worktree and branch, sequenced after E3 validation:

- [ ] JavaScript if modeling with guarded/unguarded regression pairs.
- [ ] Re-measure remaining large requests and determine relevance-filter need.
- [ ] Run paired ablation before helper/model relevance filtering.
- [ ] Implement and validate data-path slicing after precise branch modeling.

## Definition of done

- [x] All acceptance rows have evidence or an explicit validation limit (citation criterion uncheckable; retention proxy verified).
- [x] Strategy statuses and evidence ledger match implemented behavior.
- [x] New traces replay exactly; old evidence is preserved.
- [x] Required repository and sample checks pass; defects are resolved.
- [x] Draft review evidence and run log reflect final implementation.

## Agent implementation prompt

Continue this contract in `analyzer-assessment-coverage`, using its shared assessment
coverage run log. Read the referenced design/standards, verify branch and changes,
complete baselines before coding, implement the listed deltas, test them, measure eight
apps offline, and run only the owner's capped paid checks. Keep source-backed evidence
and conservative gates. Never merge integration or fabricate refreshed model answers.

## Implementation and review change log

2026-11-15: Initial contract from the owner's E3 handoff execution request. Optional
flow modeling and paid cap are pending; independent offline baseline work is authorized.

2026-11-15: Independent QA added character-column locators for same-line evidence, unioned catalog obligations, stable inner dispatch, async-factory/recursive-wrapper rejection and exact-header middleware summaries. See [verification](../evaluation/wire-bundle-v7-results.md). Outer-key cache reordering and general source-whitespace trimming were rejected based on provider semantics and literal fidelity.

2026-11-15: Final sample scope preserves VulnPy command/SQL/XSS publication and runs every analyzer on Juice Shop; other samples exclude standalone validation to stay within 440 requests. Final charged total 434, including interrupted allowance. All 406 final traces replay exactly. Optional flow/relevance work remains queued in this same branch. Full historical path-corpus re-recording is not claimed.
