# Architecture phase 5 — Measured recall gaps and first closure

- **Worktree and branch** `recall-gap-inventory`
- **Plan** [Architecture update plan](architecture-update-plan.md#phase-sequence), phase 5
- **Prerequisite** Phase 1 integrated. Use current `origin/stage` and reconcile the phase 3
  package paths. Phase 4 changes assessment scheduling and is independent of this offline
  delivery. Follow the owner's phase order.
- **Delivery** One assigned worktree and one draft PR into `stage`. Separate inventory and
  closure commits when a closure is eligible.
- **Run log** `.zazz/ephemeral/architecture-phase-5-accuracy-gaps-run-log.md`

## 1. Capability

Produce a reproducible offline inventory of source-reviewed positive candidates and expected
registration outcomes, then close at most one bounded structural miss. Measure candidate presence
and evidence quality independently of model assessment. A source-established positive that already
has a candidate may still need better evidence, policy, or assessment coverage. Record that
diagnosis for the relevant follow-on and keep this delivery focused on candidate and registration
recall.

Reconcile known historical results before choosing work. The current VulnPy guide still groups
`VP-XSS-JINJA` with deferred work. The existing case key, language adapter and XSS evaluation
document the delivered support. Check the current pin offline and correct the historical guide
sentence, documenting any current regression separately if one is observed.
[VulnPy guide](../evaluation/vulnpy-detection-guide.md#d5-confirmation-and-remaining-gaps) ·
[XSS evaluation](../evaluation/xss-hardening/final-evaluation.json)

## 2. Required reading

- [Plan and shared rules](architecture-update-plan.md#shared-rules-for-every-phase), [implementation plan](../project/implementation-plan.md), and [architecture baseline](../evaluation/architecture-baseline.md#guard-test).
- [Sample catalog](../project/vulnerable-sample-apps.md#applications) and [sample handling](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps).
- [Source index](../architecture/repository-graph.md#implementation-direction-source-index-not-a-graph-store-2026-11-17), [D5 results](../evaluation/common-entry-dispatch-results.md#d5--bounded-dynamic-http-registration-2026-11-04), and [summary witness completion](architecture-phase-1-summary-completion.md#1-capability).
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [calibration controls](../../docs/analysis/calibration.md#regression-pairs), the selected family's [analysis guide](../../docs/analysis/README.md), and [testing standards](../standards/testing.md).
- [Python evaluator and keys](../../docs/samples/evaluate-python.py), [DVWA structural checks](../evaluation/dvwa-detection-guide.md#coverage-boundaries-and-acceptance), and the source keys in §5.

## 3. Invariants

- The source oracle stays independent of scanner output. Record disputed rows with source evidence
  and their disposition pending source review. Preserve existing answer keys.
- Sample checkouts are read-only at the exact pins. Offline runs use no provider or discovery.
- Candidate evidence stays specific to the operation, operand, entry and value path. A relevant
  missing binding or guard stays visible and blocks the affected claim under existing policy.
- Changed evidence gets its own request and proof. Exact replay applies only to matching requests
  under the existing protocol and component checks.
- Every unrelated compatibility fixture and source-reviewed case stays stable. The selected
  fixture and sample deltas are listed before refreshing the golden.

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `.zazz/evaluation/recall-gap-inventory.md` | New | Pinned expected-case matrix, verification commands, exclusions, ranking and results |
| `.zazz/evaluation/vulnpy-detection-guide.md` | Modified | Reconcile the historical Jinja note with delivery and current evidence |
| This spec | Modified | Record the selected scope, fixtures and expected deltas before code |
| One of `internal/langjs/`, `internal/langpy/`, `internal/langphp/`, or `internal/parse/` and the selected fixture owner | Conditional | One localized closure and its regression controls. Name exact files and owners before code. |
| `cmd/scan/testdata/architecture-baseline.json` | Conditional | Add the new fixture rows and update individually listed affected rows |
| Selected analysis and detection guides | Conditional | Document the recovered subset and remaining limits |

The inventory is a reviewable commit. The optional closure stays in the same PR as a separate
commit. Framework expansion, new vulnerability families, policy or prompt calibration, Protected
recognition work, scheduling, new graph schemas, and equivalence or wire protocol redesign belong
in separate contracts.

## 5. Decisions

**D-1. Freeze the evaluation set before running.** Enumerate every explicit supported positive,
registration expectation and relevant control in the source-reviewed keys at the selected pins.
Record intentional exclusions and their reasons. Deduplicate overlapping sources by case and record
all cited keys. Use the following minimum corpus and carry the cited historical records for comparison.

| Cohort | Samples and authority |
|---|---|
| JavaScript / TypeScript | vuln-demo-app, vulnerable-typescript-app, nodejs-goof, Juice Shop, OSS OopsSec Store and vuln-nextjs. Follow each pin and expected reference in the [catalog](../project/vulnerable-sample-apps.md#applications), including the cited XSS keys, living lab test key and the source-reviewed supported-family expectation tables. |
| Python | VulnPy, ThreatByte, python-insecure-app and Vulnerable Flask App. Use `docs/samples/<app>/cases.json` with each app's published `metadata.json`; use the [Python results](../evaluation/python-support-results.md#pinned-corpus-and-final-results) for pin cross-checks. |
| PHP | DVWA, with pin and controls from the [DVWA guide](../evaluation/dvwa-detection-guide.md) and [metadata](../../docs/samples/dvwa/metadata.json). |

Record full target SHA, scanner SHA, command, scope, output path and pre/post status for each run.
If a checkout is unavailable, off-pin or has changes including ignored files, preserve it and use an
existing clean pinned copy or an uncontaminated source snapshot if available. Verify snapshot
provenance and scanner input scope, including any Git metadata needed by that target. Otherwise
mark the sample unmeasured and exclude its rows from rates and ranking. Continue with verified
samples. Report what could affect the priority order.

**D-2. Evaluate each expectation at its actual stage.** A candidate witness is identified by family
or kind, source anchor, entry/dispatch context and operand/source when the key distinguishes them.
Pin alone establishes the file revision and a same-line match alone establishes location. Multi-entry
or stored-flow rows require the corresponding context on both sides when specified by the key.

| Row kind | Offline outcomes |
|---|---|
| Expected positive | `candidate_with_witness`, `candidate_evidence_gap`, or `missing_candidate`. Capture the observed use, evidence or blocker. Both candidate-present states count as candidate presence. |
| Expected registration | `resolved`, `explicit_gap`, or `missing_registration`. Verify source anchor and registration → binding → callable → invocation when resolution is expected. An explicit gap satisfies a registration-or-gap key only. A gap on a key requiring resolution remains a resolution miss. |
| Controls and other rows | Record the expected bounded/encoded/absent or unresolved structural outcome. Label judge-dependent outcomes and unsupported, disputed or unavailable cases separately. |

The existing Python evaluator is supporting evidence. Its location matcher and aggregate positive
count cannot identify all entry/operand distinctions. `not_confirmed`, `validation_enforced` and
similar rows may depend on assessment state. Inspect the saved report per row to establish whether
the oracle is structural or assessment-dependent, and record a present candidate separately from
whether the assessment satisfies its expectation. Record the evaluator exit status and distinguish
an expected row mismatch from a command or parse failure. Use equivalent manual structural checks
for Markdown keys. Report positive candidate presence, complete witness coverage and registration
resolution as separate counts with denominators. List unmeasured rows explicitly.

**D-3. Diagnose and rank distinct fixes.** Assign one primary cause at the first proven failure per
miss and link any contributing blockers. Use `registration`, `call_binding`, `value_transfer`,
`sink_model`, `framework_adapter` or `out_of_family`. Record input/parse or work-limit failures
explicitly and map to a cause only when the first failing stage is established. Preserve prior
delivery evidence and distinguish a newly observed miss from a reproduced regression.

Group eligible misses by a shared root cause with a source-backed explanation of how one change
recovers them. Eligible changes affect one owning language adapter or a tightly scoped core seam
for one adapter, reuse an existing analyzer family and fit the compatibility contract. Rank by
distinct expected positive cases recovered (descending), then expected registration outcomes
satisfied (descending), adapter-local before core, estimated files touched (ascending), then
lexicographic order of the sorted case-ID list. Count each case once. Record the top five or all
eligible groups if fewer, and show why higher-impact groups were deferred. A gap-only
improvement behind an existing candidate goes to
the evidence follow-on.

**D-4. Close one measured miss with three controls.** Lock the patch scope and expected fixture
deltas at the checkpoint. A recovered positive must carry the source-to-sink witness, or the
complete source-backed registration chain for a registration closure. The safe sibling proves
bound, encoded or otherwise relevant protection evidence where applicable. The unresolved sibling
proves the relevant gap remains visible and blocks a decisive claim. An offline `not_run`
assessment alone supplies no evidence for either control.

## 6. Agent implementation rules

Use the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Post the ranked inventory and the proposed exact patch scope before writing production code. Proceed
with rank 1 from the verified population if eligible and there is no owner redirect. If the data
supports no eligible closure, deliver the measured inventory and explain what remains. If scope
expands or an unrelated golden delta appears, stop that closure and preserve the inventory for review.

The Lead Agent owns the matrix, selection and writes. Assigned Contributor Agents, if used, may
collect disjoint sample outputs read-only, each in its own run folder. Serialize shared file edits.

## 7. Acceptance criteria

1. **AC1 — Oracle coverage.** The inventory accounts for every source-key row from the frozen
   corpus. Each checked row records case ID, app and pin, family, anchor, entry/operand discriminator
   when applicable, expectation, current result, and evidence locator. Every unmeasured row has a
   reason. Commands, observed denominators and evidence locations are reproducible from the run log.
2. **AC2 — Reconciliation.** The inventory verifies historical delivered claims against current
   evidence and distinguishes delivered, regressed and unmeasured. For `VP-XSS-JINJA`, inspect the
   raw XSS record at `apps/templates/jinja/xss.html:30` and its Flask source path, and update the
   guide to reflect the historical delivery and current measurement.
3. **AC3 — Selection.** The checked-in inventory includes ordered eligible groups with counts and
   exclusions. The run log and §14 identify one chosen group with its proposed file/fixture deltas,
   or the inventory-only outcome and reason.
4. **AC4 — Closure, when selected.** The targeted adapter test fails on baseline, then proves the
   recovered witness plus the safe and unresolved controls. A fresh offline scan at the same sample
   pin verifies the recovered expectation. Add exact commands, test name, anchors and changed
   fixture rows to this criterion before coding.
5. **AC5 — Compatibility.** `go test ./cmd/scan -run '^TestArchitectureBaseline$' -count=1`
   passes, with golden changes limited to the named rows. Compare before/after case outcomes for
   the verified corpus and account for every changed structural row. An inventory-only delivery
   has no golden change.
6. **AC6 — Evidence and gate.** Publish the inventory and matched guide changes. For a code
   closure, run the [contributor gate](../../docs/contributing.md#verification). For inventory-only
   changes, run the [documentation checks](../../.agents/skills/doc-check/SKILL.md) and retain
   AC1–AC3 and AC5 verification in the run log.

## 8. Test strategy

Use a table-driven test in the owning fixture suite and the architecture golden for collateral
changes. Name the test and its three source controls at selection. Real samples provide independent
offline verification of the oracle and recovered case. Keep those reports outside the worktree and
unit-test dependencies. Existing evaluator behavior remains independently checkable.

## 9. Execution sequence

1. Record scanner/toolchain and pins. Run the architecture baseline on the assigned branch.
2. Freeze the case universe from §5. Build once. Run each verified sample with
   `scan --analyze --output-dir <fresh-run-dir> <sample-root>` with provider keys unset, and use
   `findings.json` as the structural source. Run
   `python3 docs/samples/evaluate-python.py <app> <findings.json>` for the four Python samples.
   Verify pins and status before and after.
3. Commit the inventory and historical reconciliation. Post the D-3 checkpoint. For an eligible
   closure, signpost the exact fixture anchors, functions, expected evidence and golden deltas in
   §4, §7 and §14.
4. Start with the failing fixture assertion. Repair the first proven failing stage using existing
   flow, facts and claim policy. Run targeted tests, compare the verified corpus and golden,
   document the subset and prepare the draft PR.

## 10. Definition of done

- [ ] Case coverage, pin checks, evaluator interpretation and ranking are recorded.
- [ ] The historical Jinja note is reconciled.
- [ ] One bounded closure passes AC4–AC6, or the inventory records why AC4 does not apply.
- [ ] Sample inputs retain their pre-run pins and clean state. Evidence remains outside them.
- [ ] Independent verification checks the selected result and compatibility, or checks the
      inventory's counts and rationale when no closure ships.

## 11. Open questions

The measured corpus determines the closure. Record exact patch scope and the owner's redirects at
the checkpoint. A technically out-of-scope closure requires its own contract.

## 12. Run log protocol

Use the plan's run-log rules. Append scanner SHA, toolchain, command and output locations, full
sample pins and statuses, evaluator results, exclusions, ranking, selected patch/fixtures, checks
and verifier outcome. The tracked inventory carries the reviewable evidence and denominators.

## 13. Agent implementation prompt

> Work in the owner-assigned `recall-gap-inventory` sibling worktree based on integrated
> `origin/stage`. Read AGENTS.md, the orientation contents, this spec and the plan's session-start
> and common rules. Record standards and baseline checks in the phase run log. Execute §9,
> post the ranked checkpoint, and limit code to one eligible closure. Keep the sample inputs
> read-only and the evaluator offline. Deliver the inventory and evidence, with the optional
> closure in a separate commit, as a draft PR into `stage`. For independent verification, rerun
> the selected case and inspect its safe and unresolved controls, spot-check two unrelated oracle
> rows, and verify the golden diff against the declared scope. For inventory-only delivery,
> independently spot-check the row totals, exclusions, ranking rationale and Jinja reconciliation.
> Record PASS or FAIL and the supporting evidence in the run log.

## 14. Implementation and review change log

### 2026-11-18 — Paths after architecture phase 3B

Phase 3B moved JS/TS to `internal/langjs` and Python to `internal/langpy`. `internal/parse` is
the language core. [Phase 3B](architecture-phase-3-js-ts-python-package.md)

### 2026-11-18 — Architecture review

Retained the offline inventory and single-closure sequence. Reconciled corpus and package
references, separated registration and candidate outcomes from judgment, defined per-case matching
and ranking, and made the controls and partial-corpus handling explicit. §7 now requires
structural witnesses and before/after evidence.
