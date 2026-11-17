# Architecture phase 5 — Measured recall gaps and first closure

**Worktree / branch:** `recall-gap-inventory`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 5. Objective: accuracy
**Depends on:** phase 1 merged (default order runs it after phase 4)
**Delivery topology:** one deliverable, one branch, one draft PR into `stage`
**Coordination:** Lead Agent. Contributor Agents may run the per-sample inventory scans in parallel (read-only)
**Run log:** `.zazz/ephemeral/architecture-phase-5-accuracy-gaps-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Replace assumed gaps with measured ones, then close the top one.

1. **Inventory.** Run fresh offline scans of every pinned sample with a source-reviewed answer key.
   Produce one capability matrix of **recall misses**: an expected positive that has no candidate
   at its source anchor, or an expected registration that is neither resolved nor an explicit gap.
   Each miss is classified by cause.
2. **Closure.** Close the highest-ranked miss (D-3) with paired fixtures. The judge never sees a
   missing candidate, so recall is the accuracy lever this phase owns.

Judgment-level accuracy is out of scope: a candidate that exists but lands in Review, or a
Protected recognition. That belongs to the container-root follow-on accuracy handoff.

The plan's earlier assumption that `VP-XSS-JINJA` was open is wrong. xss-hardening delivered
`jinjaFileTemplate` (`internal/parse/python_html_responses.go`), and the case passes in
[final evaluation](../evaluation/xss-hardening/final-evaluation.json). This phase corrects the stale
checkbox in the [VulnPy guide](../evaluation/vulnpy-detection-guide.md).

## 2. Required reading

- Plan [capability matrix](architecture-update-plan.md#capability-matrix) and [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).
- [Sample catalog](../project/vulnerable-sample-apps.md#applications) (pins), [orientation: samples](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps).
- Answer keys: `docs/samples/{vulnpy,ThreatByte,python-insecure-app,vulnerable-flask-app}/cases.json`
  with `docs/samples/evaluate-python.py`; detection guides for juice-shop, nodejs-goof,
  vulnerable-typescript-app, vuln-nextjs, oss-oopssec-store, and DVWA under `.zazz/evaluation/`.
- [Evidence and claims: completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [calibration pairs](../../docs/analysis/calibration.md#regression-pairs), and the analysis guide for the selected family.
- [D5 results](../evaluation/common-entry-dispatch-results.md#d5--bounded-dynamic-http-registration-2026-11-04) (already-delivered dynamic registration).

## 3. Invariants

- Answer keys are never edited to match output. A disputed expectation is recorded with its
  source evidence and left to the owner.
- Samples stay read-only and pinned (plan common rules). There are no paid calls.
- Closure changes only the evidence for the selected miss. Every other fixture's phase 0 digest is
  unchanged, and the spec lists the expected delta fixture by fixture.
- New graph relations are added only if the selected gap needs a cross-record relation. They then
  follow the phase 1 schema rules (endpoint table, slot, rule version).

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `.zazz/evaluation/recall-gap-inventory.md` | new | Matrix: case ID, sample and pin, language, family, source anchor, current output, cause class, owning layer, estimated scope, recovered-by |
| `.zazz/evaluation/vulnpy-detection-guide.md` | modified | Correct the stale Jinja checkbox with a link to the xss-hardening evidence |
| Selected gap's adapter files (one language package or `internal/parse` area), plus fixtures under its `testdata/<language>/<case>/` | modified or new | Closure, decided at D-3 and recorded in §14 |
| `cmd/scan/testdata/architecture-baseline.json` | modified | Expected delta for the new fixture and the changed fixture only |
| The family's analysis guide and detection guide | modified | Recovered case and remaining limits |
| This spec | modified | §4 and §7 closure rows are filled in after selection, with a change-log entry |

Out of scope:

- judgment calibration and Protected recognition;
- new vulnerability families;
- new frameworks;
- library mode;
- changes to equivalence or the request wire beyond the selected evidence.

## 5. Decisions

- **D-1 Keep the inventory first, in the same session as the fix.** A closure chosen from an
  unmeasured list risks fixing a delivered case; the stale Jinja item shows this. The inventory
  is cheap: offline scans plus existing evaluators.
- **D-2 Cause classes.** Each miss gets exactly one primary class:
  - `registration` (entry or dispatch not found);
  - `call_binding` (helper, callback, or factory argument not bound);
  - `value_transfer` (projection, container, or async transfer lost);
  - `sink_model` (operation not modeled);
  - `framework_adapter` (unsupported framework);
  - `out_of_family`.
  Only the first four are closable in this phase.
- **D-3 Selection rule.** Rank closable misses by number of source-reviewed positives recovered,
  descending; then by a single language adapter touched; then by fewest files touched. Implement the
  top one. Ask the owner before taking a second one. A deterministic rule lets the session continue
  without waiting, and the owner can still redirect at the checkpoint.
- **D-4 Fixtures are paired.** Each closure adds a vulnerable fixture, a genuinely protected
  sibling, and an unresolved sibling under the [calibration pair](../../docs/analysis/calibration.md#regression-pairs)
  rules. A positive-only fixture would invite a false-Protected regression.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- **Checkpoint.** After the inventory is committed, post the ranked top five in the run log and the
  session. Proceed with rank 1 unless the owner redirects.
- Rank 1 needs more than one language adapter or a new family. Report it and stop.
- The closure changes a digest for a fixture not listed in §7.

## 7. Acceptance criteria

1. **AC1 Inventory.** `recall-gap-inventory.md` lists every expected positive from each named answer
   key, with its current status from a fresh offline scan at the recorded pin. Each miss has a D-2
   class and an anchor `file:line`. The evaluator commands and their outputs are in the run log.
2. **AC2 Reconciliation.** Every miss already marked delivered in an evaluation record is either
   confirmed delivered, with the stale note corrected, or recorded as a regression with both
   outputs. The Jinja row is reconciled.
3. **AC3 Selection.** The inventory names the D-3 rank order, and §14 records the selected gap.
4. **AC4 Closure.** Fill these in after selection, in §14 and here:
   - the vulnerable fixture yields a candidate at the expected anchor with the source witness;
   - the protected sibling is not Confirmed and carries the protection evidence;
   - the unresolved sibling carries an explicit gap;
   - the original sample case flips from miss to recorded candidate in a fresh offline scan.
5. **AC5 No collateral.** `TestArchitectureBaseline` differs only in the §7 listed fixtures.
   The evaluators for all other cases show no new misses.
6. **AC6 Docs and gate.** The analysis guide, detection guide, and capability matrix rows are
   updated, and the contributor gate passes.

## 8. Test strategy

The inventory is evidence, not a test. The closure adds one table-driven test over the three
paired fixtures in the owning language's test file. Recovery on the sample is checked by the
existing evaluator or guide and is not committed as a sample-dependent test. The phase 0 golden
covers collateral change.

## 9. TDD entry point and execution sequence

1. Record the sample pins and clean status. Run offline scans to
   `_test-findings/<app>/run-recall-inventory/`, then run `evaluate-python.py` and the guide checks.
2. Write and commit the inventory and reconciliation (AC1–AC3). Post the checkpoint.
3. **Red:** write the paired-fixture test for rank 1.
4. Implement within the owning adapter. Use the existing value and flow facts; add a graph relation
   only under §3.
5. Fill §4 and §7 rows. Regenerate the golden. Verify that the diff is limited to listed fixtures.
6. Rescan the affected sample and record the recovery. Update docs, run the gate, open a draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC6 verified, with evidence in the run log.
- [ ] Samples are clean at their pins afterward.
- [ ] The PR separates the inventory (evidence) from the closure (behavior change).

## 11. Open questions

None before start. The D-3 checkpoint is the owner's redirect point.

## 12. Run log protocol

Use the plan's common rules. Record the per-sample scan commands, evaluator output, and ranking.

## 13. Agent implementation prompt

> Work in the `recall-gap-inventory` sibling worktree, cut from `origin/stage` after the phase it
> follows in the plan has merged. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md),
> and this spec. Follow the plan's session start and common rules. Execute §9. You may delegate
> per-sample offline scans and evaluator runs to Sonnet Contributor Agents. They are read-only on
> samples and write only under `_test-findings`. You own the inventory, ranking, and closure. Post the
> D-3 checkpoint before coding. Make no paid calls. Finish with a draft PR into `stage`. Verifier: a
> fresh-context subagent re-runs the evaluator for the recovered case and two unrelated cases. It
> confirms the golden diff is limited to the listed fixtures, and checks that the protected sibling
> is not Confirmed. It reports PASS or FAIL.

## 14. Implementation and review change log

No changes recorded.
