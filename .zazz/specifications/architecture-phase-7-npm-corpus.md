# Architecture phase 7 — npm library corpus and direct-model baseline

**Worktree / branch:** `npm-library-rce-mvp`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 7. Objective: feature evaluation (what phase 8 must beat)
**Depends on:** the plan only. No engine dependency. Its paid steps need an owner cap
**Delivery topology:** one deliverable, one branch, one draft PR into `stage` (contract, answer keys, results only)
**Coordination:** Lead Agent. Contributor Agents may pin and review corpus rows in parallel, one package each
**Run log:** `.zazz/ephemeral/architecture-phase-7-npm-corpus-run-log.md`
**Product scope source:** container-root `3-npm-library-rce-mvp-proposal.md`, "Test corpus",
"React2Shell checkpoint", "Phase 0", and "Handling findings in third-party code". This phase
records that scope. It does not widen it.
**Drafted:** 2026-11-17

## 1. Capability

Execute the proposal's phase 0 with no scanner changes:

- confirm every corpus row against its GitHub advisory and fix diff;
- pin vulnerable and fixed revisions;
- write one source-reviewed answer key per case: the vulnerable pin, the fixed pin, and at least
  one named bypass sibling;
- run a capped direct-model baseline over the vulnerable pins.

Phase 8's library mode must beat that baseline on recall and unsupported claims.

## 2. Required reading

- The proposal sections named in the header.
- [Orientation: samples](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps), [sample reference policy](../../docs/samples/reference-policy.md).
- [Decision models: scope a live run](../../docs/decision-models.md#scope-a-live-run), [AGENTS credentials](../../AGENTS.md#credentials-and-live-model-calls).
- [Code injection analysis rules](../../docs/analysis/README.md), and the command analysis guide, for the vector vocabulary.

## 3. Invariants

- There is no change under `cmd/` or `internal/`. `TestArchitectureBaseline` is untouched.
- Corpus checkouts live under `<DEV_ROOT>/npm-corpus/<package>@<version>/`, outside every worktree.
  They are read-only and never installed or executed.
- Only versions with published advisories enter tracked files. A newly suspected weakness is
  recorded outside public checkouts and goes to the maintainer privately first.
- Paid calls only within the owner's stated provider, model, and numeric cap. Every request is
  counted, with no fallback model. The ledger is retained under `_test-findings/npm-corpus/` (ignored).

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `.zazz/evaluation/npm-library-rce/corpus.json` | new | Per row: package, advisory IDs, repository URL, vulnerable and fixed commits, manifest path, export path, parameter, vector, sink `file:line`, fix summary |
| `.zazz/evaluation/npm-library-rce/answer-keys/<package>.md` | new | Source-reviewed expected outcome for vulnerable, fixed, and bypass sibling |
| `.zazz/evaluation/npm-library-rce/baseline-results.md` | new | Direct-model recall, unsupported claims, cost, run-to-run variation |
| `.zazz/project/vulnerable-sample-apps.md` | modified | Corpus pins section |
| `.zazz/specifications/README.md`, this spec | modified | Index, change log |

Out of scope: library mode (phase 8), new sinks, the pollution pack, feasibility consumer, and proposal 4.

## 5. Decisions

- **D-1 A separate phase, before the engine work.** It needs no scanner change and can run while
  foundation phases proceed. It defines the bar phase 8 is judged against, so phase 8 cannot
  quietly lower it.
- **D-2 The tracked answer keys hold only published advisories.** This follows the proposal's
  third-party disclosure rule.
- **D-3 The paid baseline is a separate checkpoint.** All offline pinning and keys are committed
  first. Without an owner cap the phase ends there, with the baseline marked "not run". That is a
  valid partial exit, recorded in the run log.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Before cloning, list the repositories and approximate sizes and get owner approval. Downloads
  need explicit permission.
- A row's advisory and fix diff disagree with the proposal's version guess. Record both and ask.
- The paid cap is reached, or a provider error occurs. Stop; do not retry.

## 7. Acceptance criteria

1. **AC1** `corpus.json` has every proposal row, React2Shell included. Each row has confirmed
   vulnerable and fixed commits that resolve in the cloned repository, and the "to confirm" `pug`
   and `lodash` versions are resolved.
2. **AC2** Each answer key names the vulnerable export, parameter, vector, and sink anchor; the
   fixed revision's control; and one bypass sibling name. For React2Shell it names the exact
   decoder function from the 19.2.0→19.2.1 fix diff.
3. **AC3** Corpus HEADs and clean status are recorded before and after.
4. **AC4** With an owner cap: `baseline-results.md` reports per-row detection on vulnerable pins,
   unsupported claims, requests, cost, and run-to-run variation on at least two rows (2 runs each).
   Without a cap: the file states "baseline not run: no cap", and AC4 is deferred, not failed.
5. **AC5** Doc-check passes on the new documents.

## 8. Test strategy

There are no automated tests. Evidence is pinned commits, keys reviewed against advisories and
fix diffs, and the paid ledger.

## 9. TDD entry point and execution sequence

1. Get approval for the clone list, then clone and pin (AC1, AC3).
2. Write the answer keys from the advisories and fix diffs (AC2). Commit.
3. Checkpoint: ask for provider, model, and cap.
4. If granted, run the baseline method agreed in OQ-1 and write the results (AC4).
5. Doc-check, then a draft PR.

## 10. Definition of done

- [ ] AC1–AC5 verified, or AC4 deferred with its reason.
- [ ] No tracked file contains unpublished findings.
- [ ] The paid ledger is retained, and the request count is stated in the PR.

## 11. Open questions

- **OQ-1** Baseline method. Option (a): one direct-model prompt per vulnerable pin, with the export
  file and its transitive local imports up to a byte cap. Option (b): the same prompt through the
  owner's chosen model UI. Recommendation: (a), scripted under `_test-findings/`, with the prompt
  text committed in `baseline-results.md`.
- **OQ-2** Provider, model, and numeric request cap for AC4.

## 12. Run log protocol

Use the plan's common rules. Record OQ answers verbatim, clone approvals, and per-row pin evidence.

## 13. Agent implementation prompt

> Work in the `npm-library-rce-mvp` sibling worktree, cut from current `origin/stage`. Read AGENTS.md,
> the orientation contents, the [plan](architecture-update-plan.md), this spec, and the container-root
> npm proposal sections it names. Follow the plan's common rules. Ask for clone approval and OQ-1
> first. Make no changes under `cmd/` or `internal/`. Make paid calls only within OQ-2's cap. You may
> delegate one corpus row per Sonnet Contributor Agent for pinning and key drafting. You review
> every key against its advisory. Finish with a draft PR into `stage`. Verifier: a fresh-context
> subagent checks three random rows' commits and sink anchors against the advisory and fix diff,
> confirms that no tracked file names an unpublished issue, and reports PASS or FAIL.

## 14. Implementation and review change log

No changes recorded.
