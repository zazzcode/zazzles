# False positives and Review noise (proposal)

- **Status** Proposal. Not greenlit. The owner decides the open questions in §11 and assigns a
  worktree before any implementation.
- **Worktree and branch** To be assigned. Suggested: `accuracy-fp-noise`.
- **Prerequisite** [Phase 5](architecture-phase-5-accuracy-gaps.md) is integrated: its inventory,
  checker and before/after method are the measurement base. Its PR, zazzcode/zazzles#28, is not yet
  merged.
- **Delivery** One draft PR into `stage`, with one commit per workstream that ships.
- **Run log** `.zazz/ephemeral/accuracy-false-positive-noise-run-log.md`

## 1. Capability

Reduce the false positives and low-value Review volume that reach a reader, and keep recall
measured. Each change either removes a record that has no source-backed security claim, makes the
evidence of a kept record more precise, or groups repeated records in the presentation while every
record stays in canonical JSON. Precision gets a measured denominator next to the phase 5 recall
denominators. No change may lower recall.

## 2. Measured baseline

These figures come from offline scans of the eleven pinned samples with the phase 5 closure scanner
(zazzcode/zazzles#28, 2026-11-19).

| Source of noise | Measurement | Example |
|---|---|---|
| Standalone input-validation records | VulnPy 2,830 of 3,350 records; Juice Shop 95 of 251; OopsSec 87 of 128; vuln-nextjs 19 of 54 | The [OopsSec guide](../evaluation/oss-oopssec-store-detection-guide.md#saved-results-and-verification) assessed 86 validation contexts. Most were inconclusive |
| Shared-sink fan-out | DVWA has 82 XSS records at `dvwa/includes/dvwaPage.inc.php:388` and 24 SQL records at `:570`. VulnPy has 28–30 command and path records at each shared trigger sink | Every DVWA page renders through one function. Pages with no module input reach it only through the `theme` and `security` cookies |
| Request origin through an own-API response | Path candidate at OopsSec `app/vulnerabilities/[slug]/page.tsx:49` (`OOPS-PATH-N01`). The key expects no path finding | The slug selects an API row whose `markdownFile` is read. It is held at Review by `unknown_transfer` |
| Raw output from storage with no request write | vuln-demo-app 2 (`server.js:131`, `:280`); Juice Shop 2 (`routes/dataErasure.ts:50`, `views/dataErasureForm.hbs:38`) | `DEMO-XSS-N02`: `users` is written only by literal seed SQL |
| Unresolved type shown with `raw` protection | Stored records with an unknown response type, such as OopsSec `uploads/[...path]/route.ts:44` and fixture `server.js:16` | Context is unknown, yet the protection field reads `raw`. Blockers keep it Review, but the presented label overstates it |
| Closed constant type maps | OopsSec `uploads/[...path]/route.ts:44` takes its type from a constant map of image types | Raster types cannot render HTML. `image/svg+xml` can, when opened directly |

Two suspected sources turned out not to be problems. No sample emits a security record from a test,
fixture or Cypress path, because the walker already excludes them. The Juice Shop logger
false positives on constant text (`lib/startup/validateConfig.ts:45`, `:47`) are Bearer's; zazzles
emits only the `server.ts:366` access-log records there.

## 2a. Required reading

- [Phase 5 inventory](../evaluation/recall-gap-inventory.md) and its [checker](../evaluation/recall-gap-inventory/check.py), which give the recall floor and the method.
- [Calibration](../../docs/analysis/calibration.md#evaluation-and-audit), [claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) and the [reporting design](../architecture/reporting-and-sarif.md).
- [Input validation analysis](../../docs/analysis/input-validation.md), [XSS analysis](../../docs/analysis/xss.md) and [path traversal analysis](../../docs/analysis/path-traversal.md).
- [Practice accuracy results](../evaluation/practice-accuracy/results.md), the precedent for precision denominators and protected controls.
- [Testing standards](../standards/testing.md) and the plan's [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).

## 3. Invariants

- **Recall floor.** The phase 5 checker still reports 91/91 required positives with a witness,
  30/30 structural controls and 4/4 registrations, and no required positive changes outcome.
- **Canonical JSON keeps every record.** Grouping changes only HTML and SARIF presentation and adds
  grouping fields. It never deletes a candidate or merges judgments.
- **Records stay unless the claim is impossible.** A record is removed only when source evidence
  shows that the claim it carries is impossible: no request origin, or a non-HTML type. Uncertainty
  stays Review.
- **Labels stay out of the scanner.** Expected labels, sample names and case IDs never enter scanner
  logic or model input.
- **Changed evidence is judged afresh.** It gets a new judgment, and existing replay rules apply.
- **Stable IDs.** IDs and golden rows change only where this spec lists them.

## 4. Scope and review shape

| Workstream | Likely owner | Change |
|---|---|---|
| W1. Standalone validation volume | `internal/analysispacks` (selection), `internal/report`, `cmd/scan` (only if a flag is chosen) | Depends on the owner's choice in §11 Q1 |
| W2. Root-sink grouping | `internal/report` (JSON grouping field, HTML, SARIF) | Group records by sink span and family, with the entries and origins listed. Each group keeps its member records and judgments |
| W3. Origin precision | `internal/langjs`, `internal/langphp` | Treat a value selected from an own-API response row as storage-origin, not request-origin. Treat storage with only literal writes as having no request origin. Resolve closed constant `Content-Type` maps |
| W4. Presentation consistency | `internal/parse` (XSS claim assembly), `internal/report` | A record with unknown context presents protection `unknown`, not `raw` |
| W5. Precision measurement | `.zazz/evaluation/` | Extend the phase 5 checker with per-family precision rows. Add a held-out, source-reviewed protected-control set for the security families |

Out of scope: new analyzer families, the Review-burden work on `needs_evidence` (a separate
contract, phase 5 §11), detection gaps, prompt or policy calibration, and paid runs beyond §6.
Each workstream may land on its own. W5 lands first so the others are measured.

## 5. Decisions

- **D-1. Measure before changing.** W5 adds precision rows to the phase 5 checker and a protected
  set. Each family gets `noise_record`, `kept_review` and `removed` counts, so every later
  workstream reports a before/after delta. A smaller report is not a win without that delta.
- **D-2. Group, don't drop, repeated sinks (W2).** The same sink reached from many entries is one
  defect with many exposures. The JSON grouping key is the family plus the sink span plus the
  origin kind. HTML shows one row with its entries, and SARIF uses one result with related
  locations. Per-entry evidence stays, because guards and protections differ by entry.
- **D-3. Remove only impossible claims (W3).** Raw output whose every storage write is literal is
  removed for XSS, and the storage key is kept as context for a future SQL-chain claim. A value
  selected from an own-API response row loses its request origin for a path claim. The row
  selector stays as context, and the value becomes storage-origin. A closed map whose values are
  all non-HTML types produces no XSS record. A map containing `image/svg+xml` or an HTML type stays
  unresolved Review. Any other uncertainty stays.
- **D-4. Presented protection follows the context (W4).** An unknown output context presents
  protection `unknown`, never `raw`. The raw path stays in the evidence.
- **D-5. Choose a validation policy explicitly (W1).** Standalone validation records are most of
  the record volume but rarely decisive. The owner picks one option in §11 Q1. The default
  recommendation is to keep the records, exclude them from the default judged scope, and present
  them grouped per entry and field. They are judged only when `--only-family input-validation` is
  given or a `--checks` requirement names the field.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls). Each workstream starts with a failing
fixture, then runs the phase 5 checker and the corpus record diff before and after. Paid calls are
limited to the owner's standing live check (`openai`, `gpt-6-luna`, default judge limit, one sample)
when a workstream changes judged records; anything more needs the owner's word. Halt if the recall
floor moves, an unlisted golden row changes, or a removal lacks a source-backed impossibility.

## 7. Acceptance criteria

1. **AC1 (W5).** `check.py` reports per-family precision rows and the protected set with
   denominators. Their offline baseline is recorded in a new evaluation record.
2. **AC2 (W2).** On DVWA, `dvwaPage.inc.php:388` presents as one HTML row and one SARIF result
   listing 82 exposures, while JSON keeps all 82 records with unchanged IDs. A report test checks
   grouping and record preservation.
3. **AC3 (W3).** The fixture test for each origin rule fails on the baseline and passes after:
   - `OOPS-PATH-N01` is no longer a request-origin path candidate.
   - `DEMO-XSS-N02` produces no XSS record.
   - A raster-only type map produces no record.
   - A map containing SVG stays Review.

   Corpus deltas are limited to listed rows, and the recall floor holds.
4. **AC4 (W4).** Every XSS record with an unknown context presents protection `unknown` in JSON,
   HTML and SARIF, checked by a claim-assembly test.
5. **AC5 (W1).** The chosen validation policy is implemented with its own test. The default-scope
   record and request counts before and after are reported per sample.
6. **AC6.** The contributor gate passes, the phase 5 checker floor holds, and every golden delta is
   listed. Where W1 or W3 changes judged records, one owner-authorized live check of OopsSec records
   the judged outcome counts.

## 8. Test strategy

- **Report.** Table-driven tests for grouping keys, HTML rows and SARIF related locations, plus a
  JSON round-trip that proves records are preserved.
- **Adapters.** Paired fixtures for each W3 rule, each with the vulnerable sibling it must not
  suppress: a request-origin path, a storage key with a request write, and an HTML type in the map.
- **Measurement.** Recall and precision are checked with the phase 5 checker and the record diff
  across all eleven pinned samples, before and after each workstream.

## 9. Execution sequence

1. W5: precision rows, the protected set and the baseline record.
2. W4: presentation consistency, the smallest change.
3. W3: origin rules, one at a time, each with its pair.
4. W2: grouping.
5. W1, after the owner's policy choice.

Each step is its own commit with its own before/after evidence.

## 10. Definition of done

- [ ] Precision baseline and the protected set are recorded (AC1).
- [ ] Each shipped workstream meets its AC with before/after evidence.
- [ ] The recall floor holds and the golden deltas are listed (AC6).
- [ ] Analysis guides and the inventory are updated for every changed behavior.

## 11. Open questions (owner)

1. **Validation policy (W1).** Pick one:
   - (a) Exclude standalone validation from the default judged scope and present it grouped
     (recommended).
   - (b) Keep judging it but group the presentation.
   - (c) Emit only fields named by `--checks` or a concrete defect.
2. **Grouping in SARIF (W2).** Use one result with related locations (recommended), or keep one
   result per exposure with a shared `partialFingerprints` group.
3. **SVG.** Should `image/svg+xml` count as an HTML-capable response type for the XSS sink, which
   turns the uploads route into a stored-XSS claim? Or should it stay unresolved Review?
4. **Paid budget.** Is the standing live check enough for AC6, or is a per-workstream cap wanted?

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, sample pins and status, checker summaries
before and after each workstream, record diffs, owner answers to §11 and any paid-call counts.

## 13. Agent implementation prompt

> Work in the owner-assigned worktree based on integrated `origin/stage`, which includes phase 5.
> Read AGENTS.md, the orientation contents and this spec. Confirm the owner's §11 answers in the
> run log. Execute §9 in order: each workstream starts with a failing fixture and ends with the
> phase 5 checker, the corpus record diff and the gate. Keep samples read-only and scans offline
> except the owner's standing live check. Deliver as a draft PR into `stage`, one commit per
> workstream, with an independent verification of the recall floor and two removed or grouped
> records.

## 14. Implementation and review change log

### 2026-11-19 — Proposal

Drafted from the phase 5 inventory observations and fresh offline measurements. No changes
recorded since.
