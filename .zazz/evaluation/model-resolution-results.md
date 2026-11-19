# Model-assisted evidence resolution: results

[Contract](../specifications/model-assisted-evidence-resolution.md) ·
[Checker](recall-gap-inventory/check.py) · [Precision baseline](precision-noise-baseline.md)

## Method

Scanner `model-evidence-resolution` at `064c492` for the VulnPy and OopsSec runs and `b6e050d` for
the DVWA run (after the stored-origin fix below), 2026-11-19. Each sample was at its
[pin](recall-gap-inventory.md#corpus-and-pins) with an empty `git status --porcelain --ignored`
before and after the run. Judge `openai` `gpt-6-luna`, default judge limit, `JUDGE_RPM=4500`,
`JUDGE_TPM=1800000`, only the OpenAI key passed to the scanner. Runs are the three the owner
authorized: VulnPy `--only-family path`, OopsSec in full and DVWA in full. Planned request counts
came from an offline stub planner before any call. Measures come from the checker's precision and
resolution columns; the other eight samples use the offline W3a reports, so the recall rows cover
the whole corpus.

## Requests

| Sample | Planned | Assessment requests | Follow-ups sent | Follow-up items unresolved | Records gated (D-7) | Failed |
|---|---:|---:|---:|---:|---:|---:|
| VulnPy path | 260 + ≤65 | 260 | 61 | 2 | 0 | 0 |
| OopsSec | 27 + ≤6 | 27 | 0 | 1 | 3 | 0 |
| DVWA | 183 + ≤45 | 169 | 0 | 16 | 61 | 0 |

The first DVWA run (`064c492`, 183 requests) had 14 `HTTP 400` failures: a stored-origin record
whose census listed only literal writes sent a citation question with one choice, below the
provider's minimum of two. Such a record has nothing to cite and no closed-store fact, so it is now
gated instead of asked (`b6e050d`), and DVWA was rerun. The planner's 183 counted those 14.

## Resolution measures

| Sample · family | Blocked records sent | Blockers resolved | Citations rejected | Model-resolved finding / Protected / Review |
|---|---:|---:|---:|---|
| VulnPy · path | 64 | 10 | 0 | 0 / 0 / 8 |
| OopsSec · XSS | 2 | 0 | 0 | 0 / 0 / 0 |
| DVWA · path | 0 | 0 | 0 | 1 / 0 / 0 |

Every unverified answer chose `none` for its citation: 177 VulnPy flow-gap and 64 witness answers,
2 OopsSec stored-origin answers, and 6 witness and 3 bypass answers on DVWA. No offered chain
failed verification. Flow-gap answers on VulnPy: 126 `cannot_tell`, 90 `value_constrained`, 39
`value_preserved` (10 with a verified chain), 1 `value_replaced`.

## Against the measured baseline

| Measure | §2 baseline | This run |
|---|---|---|
| OopsSec fixed-outcome requests | 5 of 30 | 2 of 27 (both stored-origin XSS records whose model named a write but cited none) |
| OopsSec findings and keyed true per family | | Unchanged in every family (log, redirect, path, SQL, SSRF, XSS) |
| DVWA command findings and keyed true | 12 and 4 (`CMD-001` demotions kept) | 12 and 4 |
| DVWA records not sent | | 61 whose blocker has no question (55 SQL, 6 XSS) |
| VulnPy path fixed-outcome requests | not measured | 64: records with a flow-gap question, sent by D-7, that stay Review |

DVWA keyed true findings hold in every family; its other families were offline in the previous
live run, so their judged counts have no earlier same-scanner comparison. Juice Shop was not part
of the authorized runs, so its §2 row (34 of 62) is not re-measured here.

Recall floor: 91 `candidate_with_witness`, 30 `control_pass`, 4 `resolved`, unchanged. No keyed
positive lost its finding. No control record became a finding.

## Source review

Every record whose status rests on a model resolution, plus every discharged resolution:

| Record | Resolution | Outcome | Review |
|---|---|---|---|
| DVWA `vulnerabilities/fi/index.php:36` `include($file)`, source `fi/source/medium.php:4` | Witness: the model answered vulnerable and cited the chain `$_GET['page']` → two `str_replace` calls → `include`; the scanner held no witness | Confirmed, model-resolved | **True.** The medium level removes `../` once, so `....//` becomes `../`, and an absolute path passes untouched. Keyed `FI-001` |
| VulnPy `common/templating.py:27`, 8 records | Flow gap `app.py:70` (`[s for s in PATH_INFO.split("/") if s != ""]`), `value_preserved` ×4 | Review (other gaps open) | Correct: the comprehension keeps the request's path segments |
| Same records | Flow gap `util.py:56` call and dispatch, `value_preserved` ×3 | Review | Plausible; not decisive, as the record stays Review |
| Same records | Flow gap `app.py:84` (`[s for s in TRIGGER_MAP.keys() if s == name][0]`), `value_preserved` ×3 | Review | **Wrong.** This selects a key from a fixed map (`value_constrained`). No false finding resulted |

The wrong `app.py:84` answer led to a fix: the scanner already records that the operand is
selected from a collection by comparison, now as a structured `PathFlow.selection` fact
(`2f41d5c`). Neither a flow-gap discharge nor a cited witness can turn such a flow into a raw
witness (`TestFlowGapSelectionStaysReview`). The VulnPy run predates this fix; the fix can only
keep records in Review, and none of the 8 left Review.

A verified citation shows the model followed supplied evidence, not that its answer about that
evidence is right. Model-resolved findings: 1 of 1 true, 0 false (AC6). Model-resolved Protected: 0.

## Limits

- Write-set coverage is 29 of 45 stored-origin records offline (AC3 asks 40): the Juice Shop
  configuration-endpoint records and file reads have no storage read to census. DVWA session
  writes made through a returned reference are not visible to the text census.
- Follow-ups were sent only on VulnPy (61). On DVWA every named item (16) was a value or helper
  without a single exact definition in the snapshot, so none was sent.
- One model, one run per sample: these are bounded calibration counts, not accuracy rates.
