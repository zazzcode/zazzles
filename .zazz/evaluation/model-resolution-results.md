# Model-assisted evidence resolution: results

[Contract](../specifications/model-assisted-evidence-resolution.md) ·
[Checker](recall-gap-inventory/check.py) · [Precision baseline](precision-noise-baseline.md)

## Method

Scanner `model-evidence-resolution` at `064c492` for the VulnPy and OopsSec runs and `b6e050d` for
the DVWA run (after the stored-origin fix below), and `db3d4f7` for Juice Shop, 2026-11-19. Each sample was at its
[pin](recall-gap-inventory.md#corpus-and-pins) with an empty `git status --porcelain --ignored`
before and after the run. Judge `openai` `gpt-6-luna`, default judge limit, `JUDGE_RPM=4500`,
`JUDGE_TPM=1800000`, only the OpenAI key passed to the scanner. Runs are the three the owner
authorized for this contract (VulnPy `--only-family path`, OopsSec in full, DVWA in full), plus the
owner's standard Juice Shop live check, requested afterwards in chat. Planned request counts
came from an offline stub planner before any call. Measures come from the checker's precision and
resolution columns; the other seven samples use the offline W3a reports, so the recall rows cover
the whole corpus.

## Requests

| Sample | Planned | Assessment requests | Follow-ups sent | Follow-up items unresolved | Records gated (D-7) | Failed |
|---|---:|---:|---:|---:|---:|---:|
| VulnPy path | 260 + ≤65 | 260 | 61 | 2 | 0 | 0 |
| OopsSec | 27 + ≤6 | 27 | 0 | 1 | 3 | 0 |
| DVWA | 183 + ≤45 | 169 | 0 | 16 | 61 | 0 |
| Juice Shop | 28 + ≤7 | 28 | 0 | 0 | 34 | 0 |

Juice Shop named one follow-up item on two records, both already Confirmed, so neither was sent.

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
| Juice Shop · path | 0 | 0 | 0 | 0 / 0 / 0 |

On Juice Shop one path witness (`routes/vulnCodeFixes.ts:83`) offered a chain that verified, but
the record's answers contradicted the scanner's path facts, so nothing was discharged and it stays
Review. Every unverified answer chose `none` for its citation: 177 VulnPy flow-gap and 64 witness answers,
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
live run, so their judged counts have no earlier same-scanner comparison.

**Juice Shop** (added after the three runs; the owner asked for its standard live check, scanner
`db3d4f7`): fixed-outcome requests went from 34 of 62 (§2) to 0 of 28. The 34 records whose
blocker has no question are not sent (19 XSS, 9 path, 3 NoSQL, 1 each redirect, SQL and SSRF).
Keyed true findings match the published sample in every family (XSS 9, NoSQL 3, SQL 2, log 1).

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
- Follow-ups were sent only on VulnPy (61). On DVWA all 16 Review records asked for the same item,
  the definition of the `$_DVWA` configuration array. Its only definition is in
  `config/config.inc.php.dist`, a template the installer copies to `config.inc.php`; the scanned
  snapshot has no `.php` definition, so none was sent. The template's values are install-time
  settings, so they would not settle these records either. A further 37 confirmed records asked for
  the same item and were not sent because they were not Review.
- One model, one run per sample: these are bounded calibration counts, not accuracy rates.

## Refresh runs and two fixes

After the four runs above, the owner asked for paid runs of the TypeScript app and the vuln-nextjs
lab and for every sample's results to be brought up to date. Each run used `openai` `gpt-6-luna`,
the default judge limit and only the OpenAI key; every pin was clean before and after.

Two defects came out of scoring and source review, and both are fixed:

1. **Bound-only PDO statement Confirmed** (`df540c3`). DVWA `brute/source/impossible.php:90`, a
   PDO `execute()` whose only request value is bound with `bindParam`, was Confirmed SQL injection
   in both runs on `sql-components-v4`. The record carried the bindings but not the prepared SQL
   text, and the model answered vulnerable with probability 0.5. `execute()` now carries its
   statement's prepared text. A SQL record whose every dependency is a bound parameter, and whose
   text is not interpolated, gets a `bound_parameters_only` blocker on a vulnerable answer. In the
   rerun, line 90 is Protected, and line 96, answered vulnerable again, stays Review on that
   blocker.
2. **Empty citation labels** (`50d4a8f`). Deduplicated evidence carries its text through
   `text_ref`, and the citation index read only the inline text. Every chain choice therefore
   reached the model as `e40 "" routes/index.js:168 -> …`. This explains why nearly every citation
   above chose `none`. Labels now show the cited code, and the citation questions moved to v2. In
   the rerun, 12 citations were offered and verified, against none before.

A wording change that told the model to choose a fitting listed chain was tried on Goof and
reverted: its score for the correct bypass chain fell from 0.44 to 0.06, and to 0.28 with the guard
named.

| Sample | Run | Scanner | Requests | Follow-ups | Not sent (D-7) | Model-resolved |
|---|---|---|---:|---:|---:|---|
| Juice Shop | `run-3093352752` | `50d4a8f` | 28 | 0 | 34 | 0 |
| OopsSec Store | `run-796729664` | `50d4a8f` | 27 | 0 | 3 | 0 |
| DVWA | `run-1794714987` | `50d4a8f` | 169 (7 over the wire limit) | 0 | 61 | 1 finding, `fi/index.php:36`, true |
| vuln-nextjs | `run-3943326285` | `50d4a8f` | 27 | 0 | 0 | 0 |
| Node.js Goof | `run-1380275680` | `50d4a8f` | 11 | 0 | 8 | 0 |
| ThreatByte | `run-1522805296` | `50d4a8f` | 58 | 1 | 1 | 0 |
| Vulnerable Flask App | `run-445025256` | `50d4a8f` | 11 | 0 | 2 | 0 |
| Vulnerable TypeScript app | `run-3223900652` | `df540c3` | 7 | 0 | 1 | 0 |
| Python insecure app | `run-415226149` | `df540c3` | 1 | 0 | 0 | 0 |
| vuln-demo-app | `run-2873229226` | `df540c3` | 13 | 0 | 0 | 0 (2 stored-origin answers, Review) |

The TypeScript app, Python insecure app and vuln-demo-app sent no citation question, so the label
fix does not change their requests. These runs are the published samples, except vuln-demo-app,
which has none. VulnPy was then rescanned in full at the owner's word. The first rescan
(`run-1329700200`, scanner `614e435`, 456 requests) left 64 path records with flow-gap questions
unsent: once their citation labels carried text, they exceeded the 64KB limit. `7e333aa` sends
such a record without its resolution questions. The published rerun (`run-1549598806`, `57c29dc`)
sent all 520 with no failures, found all 6 keyed positives and has 455 Confirmed records; the 64
stay Review, as before. Requests charged in this refresh:
301 (first pass, `df540c3`) + 337 (reruns, `50d4a8f`) + 22 (Goof wording trials) + 456 + 520 (VulnPy)
= 1,636.

The recall floor over the published reports holds: 91 `candidate_with_witness`, 30 `control_pass`,
4 `resolved`.

## Accuracy against the answer keys

Scored on 2026-11-19 with [`accuracy.py`](recall-gap-inventory/accuracy.py) over the published
sample reports, plus vuln-demo-app's run above. The [sample reports](../../docs/samples/README.md) describe the published runs. This evaluation
covered 91 keyed positives across 11 samples: 88 found
(85 Confirmed and 3 practice findings where the key expects construction practice), 3 Review and
0 missed. None of the 55 keyed and protected controls shows as a finding.

| Row | Sample | Status | Assessment |
|---|---|---|---|
| `GOOF-CMD-01` | Node.js Goof | Review | The model answered `bypass_identified` for the `/\!\[alt text\]\((http.*)\s\".*/` guard but cited `none` for the one offered chain (0.56 against 0.44), so D-8 keeps the guarded path in Review. The published 2026-11-15 report, on `command-components-v2` without a bypass question, had it Confirmed |
| `UPLD-001` | DVWA | Review | `low.php` applies `basename()` to the name, so the key row is not a path traversal, and the model answered protected. The flaw is unrestricted file type, outside our analyzers. The key row should move |
| `PI-VAL-NAME` | Python insecure app | Review | A field-validation defect; undecidable validation records are not sent |

The five rows that the earlier sample reports could not score now pass: the TypeScript app's
`eval` and open redirect, and vuln-nextjs `JS-001`, `JS-002` and `REDIR-001`.

**False positives.** None among keyed controls. The one that source review found outside the key
(DVWA `brute/source/impossible.php:90`) is fixed, as described above. After the fix, no DVWA
Confirmed record comes only from impossible-level code.

**Findings outside the key** (490 in all) are counted, not judged. Juice Shop's eight match known
challenge routes; the rest are unreviewed.
