# Close findings gaps — results

Contract: [close-findings-gaps](../specifications/close-findings-gaps.md). Branch
`close-findings-gaps-dvwa`, scanner commits `237596f`..`1158e65` on `stage` `58e94e7`. All runs here
are offline (no provider key); the live check (AC11) has not run.

## Corpus

Eleven samples at their [pins](recall-gap-inventory.md#corpus-and-pins), clean before and after
(`git status --porcelain --ignored` empty for DVWA `a1978a2`, nodejs-goof `add14ba`,
python-insecure-app `b188493`). Reports were written under the container's `_test-findings/`.

## Recall floor (check.py)

| Measure | Before (`58e94e7`, keys as before) | After W7a keys, before code | After (`1158e65`) |
|---|---:|---:|---:|
| candidate_with_witness | 91 | 90 | 94 |
| control_pass | 30 | 30 | 30 |
| resolved | 4 | 4 | 4 |
| missing_candidate | 0 | 4 | 0 |
| total rows | 174 | 179 | 179 |

W7a re-keyed UPLD-001 and PI-VAL-NAME and added five rows, so the middle column is the failing-first
baseline every later step is measured against. No keyed or protected control presents as a finding
in any report (accuracy.py: no `FALSE_POSITIVE` row).

## §1 rows (offline)

| ID | Before | After (offline) | Closed by | Remaining for AC11 |
|---|---|---|---|---|
| GOOF-CMD-01 | guarded path, Review | raw shell path: `(http.*)` classified `admits_any` | W2 (W1 for guards W2 cannot classify) | Confirmed needs the judged run |
| DVWA-API-CMD-01 | no candidate | witnessed raw command candidate under `api/public/index.php` | W3 | Confirmed needs the judged run |
| XSSS-001 | 4 records `evidence_too_large` | each planned as 3 path-group requests (51–64 KB) | W4 | Confirmed stored XSS needs the judged run |
| DVWA-SIZE | 3 more records over the limit (one more measured: 8 in all) | all grouped; `sqli/index.php` (83 KB) leaves `sqli/source/medium.php` past the 4-group cap | W4 | — |
| UPLD-001 | path claim Review (`path_answers_inconsistent`) | `file_upload_candidate`, practice finding offline; path claim unchanged | W5, W7 | Confirmed needs the judged run |
| PI-SSTI-NAME, PI-SSTI-REMOTE | XSS only | `template_injection_candidate` with both sources, linked to the XSS record | W6 | Confirmed needs the judged run |
| PI-VAL-NAME | required positive | Review-expected (key corrected) | W7 | — |
| GOOF-CHAT | 3 `unresolved_handler` | resolved; 3 new input-validation records, unsent offline | W8 | — |
| GOOF-REDIR-01 | outside the key | keyed positive | W7 | Confirmed already in the published report |

## W4 measurement (D-13)

8 DVWA records exceed 65,536 bytes (67,703–83,340). After shedding, every request repeats about
18–20 KB of page-shell `source_excerpts` and ~8 KB of fixed sections, so one source-file group alone
costs 51–60 KB. Path groups are lossless and fit; whole groups are packed while a request fits, giving
23 group requests. D-16's re-open condition for S2 is met; S2 is lossy and needs the owner's paid
ablation, so it was not started.

## New records outside the key (offline)

| Sample | Records | Note |
|---|---|---|
| DVWA | +7 | API command (keyed), six upload records (low/medium/high via two entries each) |
| nodejs-goof | +3 | chat handler input-validation records (W8) |
| ThreatByte | +2 | upload records `server/routes.py:217`, `:264` (unkeyed, unreviewed) |
| Vulnerable Flask App | +2 | upload `:209` (blocked), template injection `:51` (unkeyed) |
| python-insecure-app | +1 | template injection (keyed) |

## Deviations from the contract

- **W4:** whole structural groups are packed into one request while it fits. Without packing two
  `sqli` levels fell past the 4-group cap.
- **W5 (AC6 partial):** adapters exist for PHP `move_uploaded_file` and Werkzeug `FileStorage.save`.
  Node `express-fileupload`/`multer`, Starlette `UploadFile` and Symfony `UploadedFile::move` have
  registered contracts and no adapter. DVWA's impossible level stores via `rename()` of a re-encoded
  temp file, so `PC-UPLD-01` passes with no record.
- **W6:** Jinja `Environment.from_string` on an environment object is not recognised.
- **W3:** `json_decode` of the raw `php://input` body keeps request values raw (the content-effect
  table is unchanged for every other argument).

## Live check (AC11)

Not run. It needs the owner's word (§11 OQ-2): one judged scan each of nodejs-goof, DVWA and
python-insecure-app with `--judge openai --judge-model gpt-6-luna`, `JUDGE_RPM=4500`,
`JUDGE_TPM=1800000`, plus about 23 DVWA path-group requests. The README accuracy table is updated
from accuracy.py output of that run only, so it is unchanged here.
