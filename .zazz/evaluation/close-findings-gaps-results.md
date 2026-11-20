# Close findings gaps — results

Contract: [close-findings-gaps](../specifications/close-findings-gaps.md). Branch
`close-findings-gaps-dvwa`, scanner commits `237596f`..`fdc1148` on `stage` `58e94e7`. Offline runs use no provider key;
the live check (AC11) is reported at the end.

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

| ID | Before | After (offline) | Closed by | Live (AC11) |
|---|---|---|---|---|
| GOOF-CMD-01 | guarded path, Review | raw shell path: `(http.*)` classified `admits_any` | W2 (W1 for guards W2 cannot classify) | Confirmed |
| DVWA-API-CMD-01 | no candidate | witnessed raw command candidate under `api/public/index.php` | W3 | Confirmed |
| XSSS-001 | 4 records `evidence_too_large` | each planned as 3 path-group requests (51–64 KB) | W4 | Confirmed |
| DVWA-SIZE | 3 more records over the limit (one more measured: 8 in all) | all grouped; `sqli/index.php` (83 KB) needs five groups, within the cap of 5 (raised from 4 by the owner) | W4 | — |
| UPLD-001 | path claim Review (`path_answers_inconsistent`) | `file_upload_candidate`, practice finding offline; path claim unchanged | W5, W7 | Confirmed |
| PI-SSTI-NAME, PI-SSTI-REMOTE | XSS only | `template_injection_candidate` with both sources, linked to the XSS record | W6 | Confirmed (after the origin-scoping fix) |
| PI-VAL-NAME | required positive | Review-expected (key corrected) | W7 | — |
| GOOF-CHAT | 3 `unresolved_handler` | resolved; 3 new input-validation records, unsent offline | W8 | — |
| GOOF-REDIR-01 | outside the key | keyed positive | W7 | Confirmed |

## W4 measurement (D-13)

8 DVWA records exceed 65,536 bytes (67,703–83,340). After shedding, every request repeats about
18–20 KB of page-shell `source_excerpts` and ~8 KB of fixed sections, so one source-file group alone
costs 51–60 KB. Path groups are lossless and fit; whole groups are packed while a request fits, giving
24 group requests at the cap of 5. D-16's re-open condition for S2 is met, but the
offline measurement below shows S2 could remove at most about 5 KB per request, so it is not adopted.

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
  `sqli` levels fell past the group cap. The cap was later raised from 4 to 5 so that `sqli`'s fifth group
  (`medium.php`) is judged: 24 group requests offline, none past the cap.
- **W5 (AC6 partial):** adapters exist for PHP `move_uploaded_file` and Werkzeug `FileStorage.save`.
  Node `express-fileupload`/`multer`, Starlette `UploadFile` and Symfony `UploadedFile::move` have
  registered contracts and no adapter. DVWA's impossible level stores via `rename()` of a re-encoded
  temp file, so `PC-UPLD-01` passes with no record.
- **W6:** Jinja `Environment.from_string` is recognised since `fdc1148`.
- **S2 (D-16), measured:** in each DVWA group request, 12.6–18.6 KB of the source excerpts are on
  dependency chains and only 3.0–5.0 KB off them. A relevance filter could save at most about 5 KB
  (~7%) and would not lift `sqli`'s fifth group under the cap, so S2 is not adopted.
- **W3:** `json_decode` of the raw `php://input` body keeps request values raw (the content-effect
  table is unchanged for every other argument).

## Live check (AC11)

Run on the owner's word, 2026-11-19, under the AGENTS.md standing terms: `--judge openai --judge-model
gpt-6-luna`, the default judge limit (every candidate), `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`, only
the OpenAI key passed. Traces are saved under `_test-findings/<app>/run-cfg-live*/traces`.

| Run | Scanner | Sample | Requests |
|---|---|---|---:|
| 1 | `856fe70` | nodejs-goof | 11 |
| 1 | `856fe70` | python-insecure-app | 2 |
| 1 | `856fe70` | DVWA | 195 (19 of them path-group requests; 0 follow-ups) |
| 2 | `fdc1148` | python-insecure-app | 2 |
| 2 | `fdc1148` | DVWA `--only-family upload` | 6 |

Run 1 exposed two defects, fixed in `fdc1148`:
- The upload facts were not in the request, so the model answered `execution_exposure: unknown`.
- The template record was blocked whole by its remote-response sibling (`code_origin_unresolved`).

Run 2 re-judged only the records those fixes touch. No other DVWA request changed between the two
scanners, so the scored DVWA report is run 1 with its six upload records taken from run 2.

| Sample | Expected | Confirmed | Review | False positives |
|---|---:|---:|---:|---:|
| Node.js Goof | 7 | 7 | 0 | 0 |
| DVWA | 11 | 11 | 0 | 0 |
| Python insecure app | 3 | 3 | 0 | 0 |

Every §7 target row is met. Per-row detail:
- GOOF-CMD-01, DVWA-API-CMD-01 and GOOF-REDIR-01 are Confirmed.
- XSSS-001 is Confirmed as stored XSS: of seven grouped records, six are Confirmed and one (a `sqli` render) is Review.
- UPLD-001 is Confirmed. Its path claim is not a finding.
- PI-SSTI-NAME and PI-SSTI-REMOTE are Confirmed, both on one template record.
- DVWA upload medium is Confirmed on one entry. On the other, the model answered `none` beside the recorded client-type check, which is inconsistent, so it stays Review. High stays Review, as D-22 expects.

No keyed or protected control is a finding. The README table is updated from `accuracy.py` output of these reports.
