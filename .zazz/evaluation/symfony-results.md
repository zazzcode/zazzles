# Symfony evaluation results

The [detection guide](vuln-symfony-detection-guide.md) defines the expected outcomes for
`vuln-symfony` at `086f81f941501bd1170b249e01107ba99beb2962`.

## Offline baseline

The 2026-11-21 run `run-1210193297` used scanner checkpoint `2ccc908`, whose scanner code
matches `stage` at `a8edac7`. The sample was at its pinned revision and clean before and after
the scan, including ignored files. The run used no decision provider.

| Measure | Result |
|---|---|
| Entries | 28 total. 25 internal PHP file mappings, two public PHP mappings, and one browser entry. |
| Route entries | 0 |
| Candidates | One encoded browser XSS candidate at `public/js/script.js:6` (`innerText`). |
| Required positive candidates with a witness | 0 of 14 |
| Controls | 20 passed the offline check, including 11 with no matching record. |
| Assessment-dependent rows | All three lacked the required evidence. |

The scan used `go run ./scan/cmd/scan --analyze --output-dir <output> <sample>`.
The [offline checker](recall-gap-inventory/check.py) scored the saved JSON report against
the [frozen cases](recall-gap-inventory/cases.json). Run artifacts are local and unpublished.

## Implemented offline

Scanner commit `9f2995b` produced 34 entries, including all 31 keyed Symfony routes,
two public PHP file entries, and one browser entry. No `FILE` entry appeared under
`src/`. All 14 positives had witnessed paths at their keyed anchors, all 20 controls
met their offline expectations, and all three assessment-dependent rows had their
expected evidence. Both samples stayed at their pins and clean, including ignored files.

## Judged acceptance

All runs used OpenAI `gpt-6-luna` with the default candidate limit, 4,500 RPM, and
1,800,000 TPM. The sample was clean at its pin before and after each run.
The final full run met AC14 with **14 Confirmed positives and zero control findings**.

| Run ID (UTC) | Scanner | Scope | Requests | Input tokens | Key outcome |
|---|---|---|---:|---:|---|
| `20261122T125218Z` | `a2b53aa` | Full | 46 | 202,486 | 12 confirmed, zero control findings |
| `20261122T125705Z` | `9f2995b` | Path and SSRF only | 6 | 26,933 | Both corrected rows and the other keyed rows in scope confirmed, zero control findings |
| `20261122T125714Z` | `9f2995b` | Full | 46 | 202,553 | 14 confirmed, zero control findings |

The first full run left two required rows in Review. For `SYM-SSRF-01`, the first
failing stage was guard evidence. A PHP emptiness test was attached as a destination
control. The scanner now distinguishes the presence-only test from a restriction,
using PHP syntax and the recorded branch span. For `SYM-PATH-02`, the first failing
stage was request selection. The path operand pointed to invocation evidence in the
request and omitted the observed construction. The scanner now indexes the actual
operand and carries source-established concatenation and base directory facts.
Synthetic SV-05 and SV-06 extensions failed before the fixes and passed afterward.
Both corrected rows confirmed in the scoped and final full runs. The other required
positives and all control outcomes held between the full runs.

### Final keyed outcomes

| Case | Outcome |
|---|---|
| `SYM-SQL-01` | Confirmed |
| `SYM-SQL-02` | Confirmed |
| `SYM-XSS-01` | Confirmed |
| `SYM-XSS-02` | Confirmed |
| `SYM-XSS-03` | Confirmed |
| `SYM-CMD-01` | Confirmed |
| `SYM-CMD-02` | Confirmed |
| `SYM-PATH-01` | Confirmed |
| `SYM-PATH-02` | Confirmed |
| `SYM-PATH-03` | Confirmed |
| `SYM-SSRF-01` | Confirmed |
| `SYM-UPLOAD-01` | Confirmed |
| `SYM-SSTI-01` | Confirmed |
| `SYM-DESER-01` | Confirmed |
| `SYM-SQL-N01` | Protected |
| `SYM-SQL-N02` | No record |
| `SYM-SQL-N03` | No record |
| `SYM-SQL-N04` | No record |
| `SYM-SQL-N05` | No record |
| `SYM-XSS-N01` | Review |
| `SYM-XSS-N02` | Review |
| `SYM-XSS-N03` | No record |
| `SYM-XSS-N04` | No record |
| `SYM-XSS-N05` | Protected |
| `SYM-XSS-N06` | Review |
| `SYM-XSS-N07` | No record |
| `SYM-XSS-N08` | Review |
| `SYM-XSS-N09` | No record |
| `SYM-REDIR-N01` | No record |
| `SYM-PATH-N01` | No record |
| `SYM-SSRF-N01` | No record |
| `SYM-PATH-N02` | No record |
| `SYM-LOG-N01` | No record |
| `SYM-CODE-N01` | No record |
| `SYM-XSS-R01` | Confirmed |
| `SYM-XSS-R02` | Confirmed |
| `SYM-VAL-R01` | Both automatic query checks present |

### Remaining Review records

| Entry and anchor | Source review |
|---|---|
| `ANY /admin`, `templates/admin/index.html.twig:44` | The stored email is rendered in HTML text. The model did not establish protection across the reported paths. |
| `ANY /`, `templates/blog/index.html.twig:21` | Twig renders the stored author name in HTML text. The assessment answers disagreed on the effect of the escaping evidence. |
| `ANY /post/{post}`, `templates/blog/post.html.twig:33` | The avatar goes through `asset()` with a fixed local prefix inside a quoted URL attribute. The scanner does not credit ordinary HTML encoding for the full URL context. |
| `ANY /local/posts`, `src/Controller/LocalController.php:101` | The HTML list includes stored fields. The traced read has a stored-origin blocker for content without a witnessed request writer. |
| `ANY /reset`, `src/Services/UserPref.php:36` | The global service reads and decodes a cookie before deserializing it. This invocation carries unresolved loop evidence from the reset action. The keyed search invocation confirmed. |
| `ANY /user`, `templates/user/index.html.twig:28` | The user's about text is rendered in a textarea. The model's exposure and encoding answers disagreed. |
| `ANY /user`, `templates/user/index.html.twig:45` | The flash text is rendered from session state. The source review found literal flash messages, and the scanner has no witnessed request writer for this path. |
| `ANY /user`, `templates/user/index.html.twig:64` | The avatar is rendered with a fixed local prefix in a quoted URL attribute. The report preserves the output-context blocker. |
| `POST /user/avatar/{user}`, `src/Controller/UserController.php:99` | The move writes the upload to the configured directory using a generated stem and a client extension. The path assessment was inconsistent with the component handling evidence. The separate upload claim confirmed. |
| `GET /user/edit/`, `templates/user/edit.html.twig:14` | Twig emits the stored first name in a quoted attribute. The assessment did not establish sufficient evidence for the path. |
| `GET /user/edit/`, `templates/user/edit.html.twig:16` | Twig emits the stored last name in a quoted attribute. The assessment did not establish sufficient evidence for the path. |

The report also records a confirmed path claim outside the answer key at
`src/Controller/UserController.php:82`. The upload action deletes the previous avatar
using the same stored field and configured directory as the keyed delete action.
The two command assessments with model-resolved evidence were source-reviewed against
the recorded call, conditional configuration, and URL-format guard. The reports and
request traces remain local and unpublished.
