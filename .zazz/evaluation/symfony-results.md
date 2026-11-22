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

## Independent review

A separate review session on 2026-11-22 scanned a probe application that exercises the claimed
Symfony coverage form by form, then fixed what it missed. The sample key was already met, so the
probe was the source of the findings below. The [coverage tests](../../scan/internal/langphp/symfony_coverage_test.go)
hold each one: 34 of their 40 subtests failed on scanner `187cdb1` and all pass on `5f28bb5`.

| Area | Missed or wrong before the review | Now |
|---|---|---|
| Entries | An invokable controller with a class-level route had no entry. Class-level `methods` were ignored | Both produce the documented entries |
| Route arguments | `{id<\d+>}`, `{page?1}` and `{slug}.html` did not bind their argument. An entity argument bound only when the placeholder had its name | All bind. A digits requirement and an `int`, `float` or `bool` argument are numeric |
| Request readers | `getString`, whole-bag reads of headers, cookies and attributes, and `json_decode($request->getContent())` gave no source or an unknown value | Request values |
| PHP values | `(int)` casts were not numeric, in plain PHP as well. `sprintf` and `implode` results were unknown | Casts are numeric. A literal `sprintf` format keeps `%s` arguments and makes numeric conversions numeric |
| Commands | Backtick commands were never recorded: the grammar node kind was misspelled | Recorded |
| SQL | A QueryBuilder or Query chain lost its claim at `from`, `setMaxResults`, `setFirstResult` and other setters | The chain keeps its text and bound values |
| Response | `Response::setContent` was not an output | Recorded under the response's content type |
| Twig | `{{ c ? x\|raw : y }}` was reported encoded. `{% autoescape 'js' %}` and a project `autoescape: false` were read as HTML escaping. `spaceless` was unknown. A macro body and call left no record and no gap | Raw, unknown with a gap, raw, raw, and gaps |
| Twig URL attributes | Every URL attribute was Review and never assessed | A literal local prefix is encoded. The whole URL of a link, form or frame is raw. The rest stay Review |
| Judge evidence | A Twig output was sent as the bare `{{ … }}` text, so the model could not see its element or attribute | The surrounding markup is render context evidence, as in the Jinja and EJS adapters |
| Stored values | A generated integer identifier in a rendered string blocked the origin of the whole record. A flash type with no writer stayed in Review | A numeric-typed entity field is not rendering content. An unwritten flash type has no record |

### Sample effect

Offline, the sample report at `5f28bb5` differs from the one at `187cdb1` in five records:
`templates/blog/post.html.twig:33` and `templates/user/index.html.twig:64` (the `asset()` avatar
URLs) moved from Review to Protected, `src/Controller/LocalController.php:101` moved from Review
to a finding with a resolved origin, `LocalController.php:63` lost its generated-identifier path,
and `templates/user/index.html.twig:45` (a flash type nothing writes) has no record. All 14
positives, 20 controls and three assessment-dependent rows keep their offline expectations.

### Judged runs

Same provider, model and limits as above. The sample was clean at its pin before and after each.

| Run ID (UTC) | Scanner | Scope | Requests | Input tokens | Key outcome |
|---|---|---|---:|---:|---|
| `20261122T133713Z` | `e527fe0` | Full | 48 | 212,292 | 14 confirmed, zero control findings |
| `20261122T133820Z` | `d215a80` | XSS only | 22 | 109,948 | The three XSS positives and both assessment-dependent XSS rows confirmed, zero control findings |

In the full run `LocalController.php:101` (`ANY /local/posts`) was Confirmed. It was Review in
every earlier run. The model now names the quoted-attribute context for
`templates/user/edit.html.twig:14` and `:16`, which it called HTML text before.

**Remaining limit.** Of the 16 XSS records the scanner marks encoded, seven stayed in Review in
the full run and five in the XSS-only run. In each the model's component answers agree with the
scanner (context correct, encoding adequate, every path protected) and its overall exposure answer
does not, so the policy withholds Protected. None is a finding. The second run used a rendering
contract that states Twig's escaping in full, which removed the "encoding unknown" answers. The
exposure answer is a property of the shared XSS question set and is the subject of the
protected-recognition follow-on work.

The other two Review records are unchanged: the path claim on the upload `move` at
`src/Controller/UserController.php:99`, and the deserialization record under `ANY /reset`, which
carries the loop gap of that action.

## Application-security lane, branch 1

[Branch 1](../specifications/symfony-more-analyzers-1.md) adds the `exposure` and
`mass-assignment` families and the security-field census. The sample was at its pin and clean,
including ignored files, before and after every scan.

### Offline

Scanner `fd18dd9`, `go run ./scan/cmd/scan --analyze`. The checker reports **16 of 16 positives
witnessed** and every control passing. `public/info.php:2` is the only
`info_exposure_candidate`. The `mass_assignment_candidate` at `src/Entity/User.php:59` under
`POST /user/edit/` has its request source at `src/Controller/UserController.php:239`, shape
`dynamic_property_write`, a stored target, and census roles `role_source` on
`php-sql:user.is_admin` and `php-sql:user.roles`, `credential` on `php-sql:user.password`, and
`login_identifier` on `php-sql:user.email` and `php-sql:user.username`. `ANY /admin/create`,
`POST /register` and `POST /user/about/` have no mass-assignment record. The 48 records the
sample produced before this branch are byte-identical, including their component selections.

After the judged runs, the branch added review fixes: a Twig output sink for diagnostic values and
reflection records at the `setValue` or `getProperty` call. Both scanners, `fd18dd9` and the
review-fix head, were run offline on the pinned, clean sample. Their `findings.json` files are
byte-identical, because the sample has no diagnostic value in a template and no reflection write.
The judged run at `fd18dd9` therefore stands for the submitted head. The commits between `fd18dd9`
and the review fixes (`56ab26b` to `e6f001b`) change only evaluation records, the baseline, test
fixtures, tests and specifications.

### Judged runs

OpenAI `gpt-6-luna`, the default candidate limit, 4,500 RPM and 1,800,000 TPM, with only the
provider key passed to the scanner.

| Run ID (UTC) | Scanner | Scope | Requests | Input tokens | Key outcome |
|---|---|---|---:|---:|---|
| `b1-j1-exposure-20261122T162631Z` | `55e72ee` | `--only-family exposure` | 1 | 1,949 | `SYM-INFO-01` confirmed |
| `b1-j2-mass-20261122T163743Z` | `3bb9362` | `--only-family mass-assignment` | 1 | 2,940 | `SYM-MASS-01` confirmed; no record for `SYM-MASS-N01` or `-N02` |
| `b1-j3-full-20261122T164316Z` | `fd18dd9` | Full | 50 | 222,797 | 16 of 16 positives confirmed, zero control findings |

### Final keyed outcomes (run `b1-j3-full-20261122T164316Z`)

| Case | Outcome |
|---|---|
| `SYM-SQL-01`, `-02`, `SYM-XSS-01`–`-03`, `SYM-CMD-01`, `-02`, `SYM-PATH-01`–`-03`, `SYM-SSRF-01`, `SYM-UPLOAD-01`, `SYM-SSTI-01`, `SYM-DESER-01` | Confirmed |
| `SYM-INFO-01` | Confirmed |
| `SYM-MASS-01` | Confirmed |
| `SYM-SQL-N01`, `SYM-XSS-N05` | Protected |
| `SYM-XSS-N01`, `-N02`, `-N08` | Review |
| `SYM-SQL-N02`–`-N05`, `SYM-XSS-N03`, `-N04`, `-N06`, `-N07`, `-N09`, `SYM-REDIR-N01`, `SYM-PATH-N01`, `-N02`, `SYM-SSRF-N01`, `SYM-LOG-N01`, `SYM-CODE-N01` | No record |
| `SYM-INFO-N01`, `SYM-MASS-N01`, `SYM-MASS-N02` | No record |
| `SYM-XSS-R01`, `-R02`, `SYM-VAL-R01` | Confirmed (assessment-dependent) |

### Follow-ups

- **`throw` in the shared guard engine.** The engine does not treat `throw` as terminating, so a
  rejecting `if (…) { throw …; }` does not make its false branch a dominating condition for the
  injection families. Exposure records add that evidence themselves. Changing the shared engine
  would change the `SYM-PATH-01` request (`BlogController.php:93`) and needs a protocol bump for
  each affected family.
- **Pre-existing fixture with a mass-assignment shape.** `scan/internal/langphp/testdata/symfony/doctrine-storage`
  contains a whole-bag `fill()` loop. It now also yields a `mass_assignment_candidate`, which
  changes that fixture's architecture-baseline row. The owner accepted the row update.
- **AC6 vocabulary grep.** Pre-existing files matched the grep. With the owner's approval the
  identifiers were renamed (`Note::$abstract`, `isStaff`); the grep prints nothing.
