# DVWA evaluation results

Evaluation record of the [Symfony application-security lane](../specifications/symfony-more-analyzers.md)
on the PHP sample DVWA. The [detection guide](dvwa-detection-guide.md) defines the expected
outcomes at `a1978a2fed195acd093010af6395f86a281537ca`. Scanner hashes that changed in a rebase
are mapped in the [Symfony results](symfony-results.md#scanner-commit-hashes-after-the-rebases).

## Offline review after branch 4

Offline scan of DVWA at `a1978a2fed195acd093010af6395f86a281537ca`, clean before and after,
`b4-offline` (`run-3455210590`). `TestDVWASourceKey` still passes.

| Kind | Candidates |
|---|---:|
| `configuration_candidate` | 0 |
| `ssrf_candidate` with `transport: shell_client` | 0 |

Source review of the files the allow-lists opened: `Dockerfile` copies the tree with
`--chown=www-data` and enables `rewrite`, and it has no cron line, so the scheduled-writable
check correctly records nothing. `vulnerabilities/api/.htaccess` is rewrite rules only.
Root `php.ini` is outside the deploy directories, so it is not read. The command sinks are
`ping`, not `curl` or `wget`. No candidate was wrong, and none was missing for a check the
lists cover.

## Judged run after branch 4

One judged scan of DVWA at `a1978a2fed195acd093010af6395f86a281537ca`, clean before and
after, on the owner's word of 2026-11-23 (UTC): `b4-review-accept` (`run-3336289847`), scanner
`8d97b93`, OpenAI `gpt-6-luna`, default judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`.
189 requests, 192 assessments, 1,659,153 input tokens, zero failures. 57 records were not
sent because their blockers have no model-resolvable question.

249 records: 146 Confirmed, 39 practice, 34 needs-review, 12 needs-evidence, 18 Protected.
Against the published report of 2026-11-20 (`run-2645224166`, 247 records), every one of
the 247 keeps its status. The two new records are `info_exposure_candidate` and both are
Confirmed after source review: `phpinfo.php:8` (`phpinfo()` behind login) and
`dvwa/includes/dvwaPage.inc.php:388` under `setup.php` (the PHP version and server state).

No `configuration_candidate`, `authorization_candidate`, `password_hash_candidate`,
`account_enumeration_candidate`, `recovery_delivery_candidate`, `mass_assignment_candidate`
or shell-client `ssrf_candidate` is recorded. Source review of what DVWA holds in those
classes:

| DVWA defect | Location | Recorded | Why |
|---|---|---|---|
| Passwords stored as MD5 | `login.php:27`, `vulnerabilities/csrf/source/low.php:12`, `vulnerabilities/brute/source/low.php:9` | No | The plain-PHP rule needs a digest written to a column and that column compared at login. Both exist in DVWA, and the rule still records nothing. Cause not yet established |
| Authorisation bypass | `vulnerabilities/authbypass/change_user_details.php:47`, `get_user_data.php` | No | A raw `UPDATE users … where user_id = <request id>` with no ownership or role check below the `impossible` level. The plain-PHP authorization adapter records no subject for it |
| PHP settings | Root `php.ini` (`allow_url_include = on`) | No | The file is outside the listed deployment directories, and `allow_url_include` is not a check |
| CSRF, weak session ids, brute force, CAPTCHA, CSP, cryptography | `vulnerabilities/csrf`, `weak_id`, `brute`, `captcha`, `csp`, `cryptography` | No | No analyzer for these classes in plain PHP |

The first two rows are recall gaps of analyzers this lane delivered. They are follow-up
work and are not fixed in PR #46. This run was the published sample report until the
[judged run after branch 5](#judged-run-after-branch-5) replaced it.

## Offline run after branch 5

[Branch 5](../specifications/symfony-more-analyzers-5.md) closes the first three rows above.
Offline scan (no model call) of DVWA at `a1978a2fed195acd093010af6395f86a281537ca`, clean
before and after, 2026-11-22, run `run-1467553345`, scanner branch `symfony-more-analyzers-5`.

265 records: the 249 of `run-3336289847` with unchanged ids, and 16 new. The 16 are judged in
the [next run](#judged-run-after-branch-5).

| DVWA defect | Cause of the gap | Now recorded |
|---|---|---|
| Passwords stored as MD5 | The plain-PHP rule matched the source text of the query-call argument. DVWA assigns each statement to a variable first, so the text was `$query` or `$insert` and neither the digest write nor the login comparison was read | 12 `password_hash_candidate` records, basis `sql_credential_column`: the `md5` call in `vulnerabilities/csrf/source/low.php:12`, `medium.php:14`, `high.php:39` and `vulnerabilities/captcha/source/low.php:57`, `medium.php:65`, `high.php:27`, each under its `index.php` entry and its own file entry. The compared column is read at `login.php:46` |
| Authorisation bypass | By design: branch 2 D-9 limited plain PHP to an address check over a constant-text write | 1 `authorization_candidate`, `object_level`, subject `table:users`, at `vulnerabilities/authbypass/change_user_details.php:48`; the selecting source is the request body read at `:26`. No guard is recorded: the level-and-user test at `:11` is an unclassified check |
| Remote file inclusion enabled | Root `php.ini` was outside the deployment directories, and `allow_url_include` was not a check | 1 `configuration_candidate`, check `remote_include_enabled`, at `php.ini:5`, joined to the request-reached include at `vulnerabilities/fi/index.php:36`; scope is `Dockerfile:20`, which copies the tree into the document root |
| Session cookie flags | The cookie checks did not read flags set in PHP code | 2 `configuration_candidate` records at `dvwa/includes/dvwaPage.inc.php:72`: `session_cookie_insecure_transport` (`$secure = false` at `:60`) and `session_cookie_script_readable`, value `false on some path` (`$httponly = false` at `:55`, on every level but `impossible`) |

Not recorded, and why:

- `login.php:27` and `vulnerabilities/brute/source/*.php` hash the submitted password to compare
  it. The record is made where a digest is written to the column, not where it is compared.
- The `impossible` level files (`csrf`, `captcha`) write the digest through bound parameters,
  which the static pass does not read.
- `vulnerabilities/authbypass/get_user_data.php` and the `bac` module are reads of ids, names and
  avatars. The read claim is bounded by census fields, and none of these is one (branch 5 D-6).
- A password `UPDATE` whose `WHERE` names the session user (`csrf`, `captcha`) selects no row by
  request and records no authorization candidate.
- `setcookie('security', …)` at `dvwaPage.inc.php:226` and the `dvwaSession` cookie of `weak_id`
  are not the session cookie. A name does not establish that a cookie identifies a session.
- The API module (`vulnerabilities/api/src/`): a password digest in version 1 responses, a
  caller-set `level`, and user endpoints with no token. Its users are objects in memory, so no
  census, storage or entry access anchors a claim (branch 5 D-7). Its command injection is
  recorded.

The Symfony sample at its pin is unchanged by branch 5: an offline scan records the same 84
records as `b4-review-accept`, and `TestSymfonySourceKey` and `TestDVWASourceKey` pass.

Other lane analyzers, by source review: account enumeration (every login failure gives one
message), recovery delivery (no mail flow) and mass assignment (no request bag copied to a row)
have nothing to record. Information exposure keeps its two records. CSRF, weak session
identifiers, brute force, CAPTCHA, CSP, cryptography and client-side-only controls have no
analyzer and stay not covered.

## Judged run after branch 5

One judged scan of DVWA at `a1978a2fed195acd093010af6395f86a281537ca`, clean before and
after, on the owner's word of 2026-11-23 (UTC): `b5-judged` (`run-3384633700`), scanner
`681843f` (PR #47; now `63835df`, same tree), configuration protocol
`configuration-components-v5`, OpenAI `gpt-6-luna`, default judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`.
205 requests, 208 assessments, 1,726,639 input tokens, zero failures. 57 records were not
sent because their blockers have no model-resolvable question. The sample report in
`docs/samples/dvwa/` is this run.

265 records: 158 Confirmed, 39 practice, 34 needs-review, 16 needs-evidence, 18 Protected.
Against `run-3336289847` (249 records), every one of the 249 keeps its status. None moved.

The 16 new records, each source-reviewed:

| Record | Count | Judged | Source review |
|---|---:|---|---|
| `password_hash_candidate` at `vulnerabilities/csrf/source/low.php:12`, `medium.php:14`, `high.php:39` and `vulnerabilities/captcha/source/low.php:57`, `medium.php:65`, `high.php:27`, each under two entries | 12 | Confirmed | Correct. Each is `md5` of the submitted password written to `users.password`, which `login.php:46` compares |
| `authorization_candidate` at `vulnerabilities/authbypass/change_user_details.php:48` | 1 | needs-evidence | Correct finding left in Review. The page has no login check and updates the user id the body names |
| `configuration_candidate` `session_cookie_insecure_transport` at `dvwa/includes/dvwaPage.inc.php:72` | 1 | needs-evidence | Correct finding left in Review. `$secure` is always `false` (`:60`) |
| `configuration_candidate` `session_cookie_script_readable` at `dvwa/includes/dvwaPage.inc.php:72` | 1 | needs-evidence | Correct finding left in Review. `$httponly` is `false` below the `impossible` level (`:55`) |
| `configuration_candidate` `remote_include_enabled` at `php.ini:5` | 1 | needs-evidence | Correct finding left in Review. The file-inclusion module includes a request-chosen file (`vulnerabilities/fi/index.php:36`) |

Answer probabilities of the four records in Review:

| Record | Question | Answer | Probabilities |
|---|---|---|---|
| Authorization | `subject_control` | `request_selected` | 1.00 |
| | `guard_adequacy` | `none` | 1.00 |
| | `access_adequacy` | `unknown` | unknown 0.87, inadequate 0.12, adequate 0.01 |
| Cookie, insecure transport | `setting_effect` | `in_effect` | in_effect 0.74, unknown 0.19, not_in_effect 0.07 |
| | `weakness` | `unknown` | unknown 0.55, weakens 0.44, benign 0.01 |
| | `mitigation` | `none` | 0.98 |
| Cookie, script readable | `setting_effect` | `in_effect` | in_effect 0.77, unknown 0.17, not_in_effect 0.06 |
| | `weakness` | `unknown` | unknown 0.84, weakens 0.14, benign 0.02 |
| | `mitigation` | `none` | 0.98 |
| Remote include | `setting_effect` | `in_effect` | in_effect 0.73, unknown 0.18, not_in_effect 0.09 |
| | `weakness` | `unknown` | unknown 0.88, weakens 0.06, benign 0.06 |
| | `mitigation` | `none` | 0.99 |

What the evidence lacks, as read from the recorded facts of each record. No answer was scripted and no second run
was made.

- **Authorization.** A plain-PHP entry has no access record, so `entry_access` holds only the
  entry's location. The model cannot tell from it that the page calls no login check.
- **Cookies.** The joined fact reads `session_authenticated: unknown`, because plain PHP has no
  entry access model. Nothing in the request states that the application authenticates by this
  session cookie.
- **Remote include.** The joined fact is one line naming the include. It does not carry the
  include's operand or its request source, which the path candidate at the same line does.

**After the run** (not judged; the published sample predates it). On the owner's word the two
configuration gaps were closed in the scanner, with facts only:

- The cookie records now join `session_started` (`dvwa/includes/dvwaPage.inc.php:98`) and
  `session_checked` (`:125`).
- The remote-include record's join now reads: include operand reached by the request value
  `$_GET[ 'page' ]` read at `vulnerabilities/fi/source/low.php:4`.

Offline scan with those facts, scanner `c04c677`: `b5-review-before` (`run-30307840`), DVWA clean
before and after. All 265 record ids are kept. The authorization record is unchanged: what a
plain-PHP entry's access is, is an open question of the
[branch 5 contract](../specifications/symfony-more-analyzers-5.md#6-open-question).

## Offline runs after the PR #47 review

The review resolution makes the variable reads of branch 5 D-1 and D-5 follow the dominating
assignment, and moves the configuration protocol to `configuration-components-v6`, whose
instruction states the four new fact kinds. Offline scans at the resolution, both samples clean
before and after:

| Sample | Before (scanner `c04c677`) | After (scanner `b338151`) | Records | Change |
|---|---|---|---:|---|
| DVWA | `run-30307840` | `run-1929276367` | 265 | Same ids. Only the three configuration records change, in `analysis_components` (protocol `v6`); their values and joined facts are unchanged |
| vuln-symfony | `run-2912914246` | `run-2779026670` | 84 | Same ids. Only the four configuration records change, in `analysis_components` |

`TestDVWASourceKey` and `TestSymfonySourceKey` pass.

## Judged run after the PR #47 review

One judged scan of DVWA at `a1978a2fed195acd093010af6395f86a281537ca`, clean before and
after, on the owner's word of 2026-11-23 (UTC): `b5-v6-judged` (`run-4266343441`), scanner
`d368a68`, configuration protocol `configuration-components-v6`, OpenAI `gpt-6-luna`, default
judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000`. 205 requests, 208 assessments, 1,727,093
input tokens, zero failures. 57 records were not sent because their blockers have no
model-resolvable question. The sample report in `docs/samples/dvwa/` is this run.

265 records: 159 Confirmed, 39 practice, 34 needs-review, 15 needs-evidence, 18 Protected.
Against `run-3384633700`, 264 records keep their status and one moves:

| Record | Before (`v5`) | Now (`v6`) | Source review |
|---|---|---|---|
| `session_cookie_script_readable` at `dvwa/includes/dvwaPage.inc.php:72` | needs-evidence | Confirmed | Correct. `$httponly = false` below the `impossible` level (`:55`); the application starts its session at `:98` and checks `$_SESSION['dvwa']` at `:125` |

Answer probabilities of the three configuration records and the authorization record:

| Record | Question | Answer | Probabilities |
|---|---|---|---|
| Cookie, script readable | `setting_effect` | `in_effect` | in_effect 0.72, unknown 0.20, not_in_effect 0.08 |
| | `weakness` | `weakens` | weakens 0.82, unknown 0.17, benign 0.01 |
| | `mitigation` | `none` | 0.96 |
| Cookie, insecure transport | `setting_effect` | `in_effect` | in_effect 0.74, unknown 0.17, not_in_effect 0.09 |
| | `weakness` | `unknown` | unknown 0.70, weakens 0.26, benign 0.04 |
| | `mitigation` | `none` | 0.99 |
| Remote include | `setting_effect` | `in_effect` | in_effect 0.63, unknown 0.31, not_in_effect 0.06 |
| | `weakness` | `unknown` | unknown 0.50, weakens 0.34, benign 0.16 |
| | `mitigation` | `none` | 0.98 |
| Authorization | `subject_control` | `request_selected` | 1.00 |
| | `guard_adequacy` | `none` | 1.00 |
| | `access_adequacy` | `unknown` | unknown 0.87, inadequate 0.12, adequate 0.01 |

The session facts moved the script-readable cookie: `weakness` went from unknown 0.84 to
weakens 0.82. For the insecure-transport cookie, weakens fell from 0.44 to 0.26, with unknown
at 0.70; no recorded fact states how the site is served.
For the remote include, the request source in the join raised weakens from 0.06 to 0.34. The
authorization record is unchanged; it waits on the contract's open question about plain-PHP
entry access. No answer was scripted and no second run was made.
