# Symfony analyzers 5 — plain-PHP recall on the PHP sample

- **Lane contract** [Symfony application-security analyzers](symfony-more-analyzers.md). Its §0,
  §2, §4 and §5 apply here and are not repeated.
- **Branch** `symfony-more-analyzers-5`, the top of the stack, on `symfony-more-analyzers-4`.
- **Depends on** [Branch 2](symfony-more-analyzers-2.md) D-9 and D-10 (the plain-PHP
  authorization claim and its facts) and [Branch 3](symfony-more-analyzers-3.md) D-7 (the
  `sql_credential_column` password basis).
- **Worktree** `symfony-more-analyzers`.
- **Review artifact** One draft PR, #47. Its base was `symfony-more-analyzers-4` and became
  `stage` when PR #46 merged.
- **Owner request** 2026-11-22: every lane analyzer that should record a defect of the DVWA
  sample does so. Extended the same day: every gap of the sample that an existing analyzer can
  be extended to cover is in scope; no analyzer is added.

## 1. Capability

The judged DVWA run recorded in [symfony-results.md](../evaluation/symfony-results.md#dvwa-judged-run)
found two defects that lane analyzers own and did not record. This branch closes both, and
extends the configuration family to two settings the sample holds. It adds no analyzer family
and no claim kind.

1. **Weak password hashing.** The `sql_credential_column` basis reads a SQL statement that was
   assigned to a variable before the query call.
2. **Missing authorization.** Plain PHP records an object-level candidate for a SQL `UPDATE` or
   `DELETE` whose `WHERE` clause selects the row by a request value.

3. **Remote include.** The configuration family reads a `php.ini` at the scan root and gains
   one check, `remote_include_enabled`.
4. **Session cookie flags set in PHP code.** The two session-cookie checks read
   `session_set_cookie_params` and a `setcookie` of the session cookie.

### 1.1 Causes

| Gap | Cause | Kind |
|---|---|---|
| Password hash | `readStatements` and `plainAccountCall` in `scan/internal/langphp/account_plain.go` matched the source text of the query-call argument. For `$q = "UPDATE …"; mysqli_query($c, $q)` that text is `$q`, so neither the digest write nor the login comparison was read. The sample always assigns the statement first | Defect |
| Authorization | Branch 2 D-9 limited plain PHP to an address check that is the only guard of a constant-text write. `notePlainSQL` in `scan/internal/langphp/authorization.go` returned for a statement built from request values, and `notePlainOperation` returned without an address guard | Scope limit, widened here |

### 1.2 Sample rows

Paths are relative to the DVWA root at pin `a1978a2`.

| ID | Kind | Anchor | Evidence |
|---|---|---|---|
| `DVWA-HASH-01` | `password_hash_candidate`, basis `sql_credential_column` | `vulnerabilities/csrf/source/low.php:12` | `md5` of a request value written to `users.password` (`:16`), which the login `SELECT` compares (`login.php:46`) |
| `DVWA-AUTHZ-01` | `authorization_candidate`, facet `object_level` | `vulnerabilities/authbypass/change_user_details.php:48` | `UPDATE users … where user_id = <request id>` with no ownership check |

| `DVWA-CONF-01` | `configuration_candidate`, check `remote_include_enabled` | `php.ini:5` | `allow_url_include = on`, joined to the `include` operations a request reaches |
| `DVWA-CONF-02` | `configuration_candidate`, check `session_cookie_insecure_transport` | `dvwa/includes/dvwaPage.inc.php:72` | `'secure' => $secure`, assigned `false` at `:60` |
| `DVWA-CONF-03` | `configuration_candidate`, check `session_cookie_script_readable` | `dvwa/includes/dvwaPage.inc.php:72` | `'httponly' => $httponly`, assigned `false` at `:55` on one branch |

**Controls.** A password `UPDATE` whose `WHERE` names the session user
(`vulnerabilities/csrf/source/low.php:16`) records no `authorization_candidate`. The login files
record no `account_enumeration_candidate`.

## 2. Decisions

**D-1. A SQL statement held in a variable.** When the SQL argument of a modeled query call is a
variable, the static pass reads the text of the nearest preceding assignment to that variable in
the same function or file scope. The right side must be a string, an interpolated string, a
concatenation, or one of those in parentheses. Anything else leaves the statement unread, as
before. *Why by position:* one file commonly reuses `$query` for several statements. *Bound:* an
assignment in another branch, function or file is not followed, and `.=` is not followed.

**D-2. A request-selected row in plain PHP.** This amends
[Branch 2 D-9](symfony-more-analyzers-2.md). A plain-PHP `authorization_candidate` with facet
`object_level` is recorded when all hold:

- The statement of a modeled query call is an `UPDATE` or a `DELETE` with a `WHERE` clause.
- The statement text is built by concatenation or interpolation, and a part compared by `=` to a
  column in the `WHERE` clause carries a request dependency that did not pass through session
  storage.

The record's subject is `table:<name>` with provenance `request_selected`, and its selecting
sources are the request dependencies of that part. Guards are recorded as D-5 of branch 2
classifies them; none are required and none suppress the record. When another `WHERE` part reads
`$_SESSION`, the record carries an `ownership_check` guard of form `query_scope`. The scanner
does not decide whether a guard is enough.

*Why this is not a guess about what a record is:* the `WHERE` clause states which row changes,
and the dependency path states that the request chose it. *Not covered:* `SELECT` (plain PHP has
no census to say which columns are sensitive), `INSERT`, statements with bound parameters, and
a `WHERE` value compared by anything other than `=`.

*Consequence:* a page that is anonymous by design and updates the row a request names, such as
a recovery page that stores a token for a submitted address, is recorded too. The scanner does
not tell it from a defect; the model judges it. The fixture `testdata/account-plain/forgot.php`
gains one such record.

**D-3. The address-guard shape of D-9 is unchanged.** A constant-text write still records only
under an address check. Cases `AZ-22` to `AZ-24` keep their expectations.

**D-4. A `php.ini` at the scan root, and `remote_include_enabled`.** This amends
[branch 4 D-1 and D-4](symfony-more-analyzers-4.md#5-decisions).

- The `Deploy` list adds `php.ini` at the scan root. Its scope evidence is the `COPY` that ships
  it when a Dockerfile copies it with its directory, else the file itself.
- Check `remote_include_enabled` (CWE-98) is recorded when a read `php.ini` sets
  `allow_url_include` to `On`, `1`, `true` or `yes`. Joined facts: up to eight `include` or
  `require` operations whose operand a request reaches (the path family's `php-include-v1`
  candidates), sorted by location, or one fact stating that none is recorded.
- No record for `Off`, `0`, an absent directive, or `allow_url_fopen`, which is PHP's default.

*Why the scan root only:* a `php.ini` in an arbitrary directory is as likely a sample or a
vendored file as a deployed one. Whether PHP loads a `php.ini` outside its configuration path
depends on the server interface, so the model answers `setting_effect` from the recorded scope.

**D-5. Session cookie flags set in PHP code.** This amends
[branch 4 D-4](symfony-more-analyzers-4.md#5-decisions) and removes "cookie attributes set in PHP
code" from branch 4 §4's exclusions for the session cookie only. Checks
`session_cookie_script_readable` and `session_cookie_insecure_transport` are also recorded at:

| Call | Flag position |
|---|---|
| `session_set_cookie_params(array)` | Elements `httponly` and `secure` |
| `session_set_cookie_params(lifetime, path, domain, secure, httponly)` | Arguments 4 and 5 |
| `setcookie` or `setrawcookie` whose name argument is a `session_name()` call | Arguments 6 and 7, or elements `secure` and `httponly` of an options array in argument 3 |

A flag is recorded when its value is the literal `false` or `0`, or a variable that an
assignment earlier in the same function or file scope sets to one of those. A variable with
both a false and a true assignment is recorded with value `false on some path`, and each false
assignment is a joined `value_assignment` fact. An absent flag is not recorded: its value comes
from `php.ini`, which has its own row. A `setcookie` of any other cookie is not recorded: that a
cookie identifies a session is not established by its name.

Joined facts are those of the existing checks. In a project with no access model the session
fact reads `session_authenticated: unknown`, because plain PHP has no entry access to answer it.
The literal `ini_set` form of branch 4 D-4 is recorded for plain PHP as well as Symfony.

**D-5b. Evidence added after the first judged run.** That run left the three configuration
records in Review with `weakness` unknown. Two facts were missing, and both are now recorded.
Neither states an answer.

- A plain-PHP cookie record joins `session_started` (the first `session_start()` call) and
  `session_checked` (the first condition that reads `$_SESSION`), in file order. Without them
  nothing in the record says the application uses the session cookie.
- A `request_include` fact names the request value and where it is read, taken from the path
  candidate's first dependency.

The authorization record needs a decision, not a fact: see §6.

**D-5a. The configuration protocol is unchanged.** `configuration-components-v5` and its
instruction are not edited, so every existing configuration request is byte-identical and the
judged Symfony results stand. The two new fact kinds, `request_include` and `value_assignment`,
state what they are in their own text. Only the new check has a new effect statement.
*Reviewer's call:* naming the two kinds in the instruction would be clearer and needs `v6`.

**D-6. Reads stay out of the plain-PHP authorization claim.** Decided, not built. The existing
read claim (branch 2 D-5, facet `data_exposure`) is bounded by the census: the response must
carry a `credential`, `login_identifier` or `role_source` field. The sample's reads
(`vulnerabilities/authbypass/get_user_data.php:15`, `vulnerabilities/bac/source/*.php`) return
ids, names and avatars, which no census role covers. Recording every column of an account table
would report each public profile lookup, including the sample's own SQL-injection pages, and
whether a name is private is not a fact the source states. That is a new rule, not an extension.

**D-7. The API module needs no change to an existing analyzer.** Source review of
`vulnerabilities/api/src/` at the pin:

| Defect | Location | Why no existing analyzer records it |
|---|---|---|
| Version 1 responses carry the password digest | `User.php:39`–`46`, `UserController.php:91`, `:115` | The users are objects built in memory. No census and no storage establishes `password` as a credential; a property name establishes nothing (lane rule) |
| A caller sets a user's `level` | `UserController.php:212`–`214` | Each field is copied by name. Mass assignment is a request bag copied without a field list, and this is its negative control. A function-level claim needs a `role_source` census field |
| User endpoints need no token, order endpoints do | `UserController.php`, `OrderController.php:24` | No stored write and no entry access model: there is no protected operation to anchor a claim |
| Hard-coded login and token secrets | `LoginController.php:60`, `Login.php` | Committed secrets are outside the lane |

The command injection in `HealthController.php:88` is already recorded.

## 3. Acceptance criteria

1. **AC1.** `PH-14`: a digest write and a login comparison whose statements are both assigned to
   variables first, with the variable reused for an unrelated statement, record one
   `sql_credential_column` candidate at the digest. `PH-11` is unchanged.
2. **AC2.** `EN-18`: a login `SELECT` held in a variable that compares the credential column
   records no enumeration candidate.
3. **AC3.** `AZ-26` to `AZ-30` of §4 pass. `AZ-22` to `AZ-24` are unchanged.
4. **AC4.** The new cases fail before the change and pass after it.
5. **AC5.** `TestDVWASourceKey`, `TestSymfonySourceKey` and `TestArchitectureBaseline` pass.
   Every baseline row that moves is explained in the PR.
6. **AC6.** An offline DVWA scan records `DVWA-HASH-01` and `DVWA-AUTHZ-01`, and every record of
   the earlier run is still present.
7. **AC7.** No rule, fixture or test names a sample's path, table or user.
8. **AC8.** Cases `DP-17` to `DP-19` and `SC-01` to `SC-07` of §4 pass, each with a hardened
   sibling that records nothing. An offline DVWA scan records `DVWA-CONF-01` to `DVWA-CONF-03`.

## 4. Test cases

| ID | Fixture | Shape | Expectation |
|---|---|---|---|
| `PH-14` | `testdata/account-plain-variable/` | `md5` of a request value, `$sql = "UPDATE … SET <column> = '$digest' …"`, query call on `$sql`; a login file assigns `$sql` twice and compares the column | Candidate at the digest, `sql_credential_column` |
| `EN-18` | same | the login file | No enumeration record |
| `AZ-26` | `testdata/authorization-plain/selected.php` | `UPDATE … WHERE id = <request value>` by concatenation, no guard | Candidate, `object_level`, `request_selected`, subject `table:members`, no guard |
| `AZ-27` | `…/selected_signed.php` | the same after a `$_SESSION` test with exit | Candidate with an `authenticated_check` guard |
| `AZ-28` | `…/own.php` | `UPDATE … WHERE id = <session value>`, request values only in `SET` | No record |
| `AZ-29` | `…/removed.php` | `DELETE … WHERE id = <request value> AND owner = <session value>` by interpolation | Candidate with an `ownership_check` guard of form `query_scope` |
| `AZ-30` | `testdata/account-plain/forgot.php` | `UPDATE … SET token = <generated> WHERE mail = <request value>` | Candidate (D-2 consequence), no guard |

Configuration cases use the overlay harness of `configuration_test.go` on
`testdata/configuration/`.

| ID | Shape | Expectation |
|---|---|---|
| `DP-17` | Root `php.ini` with `allow_url_include = On`; a page includes a request-chosen file | `remote_include_enabled`, joined to the include operation, scope the `COPY` that ships the file |
| `DP-18` | The same with no include of a request value | Recorded, joined fact states none |
| `DP-19` | `allow_url_include = Off`; only `allow_url_fopen = On`; a `php.ini` in an unlisted directory | No record |
| `SC-01` | `session_set_cookie_params(['secure' => false, 'httponly' => false])` | Both checks at the call |
| `SC-02` | `'httponly' => $flag` with `$flag = true` on one branch and `false` on the other | `session_cookie_script_readable`, value `false on some path`, joined `value_assignment` |
| `SC-03` | Positional form with `false, false` | Both checks |
| `SC-04` | `setcookie(session_name(), $id, 0, '/', '', false, false)` | Both checks |
| `SC-05` | Flags `true`; flags absent; a variable only ever assigned `true` | No record |
| `SC-06` | `setcookie('theme', $v, 0, '/', '', false, false)` | No record |
| `SC-07` | Plain PHP `ini_set('session.cookie_httponly', '0')` | `session_cookie_script_readable` |

## 5. Other lane analyzers on the sample

Source review at the pin, 2026-11-22. None of these needs a change.

| Analyzer | Sample holds | Result |
|---|---|---|
| Account enumeration | Login and brute-force pages answer every failure with one message | Nothing to record |
| Recovery delivery | No mail or reset flow | Nothing to record |
| Mass assignment | No request bag copied onto an object or row | Nothing to record |
| Information exposure | `phpinfo()` and server state on the setup page | Recorded (two Confirmed) |
| Configuration | Root `php.ini` with `allow_url_include`; session cookie flags set in code | Extended by D-4 and D-5 |

**Not covered, no analyzer:** CSRF, weak session identifiers (including the `dvwaSession`
cookie), brute force, CAPTCHA bypass, CSP bypass, cryptography exercises, client-side-only
controls, reads of other users' records (D-6) and the API module's defects (D-7).

## 6. Open question

**OQ-1. What a plain-PHP entry's access is.** The judged run answered `access_adequacy` unknown
for the request-selected write, because a plain-PHP entry carries no access record. Two facts
could be recorded, and each changes results beyond the sample:

- `authentication: none` when the entry's flow reads no `$_SESSION` value before the operation.
  This is sound for a page with no session at all. It would also turn the recovery-page record
  of D-2 (`AZ-30`) from Review into Confirmed, which is wrong for a page that is anonymous by
  design. It needs D-2 narrowed first, for example to writes whose `SET` also takes a request
  value.
- The session-dependent early exit that dominates the operation, which is dropped today as
  unclassified. The sample's page has one that applies at one security level only. Recording it
  keeps the record in Review under branch 2's rule that an unclassified guard blocks, unless
  that rule changes for plain PHP.

Neither is built. The owner decides.

## 7. Change log

### 2026-11-22 — Drafted and implemented

Causes established by bisection on scratch copies of `testdata/account-plain` and by source
review of `authorization.go`. Owner go-ahead the same day. The owner then widened the branch to
every extension of an existing analyzer: D-4 and D-5 were added, and D-6 and D-7 record what
was reviewed and not built. After the judged run, D-5b added two facts to the configuration
records, and §6 records the access question the authorization record raised.
