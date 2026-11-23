# Symfony analyzers 5 — plain-PHP recall on the PHP sample

- **Lane contract** [Symfony application-security analyzers](symfony-more-analyzers.md). Its §0,
  §2, §4 and §5 apply here and are not repeated.
- **Branch** `symfony-more-analyzers-5`, the top of the stack, on `symfony-more-analyzers-4`.
- **Depends on** [Branch 2](symfony-more-analyzers-2.md) D-9 and D-10 (the plain-PHP
  authorization claim and its facts) and [Branch 3](symfony-more-analyzers-3.md) D-7 (the
  `sql_credential_column` password basis).
- **Worktree** `symfony-more-analyzers`.
- **Review artifact** One draft PR whose base is `symfony-more-analyzers-4`.
- **Owner request** 2026-11-22: every lane analyzer that should record a defect of the DVWA
  sample does so.

## 1. Capability

The judged DVWA run recorded in [symfony-results.md](../evaluation/symfony-results.md#dvwa-judged-run)
found two defects that lane analyzers own and did not record. This branch closes both. It adds no
analyzer family, no claim kind and no configuration check.

1. **Weak password hashing.** The `sql_credential_column` basis reads a SQL statement that was
   assigned to a variable before the query call.
2. **Missing authorization.** Plain PHP records an object-level candidate for a SQL `UPDATE` or
   `DELETE` whose `WHERE` clause selects the row by a request value.

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

**D-3. The address-guard shape of D-9 is unchanged.** A constant-text write still records only
under an address check. Cases `AZ-22` to `AZ-24` keep their expectations.

## 3. Acceptance criteria

1. **AC1.** `PH-14`: a digest write and a login comparison whose statements are both assigned to
   variables first, with the variable reused for an unrelated statement, record one
   `sql_credential_column` candidate at the digest. `PH-11` is unchanged.
2. **AC2.** `EN-18`: a login `SELECT` held in a variable that compares the credential column
   records no enumeration candidate.
3. **AC3.** `AZ-26` to `AZ-29` of §4 pass. `AZ-22` to `AZ-24` are unchanged.
4. **AC4.** The new cases fail before the change and pass after it.
5. **AC5.** `TestDVWASourceKey`, `TestSymfonySourceKey` and `TestArchitectureBaseline` pass.
   Every baseline row that moves is explained in the PR.
6. **AC6.** An offline DVWA scan records `DVWA-HASH-01` and `DVWA-AUTHZ-01`, and every record of
   the earlier run is still present.
7. **AC7.** No rule, fixture or test names a sample's path, table or user.

## 4. Test cases

| ID | Fixture | Shape | Expectation |
|---|---|---|---|
| `PH-14` | `testdata/account-plain-variable/` | `md5` of a request value, `$sql = "UPDATE … SET <column> = '$digest' …"`, query call on `$sql`; a login file assigns `$sql` twice and compares the column | Candidate at the digest, `sql_credential_column` |
| `EN-18` | same | the login file | No enumeration record |
| `AZ-26` | `testdata/authorization-plain/selected.php` | `UPDATE … WHERE id = <request value>` by concatenation, no guard | Candidate, `object_level`, `request_selected`, subject `table:members`, no guard |
| `AZ-27` | `…/selected_session.php` | the same after a `$_SESSION` test with exit | Candidate with an `authenticated_check` guard |
| `AZ-28` | `…/own.php` | `UPDATE … WHERE id = <session value>`, request values only in `SET` | No record |
| `AZ-29` | `…/removed.php` | `DELETE … WHERE id = <request value> AND owner = <session value>` by interpolation | Candidate with an `ownership_check` guard of form `query_scope` |

## 5. Other lane analyzers on the sample

Source review at the pin, 2026-11-22. None of these needs a change.

| Analyzer | Sample holds | Result |
|---|---|---|
| Account enumeration | Login and brute-force pages answer every failure with one message | Nothing to record |
| Recovery delivery | No mail or reset flow | Nothing to record |
| Mass assignment | No request bag copied onto an object or row | Nothing to record |
| Information exposure | `phpinfo()` and server state on the setup page | Recorded (two Confirmed) |
| Configuration | Root `php.ini` with `allow_url_include` | No existing check applies |

**Not covered, no analyzer:** CSRF, weak session identifiers, brute force, CAPTCHA bypass, CSP
bypass, cryptography exercises and `allow_url_include`. They stay listed as not covered.

## 6. Change log

### 2026-11-22 — Drafted and implemented

Causes established by bisection on scratch copies of `testdata/account-plain` and by source
review of `authorization.go`. Owner go-ahead the same day.
