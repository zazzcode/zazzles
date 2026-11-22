# vuln-symfony detection guide

Source reviewed at `086f81f941501bd1170b249e01107ba99beb2962` in the [pinned sample](https://github.com/zazzcode/vuln-symfony/tree/086f81f941501bd1170b249e01107ba99beb2962). Paths are relative to the sample root. See the [Symfony contract](../specifications/php-symfony-support.md) and [measured results](symfony-results.md).

## Expected route entries

| Entry | Controller action | Attribute line |
|---|---|---:|
| `ANY /admin` | `AdminController::index` | 17 |
| `POST /user/role/{user}` | `AdminController::changeRole` | 28 |
| `ANY /admin/delete/{user}` | `AdminController::deleteUser` | 39 |
| `ANY /admin/create` | `AdminController::createUser` | 62 |
| `ANY /` | `BlogController::index` | 20 |
| `ANY /post/{post}` | `BlogController::post` | 32 |
| `POST /post/{post}/comment` | `BlogController::comment` | 45 |
| `GET /search` | `BlogController::search` | 67 |
| `ANY /legal` | `BlogController::legal` | 79 |
| `GET /legal/content` | `BlogController::legalContent` | 88 |
| `ANY /local/` | `LocalController::list` | 25 |
| `ANY /local/users` | `LocalController::users` | 41 |
| `ANY /local/promote/{user}` | `LocalController::promote` | 66 |
| `ANY /local/posts` | `LocalController::posts` | 84 |
| `GET /login` | `LoginController::index` | 18 |
| `POST /login` | `LoginController::index` | 18 |
| `GET /logout` | `LoginController::logout` | 49 |
| `GET /register` | `LoginController::register` | 58 |
| `POST /register` | `LoginController::register` | 58 |
| `ANY /reset` | `PasswordResetController::index` | 18 |
| `ANY /reset/{email}/{token}` | `PasswordResetController::resetPassword` | 53 |
| `ANY /user` | `UserController::index` | 17 |
| `POST /user/password/{user}` | `UserController::changePassword` | 30 |
| `POST /user/email/{user}` | `UserController::changeEmail` | 52 |
| `POST /user/avatar/{user}` | `UserController::uploadAvatar` | 72 |
| `POST /user/avatar/url/{user}` | `UserController::getAvatarFromUrl` | 111 |
| `GET /user/avatar/delete/{user}` | `UserController::deleteAvatar` | 151 |
| `GET /user/avatar/resize/{user}` | `UserController::resizeAvatar` | 177 |
| `POST /user/about/` | `UserController::about` | 206 |
| `GET /user/edit/` | `UserController::editForm` | 221 |
| `POST /user/edit/` | `UserController::edit` | 232 |

## Answer key

**Required positives.** Each must be a witnessed candidate offline (AC13) and a Confirmed finding in
the judged scan (AC14).

| ID | Kind | Entry and source | Sink anchor | Why it is a defect |
|---|---|---|---|---|
| `SYM-SQL-01` | `sql_query_candidate` | `GET /search`, `s` at `src/Controller/BlogController.php:70` | `src/Repository/PostRepository.php:67` (`executeQuery`), query text built at `:64` | Request text concatenated into SQL, run by DBAL `prepare` with an empty parameter array |
| `SYM-SQL-02` | `sql_query_candidate` | `POST /login`, `email` at `src/Controller/LoginController.php:22` | `src/Repository/UserRepository.php:77`, query text at `:74` | Request text interpolated into SQL. The `password` operand is an `md5` hash and carries no content path |
| `SYM-XSS-01` | `xss_candidate` | `GET /search`, `s` | `templates/blog/index.html.twig:11` | `{{ search \| raw }}` |
| `SYM-XSS-02` | `xss_candidate`, stored | Written by `POST /post/{post}/comment`, `comment` at `BlogController.php:56` | `templates/blog/post.html.twig:40`, read on `ANY /post/{post}` | `Comment.content` (`php-sql:comment.content`) rendered by `{{ comment.content \| raw }}` |
| `SYM-XSS-03` † | `xss_candidate`, stored | Written by `POST /user/about/`, `about` at `src/Controller/UserController.php:213` | `templates/blog/post.html.twig:37`, read on `ANY /post/{post}` | `User.aboutMe` (`php-sql:user.about_me`) is the template source of an `is_safe` function, so its literal text is emitted unescaped |
| `SYM-CMD-01` | `command_execution_candidate` | `ANY /` and `ANY /post/{post}`, `Referer` header at `src/Services/Analytics.php:25` | `src/Services/Analytics.php:32` | `shell_exec('curl … ' . $referer)`, guarded only by `FILTER_VALIDATE_URL` (`:40`), behind the `trackingEnabled` configuration flag |
| `SYM-CMD-02` | `command_execution_candidate`, stored | `GET /user/avatar/resize/{user}`, `User.avatar` read at `UserController.php:185` | `UserController.php:195` | `php-sql:user.avatar` reaches `shell_exec`. Request writers: the client extension at `:98`–`101` and the wildcard write at `:239` |
| `SYM-PATH-01` | `path_traversal_candidate` | `GET /legal/content`, `p` at `BlogController.php:91` | `BlogController.php:95` | `file_get_contents` of a concatenated path. `is_dir` and `file_exists` do not contain it |
| `SYM-PATH-02` † | `path_traversal_candidate`, stored | `GET /user/avatar/delete/{user}`, `User.avatar` | `UserController.php:159` | `unlink` of a path built from `php-sql:user.avatar`, which the wildcard write at `:239` sets to any text |
| `SYM-PATH-03` † | `path_traversal_candidate` | `POST /user/avatar/url/{user}`, `url` at `UserController.php:123` | `src/Services/Avatar.php:18` | The whole `file_get_contents` operand is request text, so a local path or `file://` URL is read and saved to a served directory |
| `SYM-SSRF-01` | `ssrf_candidate` | Same entry and source | `src/Services/Avatar.php:18` | The same operand is a request-controlled URL |
| `SYM-UPLOAD-01` | `file_upload_candidate` | `POST /user/avatar/{user}`, uploaded file at `UserController.php:85` | `UserController.php:99` | Stored under `public/uploads/avatars` with the client's extension (`:98`) |
| `SYM-SSTI-01` | `template_injection_candidate`, stored | Written by `POST /user/about/`, read on `ANY /post/{post}` through `templates/blog/post.html.twig:37` | `src/Twig/TemplateFromStringExtension.php:22` | `User.aboutMe` compiled by `createTemplate` |
| `SYM-DESER-01` † | `deserialization_candidate` | Every entry that renders a template; checked under `GET /search`. `USER_PREF` cookie at `src/Services/UserPref.php:30` | `src/Services/UserPref.php:36` | `unserialize` of the cookie after `urldecode` and `base64_decode`. The service is a Twig global |

**Required controls.** None may be a finding in the judged scan. The offline expectation uses the
vocabulary of `cases.json` (`no_record`, `bound`, `not_raw`, `not_decisive`).

| ID | Location | Offline expectation | Why it is safe for its claim |
|---|---|---|---|
| `SYM-SQL-N01`–`N03` | `src/Repository/CommentRepository.php:52`–`57`, `:62`–`67`; `PostRepository.php:72`–`77` | `bound` | QueryBuilder text is constant; values bind through `setParameter` |
| `SYM-SQL-N04` | `LoginController.php:32`, `:76`, `:83`; `src/Controller/PasswordResetController.php:34`, `:64`; `src/Controller/AdminController.php:79`, `:86` | `no_record` | `findBy` and `findOneBy` criteria arrays bind their values |
| `SYM-SQL-N05` | `PostRepository.php:53`–`56` | `no_record` | Literal QueryBuilder text, `orderBy` with literal arguments, and no bound value |
| `SYM-XSS-N01` | `templates/blog/post.html.twig:12`, `:13`, `:35`; `templates/user/index.html.twig:8`–`14`, `:28` | `not_raw` | Autoescaped `{{ }}` in HTML text and in a `<textarea>` |
| `SYM-XSS-N02` | `templates/user/edit.html.twig:14`, `:16` | `not_raw` | Autoescaped in a quoted attribute |
| `SYM-XSS-N03` | `templates/blog/post.html.twig:20`, `{{ post.content \| nl2br }}` | `not_raw` | `nl2br` escapes its input first |
| `SYM-XSS-N04` | `templates/blog/index.html.twig:32`, `{{ post.content \| nl2br \| u.truncate(150, '...') }}` | `not_raw` | The outermost operation is a method call, which is not safe-marked, so autoescape applies to the result |
| `SYM-XSS-N05` | `public/js/script.js:6` | Protected today | `innerText` |
| `SYM-XSS-N06` | `templates/commons/messages.html.twig:6`, `:13`; `templates/user/index.html.twig:45` | `not_decisive` | Every `addFlash` message in the application is a literal |
| `SYM-XSS-N07` | `templates/blog/index.html.twig:28`; `templates/blog/post.html.twig:17`, `{{ post.img }}` in `src` | `not_decisive` | `Post.img` has no request writer. Its only writer is a console command |
| `SYM-XSS-N08` | `templates/blog/post.html.twig:33`; `templates/user/index.html.twig:64` | `not_raw` | `asset('uploads/avatars/' ~ …)`: a constant path prefix fixes the scheme, and the attribute is quoted and escaped |
| `SYM-XSS-N09` | Every `{{ path(…) }}` in an `href` or `action` | `no_record` | A generated internal URL whose parameters are percent-encoded |
| `SYM-REDIR-N01` | Every `redirectToRoute(…)` call (39 calls in `src/Controller/`) | `no_record` | The target is a route name, not a request URL |
| `SYM-PATH-N01` | `UserController.php:139`, `file_put_contents` | `not_decisive` | The path is a configured directory and a server-generated name; only the content is external |
| `SYM-SSRF-N01` | `BlogController.php:95`, `file_get_contents` | `no_record` | The operand starts with a literal local directory, so it cannot name a URL scheme |
| `SYM-PATH-N02` | `UserController.php:94`–`95`, `file_exists` and `mkdir` on the configured directory | `no_record` | No request or stored value reaches the operand |
| `SYM-LOG-N01` | `src/Services/Analytics.php:35`, `src/Services/Avatar.php:20` | `no_record` | The logged values are a status code and an exception message, not a sensitive data class |
| `SYM-CODE-N01` | Whole sample | `no_record` | No `eval`, string `assert` or `create_function` |

**Assessment-dependent rows.** A candidate is required offline (`cases.json` expectation
`present`). The judge decides the status, and the row counts neither as a required positive nor as
a control.

| ID | Location | Note |
|---|---|---|
| `SYM-XSS-R01` | `src/Controller/LocalController.php:63` | `new Response($list)` with stored `User.username` and `User.email`, default `text/html`. The action is guarded by a client-address check (`:22`) |
| `SYM-XSS-R02` | `BlogController.php:95` | `new Response(file_get_contents(…))`: the request value selects the file whose content is the response. The existing rule treats path control as content control |
| `SYM-VAL-R01` | The `automatic-php-query` check on the `SYM-SQL-01` and `SYM-SQL-02` candidates | Not a separate candidate. The check lists field `s`, and `email`. No server validation exists for either |

## Application-security lane rows

The [Symfony application-security lane](../specifications/symfony-more-analyzers.md) closes the
README entries that PR #39 left outside Code Scan. Its rows are frozen here and in
[`cases.json`](recall-gap-inventory/cases.json) by the branch that owns them, and are never
relabeled.

### README entries

| README entry | Row | Branch |
|---|---|---:|
| 1 SSRF half of the `Referer` command | `SYM-SSRF-02` | 4 |
| 2, 3, 4, 5, 11, 12, 14, 15 | Found at the baseline (the 14 required positives above) | — |
| 6 User enumeration | `SYM-ENUM-01` | 3 |
| 7, 9, 10, 13 Missing right control | `SYM-AUTHZ-01` to `-04` | 2 |
| 8 Missing right control on `/user/delete/{user}` | Not present in source at the pin. The delete action is routed under `^/admin` and is control `SYM-AUTHZ-N03` | 2 |
| 16 Sensitive endpoint for SSRF | `SYM-LOCAL-01`, `SYM-LOCAL-02` | 2 |
| 17 `phpinfo` | `SYM-INFO-01` | 1 |
| 18 Directory listing | `SYM-CONF-01` | 4 |
| 19 Mass assignment on `/user/edit/` | `SYM-MASS-01` | 1 |
| 20 Recovery token to request-chosen recipients | `SYM-RESET-01` | 3 |
| 21 Cron privilege escalation | `SYM-CONF-02` | 4 |
| Unlisted, source-reviewed | `SYM-ENUM-02`, `SYM-HASH-01` (3), `SYM-CONF-03`, `SYM-CONF-04` (4) | 3, 4 |

### Branch 1 rows

Owned by [branch 1](../specifications/symfony-more-analyzers-1.md#11-sample-rows-owned-by-this-branch).
`SYM-INFO-01` and `SYM-MASS-01` are required positives with expected status
`confirmed_vulnerability`.

| ID | Kind | Entry | Anchor | Offline expectation | Source evidence |
|---|---|---|---|---|---|
| `SYM-INFO-01` | `info_exposure_candidate` | `FILE /public/info.php` | `public/info.php:2` | Positive. The kind has no request source, so the candidate is met at its anchor with no completeness blocker | `echo phpinfo();` is the whole file, served from the document root with no condition on the path |
| `SYM-INFO-N01` | `info_exposure_candidate` | Whole sample | — | Exactly one candidate of this kind in the report (`only_lines` with `public/info.php:2`, at most one use) | No other `phpinfo`, `debug_print_backtrace`, environment dump or `dump()` call exists in `src/`, `public/` or `templates/` |
| `SYM-MASS-01` | `mass_assignment_candidate` | `POST /user/edit/` | Sink `src/Entity/User.php:59`, source `src/Controller/UserController.php:239` | Positive, with census roles on the written fields | `$user->fromArray($request->request->all())` passes the whole form bag to a loop that writes `$this->$key = $value`. `isAdmin` (`:48`) is read by the `#[ORM\PreUpdate]` and `#[ORM\PrePersist]` callbacks (`:63`–`73`) that write `roles`, which `getRoles()` (`:105`–`112`) returns. `password` (`:30`) is the credential and `email` (`:21`) is the provider's `property` in `config/packages/security.yaml` |
| `SYM-MASS-N01` | `mass_assignment_candidate` | `ANY /admin/create`, `POST /register` | `src/Controller/AdminController.php:99`–`105`, `src/Controller/LoginController.php:102`–`106` | `no_record` | Each field is set by a named setter from a named request field |
| `SYM-MASS-N02` | `mass_assignment_candidate` | `POST /user/about/` | `src/Controller/UserController.php:213`–`215` | `no_record` | One named field through one named setter |

### Branch 2 rows

Owned by [branch 2](../specifications/symfony-more-analyzers-2.md#11-sample-rows-owned-by-this-branch).
`security.yaml` requires `ROLE_ADMIN` for `^/admin` and `ROLE_USER` for `^/user`
(`config/packages/security.yaml:35`–`36`). The five positives have expected status
`confirmed_vulnerability`. `guarded` means a candidate at the anchor carries the stated guard,
or the entry's recorded roles.

| ID | Kind | Entry | Anchor | Offline expectation | Source evidence |
|---|---|---|---|---|---|
| `SYM-AUTHZ-01` | `authorization_candidate` | `POST /user/role/{user}` | `src/Controller/AdminController.php:32` | Positive. Writes `role_source` field `php-sql:user.is_admin` of a path-selected record. Entry roles `ROLE_USER`. No guard. Peer entries that write the same field require `ROLE_ADMIN` | `setAdmin` of the entity argument bound from `{user}` |
| `SYM-AUTHZ-02` | `authorization_candidate` | `POST /user/password/{user}` | `src/Controller/UserController.php:41` | Positive. Writes the `credential` field of a path-selected record. Entry roles `ROLE_USER`. No ownership guard | `setPassword` of the `{user}` entity |
| `SYM-AUTHZ-03` | `authorization_candidate` | `POST /user/email/{user}` | `src/Controller/UserController.php:62` | Positive. Writes the `login_identifier` field of a path-selected record. No ownership guard | `setEmail` of the `{user}` entity |
| `SYM-AUTHZ-04` | `authorization_candidate` | `GET /user/avatar/delete/{user}` | `src/Controller/UserController.php:159` and `:161` | Positive. Deletes a file named by a path-selected record's field and clears the field. No ownership guard. State change on `GET` (`method_safe: yes`) | `unlink` of `getAvatar()` and `setAvatar(null)` |
| `SYM-LOCAL-01` | `authorization_candidate` | `ANY /local/promote/{user}` | `src/Controller/LocalController.php:77` | Positive. Writes `role_source` of a path-selected record. Entry authentication `none`. The only guard is `address_check` at `:22` against `127.0.0.1` and `::1` | `setAdmin(true)` after `isLocalRequest` |
| `SYM-AUTHZ-N01` | `authorization_candidate` | `POST /user/avatar/{user}`, `POST /user/avatar/url/{user}` | Writes `:99`–`102` and `:139`–`142` | `guarded`: a candidate with an `ownership_check` at `:75` and `:118` | `if ($user !== $this->getUser())` returns before the write |
| `SYM-AUTHZ-N02` | `authorization_candidate` | `ANY /user`, `POST /user/about/`, `GET /user/edit/`, `POST /user/edit/` | `UserController.php:17`, `:214`, `:221`, `:239` | `no_record` | The record is the session user (`#[CurrentUser]`), not a request-selected one |
| `SYM-AUTHZ-N03` | `authorization_candidate` | `ANY /admin`, `ANY /admin/delete/{user}`, `ANY /admin/create` | `templates/admin/index.html.twig:44`, `AdminController.php:53`, `:101` | `guarded`: entry roles `ROLE_ADMIN` | `^/admin` requires `ROLE_ADMIN`. README entry 8 is this delete, routed at `/admin/delete/{user}` |
| `SYM-AUTHZ-N04` | `authorization_candidate` | `POST /post/{post}/comment` | `src/Controller/BlogController.php:53`–`58` | `no_record` | A new record is created as the session user. No existing record is changed |
| `SYM-AUTHZ-N05` | `authorization_candidate` | `ANY /reset/{email}/{token}` | `src/Controller/PasswordResetController.php:78`–`80` | `guarded`: a `secret_check` at `:65` | The stored reset value is compared with the path token before the write |
| `SYM-AUTHZ-N06` | `authorization_candidate` | `BlogController::post`, `index`, `search` | — | `no_record` | Public reads of non-account fields |
| `SYM-AUTHZ-N07` | `authorization_candidate` | `GET /user/avatar/resize/{user}` | `UserController.php:177`–`199` | `no_record` | No stored change and no file write or delete. Its command claim is `SYM-CMD-02` |
| `SYM-LOCAL-N01` | `authorization_candidate` | `ANY /local/` | `LocalController.php:25`–`39` | `no_record` | Literal text only |
| `SYM-LOCAL-N02` | `authorization_candidate` | `ANY /local/posts` | `LocalController.php:84`–`102` | `no_record` | No census field is returned |
| `SYM-LOCAL-02` | `authorization_candidate` | `ANY /local/users` | `LocalController.php:51`–`63` | `present` | Returns `login_identifier` and `role_source` of every account behind the address guard only |
| `SYM-AUTHZ-R01` | `authorization_candidate` | `ANY /reset` | `src/Services/Mail.php:38` | `present` | An unauthenticated entry writes a field of an account selected by a request value. The defect in this flow is branch 3's `SYM-RESET-01` |

### Branch 3 rows

Owned by [branch 3](../specifications/symfony-more-analyzers-3.md#11-sample-rows-owned-by-this-branch).
The four positives have expected status `confirmed_vulnerability`. `SYM-ENUM-01` and
`SYM-HASH-01` list several anchors, and every anchor must have a candidate (`each_anchor`).
`password_hash_candidate` has no request source, so a candidate at its anchor with no
completeness blocker meets it.

| ID | Kind | Entry | Anchor | Offline expectation | Source evidence |
|---|---|---|---|---|---|
| `SYM-ENUM-01` | `account_enumeration_candidate` | `POST /register` | Lookups `src/Controller/LoginController.php:76` and `:83` | Positive, one candidate per lookup, entry access `none`, differing response lists | `findOneBy` on the user class by request `email`, then by request `username`. The found branch flashes a distinct literal (`:78`, `:85`) and redirects; the other continues to create the account |
| `SYM-ENUM-02` | `account_enumeration_candidate` | `ANY /reset` | Lookup `src/Controller/PasswordResetController.php:34` | Positive | `findBy` by request `email`. The not-found branch flashes `:36` and redirects; the found branch flashes `:43` and renders |
| `SYM-RESET-01` | `recovery_delivery_candidate` | `ANY /reset` | Send `src/Services/Mail.php:35`, source `PasswordResetController.php:28` | Positive. Secret `:40` (`csprng`), `recipient_validated: partial`, `recipient_count: request_controlled`, use sites `:34` and `Mail.php:23`, stored field `php-sql:user.reset` with role `recovery_secret` | A `random_bytes` secret reaches a mail link (`Mail.php:24`, `:33`) to each element of the request array (`:31`) and the stored field of each matching account (`:38`). Only element `[0]` was looked up (`:34`) |
| `SYM-HASH-01` | `password_hash_candidate` | Several | `src/Security/Hasher/Md5Hasher.php:15`; `src/Controller/UserController.php:41`, `LoginController.php:106`, `src/Controller/AdminController.php:105`, `PasswordResetController.php:78` | Positive at each anchor, `algorithm: md5`, `salted: no` | `md5` is the return of a `PasswordHasherInterface::hash` implementation that `config/packages/security.yaml:5` selects (`hasher_class`), and `md5` of a request value is written to the `credential` field at four sites (`credential_field`) |
| `SYM-ENUM-N01` | `account_enumeration_candidate` | `POST /login` | `LoginController.php:21`–`46` | `no_record` | The only finder (`:32`) takes a database value, not a request value. Every failure path uses one literal |
| `SYM-ENUM-N02` | `account_enumeration_candidate` | `ANY /admin/create` | `AdminController.php:79`–`90` | `no_record` | The same lookup-and-message shape under entry access `required` |
| `SYM-RESET-N01` | `recovery_delivery_candidate` | `ANY /reset/{email}/{token}` | `PasswordResetController.php:63`–`84` | `no_record` | No secret is generated or mailed. Its authorization control is `SYM-AUTHZ-N05` |
| `SYM-HASH-N01` | `password_hash_candidate` | `POST /user/avatar/{user}`, `POST /user/avatar/url/{user}` | `UserController.php:98`, `:138` | `no_record` | `md5(uniqid())` names a file. The input is not a password and the output is not a credential |

**Not covered by any analyzer.** Recorded in the guide so a clean report is not read as a pass.
Mass assignment, `phpinfo()`, and missing authorization are covered by branches 1 and 2 of the
lane (rows above). The wildcard write stays modeled as a storage writer (D-15) as well.

- User enumeration (including the request-shaped `email` lookup at `PasswordResetController.php:34`,
  previously listed with mass assignment), MD5 password hashing, directory listing,
  secrets in `.env`, disabled CSRF protection, the `httponly`-less session cookie, and the cron
  privilege escalation.
- The request made by `curl` inside `SYM-CMD-01`. It is covered by the command claim. A URL passed
  to a shell program is not an `ssrf` operand.
