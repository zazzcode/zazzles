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

**Not covered by any analyzer.** Recorded in the guide so a clean report is not read as a pass.

- Missing authorization on six `/user/…` and `/admin/…` actions, and the `/local` endpoints.
- Mass assignment (`src/Entity/User.php:56`–`61`, `PasswordResetController.php:34`). The wildcard
  write is modeled as a storage writer (D-15). The privilege escalation itself is not a claim.
- User enumeration, MD5 password hashing, `phpinfo()` at `public/info.php`, directory listing,
  secrets in `.env`, disabled CSRF protection, the `httponly`-less session cookie, and the cron
  privilege escalation.
- The request made by `curl` inside `SYM-CMD-01`. It is covered by the command claim. A URL passed
  to a shell program is not an `ssrf` operand.
