# Insecure configuration

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/configuration.md)

The `configuration` family reads a bounded set of framework and deployment files and
records settings that can weaken an application, each joined to the application facts
that give the setting meaning. A judged scan can report **Insecure configuration**.
Use `--only-family configuration` with `--analyze --judge` to assess this family alone.

The claim has no request source. A file outside the lists below is not read.

## Files read

| List | Paths, relative to a project |
| --- | --- |
| Framework | `config/packages/framework.yaml`, `config/packages/web_profiler.yaml`, `.env`, `.env.local`, `.env.prod`, `.env.prod.local`, and a Dockerfile `COPY` that places a project file as one of those |
| Deployment | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`; `.htaccess` in any directory; `*.conf` and `php.ini` under `docker/`, `.docker/`, `deploy/`, `config/apache/`, `config/nginx/`, `apache/`, `nginx/` and `etc/`; a `php.ini` at the scan root; files named `crontab` or `*.cron`, and files under `cron.d/`; a script a schedule line executes when it is a project file |

Each file is at most 256 KiB. Each list holds at most 200 files, and a list that passes
the limit records `config_list_truncated`. Symbolic links are not opened, including a
link in the path of a file that a deployment file names. `vendor/`, `var/` and
`node_modules/` are not read. A path that a `COPY` or a schedule line names is read only
when it stays inside the scanned project.

An environment file contributes only `APP_ENV` and `APP_DEBUG`. Each line is read on its
own, and a value that is not one plain word is discarded, so no other variable's value
can reach a report or a model request.

## Checks

| Check | Recorded when |
| --- | --- |
| Directory listing | Apache `Options` whose effective list includes `Indexes`, or nginx `autoindex on` |
| CSRF disabled | `framework.csrf_protection: false` or `{ enabled: false }` at the top level or under `when@prod` |
| Session cookie readable by script | `cookie_httponly: false`, `session.cookie_httponly` of `0`, `Off` or `false`, or `ini_set('session.cookie_httponly', …)` with a literal false. In PHP code: `session_set_cookie_params` and a `setcookie` whose name is `session_name()`, when the flag is `false` or `0`, or a variable that an assignment reaching the call sets to one of those |
| Session cookie on an insecure transport | `cookie_secure: false`, or `session.cookie_secure` of `0` or `Off`. The same PHP calls as the row above, for the `secure` flag |
| Debug enabled | Deployed `APP_DEBUG` of `1` or `true`, `APP_ENV=dev`, `display_errors` of `On`, `1` or `stdout`, or `web_profiler` enabled |
| Remote include enabled | `allow_url_include` of `On`, `1`, `true` or `yes` in a read `php.ini`, joined to the `include` and `require` operations a request reaches |
| Scheduled privileged writable file | A cron line, a command chain and a file in that chain that a less privileged user can write |

### How each file is read

| File | Forms read |
| --- | --- |
| Apache `*.conf`, `.htaccess` | `Options` in a `<Directory>` block, a virtual host or the server scope. A list of `+` and `-` names edits the list in force, and a bare list replaces it. `All` includes `Indexes`. Names are compared without case. An `.htaccess` applies to its own directory. `Options` inside `<Location>`, `<Files>` or a pattern block is not read |
| nginx `*.conf` | `autoindex` and `root`, with statements split at `;` and blocks by braces. A prefix `location` resolves under the `root` in force. A pattern `location` and an `alias` are not resolved |
| Symfony YAML | A `when@prod` block overrides the top level. `when@dev` and `when@test` are not deployed and are not read. Any other `when@` block is read as an environment of its own |
| `Dockerfile` | The last build stage. `WORKDIR`, `USER`, `COPY` and `ADD` with literal operands, in shell or JSON form. `RUN` commands separated by `&&`, `||` or `;`: `chown`, `chmod`, `a2enmod`, `crontab <file>`, and `echo "…" > /etc/cron.d/<name>` |
| Cron files | Five schedule fields or one `@` nickname. A file installed with `crontab <file>` runs as the Dockerfile user in force. Any other cron file has a user field after the schedule |
| PHP source | `session_set_cookie_params` with an options array or five positional arguments. `setcookie` and `setrawcookie` only when the name argument is a `session_name()` call. A variable flag is read from the assignments that reach the call in the same function or file: the nearest earlier assignment statement in an enclosing block and each later assignment in a branch. A later assignment overrides an earlier one. A flag that is false on only some paths is recorded as `false on some path`. An absent flag is not recorded |
| `php.ini` | `display_errors`, `session.cookie_httponly`, `session.cookie_secure`, `allow_url_include`. `allow_url_fopen` is PHP's default and is not a check |

A deployed environment value is the project's `.env`, then `.env.local` over it, then
each file a `COPY` places at the project root under one of those names, in order.

A scheduled command's relative path resolves only after a leading `cd <dir>`. The last
`chown` that covers a file names its owner. A `chmod` counts when it gives group or
other write, in octal (`777`, `0664`) or symbolic (`o+w`, `a+rwx`, `go=rwx`) form.

## Recorded and decidable

Each record names the setting, its scope and the joined facts: the directory a listing
exposes and whether uploads land there, the state-changing entries under a disabled
CSRF setting, whether a session-authenticated entry exists, which environment file is
the deployed one, and the schedule, chain and ownership lines. The decision model
weighs whether the setting is in effect, whether those facts make it a weakness, and
whether a recorded mitigation removes it.

## Recorded in Review

| Gap | Meaning |
| --- | --- |
| `deploy_mapping_unresolved` | A scope path or a `COPY` operand could not be mapped. A build argument or a glob is not expanded, a `COPY --from` takes files from another build stage, and a source outside the project is not followed |
| `config_file_unread` | An allow-listed file was over the size limit, unreadable, or not valid YAML |
| `config_list_truncated` | A file list passed 200 files, and the files after the limit were not read |
| `configuration_entry_missing` | A setting was read in a project with no entry to report it under |

A record whose scope has no evidence, such as a server-wide `Options` in a file that
states no document root in a plain PHP project, also stays in Review.

## Not recorded

Kubernetes manifests, Helm, Terraform, Ansible, docker-compose service definitions, CI
files, and systemd units. Apache and nginx beyond the check list. Dockerfile practice
checks such as an unpinned base image. Shell script analysis beyond one level from a
scheduled command. Security headers, and the attributes of any cookie other than the session cookie, set in PHP code. Committed
secrets. A file that is not on the lists above. A Dockerfile build stage other than the
last one. A cron line whose relative path has no `cd`. A `curl` or `wget` reached through
`-K`, `xargs` or a URL read from a file.

## Remediation

| Check | What to change |
| --- | --- |
| Directory listing | Remove `Indexes` from a served directory, and keep uploads out of a listed directory |
| CSRF disabled | Leave CSRF protection enabled and validate a token on state-changing entries |
| Script-readable session cookie | Set `cookie_httponly` to true, or pass `httponly` as true in the PHP call |
| Insecure session cookie | Set `cookie_secure` to true or auto, or pass `secure` as true in the PHP call |
| Debug enabled | Deploy with `APP_ENV=prod` and `APP_DEBUG=0`, and leave `display_errors` off |
| Remote include enabled | Set `allow_url_include` to `Off`, and choose included files from a fixed list |
| Scheduled writable file | Run the job as the user that owns the file, or remove the write bit for every other user |

## JavaScript and TypeScript (Express)

Two checks read Express source. No deployment file is needed: a registration or cookie option in
the source that builds the application is applied by that application.

| Check | Recorded when |
| --- | --- |
| Directory listing (CWE-548) | A [`serve-index`](https://github.com/expressjs/serve-index#readme) call is passed to `app.use`. The record joins the mount path, the directory argument, the access of the mount and each middleware before it on the same call |
| Session cookie readable by script, session cookie on insecure transport (CWE-1004, CWE-614) | The `cookie` option of `express-session`, or the options of `cookie-session`, set `httpOnly: false` or `secure: false`, as a literal or through a constant |

An absent option and a `true` are not recorded, and a `res.cookie` call is not recorded because
its name does not establish that it carries the session. The deployment-file readers do not yet
run for a JavaScript project.
