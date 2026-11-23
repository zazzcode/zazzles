# Configuration analysis

Configuration scanning is in Code Scan because a setting is a defect only together with
application facts: which directory a listing exposes, which entries change state, which
file a privileged schedule runs. It stops at a closed allow-list and a closed check list.
It is not an infrastructure-as-code scanner. Nothing is executed and no variable is expanded.

## Allow-lists

`Result.Config` holds framework files of a detected project. `Result.Deploy` holds
deployment files. Each file is at most 256 KiB. Each list holds at most 200 files.
Symbolic links are not opened. Paths under `vendor/`, `var/` and `node_modules/` are
not read. An over-limit or unreadable file records `config_file_unread`, and a list past
200 files records `config_list_truncated`.

A deployment file can name another file: a `COPY` source, the script of a schedule line.
Such a path is opened through `containedPath`, the same rule as a walked file. It is
cleaned, it must stay inside the scan root, and no component may be a symbolic link or a
skipped directory. Each file is read once per scan (`fileText`) and parsed once per
project (`deployment`), and every check and the address-trust reader share that view.

| List | Paths |
| --- | --- |
| Config | `config/packages/framework.yaml`, `config/packages/web_profiler.yaml`, `.env`, `.env.local`, `.env.prod`, `.env.prod.local`, and a file a Dockerfile `COPY` places as one of those |
| Deploy | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`; `.htaccess` anywhere; `*.conf` and `php.ini` under `docker/`, `.docker/`, `deploy/`, `config/apache/`, `config/nginx/`, `apache/`, `nginx/` and `etc/`; a `php.ini` at the scan root; `crontab`, `*.cron` and `cron.d/`; a script a schedule line executes when it resolves to a project file |

## Environment files

An environment file contributes `APP_ENV` and `APP_DEBUG` only. Every other line is
discarded before a value is stored. The reader takes one physical line at a time, because
dotenv has no line continuation, and keeps a value only when it is one plain word. Joining
a continuation line would put the next variable's value into the kept key. The deployed
value is the project's `.env`, then `.env.local`, then each file a `COPY` places at the
project root under one of those names, in order.

## Why the records are judged

Each record carries the setting, its scope and the joined application facts. The model
answers `setting_effect`, `weakness` and `mitigation` (`configuration-components-v5`).
A hardened value makes no record. The scanner does not decide that a setting is a defect.
The request instruction states what each joined fact kind means and what the check's
directive does as documented, and prescribes no answer. Whether the setting is in effect
rests on recorded facts: the `COPY` that ships the file, the `a2enconf` or `a2ensite` that
enables an Apache file under an `-available` directory, and the `environment` fact for a
framework setting.

The `scope` evidence role is the place that fixes where a setting applies: the
`<Directory>` or `location` line, the `.htaccess` file, the `when@` block or the project
manifest, the `COPY` that deploys an environment file, the image or cron file of a
schedule. A setting with no such place keeps the role empty, and the policy holds the
claim for evidence. Each setting is anchored at its own line and byte range, so two
settings of one file are two findings.

The policy follows the order of every family: protocol, facts and evidence, an answer
that contradicts a recorded fact, a blocking gap, then the status. Each check has its own
SARIF rule, `scan/insecure-configuration/<check>`.

## Checks

| Check | Recorded when | Joined facts | No record when |
| --- | --- | --- | --- |
| `directory_listing` | Apache `Options` whose effective list includes `Indexes`, or nginx `autoindex on` | Scope directory, whether it maps to the document root, upload destinations inside it | `-Indexes`, `Options None`, `autoindex off`, or the directive absent |
| `csrf_disabled` | `framework.csrf_protection: false` at the top level or under `when@prod`, which overrides the top level for every framework key. `when@dev` and `when@test` are not read | Up to eight session-authenticated state-changing entries, and any `isCsrfTokenValid` or `csrf_token_id` mitigation | `true`, `~`, or the key absent |
| `session_cookie_script_readable` | `cookie_httponly: false`, or `session.cookie_httponly` of `0`, `Off` or `false`, or `ini_set` of a literal false, or the `httponly` flag of `session_set_cookie_params` or of a `setcookie` named by `session_name()` when it is false or a variable assigned false earlier in the same scope | Whether a session-authenticated entry exists (`unknown` in plain PHP, which has no access model), and each false assignment of a variable flag | `true`, absent, or `On` |
| `session_cookie_insecure_transport` | `cookie_secure: false`, or `session.cookie_secure` of `0` or `Off`, or the `secure` flag of the same PHP calls | The same | `true`, `auto`, absent |
| `debug_enabled` | Deployed `APP_DEBUG` of `1` or `true`, `APP_ENV=dev`, `display_errors` of `On`, `1` or `stdout`, or `web_profiler` enabled outside `when@dev` and `when@test` | Which file is the deployed one | `prod`, `0`, `Off`, or a `when@dev` block |
| `remote_include_enabled` | `allow_url_include` of `On`, `1`, `true` or `yes` in a read `php.ini` | Up to eight `include` or `require` operations whose operand a request reaches (`php-include-v1` path candidates), or a fact that none is recorded | `Off`, `0`, absent. `allow_url_fopen` is not a check |
| `scheduled_privileged_writable` | A schedule, an execution chain and a writable link all exist | The schedule, the chain and the ownership line | No link is writable by a lower-privileged user |

## Deployment mapping

`WORKDIR`, `COPY` and `ADD` with literal operands map container paths to project paths.
The mappings are a list in `COPY` order. The longest destination wins and, between equal
ones, the later `COPY`. A Go map here made the output depend on iteration order. Only the
last build stage is read. A build argument, a glob, a `COPY --from` or a source outside
the build context records `deploy_mapping_unresolved`. A web-server file copied
under `/etc/apache2/`, `/etc/httpd/`, `/usr/local/apache2/conf/` or `/etc/nginx/`, or a
`.htaccess` under the document root, is `config_installed`. An `.htaccess` scope is its own
directory, a project path that needs no mapping. With no Dockerfile, a scope path matches
an existing project directory by its trailing segments, longest first, or the record
carries `deploy_mapping_unresolved`. The document root is a stated `DocumentRoot` or
server-level nginx `root` that maps to the project, else the framework's public
directory, else the project root, which plain PHP serves whole.

## Readers

`deployconf` has one file per format over a shared lexer. The formats differ in ways a
single reader got wrong. `;` is a comment only in `php.ini`; it ends a statement in nginx
and separates commands in a `RUN`. A trailing backslash continues a line in Apache and
Dockerfile syntax and nowhere else. Apache `Options` merges a relative list with the list
in force in the same scope, compares names without case and expands `All`. nginx is read
as statements and nested blocks, and a prefix `location` resolves under the `root` in
force wherever in the block that `root` is written.

## Scheduled commands

A system crontab line has six fields, the sixth a user. A five-field line installed by
`crontab` runs as the Dockerfile `USER`, default `root`. `cd <dir> &&` sets the working
directory for the rest of the line and for one level of `bash`, `sh`, `php` or `./`
script. A relative path with no `cd` is not resolved, because cron's own directory is not
in the files. Only a word that is a plain path counts as a file of the chain. The last
`chown` that covers a file names its owner, so a later `chown` back to the schedule user
removes the link. A link is writable when the same Dockerfile `chown`s it, or a directory that
contains it with `-R`, to a user other than the schedule user, or `chmod` gives group
or other write, or `COPY --chown=` names such a user. `root` against any other name is
the privileged case. Two equal names record nothing.

## Address trust

For each `address_check` whose source is `framework_client_ip`, the record gains
`address_trust` of `configured`, `not_configured` or `partial` from `trusted_proxies`,
`trusted_headers`, Apache `remoteip` and nginx `real_ip`. The values ride the existing
evidence text. The authorization protocol does not change. The gap
`address_trust_configuration_unread` stays when a list was unreadable.

## Shell URL client

`api.php-shell-url-client-v1` is a second record at a command sink whose literal program
is `curl` or `wget` and whose request value is in a URL position. Quoting the argument
does not remove the request. The command candidate and its request are unchanged.

A string value built by concatenation or interpolation keeps its parts in order, each
literal text or a value (`phpValue.pieces`). The contract splits those parts into shell
words and reads the option table. It evaluates nothing, so a sink inside the command
argument is recorded once, and a command held in a variable keeps each word's own value.
A join of two branches and the result of a call drop the parts. Plain PHP selects the
input component `source.php-input-ssrf-v1`.

## Gaps

`config_file_unread`, `config_list_truncated`, `deploy_mapping_unresolved`,
`configuration_entry_missing` when a project has no entry to report a setting under, and
`address_trust_configuration_unread` when the trust files could not be read.
