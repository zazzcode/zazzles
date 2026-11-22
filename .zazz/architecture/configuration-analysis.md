# Configuration analysis

Configuration scanning is in Code Scan because a setting is a defect only together with
application facts: which directory a listing exposes, which entries change state, which
file a privileged schedule runs. It stops at a closed allow-list and a closed check list.
It is not an infrastructure-as-code scanner. Nothing is executed and no variable is expanded.

## Allow-lists

`Result.Config` holds framework files of a detected project. `Result.Deploy` holds
deployment files. Each file is at most 256 KiB. Each list holds at most 200 files.
Symbolic links are not opened. Paths under `vendor/`, `var/` and `node_modules/` are
not read. An over-limit or unreadable file records `config_file_unread`.

| List | Paths |
| --- | --- |
| Config | `config/packages/framework.yaml`, `config/packages/web_profiler.yaml`, `.env`, `.env.local`, `.env.prod`, `.env.prod.local`, and a file a Dockerfile `COPY` places as one of those |
| Deploy | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`; `.htaccess` anywhere; `*.conf` and `php.ini` under `docker/`, `.docker/`, `deploy/`, `config/apache/`, `config/nginx/`, `apache/`, `nginx/` and `etc/`; `crontab`, `*.cron` and `cron.d/`; a script a schedule line executes when it resolves to a project file |

## Environment files

An environment file contributes `APP_ENV` and `APP_DEBUG` only. Every other line is
discarded before a value is stored.

## Why the records are judged

Each record carries the setting, its scope and the joined application facts. The model
answers `setting_effect`, `weakness` and `mitigation` (`configuration-components-v4`).
A hardened value makes no record. The scanner does not decide that a setting is a defect.

## Checks

| Check | Recorded when | Joined facts | No record when |
| --- | --- | --- | --- |
| `directory_listing` | Apache `Options` whose effective list includes `Indexes`, or nginx `autoindex on` | Scope directory, whether it maps to the document root, upload destinations inside it | `-Indexes`, `Options None`, `autoindex off`, or the directive absent |
| `csrf_disabled` | `framework.csrf_protection: false` outside `when@test` and `when@dev` | Up to eight session-authenticated state-changing entries, and any `isCsrfTokenValid` or `csrf_token_id` mitigation | `true`, `~`, or the key absent |
| `session_cookie_script_readable` | `cookie_httponly: false`, or `session.cookie_httponly` of `0`, `Off` or `false`, or `ini_set` of a literal false | Whether a session-authenticated entry exists | `true`, absent, or `On` |
| `session_cookie_insecure_transport` | `cookie_secure: false`, or `session.cookie_secure` of `0` or `Off` | The same | `true`, `auto`, absent |
| `debug_enabled` | Deployed `APP_DEBUG` of `1` or `true`, `APP_ENV=dev`, `display_errors` of `On`, `1` or `stdout`, or `web_profiler` enabled outside `when@dev` and `when@test` | Which file is the deployed one | `prod`, `0`, `Off`, or a `when@dev` block |
| `scheduled_privileged_writable` | A schedule, an execution chain and a writable link all exist | The schedule, the chain and the ownership line | No link is writable by a lower-privileged user |

## Deployment mapping

`WORKDIR`, `COPY` and `ADD` with literal operands map container paths to project paths.
A build argument or a glob records `deploy_mapping_unresolved`. A web-server file copied
under `/etc/apache2/`, `/etc/httpd/`, `/usr/local/apache2/conf/` or `/etc/nginx/`, or a
`.htaccess` under the document root, is `config_installed`. With no Dockerfile, a scope
path matches a project directory by its trailing segments or the record carries
`deploy_mapping_unresolved`.

## Scheduled commands

A system crontab line has six fields, the sixth a user. A five-field line installed by
`crontab` runs as the Dockerfile `USER`, default `root`. `cd <dir> &&` sets the working
directory for the rest of the line and for one level of `bash`, `sh`, `php` or `./`
script. A link is writable when the same Dockerfile `chown`s it, or a directory that
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

## Gaps

`config_file_unread`, `deploy_mapping_unresolved`, and `address_trust_configuration_unread`
when the trust files could not be read.
