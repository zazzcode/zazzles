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
| Deployment | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`; `.htaccess` in any directory; `*.conf` and `php.ini` under `docker/`, `.docker/`, `deploy/`, `config/apache/`, `config/nginx/`, `apache/`, `nginx/` and `etc/`; files named `crontab` or `*.cron`, and files under `cron.d/`; a script a schedule line executes when it is a project file |

Each file is at most 256 KiB. Each list holds at most 200 files. Symbolic links are not
opened. `vendor/`, `var/` and `node_modules/` are not read. An environment file
contributes only `APP_ENV` and `APP_DEBUG`.

## Checks

| Check | Recorded when |
| --- | --- |
| Directory listing | Apache `Options` whose effective list includes `Indexes`, or nginx `autoindex on` |
| CSRF disabled | `framework.csrf_protection: false` or `{ enabled: false }`, outside `when@test` and `when@dev` |
| Session cookie readable by script | `cookie_httponly: false`, `session.cookie_httponly` of `0`, `Off` or `false`, or `ini_set('session.cookie_httponly', …)` with a literal false |
| Session cookie on an insecure transport | `cookie_secure: false`, or `session.cookie_secure` of `0` or `Off` |
| Debug enabled | Deployed `APP_DEBUG` of `1` or `true`, `APP_ENV=dev`, `display_errors` of `On`, `1` or `stdout`, or `web_profiler` enabled outside `when@dev` and `when@test` |
| Scheduled privileged writable file | A cron line, a command chain and a file in that chain that a less privileged user can write |

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
| `deploy_mapping_unresolved` | A scope path or a `COPY` operand could not be mapped. A build argument or a glob is not expanded |
| `config_file_unread` | An allow-listed file was over the size limit, unreadable, or not valid YAML |

## Not recorded

Kubernetes manifests, Helm, Terraform, Ansible, docker-compose service definitions, CI
files, and systemd units. Apache and nginx beyond the check list. Dockerfile practice
checks such as an unpinned base image. Shell script analysis beyond one level from a
scheduled command. Security headers and cookie attributes set in PHP code. Committed
secrets. A file that is not on the lists above.

## Remediation

| Check | What to change |
| --- | --- |
| Directory listing | Remove `Indexes` from a served directory, and keep uploads out of a listed directory |
| CSRF disabled | Leave CSRF protection enabled and validate a token on state-changing entries |
| Script-readable session cookie | Set `cookie_httponly` to true |
| Insecure session cookie | Set `cookie_secure` to true or auto |
| Debug enabled | Deploy with `APP_ENV=prod` and `APP_DEBUG=0`, and leave `display_errors` off |
| Scheduled writable file | Run the job as the user that owns the file, or remove the write bit for every other user |
