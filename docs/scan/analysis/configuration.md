# Insecure configuration

[Analysis index](README.md) · [Coverage](../detection-capabilities/insecure-configuration.md)

A configuration claim is one allow-listed setting joined to application facts. The
family is `configuration`, the candidate kind is `configuration_candidate`, and the
protocol is `configuration-components-v5`. There is no request source.

The scanner reads the setting and joins the facts. It does not decide that the setting
is a defect. The instruction sent with a request says what each joined fact kind states
and leaves each answer to the model. It also carries what the check's directive does as
its documentation describes it, for example that `Options Indexes` answers a request for
a directory with a list of its files. Whether that is a weakness in this application is
the question.

## Questions

| Question | Answers |
| --- | --- |
| `setting_effect` | `in_effect`, `not_in_effect`, `unknown` |
| `weakness` | `weakens`, `benign`, `unknown` |
| `mitigation` | `none`, `adequate`, `inadequate`, `unknown` |

Confirmed when the setting is in effect, the joined facts make it a weakness, and
mitigation is `none` or `inadequate`. Protected when the setting is not in effect, the
facts are benign, or an adequate mitigation is recorded.

The policy checks in this order and stops at the first that applies: the protocol, the
recorded facts and the `setting` and `scope` evidence, an answer that contradicts a
recorded fact, a blocking gap, then the status the answers give. `mitigation: adequate`
with no recorded mitigation is a contradiction, and so is `not_in_effect` for an
installed setting whose scope is mapped. `deploy_mapping_unresolved` and
`config_file_unread` are the blocking gaps.

## Evidence

`configuration.check`, `configuration.setting`, `configuration.scope`,
`configuration.joined` and `configuration.mitigations`. Each setting is anchored at its
own line.

| Joined fact | States |
| --- | --- |
| `config_installed` | The instruction that puts the file into the deployed application or the web server configuration. A file copied under Apache `conf-available` or `sites-available` is installed only when an `a2enconf` or `a2ensite` in the same Dockerfile enables it, and the fact names that instruction |
| `environment` | Which environments load a framework setting: every one for the top level of a `config/packages` file, or the named one inside a `when@` block |
| `scope_mapping`, `scope_served` | The project directory the scope resolves to, and whether it is inside the document root |
| `upload_destination` | A directory inside the scope where the application stores request-supplied files |
| `state_changing_entry` | An entry that changes stored state, with the access it requires |
| `session_authenticated` | Whether the application has entries that require a logged-in session |
| `deployed_file` | The file the deployed application reads the setting from |
| `schedule`, `chain`, `ownership` | The scheduled command and its user, a file it executes, and the instruction that lets another user rewrite that file |

The `scope` evidence is the place that fixes where the setting applies: the
`<Directory>` or `location` line, the `.htaccess` file, the `when@` block or the
project manifest, the `COPY` that deploys an environment file, or the image or cron
file a schedule belongs to. Deployment mapping uses literal
`WORKDIR`, `COPY` and `ADD` operands only. A scheduled command joins the crontab line,
one level of script, and a `chown`, `chmod` or `COPY --chown` in the same Dockerfile.

Finding type `insecure-configuration`. Each check has its own SARIF rule,
`scan/insecure-configuration/<check>`, which carries the check's CWE and help text:
directory listing 548, CSRF 352, script-readable cookie 1004, insecure cookie 614,
debug 489, remote include 98, scheduled writable file 732.
