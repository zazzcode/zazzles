# Insecure configuration

[Analysis index](README.md) · [Coverage](../detection-capabilities/insecure-configuration.md)

A configuration claim is one allow-listed setting joined to application facts. The
family is `configuration`, the candidate kind is `configuration_candidate`, and the
protocol is `configuration-components-v4`. There is no request source.

## Questions

| Question | Answers |
| --- | --- |
| `setting_effect` | `in_effect`, `not_in_effect`, `unknown` |
| `weakness` | `weakens`, `benign`, `unknown` |
| `mitigation` | `none`, `adequate`, `inadequate`, `unknown` |

Confirmed when the setting is in effect, the joined facts make it a weakness, and
mitigation is `none` or `inadequate`. Protected when the setting is not in effect, the
facts are benign, or an adequate mitigation is recorded. `deploy_mapping_unresolved`
and `config_file_unread` keep the record in Review.

## Evidence

`configuration.check`, `configuration.setting`, `configuration.scope`,
`configuration.joined` and `configuration.mitigations`. Deployment mapping uses literal
`WORKDIR`, `COPY` and `ADD` operands only. A scheduled command joins the crontab line,
one level of script, and a `chown`, `chmod` or `COPY --chown` in the same Dockerfile.

Finding type `insecure-configuration`. The SARIF rule carries the check's CWE:
directory listing 548, CSRF 352, script-readable cookie 1004, insecure cookie 614,
debug 489, scheduled writable file 732.
