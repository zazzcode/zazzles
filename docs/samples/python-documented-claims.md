# Documented Python vulnerability claims

[Sample policy](reference-policy.md) · [Python results](../../.zazz/evaluation/python-support-results.md)

This inventory separates the authors' advertised families from independently reviewed source cases.
README lists are not complete location-level answer keys. Labels and documentation claims are
**evaluation inputs only** and are never included as expected verdicts in scanner/model evidence.
Installation instructions were read as documentation; the target apps were not executed or modified.

The pinned repositories contain no additional Markdown instruction tree beyond their READMEs.
Additional inspected material includes ThreatByte's API Swagger document and FastAPI's test file
and task recipes. These provide useful intent but do not prove that a schema/validator executes.

## ThreatByte

Sources: pinned [README](https://github.com/anotherik/ThreatByte), `server/api/v1/docs/swagger.json`,
and the author's [Part 1 article](https://medium.com/@anotherik/exploring-web-vulnerabilities-with-threatbyte-from-exploitation-to-defense-part-1-4a693b4fa3fc).
The article provides a concrete SQL/search-output walkthrough; broader family names are not an
exhaustive answer key. Source cases and pinned byte hashes live in [the reference](ThreatByte/reference.md).

| Documented family | Current handling |
| --- | --- |
| SQL injection | Source-reviewed dashboard SQL path; separate parameterized controls and dynamic-column construction review |
| Reflected XSS | Raw search output through dashboard template |
| Stored XSS | Country write/read/render path; other origins and escaped fields assessed separately |
| DOM XSS | Inline jQuery comment input to HTML append |
| SSRF | Request-influenced outbound destination candidate; complete SSRF protection/exploitation judgment unsupported |
| Insecure configurations | Planned for future branches; comparator results retained |
| Weak/improper cryptography | Planned for future branches; comparator results retained |
| Brute-force protection | Planned for future branches |
| Weak session management | Planned for future branches; session logging is a distinct content-sensitivity question |
| BOLA | Planned for future branches |
| BOPA | Planned for future branches |
| BFLA | Planned for future branches; Swagger's delete-route description is evaluation intent, not scanner proof |
| CSRF | Planned for future branches |
| Path traversal | Planned for future branches; comparator results retained |
| Unrestricted upload | Planned for future branches |

Form input types/required attributes also establish named field policy for the linked handler.
The server's actual checks, helpers and rejection behavior determine enforcement; SQL binding
is assessed independently. Swagger model descriptions are not proof of server-side enforcement.

## Python insecure app

Sources: pinned [README](https://github.com/trottomv/python-insecure-app), `tests/test_main.py`,
`justfile`, and the author's [FastAPI/SSTI article](https://dev.to/trottomv/secure-by-design-in-python-a-fastapi-app-with-5-devsecops-tools-and-a-real-time-ssti-vulnerability-2e6n).
The local test contains a commented SSTI TODO rather than an executed exploit assertion.
Task recipes describe external audit tooling; they were not run in the target checkout.

| Documented family | Current handling |
| --- | --- |
| Insecure dependencies | SCA planned for a future branch |
| Hardcoded secrets | Secret scanning planned for a future branch |
| SSTI | Distinct family not implemented; the same source path has separately reviewed raw HTML/XSS evidence |

The author's constant-template/variable repair changes template-source injection behavior.
For XSS, a Jinja constant template also needs appropriate autoescaping. Paired scanner tests cover
constant templates with autoescape enabled, disabled and unresolved; an SSTI repair is not
silently accepted as XSS protection. See [source reference](python-insecure-app/reference.md).

## Vulnerable Flask App / Erlik 2

Sources: pinned [README](https://github.com/anil-yelken/Vulnerable-Flask-App) through the retained
fork and [OWASP project description](https://owasp.org/projects/vulnerable-flask-app).
These list categories, not every expected location. The retained source is pinned in
[the source reference](vulnerable-flask-app/reference.md).

| Documented family | Current handling |
| --- | --- |
| HTML injection | Raw browser HTML output subset; no universal HTML-injection engine |
| XSS | Raw reflected return, template-source output and supported exception-path return |
| SQL injection | Interpolated sqlite3 search; correct binding controls tested independently |
| SSTI | Separate family unsupported; raw HTML flow reviewed independently |
| Information disclosure | General family out of scope; sensitive log contents have separate evidence gates |
| Command injection | Planned for future branches |
| Brute force | Planned for future branches |
| Deserialization | The pickle call receives socket bytes. The current analyzer emits no request-derived candidate for this sample. [Coverage](../scan/detection-capabilities/unsafe-deserialization.md) |
| Broken authentication | Planned for future branches |
| DoS | Planned for future branches |
| File upload | Planned for future branches |

No selected app supplies a Python MongoDB/NoSQL driver example. Python NoSQL remains unimplemented,
not a passed negative test. Saved Semgrep CE/Bearer counts span broader/different rules; neither
agreement nor a lower Inconclusive count establishes accuracy or whole-product parity.
