# ThreatByte source reference

Pinned source and reviewed files: [hash manifest](source-hashes.json). The application README
lists SQL injection, reflected/stored/DOM XSS and SSRF, alongside families outside this adapter.
These labels are source-reviewed expectations, never scanner/model inputs.

| Case | Source | Expected and rationale |
| --- | --- | --- |
| TB-SQL-01 | `server/routes.py`, dashboard `cursor.execute(s_query)` | SQL text interpolates request `search`; parameter tuple is absent. Construction finding and injection candidate. |
| TB-SQL-02 | dashboard username lookup and empty-search branch | Literal SQL plus tuple binding: injection-protected controls. Session/database origin differs from direct request origin. |
| TB-SQL-03 | `server/api/v1/api_v1.py`, update-profile `execute(update_query, ...)` | Dynamic column names come from allowed/sensitive key lists; values use placeholders. Must not label this confirmed injection solely because SQL is built. Comprehension/allow-list semantics need Review if unsupported. |
| TB-XSS-01 | `client/templates/dashboard.html`, `search_query \| safe` | Reflected raw HTML from request search, paired with escaped outputs. |
| TB-XSS-02 | `client/templates/profile.html`, `user.country \| safe` | Stored raw HTML: signup/update writes country to users; profile reads users. Storage correlation must show write/read evidence and assumptions; unresolved identity remains Review. |
| TB-XSS-03 | dashboard/profile escaped `{{ ... }}` | Protected only for established HTML-text or quoted non-active attribute contexts, verified Flask autoescape and complete origins. |
| TB-OUT-01 | `server/api/v1/api_v1.py`, ProfilePicture `requests.get(picture_url)` | Request payload supplies `picture_url` directly to verified `requests.get`, with no pre-request destination constraint. Expect an SSRF candidate under the implemented Python HTTP URL contract; response MIME/status checks occur after the outbound request and cannot constrain its destination. |
| TB-LOG-01 | update-profile `print(session)` | Whole-session logging: Review, not an established credential-content leak. |

Semgrep reports SQL twice (construction and execution locations), MD5 and Dockerfile issues.
Bearer reports path traversal, MD5 and debug configuration. Neither baseline reports the two
Jinja raw outputs or outbound destination. Baselines are comparison observations, not complete keys.
MD5, authorization, traversal, uploads, configuration, CSRF and DOM behavior without Python binding
remain explicitly outside or beyond the bounded Python slice; do not claim all README vulnerabilities.

Additional source review: `dashboard.html:123` appends a value read from a comment input into
jQuery HTML (`<li>` construction). This is TB-XSS-04, a DOM XSS candidate independent of the Python
server inputs. The source's canonical jQuery CDN tag supplies the library binding. Native DOM
append(string) is a negative control, because it creates text. The matching signup form declares
required email/type=email; server presence and password-match guards do not enforce email format.
TB-VAL-EMAIL keeps that source policy separate from the parameterized insert's injection protection.

The [documented-family inventory](../python-documented-claims.md) records all advertised families,
additional local/upstream material reviewed, and current unsupported boundaries.

## Named field-policy controls

The login form declares required username/password; the handler's early return at lines 39–40
enforces presence. Signup requires all five fields; lines 87–90 reject missing values and mismatched
passwords before persistence. These six required-only claims are protected for that exact policy;
no password-complexity or length rule is inferred. Signup email also declares `type="email"`, but
its server guards enforce only presence and equality, not email syntax. This is the separate
validation defect. The insert at line 99 still binds values correctly. Seven independent cases
record these positive/protected expectations; they never enter the production detector or model.

The living [detection guide](../../../.zazz/evaluation/threatbyte-detection-guide.md) details
profile/signup SQL protection, dashboard SQL injection, output and validation controls, and future work.
