# Detection capabilities

[Documentation](../README.md) · [Analysis rules](analysis/README.md) · [Interpreting results](interpreting-results.md)

Find the weakness you are investigating, then open its coverage page for supported operations,
recognized controls, records that need Review, and gaps. Use the analyzer family with
`--only-family` to scope model assessment in a judged scan. Some families assess more than one
weakness. [Selecting families](running-scans.md#route-to-string-use-analysis)

Each record concerns one declared claim at a supported operation or input. Protected applies
to that claim and its analyzed paths. Offline scans build evidence, and judged scans can use
that evidence to classify a supported security claim. [How to read a report](interpreting-results.md)

<a id="vulnerability-families"></a>

## Vulnerability classes

| Class and coverage | Reported CWE | Analyzer family | OWASP risk references |
|---|---|---|---|
| [SQL injection](detection-capabilities/sql-injection.md) | [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | `sql` | [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| [NoSQL injection](detection-capabilities/nosql-injection.md) | [CWE-943](https://cwe.mitre.org/data/definitions/943.html) | `nosql` | — |
| [Cross-site scripting](detection-capabilities/cross-site-scripting.md) | [CWE-79](https://cwe.mitre.org/data/definitions/79.html) | `xss` | [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| [OS command injection](detection-capabilities/command-injection.md) | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) | `command` | [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| [Argument injection](detection-capabilities/argument-injection.md) | [CWE-88](https://cwe.mitre.org/data/definitions/88.html) | `command` | [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| [Path traversal](detection-capabilities/path-traversal.md) | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) | `path` | [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) |
| [Unrestricted file upload](detection-capabilities/file-upload.md) | [CWE-434](https://cwe.mitre.org/data/definitions/434.html) | `upload` | [A06:2025 Insecure Design](https://top10.owasp.org/2025/A06_2025-Insecure_Design/) |
| [Server-side request forgery](detection-capabilities/server-side-request-forgery.md) | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) | `ssrf` | [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) · [API7:2023 SSRF](https://api-security.owasp.org/editions/2023/en/0xa7-server-side-request-forgery/) |
| [Code injection](detection-capabilities/code-injection.md) | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) | `code` | [A05:2025 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) |
| [Server-side template injection](detection-capabilities/template-injection.md) | [CWE-1336](https://cwe.mitre.org/data/definitions/1336.html) | `code` | — |
| [Unsafe deserialization](detection-capabilities/unsafe-deserialization.md) | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) | `deserialization` | — |
| [Information exposure](detection-capabilities/information-exposure.md) | [CWE-200](https://cwe.mitre.org/data/definitions/200.html), [CWE-215](https://cwe.mitre.org/data/definitions/215.html) | `exposure` | [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) |
| [Mass assignment](detection-capabilities/mass-assignment.md) | [CWE-915](https://cwe.mitre.org/data/definitions/915.html) | `mass-assignment` | [API3:2023 Broken Object Property Level Authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/) |
| [Missing authorization](detection-capabilities/missing-authorization.md) | [CWE-862](https://cwe.mitre.org/data/definitions/862.html), [CWE-639](https://cwe.mitre.org/data/definitions/639.html), [CWE-291](https://cwe.mitre.org/data/definitions/291.html) | `authorization` | [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) |
| [Account enumeration](detection-capabilities/account-enumeration.md) | [CWE-204](https://cwe.mitre.org/data/definitions/204.html) | `account` | [A07:2025 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) |
| [Weak password recovery](detection-capabilities/weak-password-recovery.md) | [CWE-640](https://cwe.mitre.org/data/definitions/640.html), [CWE-1287](https://cwe.mitre.org/data/definitions/1287.html) | `account` | [A07:2025 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/) |
| [Weak password hashing](detection-capabilities/weak-password-hashing.md) | [CWE-916](https://cwe.mitre.org/data/definitions/916.html) | `account` | [A04:2025 Cryptographic Failures](https://top10.owasp.org/2025/A04_2025-Cryptographic_Failures/) |
| [Insecure configuration](detection-capabilities/insecure-configuration.md) | [CWE-548](https://cwe.mitre.org/data/definitions/548.html), [CWE-352](https://cwe.mitre.org/data/definitions/352.html), [CWE-1004](https://cwe.mitre.org/data/definitions/1004.html), [CWE-614](https://cwe.mitre.org/data/definitions/614.html), [CWE-489](https://cwe.mitre.org/data/definitions/489.html), [CWE-98](https://cwe.mitre.org/data/definitions/98.html), [CWE-732](https://cwe.mitre.org/data/definitions/732.html) | `configuration` | [A02:2025 Security Misconfiguration](https://top10.owasp.org/2025/A02_2025-Security_Misconfiguration/) |
| [Prototype pollution](detection-capabilities/prototype-pollution.md) | [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) | `pollution` | — |
| [Open redirect](detection-capabilities/open-redirect.md) | [CWE-601](https://cwe.mitre.org/data/definitions/601.html) | `redirect` | [A01:2025 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/) |
| [Sensitive data in logs](detection-capabilities/sensitive-data-logging.md) | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) | `logging` | [A09:2025 Security Logging and Alerting Failures](https://top10.owasp.org/2025/A09_2025-Security_Logging_and_Alerting_Failures/) |

CWE identifies the weakness. OWASP Top 10 references use the indicated edition and group
weaknesses into broader risks. An analyzer’s coverage is the set of operations and paths listed
on its class pages. [OWASP Web Top 10](https://top10.owasp.org/) · [OWASP API Top 10](https://api-security.owasp.org/)

## Practice checks and observations

| Check or observation | Selector | Coverage |
|---|---|---|
| Standalone input validation | `input-validation` | [Declared field policy, enforcement and Review](detection-capabilities/input-validation.md) |
| Outbound calls | `outbound` | [Destination origins and grouped observations](analysis/ssrf.md#destination-origin). A verified request-controlled destination can also have a separate `ssrf` claim |
| Next.js practice checks | Framework observations | [NX-BP checks and their bounds](nextjs-support.md#framework-practice-observations) |

<a id="languages-frameworks-and-entries"></a>

## Languages and entry points

| Language | Supported entry points | Guide |
|---|---|---|
| JavaScript and TypeScript | Supported HTTP handlers in Express, Fastify and Hapi, Next.js routes, pages and Server Actions, browser entry points, Apollo GraphQL resolvers and unary gRPC | [Node inputs](analysis/node-inputs.md) · [Next.js](nextjs-support.md) · [Entry selection](running-scans.md#common-entry-selection-and-tagged-checks) |
| Python | Supported HTTP dispatch in Flask, FastAPI, Quart, Django, Falcon, Bottle, Pyramid, aiohttp and WSGI | [Python analysis](python-support.md) |
| PHP | Server-mapped `.php` and `.phtml` files and Symfony attribute, annotation, and YAML routes. A Symfony route entry also records the access the security configuration requires of its caller. Allow-listed deployment files (Dockerfile, Apache, nginx, cron, php.ini, `.htaccess`) are read for the configuration family and are not language entries | [PHP analysis](php-support.md), [Symfony analysis](symfony-support.md), [Insecure configuration](detection-capabilities/insecure-configuration.md) |

Framework coverage pages list the entries, inputs, stored values and operations read in one
framework, across every vulnerability class.

| Framework | Coverage |
|---|---|
| Symfony | [Routes, request values, services, Doctrine and operations](detection-capabilities/symfony.md) |
| Twig | [Template outputs, escaping, URL attributes and Review cases](detection-capabilities/twig.md) |

Entry adapters acquire input and establish context for the same claim and verdict model. Each
language adapter establishes its own supported value flow and protection facts. [Technical approach](../technical-approach.md#common-entry-and-dispatch-architecture)

<a id="which-rules-are-generic"></a>

<a id="second-order-and-stored-values"></a>

## Shared evidence and stored values

Supported reads and writes can link a stored value back to an originating request. When no
writer is linked, the claim can stay in Review with `storage_origin_unresolved`. A request key
that selects a stored record does not establish the origin of its contents.
[Stored and browser analysis](analysis/xss.md#stored-and-browser-analysis)

In a Symfony project, a **security-field census** marks which stored fields hold a credential,
the login identifier or the source of a user's roles. Each role comes from a framework contract
(the security user interfaces, entity user providers and Doctrine lifecycle callbacks), never
from a field name; a name on a fixed hint list is recorded only as a hint.
[Census rules](analysis/mass-assignment.md#security-field-census)

<a id="prototype-pollution-known-gaps"></a>

## Prototype pollution coverage

The [prototype pollution coverage page](detection-capabilities/prototype-pollution.md) includes
the supported walk starts, inline handler walks and their current limits.

<a id="not-covered"></a>

## Coverage boundaries

Scans read source and do not install dependencies, execute the target or make its outbound
requests. Dependency-wide vulnerability auditing and findings that require
runtime environment or deployment behavior are outside the current scan coverage. See each
class page for its language, framework and library boundaries.
