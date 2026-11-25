# Zazzles

Zazzles is a modular security project for analyzing application code, checking deployed
endpoints, and remediating findings. **Code Scan** is available today. **Fix** and
**Endpoint Probe** are planned modules.

**Decision-model judgment is central to Code Scan.** Code Scan is not another rule-based SAST
scanner. Static analysis establishes the source facts: it traces input to sensitive operations and
records the controls on each path. A decision LLM then judges that evidence as vulnerable,
protected, poor practice, weak input validation, or inconclusive. Zazzles checks the answers
against its source facts before assigning an outcome.

[Current coverage](#current-coverage) · [Scanner comparison](#scanner-comparison) · [Run Scan](#quick-start) · [Sample reports](docs/samples/README.md) · [Modules](#modules) · [Documentation](docs/README.md)

<a id="what-exists-today"></a>
<a id="scan-current-implementation"></a>
<a id="entry-use-cases-and-delivery-status"></a>

## Current coverage

| Languages | Application entry points |
| --- | --- |
| **JavaScript and TypeScript** | Node.js HTTP handlers, Next.js routes and Server Actions, browser entry points, Apollo GraphQL resolvers, and unary gRPC |
| **Python** | HTTP handlers in Flask, FastAPI, Django, and other supported Python frameworks |
| **PHP** | Server-mapped PHP files plus Symfony routes, controllers, Twig and Doctrine |

**Vulnerabilities Code Scan can identify**

- **Injection** includes SQL injection, NoSQL injection, OS command injection, argument injection,
  code injection, and server-side template injection.
- **Web and file operations** include cross-site scripting (XSS), server-side request forgery (SSRF),
  open redirect, path traversal, and unrestricted file upload.
- **Data handling** includes unsafe deserialization, prototype pollution, and sensitive data in logs.
- **Application security** includes information exposure through diagnostic output, mass
  assignment of request-chosen properties, missing authorization of a stored write,
  a file change, or a census-field read, the account claims (account enumeration,
  weak password recovery and weak password hashing), and insecure configuration of
  allow-listed framework and deployment files (including `allow_url_include` in a root
  `php.ini`) and of session cookie flags set in PHP code. Symfony website support covers these
  families together with SSRF through a `curl` or `wget` shell URL.

**Code smells and poor practices** include building queries from untrusted strings, failing to
enforce declared input rules on the server, returning stack traces from Next.js API handlers,
and omitting security flags on cookies.

Reports point to the relevant code and show the input, operation, and controls behind each result.
Coverage varies by language, framework, and library. [Full detection coverage](docs/scan/detection-capabilities.md) · [See a sample report](docs/samples/README.md)

## Scanner comparison

Code Scan, Semgrep CE and Bearer were run on four intentionally vulnerable applications and
scored against an answer key for each application, with false positives counted.

| Application | In answer key | Code Scan found | Semgrep CE found | Bearer found |
|---|---:|---:|---:|---:|
| OWASP Juice Shop | 76 | 45 | 19 | 15 |
| vuln-nextjs | 13 | 13 | 7 | 7 |
| DVWA | 11 | 11 | 6 | 6 |
| vuln-symfony | 30 | 30 | 8 | 5 |
| **Total** | **130** | **99** | **40** | **33** |

Reviewed false positives: Code Scan 13, Semgrep CE 93, Bearer 73 and two grouped rules. Each is a
lower bound. An answer key is not a complete list of an application's vulnerabilities. Juice Shop's
was extended from its own documented challenges; the other three were not and still favor the
classes Code Scan analyzes. Code Scan misses 31 rows: 18 in classes it has no analyzer for and 13
where an existing analyzer falls short. Semgrep CE and Bearer run free and offline, and a judged
Code Scan calls a paid model provider. Code Scan was developed against these applications, so this
is not a general accuracy claim.
[Full comparison, misses and false positives by application](docs/scan/scanner-comparison.md)

## Modules

| Module | Purpose | User docs | Status |
|---|---|---|---|
| [**Code Scan**](scan/README.md) (`scan/`) | Source-code security analysis with a decision-model judge. | [Scan docs](docs/scan/README.md) | Available and in active development |
| [**Fix**](fix/README.md) (`fix/`) | Agent skills, standards and playbooks for fixing findings from Zazzles modules or external scanners — including SAST, dependency audit, DAST, and endpoint probe / TLS and certificate scanners such as Nuclei. Guides agents from finding evidence through a repair and verification. | [Fix docs](docs/fix/README.md) | Planned |
| [**Endpoint Probe**](probe/README.md) (`probe/`) | Checks externally observable security settings on authorized endpoints (similar to TLS and certificate scanners such as Nuclei). Initial coverage will include TLS versions and configuration, expired certificates and related issues, with evidence and remediation recommendations. | [Probe docs](docs/probe/README.md) | Planned |

<a id="project-direction"></a>
<a id="project-goals-scan-inspect-audit-and-fix"></a>
<a id="project-goals-scan-audit-and-fix"></a>
<a id="project-goals-scan-quality-audit-and-fix"></a>
<a id="the-vision-scan-inspect-audit-and-fix"></a>

Code Scan is the current development focus. Fix is expected to come before Endpoint Probe.
[Implementation plan](.zazz/project/implementation-plan.md)

<a id="setup"></a>

## Quick start

Install the Go version in [`go.mod`](go.mod) and a C compiler. Build the scanner from a checkout
of `stage`, then point it at a local application checkout. [Setup guide](docs/scan/getting-started.md)

<a id="1-build-the-scanner"></a>

### 1. Build the scanner

```bash
git clone --branch stage https://github.com/zazzcode/zazzles.git
cd zazzles
go build -o bin/scan ./scan/cmd/scan
```

The root compatibility entry point `go build -o bin/scan ./cmd/scan` builds the same executable.

<a id="2-configure-openai-luna-decisions"></a>
<a id="optional-use-google-gemini-decisions-instead"></a>

### 2. Configure a decision model

Choose OpenAI or Google Gemini for the standard workflow. Put the selected provider’s API key and
one `JUDGE_DECISION_MODEL` assignment in your local, Git-ignored `.env`. Create it from
[.env.sample](.env.sample) for a new setup. On an existing setup, edit the model line and keep your
existing keys. Use a provider account with access to the selected Decisions model.

```bash
test -e .env || cp .env.sample .env
```

| Provider | API key variable | `JUDGE_DECISION_MODEL` | Scan flag |
| --- | --- | --- | --- |
| [OpenAI Decisions](https://platform.openai.com/api-keys) | `OPENAI_API_KEY` | `gpt-6-luna` | `--judge openai` |
| [Google Gemini Decisions](https://aistudio.google.com/api-keys) | `GEMINI_API_KEY` | `gemini-decision-1` | `--judge gemini` |
| [TypeSafe Jev](https://console.typesafe.ai/) | `TYPESAFE_API_KEY` | Explicit catalog ID, for example `jev-1.14.0` | `--judge jev` |

Jev is verified against local stubs. The model ID comes from TypeSafe’s catalog. [Jev models](https://docs.typesafe.ai/models) · [Provider setup](docs/scan/decision-models.md#credentials-and-local-environment)

Load your trusted `.env` in the shell that will run the scanner.

```bash
set -a
. ./.env
set +a
```

<a id="run"></a>
<a id="3-scan-and-open-the-report"></a>

### 3. Run a judged scan

Run the command for the provider you configured.

```bash
# OpenAI
./bin/scan --analyze --judge openai --output-dir "$HOME/zazzles-findings" /path/to/app

# Google Gemini
./bin/scan --analyze --judge gemini --output-dir "$HOME/zazzles-findings" /path/to/app

# TypeSafe Jev
./bin/scan --analyze --judge jev --output-dir "$HOME/zazzles-findings" /path/to/app
```

Open the printed `findings.html` path. The same folder contains JSON and SARIF. Provider requests
may incur charges. A request cap leaves candidates outside it unassessed. [Scan options](docs/scan/running-scans.md)

### Offline development and troubleshooting

Omit `--judge` to inspect source traces or troubleshoot scanner behavior without model charges.
These runs leave semantic assessments unrun. [Offline evidence inspection](docs/scan/running-scans.md#offline-development-and-troubleshooting)

<a id="how-the-decision-model-judges-a-result"></a>

<a id="how-it-works"></a>

## How Scan works

Zazzles finds supported entry points, follows data through transformations and helper calls, and
identifies the guards on each path to a sensitive operation. The judge answers focused questions
about those paths. For example, it can assess whether a guard rejects untrusted input before it
reaches a sink. Missing evidence keeps the claim in Review.
[Technical approach](docs/technical-approach.md) · [Decision models](docs/scan/decision-models.md)

<a id="how-fast-is-a-scan"></a>

Scan timings vary with the target and the number of assessment requests. [Scan speed](docs/scan/running-scans.md#scan-speed)

## Interpret results

Reports distinguish Confirmed vulnerabilities, poor-practice findings, unresolved Review records
and Protected claims. Protection applies to the specific operation and paths shown. [Read report outcomes](docs/scan/interpreting-results.md) · [Remediation philosophy](docs/philosophy.md)

<a id="explore-sample-findings"></a>
<a id="verify-a-sample-finding-yourself"></a>

## Saved results

Browse saved HTML reports or download their JSON and SARIF evidence. Each sample lists its target
revision, assessment scope and scored results. [Hosted reports](https://zazzcode.github.io/zazzles/) · [Sample index](docs/samples/README.md) · [Verify a sample finding](docs/samples/README.md#verify-a-sample-finding)

## Contributing

Build and test from an assigned feature branch or worktree, then submit a draft PR against
`stage` for human review. [Contributor guide](docs/contributing.md)

## Documentation

Start with the [user guide index](docs/README.md) or the [Scan documentation](docs/scan/README.md).
The [analysis rules](docs/scan/analysis/README.md) describe how Scan evaluates source evidence.

## License

Zazzles is licensed under the [GNU General Public License, version 3](LICENSE), with an
[output exception](OUTPUT-EXCEPTION.md) that lets you use and share the reports it generates under
terms of your choice. Third-party material in [sample reports](docs/samples/README.md) and test
fixtures remains under its own terms; see the license files and notes beside it.
