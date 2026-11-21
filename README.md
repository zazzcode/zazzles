# Zazzles

Zazzles is a modular security project for analyzing application code, checking deployed
endpoints, and remediating findings. **Code Scan** is available today. **Fix** and
**Endpoint Probe** are planned modules.

**Decision-model judgment is central to Code Scan.** Static analysis traces input to sensitive
operations and records the controls on each path. A decision LLM evaluates that evidence to help
distinguish vulnerabilities from protected or inconclusive paths and reduce false positives.
Zazzles checks the answers against its source facts before assigning an outcome.

[Modules](#modules) · [Run Scan](#quick-start) · [Detection capabilities](docs/scan/detection-capabilities.md) · [Sample reports](docs/samples/README.md) · [Documentation](docs/README.md)

## Modules

| Module | Purpose | User docs | Status |
|---|---|---|---|
| [**Code Scan**](scan/README.md) (`scan/`) | Analyzes JavaScript, TypeScript, Python and PHP source for vulnerabilities, evidence gaps, and code smells or poor coding practices that can impact security or performance. Combines source-backed traces with a decision-model judge to classify supported claims. Reports show the operation, input paths, controls and evidence gaps. | [Scan docs](docs/scan/README.md) | Available and in active development |
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

<a id="what-exists-today"></a>
<a id="scan-current-implementation"></a>
<a id="entry-use-cases-and-delivery-status"></a>

## Current coverage

The [coverage index](docs/scan/detection-capabilities.md) lists each weakness, the `--only-family`
selector, supported entry points and known gaps. It also links to standalone field validation and
framework practice checks. The [unsafe deserialization analyzer](docs/scan/detection-capabilities/unsafe-deserialization.md) covers Python, server-side JavaScript and TypeScript, and PHP.

<a id="how-the-decision-model-judges-a-result"></a>

<a id="how-it-works"></a>

## How Scan works

Zazzles finds supported entry points, follows input to a sensitive operation and records guards
and transformations along the path. It also flags code smells and poor coding practices that can
impact security or performance. The judge answers bounded questions about whether the observed
controls are effective for the claim. The scanner validates the answers against the evidence and
keeps unresolved claims in Review.
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
revision, assessment scope and scored results. [Hosted reports](https://zazzcode.github.io/zazzles/docs/samples/) · [Sample index](docs/samples/README.md) · [Verify a sample finding](docs/samples/README.md#verify-a-sample-finding)

## Contributing

Build and test from an assigned feature branch or worktree, then submit a draft PR against
`stage` for human review. [Contributor guide](docs/contributing.md)

## Documentation

Start with the [user guide index](docs/README.md) or the [Scan documentation](docs/scan/README.md).
The [analysis rules](docs/scan/analysis/README.md) describe how Scan evaluates source evidence.
