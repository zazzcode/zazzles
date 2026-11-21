# Zazzles

Zazzles is a modular security project for analyzing application code, checking deployed
endpoints, and remediating findings. **Code Scan** is available today. **Fix** and
**Endpoint Probe** are planned modules.

[Modules](#modules) · [Run Scan](#quick-start) · [Detection capabilities](docs/scan/detection-capabilities.md) · [Sample reports](docs/samples/README.md) · [Documentation](docs/README.md)

## Modules

| Module | Purpose | User docs | Status |
|---|---|---|---|
| [**Code Scan**](scan/README.md) (`scan/`) | Analyzes JavaScript, TypeScript, Python and PHP source for vulnerabilities, evidence gaps, and code smells or poor coding practices that can impact security or performance. Reports include the affected operation, input paths, observed controls and evidence gaps. Optional model assessment uses that evidence to judge supported claims. | [Scan docs](docs/scan/README.md) | Available and in active development |
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

```bash
git clone --branch stage https://github.com/zazzcode/zazzles.git
cd zazzles
go build -o bin/scan ./scan/cmd/scan
```

The root compatibility entry point `go build -o bin/scan ./cmd/scan` builds the same executable.

<a id="run"></a>
<a id="3-scan-and-open-the-report"></a>

Run a source-only scan and open the printed `findings.html` path. The same run folder contains
JSON for tooling and SARIF for security platforms.

```bash
./bin/scan --analyze --output-dir "$HOME/zazzles-findings" /path/to/app
```

<a id="2-configure-openai-luna-decisions"></a>
<a id="optional-use-google-gemini-decisions-instead"></a>

To assess claims with a model, configure a provider and use `--judge`. The example caps the run
at ten requests. Remaining candidates stay unassessed. [Decision-model setup](docs/scan/decision-models.md) · [Scan options](docs/scan/running-scans.md)

```bash
./bin/scan --analyze --judge openai --judge-limit 10 \
  --output-dir "$HOME/zazzles-findings" /path/to/app
```

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
impact security or performance. In a judged scan, the model answers bounded questions about
that evidence. The scanner verifies the answers against its facts before classifying the claim.
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
