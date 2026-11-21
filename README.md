# Zazzles

Zazzles is a modular security project for analyzing application code, checking deployed
endpoints, and remediating findings. **Scan** is available today. **Fix** and **Probe** are
planned modules.

[Modules](#modules) · [Run Scan](#quick-start) · [Detection capabilities](docs/detection-capabilities.md) · [Sample reports](docs/samples/README.md) · [Documentation](docs/README.md)

## Modules

| Module | Purpose | Status |
|---|---|---|
| [**Scan**](scan/README.md) | Analyzes JavaScript, TypeScript, Python and PHP source for vulnerabilities and practices worth fixing. Reports include the affected operation, input paths, observed controls and evidence gaps. Optional model assessment uses that evidence to judge supported claims. | Available and in active development |
| [**Fix**](fix/README.md) | Gives coding agents skills, standards and playbooks for fixing findings from Zazzles or other SAST, dependency audit and DAST tools. Guides agents from the finding evidence through a repair and verification. | Planned |
| [**Probe**](probe/README.md) | Checks externally observable security settings on authorized endpoints. Initial coverage will include TLS versions and configuration, expired certificates and related issues, with evidence and remediation recommendations. | Planned |

<a id="project-direction"></a>
<a id="project-goals-scan-inspect-audit-and-fix"></a>
<a id="project-goals-scan-audit-and-fix"></a>
<a id="project-goals-scan-quality-audit-and-fix"></a>
<a id="the-vision-scan-inspect-audit-and-fix"></a>

Scan is the current development focus. Fix is expected to come before Probe.
[Implementation plan](.zazz/project/implementation-plan.md)

<a id="setup"></a>

## Quick start

Install the Go version in [`go.mod`](go.mod) and a C compiler. Build the scanner from a checkout
of `stage`, then point it at a local application checkout. [Setup guide](docs/getting-started.md)

<a id="1-build-the-scanner"></a>

```bash
git clone --branch stage https://github.com/zazzcode/zazzles.git
cd zazzles
go build -o bin/scan ./cmd/scan
```

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
at ten requests. Remaining candidates stay unassessed. [Decision-model setup](docs/decision-models.md) · [Scan options](docs/running-scans.md)

```bash
./bin/scan --analyze --judge openai --judge-limit 10 \
  --output-dir "$HOME/zazzles-findings" /path/to/app
```

<a id="what-exists-today"></a>
<a id="scan-current-implementation"></a>
<a id="entry-use-cases-and-delivery-status"></a>

## Current coverage

The [coverage index](docs/detection-capabilities.md) lists each weakness, the `--only-family`
selector, supported entry points and known gaps. It also links to standalone field validation and
framework practice checks.

<a id="how-the-decision-model-judges-a-result"></a>

<a id="how-it-works"></a>

## How Scan works

Zazzles finds supported entry points, follows input to a sensitive operation and records guards
and transformations along the path. In a judged scan, the model answers bounded questions about
that evidence. The scanner verifies the answers against its facts before classifying the claim.
[Technical approach](docs/technical-approach.md) · [Decision models](docs/decision-models.md)

<a id="how-fast-is-a-scan"></a>

Scan timings vary with the target and the number of assessment requests. [Scan speed](docs/running-scans.md#scan-speed)

## Interpret results

Reports distinguish Confirmed vulnerabilities, poor-practice findings, unresolved Review records
and Protected claims. Protection applies to the specific operation and paths shown. [Read report outcomes](docs/interpreting-results.md) · [Remediation philosophy](docs/philosophy.md)

<a id="explore-sample-findings"></a>
<a id="verify-a-sample-finding-yourself"></a>

## Saved results

Browse saved HTML reports or download their JSON and SARIF evidence. Each sample lists its target
revision and the scanner’s assessment scope. [Hosted reports](https://zazzcode.github.io/zazzles/docs/samples/) · [Sample index](docs/samples/README.md) · [Verify a sample finding](docs/samples/README.md#verify-a-sample-finding)

### Paid scans of the vuln-nextjs lab

The [JavaScript and TypeScript lab sample](docs/samples/vuln-nextjs/README.md) includes both reports. They used OpenAI `gpt-6-luna` and were scored against the lab’s expected cases.

| Saved report | Run date and lab pin | Paid requests | Expected positives | Detected |
|---|---|---:|---|---|
| [Full Pages Router app](https://zazzcode.github.io/zazzles/docs/samples/vuln-nextjs/findings.html) · [Full scan results](docs/samples/vuln-nextjs/README.md#full-application-scan) | 2026-11-19 · `ea10efb` | 27 | 13 in scope | 13 found (12 Confirmed and 1 practice finding) |
| [Prototype pollution fixtures](https://zazzcode.github.io/zazzles/docs/samples/vuln-nextjs/reports/prototype-pollution/findings.html) · [Fixture results](docs/samples/vuln-nextjs/README.md#prototype-pollution-fixture-scan) | 2026-11-21 · `8d26f52` | 19 | 17 in the key, 15 in scope | 14 Confirmed, 1 Review, 2 dependency cases with no record |

Both runs had zero findings on the keyed safe controls. The walk-start branch was verified
separately with an [offline rescan](.zazz/evaluation/pollution-walk-start-results.md#six-sample-noise-check).

## Contributing

Build and test from an assigned feature branch or worktree, then submit a draft PR against
`stage` for human review. [Contributor guide](docs/contributing.md)

## Documentation

Start with the [user guide index](docs/README.md). The [analysis rules](docs/analysis/README.md)
describe how the scanner evaluates source evidence.
