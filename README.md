# Zazzles

Zazzles scans JavaScript, TypeScript, Python and PHP application source for security
vulnerabilities and practices worth fixing. Each reported claim links to the operation, the
input paths and controls the scanner found, and any evidence still needed.

[Get started](#quick-start) · [Detection capabilities](docs/detection-capabilities.md) · [Sample reports](docs/samples/README.md) · [Documentation](docs/README.md)

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

## How it works

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

Both reports used OpenAI `gpt-6-luna` and were scored against the lab’s expected cases.

| Saved report | Run date and lab pin | Paid requests | Expected positives | Detected |
|---|---|---:|---|---|
| [Full Pages Router app](https://zazzcode.github.io/zazzles/docs/samples/vuln-nextjs/findings.html) · [Sample notes](docs/samples/vuln-nextjs/README.md) | 2026-11-19 · `ea10efb` | 27 | 13 in scope | 13 found (12 Confirmed and 1 practice finding) |
| [Prototype pollution fixtures](https://zazzcode.github.io/zazzles/docs/samples/vuln-nextjs-prototype-pollution/findings.html) · [Sample notes](docs/samples/vuln-nextjs-prototype-pollution/README.md) | 2026-11-21 · `8d26f52` | 19 | 17 in the key, 15 in scope | 14 Confirmed, 1 Review, 2 dependency cases with no record |

Both runs had zero findings on the keyed safe controls. The walk-start branch was verified
separately with an [offline rescan](.zazz/evaluation/pollution-walk-start-results.md#six-sample-noise-check).

<a id="project-goals-scan-inspect-audit-and-fix"></a>
<a id="project-goals-scan-audit-and-fix"></a>
<a id="project-goals-scan-quality-audit-and-fix"></a>
<a id="the-vision-scan-inspect-audit-and-fix"></a>

## Project direction

Scan is available today and includes practice checks. The roadmap covers a separate Inspect
workflow, dependency Audit, and agent-assisted Fix. [Implementation plan](.zazz/project/implementation-plan.md)

## Contributing

Build and test from an assigned feature branch or worktree, then submit a draft PR against
`stage` for human review. [Contributor guide](docs/contributing.md)

## Documentation

Start with the [user guide index](docs/README.md). The [analysis rules](docs/analysis/README.md)
describe how the scanner evaluates source evidence.
