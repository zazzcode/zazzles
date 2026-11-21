# Zazzles user documentation

Start here to scan a local JavaScript, TypeScript, Python or PHP application and act on the
source evidence in the report.

<a id="table-of-contents"></a>

## Run and read a scan

| Guide | What it covers |
|---|---|
| [Getting started](getting-started.md) | Compiler requirements, building the scanner and local configuration |
| [Running scans](running-scans.md) | Offline and judged scans, entry and family selection, report output and scan limits |
| [Decision models](decision-models.md) | Providers, credentials, bounded request evidence and spending controls |
| [Interpreting results](interpreting-results.md) | Finding, Review and Protected outcomes, evidence, counts and remediation |
| [Sample reports](samples/README.md) | Saved HTML, JSON and SARIF, target revisions and a verification walkthrough |

## Look up coverage

- [Detection capabilities](detection-capabilities.md) indexes weakness classes, CWE mappings, analyzer selectors and entry points.
- [Analysis rules](analysis/README.md) explain how Zazzles interprets specific operations, guards and evidence.
- [Finding categories and terminology](glossary.md) defines labels used in reports.
- [Next.js](nextjs-support.md), [Python](python-support.md) and [PHP](php-support.md) describe their entry and language boundaries.

## Understand and contribute

- [Technical approach](technical-approach.md) explains source-backed analysis and decision validation.
- [Remediation philosophy](philosophy.md) explains how to preserve behavior and existing protection when fixing a finding.
- [CI/CD reports](ci.md) covers report artifacts in build pipelines.
- [Contributing](contributing.md) covers verification, pull requests and documentation ownership.
- [Semgrep CE comparison](semgrep-ce-cheat-sheet.md) explains how to run a local comparison.

## First steps

[Build the scanner](getting-started.md#compile), [run a local scan](running-scans.md#run), and open
the printed HTML path. To assess supported claims with a decision model, follow the
[provider setup](decision-models.md#credentials-and-local-environment).
