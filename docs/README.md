# Zazzles user documentation

Zazzles is organized into three modules under one repository: **Code Scan** (`scan/`, available
today), **Fix** (`fix/`, planned), and **Endpoint Probe** (`probe/`, planned).

<a id="table-of-contents"></a>

## Modules

| Module | Documentation | What it covers |
|---|---|---|
| **Code Scan** | [Code Scan user documentation](scan/README.md) | Setup, decision-model judgment, result interpretation, coverage, and analysis rules |
| **Fix** | [Fix user documentation](fix/README.md) | Planned agent skills, standards, and playbooks for remediating findings from Zazzles modules and external SAST, dependency audit, DAST, and endpoint probe / TLS & certificate scanners (such as Nuclei) |
| **Endpoint Probe** | [Endpoint Probe user documentation](probe/README.md) | Planned authorized endpoint checks starting with TLS and certificates (similar to TLS & certificate scanners such as Nuclei), with remediation guidance |

## Run and read a scan

| Guide | What it covers |
|---|---|
| [Getting started](scan/getting-started.md) | Compiler requirements, building the scanner and local configuration |
| [Running scans](scan/running-scans.md) | Judged scans, offline troubleshooting, scope, report output and scan limits |
| [Decision models](scan/decision-models.md) | Providers, credentials, bounded request evidence and spending controls |
| [Interpreting results](scan/interpreting-results.md) | Finding, poor-practice, Review and Protected outcomes, evidence, counts and remediation |
| [Sample reports](samples/README.md) | Saved HTML, JSON and SARIF, target revisions and a verification walkthrough |

## Look up coverage

- [Detection capabilities](scan/detection-capabilities.md) indexes weakness classes, CWE mappings, analyzer selectors and entry points.
- [Analysis rules](scan/analysis/README.md) explain how Zazzles interprets specific operations, guards and evidence.
- [Finding categories and terminology](scan/glossary.md) defines labels used in reports.
- [Next.js](scan/nextjs-support.md), [Python](scan/python-support.md), [PHP](scan/php-support.md), and [Symfony](scan/symfony-support.md) describe their entry and language boundaries.

## Shared project guides

- [Technical approach](technical-approach.md) explains source-backed analysis and decision validation.
- [Remediation philosophy](philosophy.md) explains how to preserve behavior and existing protection when fixing a finding.
- [CI/CD reports](scan/ci.md) covers report artifacts in build pipelines.
- [Contributing](contributing.md) covers repository layout, verification, pull requests and documentation ownership.
- [Semgrep CE comparison](scan/semgrep-ce-cheat-sheet.md) explains how to run a local comparison.

## First steps

[Build the scanner](scan/getting-started.md#compile), [configure a decision model](scan/decision-models.md#credentials-and-local-environment),
and [run a judged scan](scan/running-scans.md#run). Open the printed HTML path to inspect results.
