# Code Scan user documentation

[Zazzles documentation](../README.md) · [Code Scan module](../../scan/README.md) · [Project introduction](../../README.md)

**Code Scan** (`scan/`) analyzes JavaScript, TypeScript, Python, and PHP source for security
vulnerabilities, evidence gaps, and code smells or poor coding practices that can impact security
or performance. It uses a decision-model judge to assess source-backed claims and checks the
answers against scanner evidence before classifying them.

## Run and read a scan

| Guide | What it covers |
|---|---|
| [Getting started](getting-started.md) | Compiler requirements, building the scanner, and local configuration |
| [Running scans](running-scans.md) | Judged scans, offline troubleshooting, scope, report output, and scan limits |
| [Decision models](decision-models.md) | Providers, credentials, bounded request evidence, and rate controls |
| [Interpreting results](interpreting-results.md) | Confirmed, poor-practice, Review, and Protected outcomes, evidence, counts, and remediation |
| [CI/CD reports](ci.md) | Producing and retaining report artifacts in build pipelines |
| [Sample reports](../samples/README.md) | Saved HTML, JSON, and SARIF outputs, target revisions, and a verification walkthrough |

## Coverage and analysis rules

- [Detection capabilities](detection-capabilities.md) indexes weakness classes, CWE mappings,
  `--only-family` selectors, supported entry points, and framework practice checks.
- [Analysis rules](analysis/README.md) explain how Scan interprets operations, guards, evidence,
  and poor-practice findings.
- [Finding categories and terminology](glossary.md) defines labels used in reports.
- [Next.js](nextjs-support.md), [Python](python-support.md), and [PHP](php-support.md) describe
  their entry and language boundaries.
- [Semgrep CE comparison](semgrep-ce-cheat-sheet.md) explains how to run a local comparison.

## Shared project guides

- [Technical approach](../technical-approach.md) explains source-backed analysis and decision validation.
- [Remediation philosophy](../philosophy.md) explains how to preserve behavior and existing protections.
- [Contributing](../contributing.md) covers repository layout, verification, and pull requests.
