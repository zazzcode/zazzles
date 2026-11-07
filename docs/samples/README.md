# Sample findings reports

[Project introduction](../../README.md) · [User documentation](../README.md) · [Interpret results](../interpreting-results.md)

Explore actual scan output without installing the targets, configuring keys, or calling a model.
Open the [hosted samples](https://zazzcode.github.io/zazzles/docs/samples/) in your browser, or download a standalone HTML file and open it
locally. GitHub's file view displays HTML source; it does not run the report.

| Sample | HTML report | Agent-readable evidence | Standard interchange |
|---|---|---|---|
| [OWASP Juice Shop](juice-shop/README.md) | [findings.html](juice-shop/findings.html) | [findings.json](juice-shop/findings.json) | [findings.sarif](juice-shop/findings.sarif) |
| [Vulnerable TypeScript app](vulnerable-typescript-app/README.md) | [findings.html](vulnerable-typescript-app/findings.html) | [findings.json](vulnerable-typescript-app/findings.json) | [findings.sarif](vulnerable-typescript-app/findings.sarif) |
| [Node.js Goof](nodejs-goof/README.md) | [findings.html](nodejs-goof/findings.html) | [findings.json](nodejs-goof/findings.json) | [findings.sarif](nodejs-goof/findings.sarif) |
| [ThreatByte (Python)](ThreatByte/README.md) | [findings.html](ThreatByte/findings.html) | [findings.json](ThreatByte/findings.json) | [findings.sarif](ThreatByte/findings.sarif) |
| [Python insecure app](python-insecure-app/README.md) | [findings.html](python-insecure-app/findings.html) | [findings.json](python-insecure-app/findings.json) | [findings.sarif](python-insecure-app/findings.sarif) |
| [Vulnerable Flask App](vulnerable-flask-app/README.md) | [findings.html](vulnerable-flask-app/findings.html) | [findings.json](vulnerable-flask-app/findings.json) | [findings.sarif](vulnerable-flask-app/findings.sarif) |
| [VulnPy](vulnpy/README.md) | [findings.html](vulnpy/findings.html) | [findings.json](vulnpy/findings.json) | [findings.sarif](vulnpy/findings.sarif) |

The reports include XSS discovery and the **Hide protected results** remediation
filter. Server/API routes and browser/client-side sources have separate sections and headings.
[Source-reviewed answer keys and remediation-copy policy](reference-policy.md) explain why specific
baseline flows are vulnerable, protected or unresolved, independently of detector output. Goof's
[Bearer baseline](nodejs-goof/bearer/20261101-goof-baseline-02/SUMMARY.md) and
[five-case Decisions evaluation](nodejs-goof/decisions/20261101-five-case-01/README.md) are saved
separately from the canonical zazzles results. Semgrep CE comparison runs follow the
[Semgrep CE cheat sheet](../semgrep-ce-cheat-sheet.md). Normalized Semgrep CE baselines for all three apps are
under `<app>/semgrep/20261101-baseline-01/` (JSON, SARIF, text), compared in the
[Semgrep results](../../.zazz/evaluation/semgrep-results.md).

Reports start with the grouped Findings → Review → Protected sort, highest counts first, then route
path A–Z; blank rows appear last. Click that grouped header or Route signature to change the order.
Expand a row for evidence and remediation. Type pills open the glossary. HTML is standalone, with
no external resources or model calls. JSON preserves richer analysis context.

These are evolving examples, not a complete benchmark or independent accuracy claim. Sample READMEs
record target versions, actual assessment coverage, and current limitations. Inconclusive and
unassessed records remain visible. The target root is replaced with its public project name; relative
source locations, hashes, use IDs, and provider judgments are preserved. Source excerpts belong to
the upstream projects; vulnerable fixture values are training data, not scan provider credentials.

## Refresh as zazzles improves

Build scan, then regenerate both checked-in HTML/SARIF views from the saved JSON:

```bash
go build -o bin/scan ./cmd/scan
python3 docs/samples/refresh.py --scan ./bin/scan
```

Use `--sample ThreatByte` (repeatable) to refresh only selected reports. This updates presentation only, offline. To publish improved analysis, run a fresh target scan into
your external findings directory (`<DEV_ROOT>/zazzcode/zazzles/_test-findings/`), replace the corresponding sample `findings.json` with that
run's canonical JSON, update its README's target revision/date/assessment coverage, then run the
refresh command. The script normalizes the public root label and exports matching HTML/SARIF.

Saved model judgments may be carried into a fresh scan only for a use whose whole evidence is
byte-identical to the judged use. A use whose evidence changed is published as not assessed until it
is judged again; never copy an old answer onto changed evidence.
Do not copy old judgments onto changed source evidence or invent missing model assessments.
Review the diff and preserve upstream attribution before committing the refreshed samples.

Routine scans continue to write outside the worktree. Only these deliberately curated samples are
checked in. Keep the affected sample applications current when analysis or reporting behavior changes.

## Browser-hosted previews

GitHub Pages currently deploys the `stage` branch (Settings → Pages → *Deploy from a branch*, `stage`,
root), so the reports are served under https://zazzcode.github.io/zazzles/docs/samples/, with an index linking the sample apps.
Changes reach the site when a feature branch merges into `stage`; nothing is published from feature branches.
No scan execution or provider keys are needed.

The **Publish sample findings** GitHub Actions workflow can instead publish only this directory at the
site root (`https://zazzcode.github.io/zazzles/<app>/findings.html`). To use it, a maintainer selects
**GitHub Actions** under Settings → Pages; the README links must then drop the `docs/samples/` segment.

The [Python evaluation](../../.zazz/evaluation/python-support-results.md) records 22 scoped case
checks, nine reviewed SQL/XSS discovery cases, 78 live Luna requests and the retained Review boundaries.
Python NoSQL is out of this corpus; no sample contains a MongoDB driver.

## VulnPy coverage corpus

[VulnPy](vulnpy/README.md) adds dynamically generated Python route/trigger coverage and source-backed
SQL/XSS expectations. Its six known positive misses remain visible; four controls require explicit
coverage warnings. [Living guide](../../.zazz/evaluation/vulnpy-detection-guide.md).
