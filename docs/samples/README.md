# Sample findings reports

[Project introduction](../../README.md) · [User documentation](../README.md) · [Interpret results](../scan/interpreting-results.md)

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
| [VulnPy](vulnpy/README.md) | [findings.html](vulnpy/findings.html) | [JSON, gzip](vulnpy/findings.json.gz) | [SARIF, gzip](vulnpy/findings.sarif.gz) |
| [OSS OopsSec Store (Next.js App Router)](oss-oopssec-store/README.md) | [findings.html](oss-oopssec-store/findings.html) | [findings.json](oss-oopssec-store/findings.json) | [findings.sarif](oss-oopssec-store/findings.sarif) |
| [vuln-nextjs JavaScript and TypeScript lab](vuln-nextjs/README.md) | [Full app](vuln-nextjs/findings.html) · [Prototype pollution fixtures](vuln-nextjs/reports/prototype-pollution/findings.html) | [Full app](vuln-nextjs/findings.json) · [Fixtures](vuln-nextjs/reports/prototype-pollution/findings.json) | [Full app](vuln-nextjs/findings.sarif) · [Fixtures](vuln-nextjs/reports/prototype-pollution/findings.sarif) |
| [DVWA (PHP)](dvwa/README.md) | [findings.html](dvwa/findings.html) | [JSON, gzip](dvwa/findings.json.gz) | [SARIF, gzip](dvwa/findings.sarif.gz) |
| [VulnerableSymfony (PHP, Symfony)](vuln-symfony/README.md) | [findings.html](vuln-symfony/findings.html) | [findings.json](vuln-symfony/findings.json) | [findings.sarif](vuln-symfony/findings.sarif) |

Each sample represents one application. An application’s notes list its published scans with
the target revision, scanner revision, assessment scope and observed outcomes. Use those notes when comparing a report with its
[source-reviewed expectations](../../.zazz/project/vulnerable-sample-apps.md).
The [reference policy](reference-policy.md) explains how the project evaluates keyed cases and
keeps source baselines reproducible. Dated cross-sample measures live in the
[evidence-resolution evaluation](../../.zazz/evaluation/model-resolution-results.md#accuracy-against-the-answer-keys)
and the [prototype pollution evaluation](../../.zazz/evaluation/pollution-write-shapes-results.md#ac8-live-judgment).
The [Semgrep comparison](../../.zazz/evaluation/semgrep-results.md) and
[Goof Bearer baseline](nodejs-goof/bearer/20261101-goof-baseline-02/SUMMARY.md) record external baselines.

Open an HTML report and expand an entry to see the finding location, evidence and remediation.
The **Hide protected results** filter changes the report view. JSON preserves the full evidence.
[Interpreting results](../scan/interpreting-results.md)

These are evolving examples, not a complete benchmark or independent accuracy claim. Sample READMEs
record target versions, actual assessment coverage, and current limitations. Inconclusive and
unassessed records remain visible. The target root is replaced with its public project name; relative
source locations, hashes, use IDs, and provider judgments are preserved. Source excerpts belong to
the upstream projects; vulnerable fixture values are training data, not scan provider credentials.

## Verify a sample finding

Use the target revision and scan scope in a sample’s notes. For the TypeScript command finding,
use a checkout of the sample pinned to `7f8b240a2f02beba099da3632d1ba679ff8bc32f`.
From the scanner checkout, run this scoped scan after
[configuring the decision provider](../scan/decision-models.md#credentials-and-local-environment).

```bash
./bin/scan --analyze --entry src/server.ts --route /api/ping \
  --only-family command --judge openai --judge-limit 1 \
  --output-dir "$HOME/zazzles-findings" /path/to/vulnerable-typescript-app
```

In the HTML report, expand `GET /api/ping` and compare the command call, input path and
judgment with the saved report. For evidence inspection without paid requests, omit the judge
flags. [Sample notes](vulnerable-typescript-app/README.md) ·
[Reference policy](reference-policy.md)

## Refresh as zazzles improves

Build scan, then regenerate both checked-in HTML/SARIF views from the saved JSON:

```bash
go build -o bin/scan ./scan/cmd/scan
python3 docs/samples/refresh.py --scan ./bin/scan
```

Use `--sample ThreatByte` (repeatable) to refresh selected applications. Selecting an application
refreshes its main report and any scoped reports under `reports/<scope>/`. Add new scoped reports
to the same application directory with their own metadata and a link from the app’s README. This updates presentation only, offline. To publish improved analysis, run a fresh target scan into
your external findings directory (`<DEV_ROOT>/zazzcode/zazzles/_test-findings/`), replace the corresponding sample `findings.json` with that
run's canonical JSON, update its README's target revision/date/assessment coverage, then run the
refresh command. The script normalizes the public root label and exports matching HTML/SARIF.

Saved model judgments may be carried into a fresh scan only for a use whose whole evidence is
byte-identical to the judged use. A use whose evidence changed is published as not assessed until it
is judged again; never copy an old answer onto changed evidence.
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

<a id="vulnpy-coverage-corpus"></a>

### Evaluation records

- [Python support](../../.zazz/evaluation/python-support-results.md) records offline discovery and live judgment at its sample pins.
- [VulnPy coverage](../../.zazz/evaluation/vulnpy-detection-guide.md) records generated routes, source-backed expectations and registration controls.
- [PHP support](../../.zazz/evaluation/php-support-results.md) and [command bypass support](../../.zazz/evaluation/command-bypass-support-results.md) record the DVWA evaluations.
- [Symfony results](../../.zazz/evaluation/symfony-results.md) record the VulnerableSymfony evaluations, and the [DVWA results](../../.zazz/evaluation/dvwa-results.md) the latest DVWA runs. The VulnerableSymfony excerpts are under CC BY-NC-SA 4.0; see the [sample notes](vuln-symfony/README.md#licence-of-the-source-excerpts).

For oversized reports, `refresh.py --compress` stores complete JSON/SARIF as gzip; existing gzip
samples retain that format on subsequent refreshes, including when fresh plain canonical JSON is copied in.
