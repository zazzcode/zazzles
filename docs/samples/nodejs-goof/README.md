# Node.js Goof evaluation sample

[All samples](../README.md) · [Bearer runbook](bearer-runbook.md) ·
[Capability inventory](../../../.zazz/evaluation/nodejs-goof-capabilities.md) ·
[Independent XSS answer key](xss-answer-key.md)

Added 2026-11-01 from [Snyk Labs Node.js Goof](https://github.com/snyk-labs/nodejs-goof),
package version `1.0.1`, revision `add14ba59e98240d9e00a235dd7d42cd61ae9912`.
The local reference checkout is `<DEV_ROOT>/nodejs-goof`; see the
[workspace convention](../../../.zazz/docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root).
The checkout was clean when inspected. Its README, package manifest, route registrations,
handlers and templates supplied the initial case inventory.

## Command-injection acceptance scan (2026-11-07)

The report linked above is now a full source-transmitting scan with OpenAI Decisions `gpt-6-luna` at scanner
revision `6f5cb711fe06…` (no family filter; the target stayed clean at pin `add14ba59e98…`). It has 19 entries
and 34 records. The original full pass used
34 provider requests (255,630 input tokens). **Command injection:** `POST /create` → `routes/index.js:174` `exec('identify ' + url)`, where `url` is the capture group of a regex over `req.body.content`, is a completed, gated `confirmed_vulnerability` (shell syntax, CWE-78).
Observation-only and unsupported records remain visible and unassessed; no application is declared safe and no
runtime exploitation is claimed. See the [acceptance results](../../../.zazz/evaluation/command-injection-results.md)
and [metadata](metadata.json). Earlier sections below describe previous published snapshots and are superseded by the counts here.

A later scoped NoSQL follow-up established the unmodified Express URL ID and default ObjectId casting
for `GET /destroy/:id` and `POST /update/:id`. Two fresh Luna judgments (24,847 input tokens) marked
those injection claims Protected; the other 32 judgments replayed exactly, including the confirmed
command case. The current report has **4 Findings, 27 Review and 3 Protected** records. This was not
a new full paid scan. Protection of ID lookup does not establish authorization or ownership checks.

## Previous published report

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

The current source scan has **19 route entries and 33 use records** across XSS, input validation,
Mongoose NoSQL and logging. It includes the mounted `/users` routes. Two records are Findings
(reflected login XSS, now a source-complete static Luna judgment; stored todo Markdown output,
orange construction finding). Twenty-nine are Review and two are Protected: the edit template's
escaped todo-content text and quoted attribute. Account-details fields remain Review because the
whole request object also controls rendering options. No route or application is declared safe.

Five explicitly approved `gpt-6-luna` decisions are saved with raw request/response bodies and scored
answers in the [decision evaluation](decisions/20261101-five-case-01/README.md). Other uses are
unassessed. The [independent answer key](xss-answer-key.md) defines expected source properties;
model answers never replace it. No target runtime/exploit or remediation was performed.

## Initial comparator baseline

The [pre-XSS comparison](../../../.zazz/evaluation/nodejs-goof-results.md) and
[Bearer summary](bearer/20261101-goof-baseline-02/SUMMARY.md) retain the historical 43 findings / 12
rules, including the false XSS record at fixed script creation. The initial zazzles evidence scan
had zero routes/uses because CommonJS was unsupported. Historical per-increment reports are
snapshots; earlier account-details protection labels were superseded by the current Review status.

## Saved results

Curated Bearer runs belong under `docs/samples/nodejs-goof/bearer/<run-id>/`.
Each run MUST contain these files before being listed here as a completed baseline:

| File | Purpose |
|---|---|
| `bearer-nodejs-goof.json` | Unmodified Bearer findings, grouped by severity |
| `bearer-nodejs-goof.log` | Debug diagnostics, including worker/file failures |
| `bearer-nodejs-goof.execution.json` | Exact command, duration, exit status and validity |
| `metadata.json` | Tool/rules/target identities, binary hash and environment policy |
| `nodejs-goof.scope.json` | Included source paths and SHA256 hashes, exclusions and revision |
| `bearer-version.txt`, `bearer-scan-help.txt` | Inspected binary version and supported flags |
| `SUMMARY.md` | Reviewed rule/severity totals, case matches, omissions and limitations |

The sample directory is published by the repository's sample Pages workflow. Review logs and
metadata before copying them here. Do not retain or publish Goof source snapshots: the runbook
deletes its temporary snapshot after the scan. Raw run output and machine-local paths stay in
`<DEV_ROOT>/zazzcode/zazzles/_test-findings/`. Preserve raw diagnostics there if a public log needs redaction and record
the redaction in `SUMMARY.md`. Include the upstream Apache-2.0 license when publishing source
excerpts. Do not overwrite prior runs or create empty findings as a substitute for a pending run.

Zazzles `findings.json`, HTML and SARIF reports are separate artifacts under `zazzles/<run-id>/`. The sample refresh script handles all three current zazzles reports; it does not ingest Bearer JSON.
