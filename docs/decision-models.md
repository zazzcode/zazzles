# Required decision-model assessment

[Documentation index](README.md) · [Getting started](getting-started.md) · [Interpret results](interpreting-results.md)

## Core security judgment

Decision-model assessment is required and core to Zazzles' security-assessment workflow. The scanner
builds source-backed traces and operation/guard evidence for the model to judge.
OpenAI Luna Decisions (`gpt-6-luna`, `--judge openai`) is the primary model used for
development and calibration. Google Gemini Decisions is an optional shared adapter; Jev has local
stub coverage. Model answers cannot replace missing source facts or override claim blockers.

Inventory, evidence extraction, deterministic practice checks, saved-report rendering and local tests
can run without an API key. Those are useful inspection/development modes; they do not complete the
model-assessed security workflow. Assessment completion remains separate from independent review
and runtime confirmation.

## Credentials and local environment

Select one model for the whole scan. Every supported analyzer uses this selection:

| Scanner provider | Environment variable | Selection |
|---|---|---|
| OpenAI Decisions | `OPENAI_API_KEY` | `JUDGE_DECISION_MODEL=gpt-6-luna`, `--judge openai` |
| Google Gemini Decisions | `GEMINI_API_KEY` | `JUDGE_DECISION_MODEL=gemini-decision-1`, `--judge gemini` |
| Jev (stub-tested adapter) | `TYPESAFE_API_KEY` | Explicit catalog model in `JUDGE_DECISION_MODEL`, `--judge jev` |

Obtain a key through the selected provider's account/console. Keep it in a password manager or local
ignored `.env`, never chat, tracked files, logs, or command arguments. The tracked
[.env.sample](../.env.sample) has empty credential fields. Preserve an existing `.env` rather than
replacing it. See [environment loading](getting-started.md#local-environment-file): zazzles reads process
environment variables and does not automatically load the file.

Use a single active `JUDGE_DECISION_MODEL` assignment, not a list. If `--judge-model` is also given,
it must match. Provider/model mismatches fail before scanning. Without the environment setting,
explicit CLI selection still works; OpenAI defaults to `gpt-6-luna`, Gemini to `gemini-decision-1`,
and Jev requires an explicit model. Keys do not select a provider and can coexist. No `--judge`
means no model requests, even with a configured model/key.

For the primary OpenAI setup, use your OpenAI API account key as `OPENAI_API_KEY` and set
`JUDGE_DECISION_MODEL=gpt-6-luna`. Manage spending in your API account. No local pricing or
rate configuration is required to start scanning.

For optional Gemini use, create a key in [Google AI Studio](https://aistudio.google.com/api-keys),
set `GEMINI_API_KEY` and select `JUDGE_DECISION_MODEL=gemini-decision-1` with `--judge gemini`.

To switch, edit the one model assignment and use the matching `--judge`. A fresh subshell avoids
stale exported variables. Removing/commenting a key or model in `.env` does not unset an existing
shell variable. Duplicate assignments in a shell file silently use the last value; retain only one.
Never overwrite an existing `.env` to switch providers. Alternative provider-specific model
settings (`SCAN_OPENAI_MODEL`, `SCAN_GEMINI_MODEL`, `SCAN_JEV_MODEL`) must remain unset.

## Rate and spending configuration

Manage API spending and quotas in the provider account. For ordinary OpenAI Luna scans,
use `--judge openai` with a request cap; optional RPM/TPM settings handle quota pacing.
`--judge-limit N` (or `JUDGE_LIMIT`; built-in default 10) caps the candidates sent for assessment
per scan. `.env.sample` sets `JUDGE_LIMIT=1000` as a runaway guard; spending limits belong in the
provider account.
Equivalent entry contexts share one request. Zero-call observations do not consume the cap.
Optional route discovery has its own request allowance.

### Judged-scan reliability

A judged scan is meant to run to the end, including in CI. It stops early for only two reasons:
the decision-model account fails, or the decision model stops responding.

- **Transient failures are retried.** HTTP 408, 429, 500, 502, 503, 504 and 529, timeouts and
  dropped connections are retried up to 3 times. Each retry waits for the provider's `Retry-After`
  when it is at most 60 s, otherwise 2 s, 4 s, then 8 s. Retries pass through RPM and TPM pacing and
  do not use a `--judge-limit` slot, so HTTP requests are at most four times the cap.
- **Other failures affect one candidate.** A different status (such as 400 or 404), a request whose
  retries are exhausted, or an undecodable answer marks only that candidate `failed`, with the
  reason. The scan continues.
- **Account failure stops the scan.** HTTP 401, 402 or 403, or a 429 that reports exhausted quota or
  billing, stops new requests at once.
- **An outage stops the scan.** Five requests in a row that fail after their retries, with no
  success between them, stop new requests as "decision model not responding".

A stopped scan keeps every completed answer, marks the rest `not_run` with the stop reason, prints
`scan: judge stopped: <reason>` to stderr and exits 1. A scan that ran to the end exits 0, even when
some assessments are incomplete; it then prints `scan: warning: some assessments are incomplete`
and each record gives its reason. The `Decision-model limits` line reports `retries N` when any were
sent.

Optional `--judge-rpm` / `JUDGE_RPM` and `--judge-tpm` / `JUDGE_TPM` pace requests against
provider quotas. Both default to zero (disabled), and flags override environment settings.
Discovery and assessment share one rolling rate window. TPM reserves a conservative local
estimate of one input token per 3 request bytes plus 512, and raises it to the reported input usage
when that is larger; it is not a provider tokenizer. Observed requests run about 4 bytes per token,
so set `JUDGE_TPM` just under the account's TPM limit. Oversized requests stop explicitly, and waits can be canceled. With pacing disabled,
the scanner skips rate-window bookkeeping. Spending is managed in the provider console; the
scanner has no dollar budget or token-price configuration.

`--judge-concurrency N` (or `JUDGE_CONCURRENCY`, default 4) caps assessment requests in flight at
once. The value must be a positive integer, and the flag overrides the environment. `1` sends one
request at a time, as earlier releases did. Concurrency changes wall clock only: request bytes,
report order, equivalent-context reuse and token cost are the same at every setting. Before any
request starts, the scanner assigns the `--judge-limit` slots in priority order, so the same
candidates are judged whatever the response timing. RPM and TPM pacing still apply to every
request, so a low RPM limits throughput more than concurrency does.

When the scan stops for an account failure or an outage, up to `N − 1` other requests may already
be in flight. Those requests still complete, and their answers and usage are recorded. The
`Decision-model limits` line in the report counts every attempt, including these.

## Scope a live run

Confirm the target root, entry file, selected route, and allowed source evidence before running:

```bash
(
  set -a
  . ./.env
  set +a
  ./bin/scan --analyze --json --entry server.ts \
    --route /rest/user/login --judge openai --judge-model gpt-6-luna \
    --judge-limit 1 /path/to/app
)
```

For Gemini, set `JUDGE_DECISION_MODEL=gemini-decision-1` in your local environment and replace
`--judge openai --judge-model gpt-6-luna` with `--judge gemini`.

This sends bounded source evidence to the selected provider. The cap is per run; transient failures
are retried without using a slot. Uses beyond the cap remain unassessed with a reason and a stderr
warning, and the scan exits 0. A failed assessment, oversized payload or exhausted cap is retained in
the report; a setup failure before scanning can produce no report. See
[judged-scan reliability](#judged-scan-reliability) for the exit status. Optional `--checks` files specify business and protection requirements; they are
not expected model answers.

## Read outcomes separately

Model choices include sufficient, insufficient, uncertain, and not applicable for the named question.
The raw answers, execution state, and evidence completeness are retained. A supported potential
vulnerability alone remains Review in current presentation. Existing deterministic poor-practice
findings do not disappear because the model was not run or could not establish exploitability.

For authentication/permissions, verify the selected account and key locally without printing it.
For quota/rate failures, inspect that provider's account limits. For an exit-1 JSON report, read the
assessment reason rather than treating it as an empty or protected scan. Saved HTML/SARIF exports
need neither credentials nor another model call.

## Model-bound source and request size

The model receives source-backed trace, operand, guard and invocation evidence, not application
README files or exercise answer keys. Parsed code comments and Python docstrings are masked at their
original positions in the model-facing projection; executable code, runtime strings and relevant
template content remain. Canonical local reports retain original source text and snapshot hashes.
This reduces instruction-like training prose without deleting runtime behavior.

The request builder shares overlapping source excerpts while preserving every evidence role, original
span, snapshot hash and trace/control reference. Requests that would exceed the existing 64 KiB bound
use an explicit compact column schema and shared source/gap records. This is lossless representation
compaction; it does not remove blockers or make missing coverage complete. A request that still
exceeds the bound remains unassessed. Changed projection/envelope inputs invalidate exact replay;
raw historical responses remain intact.

## Component provenance

SQL, NoSQL, standalone-validation and XSS requests compose scanner-owned interpretation material selected
by the static analyzer from verified source facts. Fresh schema-4 JSON reports identify the selected
pack/components, versions and digests; a selection alone does not mean a model assessment ran. SQL
uses `sql-components-v2`, NoSQL `nosql-components-v1` and standalone validation
`validation-components-v1`; XSS uses `xss-components-v1`. Unmigrated families retain their existing protocols. Mandatory evidence
and consistency gates remain in Go.

Missing required material, conflicting selection or size limits prevent a model request and retain
an explicit unresolved assessment. No generic guidance fallback supplies missing protection.
Exact-request replay binds selected content/provenance as well as evidence, questions and model.
Changed requests need fresh assessment; exporting an older report preserves its historical answers
and does not assign it new component identities. See the
[technical approach](technical-approach.md#analysis-knowledge-and-components).


## Outbound observations

Outbound observations have no implemented security assessment. Assessing one returns `not_run` with
an explicit reason, no question version or request digest and zero model HTTP calls. Preview returns
a non-assessable error without a request body. SQL validation/construction questions cannot establish
destination security. Static `analysis_components` metadata describes observation scope only.

A requested scan with an unassessed outbound observation remains incomplete, warns on stderr and
saves its Review record. Zero-call observations consume no request slots. Use `--skip-family outbound` to exclude
that unimplemented assessment explicitly; excluded records remain Review without making the scan incomplete. Structural-only scans do not request model completion. Saved historical
generic answers, versions and statuses remain intact on export; they are not rewritten or replayed
onto new evidence. Full SSRF, exfiltration and browser-security assessment require separate contracts.

## Request granularity

The scanner sends one request per distinct equivalent candidate context, with that analyzer's
applicable questions sharing its evidence slice. Primary security sinks (SQL, NoSQL, command, path,
XSS and logging) run before standalone input-validation checks, preserving order within each tier.

Within a scan, equivalent provider payloads share a completed decision after candidate and route
coordinates are normalized. Callable, sink, transfers, input controls/stages, converters, gaps,
selected components, questions and model remain part of the equivalence key. Derived siblings keep
separate candidate/entry IDs and exact request digests, record `deduplicated_from`, rerun scanner
policy independently, and have no billed usage assigned. `--trace-dir` saves a replayable exact
trace for each sibling. There is no persistent answer cache or cross-analyzer batch.

Use `--only-family path,command` to judge selected families, or `--skip-family outbound,xss`
to exclude families. Names are `sql`, `nosql`, `xss`, `command`, `path`, `logging`,
`input-validation`, and `outbound`. The flags are mutually exclusive; `JUDGE_ONLY_FAMILY` and
`JUDGE_SKIP_FAMILY` provide defaults. Excluded model assessments remain unrun; existing deterministic practice findings are retained,
with scope and deduplication accounting in report limitations. All analyzers use the same scan-wide
provider/model with no automatic fallback. Optional Google probability/confidence metadata never
closes static blockers.
