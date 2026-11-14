# Required decision-model assessment

[Documentation index](README.md) · [Getting started](getting-started.md) · [Interpret results](interpreting-results.md)

## Core security judgment

Decision-model assessment is required and core to Zazzles' security-assessment workflow. The scanner
builds source-backed traces and operation/guard evidence for the model to judge.
The shared judge supports OpenAI Decisions using Luna (`gpt-6-luna`) and Google Gemini Decisions
using `gemini-decision-1`. Jev has an adapter with local stub coverage; it has not been live-validated
in this delivery. Model answers cannot replace missing source facts or override claim blockers.

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

For Google, create an API key in [Google AI Studio](https://aistudio.google.com/api-keys).
The key is shared across Gemini models, but Zazzles accepts only `gemini-decision-1`. It sends the
model explicitly to `/v1beta/decisions` using Google's API-key header. The current Go integration
uses the documented REST API: the latest released Go GenAI SDK checked (v1.77.0) lacks Decisions;
Google's Python/JS SDK examples require 3.2+. See the
[official model](https://aistudio.google.com/docs/models/gemini-decision-1) and
[Decisions API](https://aistudio.google.com/docs/decisions-api).

To switch, edit the one model assignment and use the matching `--judge`. A fresh subshell avoids
stale exported variables. Removing/commenting a key or model in `.env` does not unset an existing
shell variable. Duplicate assignments in a shell file silently use the last value; retain only one.
Never overwrite an existing `.env` to switch providers. Alternative provider-specific model
settings (`SCAN_OPENAI_MODEL`, `SCAN_GEMINI_MODEL`, `SCAN_JEV_MODEL`) must remain unset.

## Rate and spending configuration

A funded account is separate from source-transmission permission. Requests remain sequential. Set limits
through process environment or flags; flags take precedence. The scanner does not auto-load `.env`.
Loading settings never enables paid calls: `--judge` remains explicit.

| Flag | Environment | Default |
|---|---|---|
| `--judge-limit` | `JUDGE_LIMIT` | 10 assessment requests; discovery retains its separate request allowance |
| `--judge-budget-usd` | `JUDGE_BUDGET_USD` | 0 (disabled) |
| `--judge-input-usd-per-million` | `JUDGE_INPUT_USD_PER_MILLION` | Required when the budget is positive |
| `--judge-rpm` | `JUDGE_RPM` | 0 (local pacing disabled) |
| `--judge-tpm` | `JUDGE_TPM` | 0 (local pacing disabled) |

Budget and pacing state is shared by discovery and all assessment families for **one scan/process**.
It does not combine separate scans or impose an account/day cap. The local spending guard reserves
maximum input cost **before** each request and reconciles valid usage; failed/missing-usage calls retain
the reservation. Known billing bounds cover `gemini-decision-1` and OpenAI `gpt-6-luna` Decisions;
other provider/models fail closed when a dollar budget is enabled. Configure the highest applicable
input price, including cache-write, long-context and regional premiums. Correct prices/provider bounds
are required; keep provider account controls in place. This is not a provider billing lock.

TPM uses request UTF-8 bytes plus a 4,096-token framing allowance as a local estimate, then retains the
larger of that estimate and reported usage for the rolling minute. It is not an authoritative tokenizer
or account quota measurement. RPM/TPM waits are cancellable; an oversized request stops explicitly.
Authentication, rate and transport failures stop subsequent calls without retry or fallback. Refused
records remain unjudged, reports retain settings/accounting, and an incomplete scan exits nonzero.

Example for a verified paid Gemini project (check your active quotas first):

```bash
scan --analyze --judge gemini --judge-limit 100 \
  --judge-budget-usd 10 --judge-input-usd-per-million 0.10 \
  --judge-rpm 60 --judge-tpm 600000 /path/to/app
```

[Google pricing](https://aistudio.google.com/docs/pricing#gemini-decision) lists $0.10/million input;
[Google quotas](https://aistudio.google.com/docs/rate-limits#gemini-decision) vary by project/tier.
For Luna, a conservative $0.30/million input example covers the documented current
[cache-write/long-context/regional premiums](https://developers.openai.com/api/docs/models/gpt-6-luna);
verify the maximum applicable rate for your account. Prices are explicit, not auto-discovered.

These controls are implemented in the continuation checkpoint and have scoped offline test evidence;
final full verification is pending at the owner's request. See the
[contract](../.zazz/specifications/decision-model-limits.md) and
[checkpoint results](../.zazz/evaluation/path-traversal-results.md).

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

This sends bounded source evidence to the selected provider. The cap is per run; there are no retries.
Additional uses beyond the cap remain unassessed and cause exit 1. A requested assessment failure,
oversized payload, or exhausted cap is retained in the report; a setup failure before scanning can
produce no report. Optional `--checks` files specify business and protection requirements; they are
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

A requested scan with an unassessed outbound observation remains incomplete and exits 1 while saving
its Review record. The conservative request-limit schedule still counts candidate positions, including
observations; it does not promise that every unused HTTP slot will be reassigned. Supported families
continue under the same cap. Structural-only scans do not request model completion. Saved historical
generic answers, versions and statuses remain intact on export; they are not rewritten or replayed
onto new evidence. Full SSRF, exfiltration and browser-security assessment require separate contracts.

## Request granularity

The scanner sends one request per candidate use with that analyzer's applicable atomic questions
sharing its evidence slice. For example, command execution asks separately about shell syntax,
executable selection, arguments and coverage within one request. Different analyzers/candidates
are assessed separately, even when their source slices overlap. All use the same scan-wide selected
provider/model; no analyzer-specific fallback or whole-subgraph cross-analyzer batch is implemented.
Google probability maps and confidence are retained for audit and never close static blockers.
