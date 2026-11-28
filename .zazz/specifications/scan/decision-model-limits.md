# Decision-model request and rate limits

## Capability and authorization

Provide a per-run assessment request cap and optional RPM/TPM pacing shared by assessment and route
discovery. The owner requested removing local dollar-budget and pricing management during
`analyzer-engine-hardening` on 2026-11-14. Spending belongs in the model provider console.

This contract supersedes the earlier currency-reservation design. Implement in the assigned
`analyzer-engine-hardening` worktree; do not modify private `.env` files or other worktrees.

## Required reading

[Agent rules](../../../AGENTS.md#authorization-and-delivery),
[decision-model guide](../../../docs/scan/decision-models.md),
[contributor checks](../../../docs/contributing.md#verification),
[testing](../../standards/testing.md), [code structure](../../standards/code-structure.md), and
[engine hardening contract](analyzer-engine-hardening.md).

## Scope and behavior

Code belongs in `internal/judge/` and `cmd/scan/`. Keep user guides, `.env.sample`, and the project
plan consistent. Removing dollar budgeting must not change provider payloads, component selection,
question protocols, deterministic evidence gates, or exact replay.

| Flag | Environment | Behavior |
|---|---|---|
| `--judge-limit` | `JUDGE_LIMIT` | Assessment request cap, default 10; discovery retains its separate allowance |
| `--judge-rpm` | `JUDGE_RPM` | Shared requests per rolling minute; zero/unset disables pacing |
| `--judge-tpm` | `JUDGE_TPM` | Shared estimated input tokens per rolling minute; zero/unset disables pacing |

Flags override environment settings. Reject negative, malformed and overflowing values before
requests. Judge-only environment settings do not affect offline analysis, inventory, or exports.
`--judge` explicitly enables requests; loading configuration does not. The scanner does not auto-load
`.env`. Requests remain sequential without retry or automatic provider fallback.

Remove `--judge-budget-usd`, `--judge-input-usd-per-million`, their environment parsing, currency
accounting, and provider-specific billing bounds. Removed flags fail as unknown arguments; stale
budget/price environment variables have no effect. Keep keys private and unchanged.

RPM/TPM waits use one shared cancellable rolling window. TPM reserves request UTF-8 bytes plus a
4,096-token framing allowance, retaining the larger of that estimate and reported input usage in
the window. This is a conservative local estimate, not an authoritative tokenizer. A request larger
than its TPM window stops explicitly instead of waiting forever. Do not probe provider quotas.
With both rate limits disabled, skip clock and rate-window work while retaining token/attempt
statistics and stop-on-failure behavior.

Authentication, rate, transport, or malformed-response failures stop subsequent calls for the scan.
Remaining records stay explicitly unjudged, reports retain the reason, and incomplete requested
assessment exits nonzero. A refused request does not establish protection. Report effective RPM/TPM,
attempts, reported input usage and unknown-usage attempts through shared limitations in JSON, HTML
and SARIF. No dollar totals or provider pricing appear in scanner accounting.

## Acceptance and verification

- Configuration tests prove flag precedence, integer validation, request-cap defaults, removed-flag
  rejection, ignored stale currency settings, and offline isolation.
- Fake-clock tests prove rolling-window pacing, cancellation, oversized-request refusal and shared
  discovery/assessment state without real waits.
- Disabled-pacing tests prove no clock reads or rate-window storage.
- HTTP stubs prove transport failures stop later requests without retries; replay makes no calls.
- CLI fixtures prove TPM refusal occurs before transport, preserves incomplete assessments and
  emits the reason and effective limits in all three output formats.
- Predecessor request tests, build, vet, changed-file formatting, full race checks and documentation
  checks pass. No live calls are required.

## Execution record

Append attempts and evidence to `.zazz/ephemeral/analyzer-engine-hardening-run-log.md`. Keep scratch
harnesses and external-corpus evidence ignored. Human review and merge remain required.

## Implementation and review change log

### 2026-11-14 — Initial controls and subsequent simplification

Earlier implementation included dollar budgets, price configuration and full-context currency
reservations alongside RPM/TPM pacing. During engine hardening, the owner explicitly removed local
spending management to keep the scanner simple and efficient. The current contract above owns the
replacement behavior; historical report exports retain their original metadata.
