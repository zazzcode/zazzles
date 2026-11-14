# Decision-model rate and spending controls

## Capability and authorization

Add shared, user-facing per-scan request, rate and dollar-budget configuration for model assessment
and optional route discovery. The owner requested implementation, README/project-plan documentation,
`.env.sample` and both existing worktrees' local `.env` updates on 2026-11-14, then requested a verified
checkpoint **before** implementing improvements. This contract records that pending work; it is not a
claim that these controls are already implemented.

## Required reading

[Agent rules](../../AGENTS.md#authorization-and-delivery),
[shared judge guide](../../docs/decision-models.md),
[contributor checks](../../docs/contributing.md#contributing),
[testing](../standards/testing.md), [code structure](../standards/code-structure.md),
[documentation hygiene](../standards/docs-hygiene.md).

## Scope, review shape and invariants

Continue in the existing `path-traversal` branch/worktree, with a focused follow-up commit after the
path-analyzer checkpoint. Shared code belongs in `internal/judge/` and CLI wiring in `cmd/scan/`.
Update README, setup/running docs, plan, this contract and `.env.sample`; modify only the requested
nonsecret settings in ignored `path-traversal/.env` and `stage/.env`. Preserve keys and model selection.
No new worktree, delegation, PR, merge, release or integration code change is authorized.

Runtime scheduling/accounting must not change request payloads, component selection, evidence gates,
question protocols or exact replay. All analyzers use the same selected client. Discovery and assessment
share the same rate/spend state. Offline scans, exports and replay make no paid requests. No automatic
provider/model fallback or retry is introduced. Limits apply to one process/scan, not an account-wide,
daily or cross-process budget.

## Configuration and decisions

| Flag | Environment | Meaning |
|---|---|---|
| `--judge-limit` | `JUDGE_LIMIT` | Existing assessment-request cap, default 10; discovery retains its separately bounded request allowance |
| `--judge-budget-usd` | `JUDGE_BUDGET_USD` | Maximum accounted per-scan spend across discovery and assessment; zero/unset disables this optional guard |
| `--judge-input-usd-per-million` | `JUDGE_INPUT_USD_PER_MILLION` | Explicit conservative maximum applicable input rate, required with a positive budget |
| `--judge-rpm` | `JUDGE_RPM` | Requests per rolling minute; zero/unset disables local RPM pacing |
| `--judge-tpm` | `JUDGE_TPM` | Input-token scheduling target per rolling minute; zero/unset disables local TPM pacing |

Flags override environment values. Reject negative, malformed, NaN, infinite and overflowing values
before any request. Invalid judge-only environment settings must not break offline scans or saved-report
export. Existing defaults remain compatible when the new settings are absent. Loading `.env` does not
enable a judge; `--judge` remains explicit. The scanner does not auto-load the file.

Currency accounting requires a pre-call conservative reservation; a post-call token sum alone cannot
prevent an overshoot. For known Decisions models, reserve the model's full documented input-context
ceiling at the configured maximum price, then reconcile only with valid usage. Failed/missing-usage calls
retain their reservation. Do not assume a failed HTTP call is free. Unknown provider/model billing must
fail closed when a budget is enabled until a verified bound exists. Use integer currency accounting
with conservative rounding. OpenAI Decisions and Gemini Decisions have no billed output tokens; do not
infer that property for other transports.

Pricing is explicit because cached writes, long-context and regional premiums can exceed a headline
input price. For the current local setup, a conservative $0.30/million covers the documented Luna input
multipliers; Gemini uses its published $0.10/million. These are setup examples, not a permanently current
pricing catalog. A cap relies on correct configured prices and provider bounds, and is not a provider
billing lock. Keep provider account controls in place.

Requests remain sequential. Implement shared rolling-window pacing with cancellable waits. Without an
authoritative provider tokenizer, declare the local pre-call token reservation/estimate and reconcile
reported usage; do not market an estimate as an exact provider quota measurement. A request larger than
the configured window must stop explicitly instead of sleeping forever. Do not discover account quotas
or probe quota errors automatically. A rate/auth/transport failure stops further calls for the scan,
leaving remaining records explicitly unjudged. Account for attempted failed calls.

Report effective settings, attempts, reported input usage and reserved/accounted spend in JSON, HTML and
SARIF through the shared canonical report/limitations. A budget refusal is not a safe/security result;
produce incomplete output and a nonzero exit status.

## Acceptance and test strategy

- Table-driven configuration tests prove flag precedence, offline isolation, finite numeric validation,
  required pricing and supported-model billing bounds.
- Local HTTP-stub tests prove refusal **before** sending an unaffordable request, valid-usage
  reconciliation, reservation retention on HTTP/malformed/missing-usage failure, and no retries.
- A fake clock proves rolling RPM/TPM waits, cancellation, oversized requests, and shared discovery/
  assessment accounting without wall-clock-dependent tests.
- CLI fixtures prove both discovery and assessment share limits, remaining uses stay incomplete, exit
  codes are correct, and all three output formats expose the effective limits/accounting.
- Existing payload/parity/replay tests and eight-app comparison prove evidence is unchanged.
- Build, vet, changed-file formatting, full race suite, and scoped documentation checks pass.

## Execution and run log

First add failing limiter/configuration/stub tests, then implement a small shared limiter at the common
transport boundary, CLI/environment wiring and report accounting; update docs to implemented behavior.
Use the existing ignored `.zazz/ephemeral/path-traversal-run-log.md` append-only. No live test or extra
spend is necessary: scheduling/accounting is verified with HTTP stubs and a fake clock. Preserve the
owner's $10 maximum authorization for any subsequent specifically scoped live evaluation.

## Definition of done

- [ ] Shared configuration, validation, pre-call reservation and rate pacing implemented.
- [ ] Discovery/assessment failure and incomplete-report behavior verified.
- [ ] README, setup/running docs, sample environment and project plan match implementation.
- [ ] Requested local environment settings verified without exposing or changing credentials.
- [ ] Required offline checks and human review completed.

## Open questions and references

No additional owner approval is required for the bounded work above. Implementation must resolve and
record the exact pacing estimate and supported billing-bound table before enabling the new settings.
Official references: [Google model](https://aistudio.google.com/docs/models/gemini-decision-1),
[Google pricing](https://aistudio.google.com/docs/pricing#gemini-decision),
[Google rate limits](https://aistudio.google.com/docs/rate-limits#gemini-decision),
[OpenAI Decisions pricing](https://developers.openai.com/api/docs/guides/decisions#pricing-and-availability),
[Luna bounds and rates](https://developers.openai.com/api/docs/models/gpt-6-luna).

## Implementation and review change log

### 2026-11-14 — Owner-requested shared controls

Recorded requested configuration, safety semantics, scope and checks before implementation. The owner
requested committing/pushing the verified analyzer and updated specifications/documentation first.
