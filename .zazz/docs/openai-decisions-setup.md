# Decision-provider integration notes

Operational instructions now live in the [decision-model user guide](../../docs/scan/decision-models.md).
It owns credentials, environment loading, scanner commands, request caps, and troubleshooting.
[Getting started](../../docs/scan/getting-started.md) owns compilation and local setup. This retained path
is for internal integration evidence and existing engineering links, not a second user setup guide.

## Implemented boundary

The Go scanner supports explicit OpenAI Decisions and Jev selection through provider-specific typed
adapters. Offline extraction and tests do not require credentials; adapter tests use local HTTP stubs.
Each provider has its own key and wire schema. Unknown/refused/invalid answers and provider errors
remain failed assessments. No automatic provider/model fallback occurs.

The [client implementation](../../scan/internal/judge/client.go) and
[judge bundle](../../scan/internal/judge/bundle.go) own transport constraints, question format, and payload
assembly. The [policy implementation](../../scan/internal/judge/policy.go) preserves raw answers separately
from claim completeness. The [reporting design](../architecture/reporting-and-sarif.md) owns the
presentation distinction between actionable poor practice, unresolved Review, and scoped protection.
A model answer does not fill missing source evidence or erase an independently established practice.

The [architecture](../architecture/README.md#provider-neutral-judge-boundary) owns provider responsibilities;
a new adapter needs its own wire validation, capabilities, and tests. Alternative adapters can be
verified with local stubs without changing the user's live-provider restriction.

## Historical access verification

On 2026-10-31, one actual OpenAI Decisions request for Juice Shop's selected login route completed
with `gpt-6-luna`: 2,247 input tokens and zero output tokens. The key was loaded privately from the
ignored `.env` into the scanner child environment; no credential was printed. The returned validation
and protection answers were `insufficient`; static gaps kept policy protection `uncertain`.
This verified integration access, not security accuracy or runtime exploitability.

Later bounded two-case evaluations are retained in [Juice Shop results](../evaluation/juice-shop/results.md),
and original controls in [corpus results](../evaluation/corpus/README.md). Those records preserve
usage, scope, outcomes, and limitations. Current account funding, subscription benefits, endpoint
access, pricing, quality, and latency must not be inferred from that historical smoke test.

Live evaluation remains separately authorized and constrained by the user's active provider/model
and request limits. Existing credentials are configuration, not permission for unbounded source
transmission or spending. Source secrets and execution logs remain outside tracked files.
