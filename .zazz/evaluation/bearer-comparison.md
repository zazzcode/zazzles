# Bearer comparison experiment

**Initial pinned CLI experiment completed, 2026-10-31** ([history](comparison-history.md)); rerun on four samples 2026-11-24. See the [scanner comparison](../../docs/scan/scanner-comparison.md), [Bearer results](bearer-results.md), the
[capability inventory](comparison-results.md#capability-inventory) and [complete Juice Shop challenge/review index](juice-shop/README.md).
The procedure below remains the repeat/extension protocol. Compare zazzles's AI-assisted route/evidence judgments
with the local traditional SAST CLI on the same pinned source. Bearer is a comparator, not ground truth.
The [long-term objective](../project.md#long-term-objectives) is equal-or-better SAST detection and
capability parity across CLI and Pro, with fewer false positives at equal-or-better detection.
Local CLI comparisons begin that evaluation; they cannot alone
establish parity with capabilities unavailable in the tested edition.

For the additional Node.js Goof target, use its [case inventory](nodejs-goof-capabilities.md) and
[baseline runbook](../../docs/samples/nodejs-goof/bearer-runbook.md). That runbook retains templates,
which the historical runner's JS/TS/JSON-only sample snapshot would omit. The
[initial Goof comparison](nodejs-goof-results.md) is complete and preserves pre-XSS coverage limits.

## Local setup evidence

Reference checkout: `<DEV_ROOT>/bearer`, commit `e3753de6347988bed15bdba80b9ff731bf028c80`,
clean when inspected. Read its README, `docs/contributing/code.md`, `go.mod` and
`.goreleaser/common.yaml` before setup. Local docs declare Go 1.26+, `go mod download`, and
`go run ./cmd/bearer/bearer.go [COMMAND]`; release build configuration uses CGO. The initial experiment
built the pinned source with readonly modules, downloaded a separate pinned rules snapshot and scanned
both sample repositories plus thirteen controls. No generation or tidy ran; see results for exact scope.

The pinned README describes data-flow/sensitive-data analysis and Pro advanced cross-file analysis,
listing Java/Python/C#/Go for the latter. It does not establish an exhaustive TypeScript CLI boundary.
Verify actual behavior on small same-file and cross-file fixtures. Recheck official upstream docs
for current product/edition claims before making broader comparisons.

## Procedure

1. Verify checkout status and available binary/version. Build from the pinned local source if needed,
   writing binaries/results to zazzles's ignored execution directory where feasible. Follow actual
   dependency/generation requirements, not a guessed Makefile; no Makefile was found at the root.
2. Inspect `--help` / `scan --help` for output formats, exclusions, rules, network/rule downloads,
   telemetry and exit semantics. Record effective defaults and rule versions. Never forward
   `OPENAI_API_KEY` or `TYPESAFE_API_KEY` to Bearer. Do not run a target server.
3. Run the original corpus, then pinned Juice Shop and the second TypeScript target. Compare equal
   source/exclusion scope; record when Bearer cannot match zazzles's entry or route selection.
4. Preserve raw output, logs, invocation/configuration and snapshot identity. Export JSON/SARIF only
   if supported by the inspected version. A tool's nonzero findings exit is not a build failure.
5. Normalize findings by route, source/sink location and weakness class. Match equivalent claims;
   compare SQL-structure protection separately from required-field/business-policy validation.
6. Hand-check disagreements: true finding, false finding, false protected claim, abstention,
   unsupported sink or untested behavior. Do not count README challenge labels as runtime truth.
7. Add original multi-function/multi-file custom-validator, mutation/bypass, query-binding and
   outbound-destination controls. Keep labels outside target roots and submitted model bundles.

## Acceptance evidence

Produce a comparison table with target/revision, case, human-reviewed expected property, scan raw
facets/status, Bearer rule/result, path evidence, missing facts and disposition. Report findings,
false findings, false safe claims and abstentions separately. Include elapsed time and Luna request/
token usage; cap live model calls explicitly and use only gpt-6-luna for this branch.

Start offline. Existing saved Luna assessments can be compared without fresh API calls. If source
or evidence changes, do not reuse an old assessment as a judgment on the new bundle. Neither tool's
miss proves safety, and agreement between tools is not independent vulnerability confirmation.

References: [original controls](corpus/README.md), [Juice Shop results](juice-shop/results.md),
[discovery/evidence design](../architecture/evidence-and-claims.md#discovery-on-novel-target-repositories).

## Capability-parity inventory

The current inventory is in the [run record](comparison-results.md#capability-inventory). The
paragraph below is the rule for extending it.

Create a versioned matrix before claiming broad parity. For each capability record the verified
Bearer version/edition and behavior, zazzles's implemented/planned/unsupported state, a corresponding
phase/spec, and acceptance evidence. Cover languages/frameworks, vulnerability families, local and
cross-file/interprocedural taint/control flow, sensitive-data classification and privacy impact,
explanations/remediation, output/configuration, baselines/incremental operation and CI integration.
Where a comparator capability cannot be exercised locally, mark comparison unverified and define
independent acceptance cases. Do not treat a free-CLI limitation as the final product boundary.
