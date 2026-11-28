# Analyzer protection and flow coverage

**Status:** In progress. Assigned 2026-11-16 by explicit owner implementation request.
**Delivery:** Existing `nextjs-analyzer-protection-flow` branch/worktree, one draft PR into `stage`.
**Baseline:** `stage` at `8d4013d` (merged [PR #19](https://github.com/zazzcode/zazzles/pull/19)).

## Capability and scope

Implement proposal 1, *Analyzer protection and flow coverage* (owner draft held outside the
repository at the container root): improve recognition of genuinely protected claims and detection
of known vulnerable paths for the shipped `code`, `redirect`, path, SSRF and Next.js flow evidence.
This is improvement work on PR #19's analyzers, not reimplementation.

Protected is a claim/operand/path result, never a certificate that a route is safe. "All
positives" means all source-verified cases in the pinned corpus below, not exhaustive detection.

Out of scope: new analyzer families, dependency scanning, any promise to eliminate every Review,
editing the merged `nextjs-support-phase-2` worktree, and paid model calls (see *Paid evaluation*).

## Required reading

- [Orientation code structure](../../docs/zazzles-agent-orientation.md#code-structure) and
  [execution discipline](../../docs/agent-execution-discipline.md#verification-discipline).
- [Phase 2 contract](nextjs-phase-2-and-code-redirect.md) and
  [results](../../evaluation/nextjs-phase-2-results.md) — the baseline this work improves.
- [Claim completeness](../../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [graph flow](../../architecture/repository-graph.md#value-flow-guards-and-taint).
- Matching analysis guides in [docs/analysis](../../../docs/scan/analysis/README.md): `code-injection`,
  `open-redirect`, `ssrf`, `path-traversal`, `nextjs`, `xss` (stored paths), `calibration`.
- [Testing conventions](../../standards/testing.md) and [contributor checks](../../../docs/contributing.md).

## Pinned corpus

Read-only; never install dependencies, execute, or modify. Re-verify the pin and a clean status
before each measurement.

| Sample | Location (`<DEV_ROOT>`-relative) | Pin |
|---|---|---|
| vuln-nextjs lab | `zazzcode/vuln-nextjs` | `ea10efb` |
| OopsSec store | `oss-oopssec-store` | `2d530ef` |
| vuln-demo-app | `vuln-demo-app` | `d27b35b` |
| vulnerable-typescript-app | `vulnerable-typescript-app` | `7f8b240` |
| nodejs-goof | `nodejs-goof` | `add14ba` |
| Juice Shop | `juice-shop` | `f189f5212` |
| VulnPy | `vulnpy` | `b81885e` |
| Vercel Commerce (reference) | archive under `<container>/_test-findings/nextjs-phase-2/` | `f7521d5` |

## Invariants and decisions

- Keep source acquisition, family interpretation and deterministic verdict gates separate.
- A guard counts only when it is verified to apply to the **same final operand on every relevant
  path**. Never borrow a guard from another branch; unknown flow never establishes protection.
- Sample labels ("safe", "vulnerable") are never scanner or model evidence. The lab's proposed safe
  redirect permits `/\host` and stays Review unless its source actually changes.
- Cycle/depth bounds remain explicit facts on the record, never silent truncation.
- Unknown writers and dynamic SQL identifiers remain unresolved without evidence.
- Request-content changes must keep exact-replay compatibility for unchanged evidence; changed
  evidence is rejudged, never copied.
- Express regression: existing candidate records stay byte-identical except where a selected
  improvement intentionally changes them, and each such change is listed in the results.

## Work items (priority order)

Each item is delivered only for the cases the inventory selects. Each selected improvement ships a
**paired fixture set**: one genuine safe control plus vulnerable siblings drawn from guard bypass,
reassignment, mixed raw operand, exceptional flow and unprotected branch.

| ID | Item | Primary ownership (files) |
|---|---|---|
| P0 | **Inventory.** Map every pinned known positive and genuine safe control to entry, sink, family, candidate, outcome and missing evidence; classify each non-final outcome as *missing candidate*, *incomplete path*, *model uncertainty* or *deterministic policy rejection*. | `.zazz/evaluation/analyzer-protection-and-flow-inventory.md` |
| P1 | **Protection evidence.** Guard/helper predicates, boolean aliases, early exits and validator results followed to the final operand; code grammar/type restrictions; parsed URL host/origin controls; affected path/SSRF protection. | `guard_climb.go`, `guard_lang.go`, `node_control_helpers.go`, `code_constraints.go`, `path_guards.go`, `path_guard_classify.go`, `outbound_ssrf.go`, `ssrf_scheme_tests.go`, `zod_validation.go` |
| P2 | **Redirect semantics.** API-specific normalization, backslashes, protocol-relative destinations, decoding, origin-prefix behavior; helper-forwarded Location/status only with verified bindings. | `redirect_guards.go`, `code_redirect.go`, `python_code_redirect.go`, `internal/judge/code_redirect.go` |
| P3 | **Flow gaps.** Bounded child props, verified context/store transitions, local async return summaries, exception/finally effects. | `react_flow.go`, `react_props.go`, `react_shared_sources.go`, `try_flow.go`, `helper_flow.go`, `conditional_flow.go`, `control_context.go`, `python_flow.go`, `python_control.go`, `python_values.go` |
| P4 | **Stored paths.** Parameterized SQL/Prisma writes, explicit mappings, dialect-sensitive identifiers, projections, read alternatives. | `xss_sql_storage.go`, `prisma_raw_storage.go`, `xss_storage.go`, `xss_storage_links.go`, `sql_libraries.go` |
| P5 | **Explain outcomes.** Report the blocking evidence for Review, preserve linked independent claims, distinguish unjudged records from completed judgments (JSON/HTML/SARIF/text). | `internal/report/`, `internal/judge/policy.go`, `internal/judge/evidence_coverage.go`, `xss_claims.go` |

Shared files (`flow.go`, `analysis.go`, `claim_assembly.go`, `internal/analysis/`, answer-key
tests, docs) are edited by the lead or by one workstream at a time with notice in the run log.
Each workstream adds its tests in new `*_test.go` files named for the item (e.g.
`protection_p1_test.go`), with paired fixtures as inline temporary repositories or under
`internal/parse/testdata/protection-flow/<item>/`. Selected cases are listed in the
[inventory](../../evaluation/analyzer-protection-and-flow-inventory.md#selected-bounded-improvements).

## Acceptance and test strategy

1. **Inventory complete.** The inventory lists every in-scope required positive and safe control
   from the pinned answer keys, detection guides and phase-2 results with a baseline outcome and
   gap class; nothing in scope is silently omitted. Selected improvements cite inventory rows.
2. **Paired fixtures per improvement.** For each P1–P4 improvement, the safe control is Protected
   or a justified candidate exclusion, and every vulnerable sibling is not Protected (offline:
   complete raw path / no protection fact). Verified by the item's `*_p<n>_test.go`.
3. **Zero false Protected and zero false Confirmed** across all paired cases and the inventory.
4. **Redirect semantics** cases cover `\`, `/\`, `//`, `%2f%2f`, `%5c`, scheme-relative, origin
   prefix (`https://site.evil`), and `new URL(x, base)` origin comparison, per API.
5. **Explain outcomes:** each Review record carries machine-readable blocking-evidence reasons;
   unjudged and judged records are distinguishable in JSON, HTML and SARIF; linked independent
   claims (e.g. redirect + XSS on one navigation) both remain. Verified by report tests.
6. **Regression gates:** `TestNextJSOopsStoreAnswerKey`, `TestNextJSVulnLab`, four Express
   before/after comparisons, parser/component/policy/report tests.
7. **Contributor gates:** `gofmt -l` on changed files, `go vet ./...`, `go build ./...`,
   `go test -race ./... -count=1`, documentation link/whitespace checks.
8. **Results:** per-case before/after matrix in
   `.zazz/evaluation/analyzer-protection-and-flow-results.md`, with remaining unknowns, answer-key
   corrections (source-backed), limitations and unresolved cases handed to proposal 2.

## Paid evaluation

No paid requests are authorized by this contract. After offline evidence settles, the lead asks
the owner for a fresh explicit cap covering changed evidence and representative safe controls.
The prior 155/180 spend creates no budget. Any authorized run: one provider/model, no fallback,
every request counted, exact replay of final retained assessments.

## Execution sequence and records

Run log: `.zazz/ephemeral/analyzer-protection-run-log.md` (ignored). Reports and scans live under
`<container>/_test-findings/analyzer-protection/`, never in a checkout.

1. P0 inventory (parallel read-only agents per sample group) → lead consolidates and selects.
2. P1–P5 in parallel by lower-cost implementation agents, each limited to its owned files.
3. Lead integrates, runs gates, produces the results matrix, updates analysis docs.
4. Owner decides on paid evaluation; draft PR into `stage`.

The lead orchestrates and reviews; implementation agents run only scoped `go test -run` checks and
must keep the package compiling. All agents share the single assigned checkout; none uses another
worktree. Offline scans use `bin/scan --analyze --json --output-dir ""` with no `--judge`; the
answer-key tests read `ZAZZLES_VULN_NEXTJS` and `ZAZZLES_NEXTJS_SAMPLE`. Allowed changes:
`internal/`, `cmd/scan/`, `docs/`, `.zazz/`.

## Definition of done

- [x] Inventory and selection recorded.
- [x] All offline acceptance criteria have passing evidence; paid confirmation pending.
- [x] Durable docs describe implemented boundaries and measured results.
- [x] Required checks pass; paid evaluation decided by the owner (10 requests, 9/9 exact replay).
- [ ] Draft PR into `stage`; human review remains the owner step.

## Implementation And Review Change Log

### 2026-11-16 — Initial contract

Owner requested implementation of proposal 1 in the assigned `nextjs-analyzer-protection-flow`
worktree, with lower-cost parallel implementation agents. File ownership was checked against the
baseline tree; all named files exist at `8d4013d`.

### 2026-11-16 — Inventory and selection

P0 recorded 135 rows across the pinned corpus with zero false Protected and one suspected older
false Confirmed handed to proposal 2. Twelve bounded selections (S1–S12) are assigned to P1–P5;
ownership gained `zod_validation.go` (P1), `internal/judge/code_redirect.go` (P2),
`control_context.go` and Python flow files (P3) and `xss_claims.go` (P5). The lead
added shared `analysis.Finding` fields (`assessment_state`, `blocking_evidence`, `linked_use_ids`).

### 2026-11-16 — Implementation and offline results

S1–S12 implemented except S3's Juice `/`-reject part (already guarded or not safely modeled).
Integration review narrowed P5's duplicate-XSS suppression to browser `eval` and fixed a P3 decoder
rule that turned `raw` into `unknown`. Offline before/after measurement, the B-JS-26 trade-off and
handoffs are in the [results](../../evaluation/analyzer-protection-and-flow-results.md). Paid
evaluation awaits an owner cap.

### 2026-11-16 — Paid evaluation and capability documentation

Owner authorized a paid run; 10 OpenAI `gpt-6-luna` requests, no fallback. O-SSRF-02, O-SQL-03 and
the VulnPy Django path/SQL cases are Confirmed; the lab zod control is Protected; the lab redirect
control stays Review. Fixes: missing fact notes (with a producer-scan test), stored-code operand
path remapping, and a general stored-origin blocker for every family. A user-facing
[detection capabilities](../../../docs/scan/detection-capabilities.md) page was added. Cross-request store
writer tracking is handed to proposal 2.
