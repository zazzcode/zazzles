# 02 — Proposed project scope

**Concept stage, 2026-10-19.** Scope and quality targets remain subject to refinement. This document,
the [architecture](../architecture/README.md), and the [phased plan](implementation-plan.md) are inputs to
future specifications; none is permission to implement.

**Provider decision (2026-10-31):** the [architecture](../architecture/README.md#current-provider-decision)
owns the current provider decision; this document defers to it.

## Objective

Establish whether a Go + Tree-sitter + bounded dataflow + semantic judge scanner can produce useful, reviewable
findings for selected OWASP-related source-code risks at acceptable cost. The long-term product
objective is **equal-or-better SAST detection and code analysis than Bearer with fewer false positives,
with equivalent coverage
of its capabilities across CLI and Pro**. For each route, report where protection is sufficient,
where it is lacking, and the poor code-practice findings an agent can fix with the dataflow fixes.
The [project objectives](../project.md#long-term-objectives)
own this ambition and its measurement criteria. Prove a small JS/TS slice first, then expand through
an explicit capability-parity inventory and measured contracts; current capability is not broad parity.

## Current work

Current repository state lives in the [project overview](../project.md#concept-stage-repository-state).
The [orientation](../docs/zazzles-agent-orientation.md#current-work) defines the active documentation
session and routes to its operating rules.

## Proposed initial scope

- Local CLI operation over explicitly selected source trees.
- JS/TS extraction and supported import/call resolution.
- Named rules for a small set of input-to-sink risks and deterministic patterns.
- Local CFG/dataflow followed by bounded resolved argument/return propagation.
- Guard-use and branch context sufficient to distinguish validation from mere validator presence.
- Traceable string candidates and evidence bundles; experiments with judge validation/sanitization
  assessment, followed by an LLM Findings Reviewer for identified issues and uncertain candidates.
- Explicit unknown/uncertain/unexamined outcomes and coverage accounting.
- JSON/Markdown output.

## Proposed later scope

- Expand the supported entry mechanisms and vulnerability coverage, followed by remaining Python
  coverage and SCA. The [implementation plan](implementation-plan.md#future-capability-branches)
  owns the current sequence; language expansion has no fixed position in that sequence.
- Additional frameworks, rule families and optional sensitive-data impact tags.
- Route-oriented reports with a bounded SARIF export; see [report design](../architecture/reporting-and-sarif.md).
- Stable finding identity, reviewable baselines, and measured CI policy after the first slices
  (backlog phases 9–10).
- Dependency-aware caching after correctness is established (backlog phase 10).
- SCA dependency auditing after the code-path foundation, using ecosystem adapters; see
  [SCA design](../architecture/sca-design.md).
- Explicit bounded scope checks for authorization/logic risks (the former Track C idea).

These require separate scope review, corpus evidence, and approved specs. There is no fixed promise
that all target languages or tracks are in the first release.

## Current delivery exclusions and limits

- Exhaustive whole-program analysis or a general solver for arbitrary aliases, reflection, dynamic
  dispatch, heap mutation, stored/second-order flows, or all asynchronous behavior.
- Execution of the target, runtime instrumentation, exploit attempts, or dynamic testing.
- Dependency vulnerability scanning and full secrets scanning.
- Generated patches, unrestricted LLM review, model-driven graph traversal, and unsupported generated claims.
- Hosted multi-tenant service, database-backed execution engine, or external tracking integration.
- A claim that clean output certifies security or covers every risk in an OWASP edition.

These are exclusions from the current delivery scope, not permanent exclusions from the long-term
Bearer capability-parity objective. Broader coverage needs explicit design, implementation and evidence.
Some excluded constructs occur inside otherwise supported programs. Report them as limitations;
do not silently treat them as absent dataflow or expand scope without a contract change.

## Delivery gates

Delivery follows the [Zazz lifecycle](../docs/zazz-methodology.md#specification-driven-delivery-cycle).
The [implementation plan](implementation-plan.md) supplies dependencies and future spec slices;
phase-specific acceptance criteria must become bounded, human-greenlit contracts before execution.

## Non-functional hypotheses

| Concern | Proposed target / required decision | Evidence before commitment |
|---|---|---|
| Correctness | Separate structural facts, approximations, predictions, and gaps | Labeled safe/vulnerable pairs and unsupported-construct fixtures |
| Determinism | Stable graphs, candidates, and rule output for fixed inputs/versions | Serial/parallel and repeated-run comparisons |
| Judge and reviewer quality | Equal-or-better detection than Bearer with lower false positives, using graph-grounded assessment of actual protection. Per route, report sufficient protection, lacking protection, and poor code-practice findings as separate results | Independent labels, matched held-out cases, recall/precision and false-positive denominators, false-safe/errors, abstentions, reviewer disagreement and completeness |
| Latency | Suitable for developer/CI use; exact budgets unset | Hardware/fixture-defined cold/warm timings and per-request p50/p95 |
| Cost | Bounded requests and run spend; exact ceiling unset | Candidate/question counts, usage, rate-limit behavior, measured billing basis |
| Resources | Bounded workers, traversal, source retention, and payload size | Peak RSS, cancellation/backpressure, adversarial large inputs |
| Local-only mode | Deterministic operation with zero external requests | No-key/offline end-to-end evidence |
| Source handling | Send only enabled, necessary evidence to the selected judge and the configured LLM Findings Reviewer | Payload inspection, logging/redaction tests, owner decision on allowed transmission to each provider |
| Portability | Predictable supported binaries/platforms | Binding/cgo/build matrix; static linking is a goal to assess, not a guarantee |
| Rescans | Cached and uncached outputs agree | Dependency and model/question/rule/policy version invalidation tests |

The old low-single-digit-second parse target, 250 ms Jev claims, fractional-cent claims, and full
multi-language release scope are not established requirements. Numeric acceptance thresholds must be
selected in the relevant future spec before evaluating its results.

## Principal risks

- **Semantic gap:** syntax extraction alone does not provide CFG/dataflow. Language lowering and
  library models are substantial engineering work.
- **Flow precision:** guards on another branch, ignored returns, reassignment, aliases, and unknown
  calls can invalidate a superficially convincing path.
- **Path growth:** bounded analysis can miss candidates; limits must remain visible.
- **Classifier fitness:** typed output can still be wrong or influenced by source comments. Evaluate
  custom validation and adversarial examples, not just obvious vulnerable snippets.
- **Evidence quality:** missing dependencies can look like missing validation; low confidence does not
  have a single cause.
- **Cache overreach:** a validator judged adequate in one context is not globally safe elsewhere.
- **Coverage inflation:** “OWASP Top 10” branding can outpace tested rules and frameworks.
- **Release complexity:** native parsing, platform support, and multiple adapters can dominate scope.

## Decision tracking

The [proposal register](03-jev-design-proposal.md#open-decision-register) owns open decisions and their
refinement gates. Update that register when scope or evidence changes rather than keeping a second
question list here.
