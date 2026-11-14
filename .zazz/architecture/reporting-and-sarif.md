# Entry-oriented findings and SARIF export

**Design and bounded implementation, 2026-10-31.** Use one versioned internal
model for route analysis, evidence and findings, with SARIF 2.1.0 as an implemented findings
export and a [standalone HTML report](html-reporting.md) for human CLI review. Avoid separate
detection/policy implementations for JSON, SARIF, and HTML.

## Output responsibilities

- **Canonical scan JSON:** full bounded source evidence, entries/uses, source hashes, assessment and
  completeness context, plus human-readable finding records. This is the primary agent-readable artifact.
- **SARIF 2.1.0:** standard security-tool interchange. Preserve extra scan context in namespaced
  properties instead of dropping uncertainty to fit a consumer's default result display.
- **Standalone HTML:** the core human-facing CLI report, generated offline from the canonical JSON.
  Show only zazzles's results. Comparator/tool benchmarking belongs in evaluation documents.

All three formats share the same use/entry/context IDs, raw assessments, and report interpretation. None
runs an additional detector, changes eligibility, or silently upgrades uncertainty to protection.

## Canonical report

The target repository is identified by snapshot and declared scope. Route records group by method,
path/receiver/mount identity and connect to handlers, input definitions, transfers, guards and sensitive
uses. Findings anchor to specific use/constraint pairs, so SQL injection and email-format validation
remain distinct even on the same route. Unknown/partial routes remain visible as coverage records.

Keep normalized findings separate from the full analysis graph. The current evidence JSON is a
bounded precursor, not a finalized public vulnerability schema. A later schema contract must settle
compatibility and edit-stable identity before baseline/CI workflows depend on it.

Proposed records:

| Record | Content |
|---|---|
| Target / scan scope | Source hashes, revision if available, selection, tool/model versions and exclusions |
| Route | Method/path, receiver/mount/handler provenance and applicable chain |
| Use / witness | Source and sink argument roles, transformations, control facts and assumptions |
| Finding | Rule/constraint, route/use reference, CWE/OWASP edition, severity policy and evidence status |
| Judge assessment | Provider/model/question versions, typed answers, usage and completion state |
| Completeness | Required facts, relevant blockers, unrelated coverage gaps and bounds |
| Review / runtime evidence | Separate independent review and controlled runtime confirmation states |
| Recommendations | Multiple complementary changes, scope/preconditions, evidence and regression expectations |
| Dependency finding | Package/version/advisory/dependency path and separate route-reachability status |

Recommendations should be organized around a route and its relevant graph slice. For login, an
appropriate set can include SQL parameter binding, server-side input type/format constraints, suitable
password storage, and authentication regression tests. Each addresses a different property. Do not
label email validation alone a sufficient SQL-injection fix or guarantee an impervious route.

## Human-readable finding interpretation

Schema-v1 evidence remains compatible. Additive `presentation_version` and `findings` fields describe
one result record per use. A record includes `id`, `use_id`, `entry_id`, `invocation_context_id`, `record_type`, `status`, `title`,
`summary`, separate `input_validation` and `use_protection` explanations, `uncertainty`, and
`recommendations`. Presentation version 2 adds `type_ids` and the report-level `finding_types`
[glossary](finding-types.md); risk families remain separate from assessment status. Evidence stays in the referenced use; it is not replaced by generated prose.
`internal/report/findings.go` owns interpretation; `guidance.go` owns reviewable remediation.

The public semantics live in [philosophy](../../docs/philosophy.md) and
[result interpretation](../../docs/interpreting-results.md). Presentation version 3 uses `record_type`
`finding` for evidence-gated static vulnerabilities and established poor practice, `analysis` for unresolved behavior/potential model claims,
and `protection` for an assessed protected claim. The Findings column is not limited to demonstrated
exploits: an established practice violation is a remediation/refactoring task. `poor_practice`
replaces the former broad `observed_pattern` presentation status for string-built executable queries.

Unmodeled NoSQL document constraints and absent modeled validator calls alone remain Review. An
advisory `supported_potential` model answer is retained as Review unless independent deterministic
practice evidence already establishes a finding. Existing practice findings remain actionable when
assessment is omitted, fails, is inconclusive, or supports protection for a separate injection claim.
Raw assessment statuses and answers are never rewritten. A query-shape/library ambiguity such as
ORM search values remains Review rather than being relabeled as a practice defect.

Descriptions explain behavior and uncertainty in ordinary language. Internal names such as
`query_text_interpolated` remain available as evidence identifiers, not the primary explanation.
For example, an interpolated ORM `Op.like` value requires library review rather than an automatic
SQL-injection finding. NoSQL document values require slot, type, key/operator and API review. NoSQL
is one word. “No validator identified” applies only to the analyzed slice; unknown validation remains
Inconclusive in the human view; raw values remain compatible. Shared uses count per route and must not be described as unique confirmed vulnerabilities.

## SARIF mapping

The exporter follows the
[OASIS specification plus errata](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html).
The current mapping is below; specific downstream consumer support has not been tested.

| Scan concept | SARIF representation |
|---|---|
| Detector / constraint definitions | Tool driver rules, rule identifiers and help |
| Source-backed finding | Result with primary location and related locations |
| Supported possible source-to-sink path | codeFlows / threadFlows with source locations |
| Route grouping | Logical locations plus namespaced scan properties carrying method/path/route ID |
| Stable identity | Snapshot-local IDs only; edit-stable fingerprints/baselines remain planned |
| Graph views | Local control edges in properties; full directed graph export remains planned |
| Concrete verified patch | fixes only when an actual edit is available; prose options remain recommendations/help |
| Judge/completeness/review details | Namespaced properties linked to the canonical evidence |
| Execution failure / partial scope | Invocation notifications and explicit completeness properties |

SARIF supports paths and directed graphs; a custom JSON format is not required merely to exchange
findings. The internal graph remains useful for analysis ownership, indexed traversal, caches and
rich route views. Export only justified code flows; do not turn an unordered dependency set or a
truncated candidate into a fabricated execution path. Preserve approximations and missing facts.

SARIF can carry source and dependency findings. SCA mapping must retain package/advisory identity
and manifest/lockfile locations without inventing a source-code sink. Route reachability is an
additional assessment, not the advisory's existence.

## Implemented interface and remediation

`--analyze --sarif` exports a current scan. `--export-sarif <saved-report.json>` converts a canonical
JSON report offline with no new judge request. These flags are mutually exclusive with `--json`.
The exporter does not recompute or upgrade saved assessments. It rebuilds deterministic human-readable
presentation from saved raw uses, including for older schema-v1 reports. `scan.finding` preserves the
human-readable finding alongside `scan.assessment`, source evidence, gaps, and recommendations.

SARIF maps presentation Findings (including poor practice) to fail/warning, Protected to pass/none,
Review to review/note, and not_applicable to notApplicable/none. This uses the shared presentation
classification rather than raw model status; `scan.assessment` retains the original status. A pass applies
only to the declared claim. Validation and use-protection answers remain separate in messages and
properties: safe SQL parameterization can coexist with missing domain validation.

Rule help and per-result recommendations include the project tenet that findings cover confirmed
vulnerabilities and weak or poor practice, because an agent can harden both cheaply, plus
complementary actions and **illustrative, unverified
code templates** where the supported library model permits them. They are not patches and do not
appear in SARIF fixes. The Decisions choice API supplies typed assessments; it does not generate code.
A future optional Responses generation stage could produce tailored examples using separately capped
Luna requests, but must preserve assumptions and require checking before any applied fix. That stage
is not implemented or used in this evaluation.

## Delivery and verification

The current exporter was validated offline against the official SARIF 2.1.0 schema on the two Juice
Shop findings and vulnerable/protected/unknown comparison reports. Unit tests cover statuses, escaped
locations, preserved incomplete assessment, deduplicated related locations and absence of fabricated
registration value paths or unverified fixes. No GitHub/IDE ingestion test has been performed.

Phase 9 still owns the stable normalized finding contract, identity/baselines, CI policy and consumer
integration. This bounded adapter does not complete that phase. Neither JSON nor SARIF changes
finding eligibility, runtime-confirmation state or independent-review policy.

The [query judgment design](query-judgment.md) owns automatic injection evidence and evidence validation.
Public [analysis rules](../../docs/analysis/README.md) describe SQL/NoSQL and validation semantics.

Current analysis JSON uses schema4 and `analysis_guidelines`; schemas1–4 remain readable
through private compatibility decoding, retaining original source/schema/answer provenance.
See [naming and compatibility](../architecture.md#naming-and-compatibility).

## Common entry migration

Current use/finding records serialize `entry_id` and `invocation_context_id` as their primary
association. Typed entry metadata supplies HTTP/browser labels; no fake HTTP route is used
for browser roots. SARIF includes generic entry/context properties and entry-level coverage
notifications for unknown dispatch, including zero-use entries. Original historical answers,
classification and source locations remain preserved during offline export. Typed presenters cover HTTP, browser events, GraphQL and gRPC. Their adapters now supply actual
source-backed entries; the [acceptance results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05)
separate parsed-source integration, synthetic policy controls and completed bounded localhost rendered inspection.

## Typed entry projection and selectors

`internal/report/entries.go` owns typed identity and detail projection for HTTP, browser,
GraphQL, gRPC and unknown entries. Text/HTML/SARIF reuse it; `findings.go` remains the
single status interpretation. Presentation version 6 preserves contextual counts and
zero-use coverage without an entry-wide protection assertion.

SARIF uses sink locations first, declaration fallback only when absent, and registration,
schema/proto and invoked-callable related locations. Results retain `scan.entryId`,
`scan.entryKind`, `scan.invocationContextId`, typed `scan.entry` and context/dispatch
properties. Non-HTTP entries have no manufactured `scan.route`. Invocation properties
preserve zero-use inventory and gaps; these do not generate security results.

`internal/analysis/selectors.go` owns kind-specific selector validation/matching and common
CLI filter intersection. Check input normalizes legacy HTTP method/path at decoding;
context-scoped requirement assembly retains existing analysis semantics. Canonical JSON
includes `selected_scope` and `check_matches` with per-context use counts. See the
[CLI contract and examples](../../docs/running-scans.md#common-entry-selection-and-tagged-checks).

SQL/NoSQL model answers that conflict with bounded hex-only SQL or relevant selector type-guard
evidence retain explicit `injection_constraint_review` and remain Review. Raw answers and construction
practice stay visible; the gate never fabricates a Protected result. See the
[database analysis rules](../../docs/analysis/database-injection.md).
