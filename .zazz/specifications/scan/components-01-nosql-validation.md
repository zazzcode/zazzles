# Analysis components 01 — NoSQL and input validation

## 0. Capability and session boundary

First follow-on session after SQL: migrate existing JS/TS NoSQL injection and existing JS/TS/Python standalone input-validation
assessment into the embedded component architecture in one implementation session and one review unit.
Preserve their separate questions, mandatory evidence, outcomes and coverage. Generalize only the
SQL-specific assumptions needed by these two real consumers; preserve working SQL behavior.

The user requested this specification on 2026-11-05 and explicitly combined NoSQL and validation in
one session. This turn creates contracts, not implementation. Outbound and all XSS types have separate
[Outbound](components-03-outbound.md) and [XSS/browser](components-02-xss.md) contracts. Logging remains a
separate future migration. Command injection remains the next new vulnerability family.

## 1. Required reading

- [AGENTS](../../../AGENTS.md#start-here) and [orientation](../../docs/zazzles-agent-orientation.md#task-reading-paths).
- [SQL contract](analysis-pack-mvp.md#2-invariants),
  [component architecture](../../architecture/analysis-packs.md#boundary-and-ownership), and
  [plan](../../project/implementation-plan.md#analysis-pack-mvp-initiative).
- [Database injection](../../../docs/scan/analysis/database-injection.md#nosql-rules),
  [validation](../../../docs/scan/analysis/input-validation.md#establish-the-field-policy),
  [trace](../../architecture/trace-judgment.md#implemented-evidence-contract).
- [spec-driven](../../../.agents/skills/spec-driven/SKILL.md),
  [execution discipline](../../docs/agent-execution-discipline.md), [standards index](../../standards/index.yaml),
  [structure](../../standards/code-structure.md), [testing](../../standards/testing.md),
  [spec hygiene](../../standards/spec-hygiene.md), [docs hygiene](../../standards/docs-hygiene.md),
  [doc-check](../../../.agents/skills/doc-check/SKILL.md).
- Current code: `internal/analysispacks/{catalog,select,material,descriptors,questions}.go`,
  `internal/guidelines/sql.go`, `internal/judge/{injection,validation,policy,components}.go`,
  `internal/parse/{checks,mongoose_query_context,python_validation}.go`; tests below.

## 2. Invariants

The SQL contract's source trust, mandatory Go gates, invocation isolation and historical-answer
invariants remain binding. Additionally:

- NoSQL validation, construction practice and injection remain independent facets. Rejecting operator
  objects does not establish a field's business validity. Schema types alone do not remove selectors.
- A standalone validation claim requires an explicit/source-backed requirement and enforcing path.
  It MUST NOT require a fabricated database API, sensitive sink or query-protection question.
- HTML form constraints may establish intended policy; they do not prove server enforcement.
  Client validation, GraphQL types/directives, names and model preference cannot invent server policy.
- Python NoSQL remains unimplemented. Record non-support; do not invent an adapter or create dummy
  Python NoSQL claims to fill a test matrix.
- Preserve source IDs/spans/hashes, entry/context relationships, original roles/gaps/blockers, raw
  answers, classification/counts and zero-use entries. Only enumerated provenance/envelope changes
  are allowed. Do not silently repair unrelated detector behavior during migration.

## 3. Scope and review shape

One combined deliverable/specification, one assigned feature worktree/branch and one intended draft
PR into `stage`. Combining these two consumers tests reuse without combining their claim semantics.
Use the currently assigned checkout if suitable; do not create a worktree, stack or PR merely to
prepare this contract. Implementation is assigned in a later session under AGENTS authorization.

**Baseline:** consume the completed SQL component tree, not just `HEAD`. At authoring, SQL changes
are still uncommitted in `analysis-pack-mvp` on merged base `f8b7dbd`. Before coding, preserve all
existing work and record the actual accepted commit or source/diff manifest plus passing baseline
commands. Do not reset/stash away SQL implementation or assume it exists in integration. A new
checkout must contain the accepted SQL implementation and this contract before implementation starts.

| Repository-relative path | Change | Purpose |
| --- | --- | --- |
| `internal/analysispacks/` | Modify/add family-specific Go files/tests | Family registration, selection/material contracts, NoSQL and validation components |
| `internal/guidelines/` | Narrow modify/add tested section selector | Explicit family projections and required-section validation without silent omission |
| `internal/judge/{injection,validation,policy,client,components,trace}.go` and tests | Modify | Selected questions/choices, per-family protocols/provenance and mandatory gates |
| `internal/parse/{analysis,checks,mongoose_query_context,check_context,python_validation}.go` and companion tests | Narrow modify | Attach selections to existing claims without changing extraction |
| `internal/analysis/{components,analysis,json}.go` and tests | Narrow modify | Generalize existing provenance types only if necessary; historical compatibility |
| `internal/report/`, `cmd/scan/` tests/wiring | Narrow modify | Existing result/format parity; avoid presentation redesign |
| `internal/parse/testdata/` | Narrow add | Minimal synthetic controls missing from current coverage |
| This spec; `.zazz/architecture/analysis-packs.md`; `.zazz/project/implementation-plan.md`; specification index | Modify | Evidence, owners and ledger |
| `README.md`, `docs/technical-approach.md`, `docs/decision-models.md`, database/validation analysis guides | Narrow modify | Describe delivered scope and protocols |

The diff MUST stay within the paths above. Remove superseded NoSQL/validation material definitions
when ownership moves; unrelated cleanup stays separate. No plugins, new languages/APIs/frameworks,
Python NoSQL, broad standards ingestion, new report domains, new detection families, outbound/XSS/
logging migration, sample edits, paid calls or target execution are included.

## 4. Decisions and extension risks to resolve

**Family-specific registration.** The current `Select`/`Attach`, required-root registry and
`requestDigest` operate only on SQL; `Material` requires an API contract and exactly three questions.
Replace those checks with explicit registrations for SQL, NoSQL and standalone validation because
these are real different consumers. Each registration identifies candidate/claim eligibility,
question protocol, required roots, material roles, cardinality and Go policy owner. An unknown family
MUST NOT fall through to a newly trusted generic security judgment. Unmigrated families keep their
existing runtime paths.

**Compatibility and identity.** Separate catalog compatibility from question/envelope protocols.
Do not make every descriptor adopt a SQL-named protocol. Keep existing SQL IDs/content stable where
possible. Do not reuse SQL-only `language.javascript` material as NoSQL/validation guidance merely
because the source language matches; give distinct material stable identities or a measured shared
section identity. Compiled capabilities declare only their actual supported claim subsets.

Use `nosql-components-v1` and `validation-components-v1` for changed requests, preserving question
names, choices and interpretations. Keep `sql-components-v1` only if its effective bytes remain
identical; otherwise record `sql-components-v2` and reject old replay. Preserve existing SQL policy
outcomes either way. Existing generic provenance fields permit schema 4; change schema only if the
serialized field contract actually changes, with an explicit compatibility record.

**Claim-specific material.** Move MarsDB collection and existing Mongoose query/casting contracts,
NoSQL all-path/coverage questions and validation requirement/enforcement questions into single owners.
NoSQL requires verified operation semantics; standalone validation does not require an API contract.
Define required questions by names and choices, not a universal count of three. Keep conflicting
primary material detection, while allowing only deliberately declared shared roles. Do not send the
whole language/catalog, SQL/XSS/logging advice or test metadata to these requests.

**Guidance omission risk.** Current SQL projection selects exact Markdown headings and removes
literal phrases. A heading/content edit can silently omit relevant guidance. Add validated named
sections or explicit embedded fragments with one canonical owner and fail on missing/duplicate
required sections. Preserve current SQL effective content during this refactor unless explicitly
versioned as above. Test a renamed/missing section; a changed digest alone does not prove that all
required interpretation survived selection.

**Evidence and provenance.** Parse records effective selected obligations separately from original
source-required roles/gaps. Go checks their deduplicated union plus mandatory family gates. Attach
selection/provenance and request digests to both new consumers, including raw historical response
preservation and zero-call failures. Validation's protocol gate MUST expect its selected protocol;
do not disable it to make the new version pass. Missing built-in roots fail catalog configuration
before scanning; target-specific unknown applicability retains the candidate and explicit failure.

**Bounds.** Retain 32 components, 16 KiB selected material and 64 KiB final requests with lossless
compaction. No silent truncation or generic fallback. Measure new payloads; a previously assessed
baseline control that no longer fits is a contract issue to resolve, not a silently skipped success.

## 5. Implementation rules and halt conditions

One Contributor Agent implements the combined session; no delegated agents or external tracker are
required. Work from the assigned root and use local toolchain/offline modules. Keep one ignored
`.zazz/ephemeral/components-nosql-validation-run-log.md`, following the directory storage policy.
Record baseline, changed files, applicable standards, compatibility decisions, test evidence and
recoveries. Tests use local HTTP stubs for both providers; no target API calls or paid models.

Halt dependent work for missing SQL prerequisite code, unexplained source/outcome drift, a required
core-gate weakening, lost field policy, new detector scope, changed review topology or out-of-scope
files. Routine internal naming and compatible representation choices may adapt with evidence.
Preserve unrelated work. Commits/pushes/PR creation need the later assignment; agents do not merge.
Review `git diff --name-only`, the accepted-base diff and `git ls-files --others --exclude-standard`.

## 6. Acceptance criteria

The named new tests are implementation requirements; existing tests remain regressions.

| ID | Observable acceptance | Verification |
| --- | --- | --- |
| N1 | SQL, NoSQL and validation registrations select independently; invalid/missing roots, incompatible choices and API-less validation are explicit; unsupported Python NoSQL gains no detector | `TestFamilyComponentSelection`, `TestFamilyCatalogValidation`, existing SQL catalog/applicability tests |
| N2 | Changed/absent/duplicate required guidance sections fail explicitly; valid SQL bytes remain unchanged or use the recorded protocol bump | `TestFamilyGuidanceCompleteness`, frozen SQL request/protocol controls |
| N3 | Actual parsed JS/TS NoSQL raw selector, constrained scalar, `$where`, conditional alternatives, Mongoose version/schema, unknown helper/API and shared-caller cases retain bindings/gaps and outcomes | `TestNoSQLComponentPipelineParity`; existing Mongoose, all-path and conditional tests |
| N4 | Actual parsed JS/TS/Python standalone validation preserves required-only, format/range when source-backed, free text, absent policy, ignored/late guards, unknown helpers and client-only policy outcomes without API requirements | `TestValidationComponentPipelineParity`; existing validation-policy and Python policy tests |
| N5 | Same field may be injection-protected and policy-invalid, or policy-valid with unsafe query use; neither facet grants the other; no duplicate issue count | `TestNoSQLValidationClaimIsolation` through parse → local judge → JSON/HTML/SARIF |
| N6 | Both provider encoders receive only selected material, correct named questions/choices and no labels; missing/conflicting/oversize selections make zero HTTP calls; core gates reject optimistic inconsistent answers | `TestFamilyComponentPayloads`, `TestFamilyComponentFailures`; existing strict decoders |
| N7 | IDs/versions/digests/request provenance present; exact replay works and changed content without version bump, questions/choices, evidence, context/model or protocol rejects it; old schema1–4 exports retain answers and absent provenance | `TestFamilyComponentReplay`, extended `TestComponentReportCompatibility` |
| N8 | SQL and unmigrated XSS/logging/outbound remain equivalent; zero-use/unsupported entries retained; full checks and scoped documentation checks pass | Baseline frozen comparisons; `go test -race ./...`, `go vet ./...`, `go build ./...` |

## 7. Test strategy

Capture the SQL-component baseline plus independent NoSQL/validation expected projections before
moving content. Reuse `TestNoSQLAllPathProtectionGate`, `TestMongooseQueryProtectionControls`,
`TestConditionalQueryOutputConstraints`, `TestAutomaticCollectionProvenance`,
`TestValidationPolicyRequiresIndependentEvidence`, `TestValidationRespectsAdditionalRequiredRoles`,
`TestPythonValidationPolicyClaims` and `TestPythonFormPolicyIsNotEnforcement`.
Use actual source fixtures and fixed stub answers, with wrong optimistic answers on incomplete slices.
Keep expected labels outside requests. Compare source roles/slots/contexts/gaps/raw answers and final
cross-format status/counts, allowing only enumerated new metadata/protocol fields. Do not regenerate
baseline goldens to approve unexplained drift. Include supported non-HTTP contexts without broadening
their adapter subsets; do not fabricate validation/NoSQL support where discovery produces no claim.
Measure component/material/body size and local allocations without timing-based pass thresholds.

## 8. TDD entry point and execution sequence

1. Preserve/identify the SQL tree, run baseline checks and inventory actual NoSQL/validation ownership.
2. First failing tests: API-less standalone validation selects valid policy material, and an unsupported
   Python NoSQL use cannot select a trusted contract. Add missing-required-section failure.
3. Generalize registrations/material/provenance for the three real families. Keep SQL behavior locked.
4. Migrate NoSQL contracts/questions and selected guidance; verify its actual pipeline checkpoint.
5. Migrate standalone validation; verify independent-policy evidence and combined claim isolation.
6. Finish protocols/replay/history/bounds and cross-format checks; remove duplicate runtime owners.
7. Run scoped tests, full contributor checks, changed-Go formatting, doc checks; update ledger/README.

Responsibility skeleton (internal names may adapt):

```text
analysispacks/families.go: compiled family registration -> roots, material roles, protocol
analysispacks/nosql.go + validation.go: canonical existing family knowledge
analysispacks/select.go + material.go: validated registered family, deterministic composition
parse/analysis.go: existing discovered claims -> selection (no new extraction)
judge: selected named questions/choices -> family decoder + unchanged mandatory Go gates
```

## 9. Definition of done

- [ ] N1–N8 have evidence with no unexplained SQL/other-family/source/outcome drift.
- [ ] Both families are working consumers; no inventory-only completion claim.
- [ ] Selection and policy failures cannot produce protection or silent omitted records.
- [ ] Compatibility/replay/bounds and both provider paths pass; historical artifacts remain intact.
- [ ] Full checks, scoped docs, owners/ledger and implementation handoff evidence are complete.

## 10. Open questions

No product-scope question blocks drafting. Implementation is not assigned by this documentation
request. The next implementation assignment must identify the accepted SQL tree; its current dirty
state is not permission to discard it. Representation details may adapt within the locked outcomes.

## 11. Run log protocol

Use the ignored local log named above, append-only, for standards verification, baseline manifest,
compatibility decisions, phases, failures/recoveries, deviations and evidence links. Scan/test artifacts
follow the repository output policy; durable acceptance summaries belong in the component architecture.
A resumed agent reads this contract, log if present, Git state and relevant diffs before editing.

## 12. Implementation prompt

> Implement `.zazz/specifications/scan/components-01-nosql-validation.md` in the explicitly assigned feature
> worktree. Read AGENTS, its referenced orientation, this contract, SQL component architecture,
> spec-driven and matched standards first. Preserve existing SQL implementation even if uncommitted;
> record the accepted source/commit baseline and passing checks. Work as one Contributor Agent for
> NoSQL plus standalone input validation in this session. Generalize SQL-only registration/material/
> provenance assumptions for these real consumers, then migrate existing NoSQL and validation
> knowledge with independent named protocols and mandatory Go gates. Do not require a database API
> for standalone field policy, invent business restrictions, add Python NoSQL or change detector scope.
> Validate guidance completeness; preserve SQL evidence/outcomes and version any changed SQL request.
> Use actual parsed fixtures and both provider localhost stubs; verify raw/protected/unknown/not-applicable
> answers, claim isolation, JSON/HTML/SARIF parity, limits, historical exports and stale replay rejection.
> Follow the ordered checkpoints and append evidence to the local ignored log. Run scoped and full
> contributor checks; update the architecture ledger, plan and README only for delivered behavior.
> No paid calls, sample edits, target execution, automatic extra worktrees/agents or integration merges.
> Report incomplete criteria candidly; follow the user's assignment for commits/pushes/draft PRs.

## 13. Implementation and review change log

### 2026-11-05 — Implementation completed in the assigned session

**Source.** User implementation assignment (§12) executed by one Contributor Agent in the
`analysis-pack-mvp` worktree.

**Changed sections.** None contractually; this entry records the sanctioned compatibility outcome
and verification. §4 allowed keeping `sql-components-v1` only if effective bytes stayed identical.

**Rationale.** Generalizing component compatibility from one SQL protocol to a family-protocol list
changes component digests and therefore SQL `analysis_components` provenance bytes, while SQL
guidance, questions, choices, discovery and outcomes are preserved.

**Summary.** SQL requests now use the recorded bump `sql-components-v2`; NoSQL uses
`nosql-components-v1` and standalone validation `validation-components-v1`; report schema stays 4.
NoSQL contracts/questions and validation questions moved to single catalog owners; family
registrations, validated guidance projections, provenance and request digests cover all three
families. JS standalone field records now use the field-policy protocol; their outcomes remain
Review/needs_evidence. Evidence: `.zazz/architecture/analysis-packs.md` migration ledger and
verification section; the ignored local run log holds the baseline manifest, decisions and
measurements.

**Verification impact.** N1–N8 checks pass offline (`go test -race ./...`, `go vet ./...`,
`go build ./...`, scoped doc checks); frozen SQL discovery hashes and `string-flow` goldens are
byte-identical to the accepted SQL tree; old SQL/NoSQL/validation protocols reject replay and
historical exports keep original answers. Accepted-base diff and manifest recorded before edits;
no reset/stash of the uncommitted SQL tree. Python NoSQL remains unimplemented.

User direction 2026-11-05 combines NoSQL and standalone validation in one implementation session;
this supersedes the earlier separate-session recommendation.
