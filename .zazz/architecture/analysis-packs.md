# Analyzers and embedded analysis packs

<a id="embedded-analysis-components"></a>

The [architecture terminology](../architecture.md#analyzer-terminology) distinguishes an **Analyzer**
(the assessment capability), its supporting **analysis pack** (versioned knowledge), reusable
**analysis components**, and the **shared analysis engine**. Internal family registrations group
related candidate kinds and protocols; they do not require separate engines or packages.

This document owns the implemented component responsibilities, source inventory, compatibility,
migration status and verification evidence. `internal/analysispacks` provides the shared catalog used
by static evidence assembly and model judgment. Entry/dispatch records describe the application's
wiring; analysis components describe the scanner knowledge applicable to a particular candidate.

The [original design](../project/analysis-pack-mvp.md) records rationale; the
[implementation plan](../project/implementation-plan.md#analysis-pack-mvp-initiative) owns remaining
work. The [database guide](../../docs/analysis/database-injection.md#query-component-selection) and
[XSS guide](../../docs/analysis/xss.md) own product interpretation rules.

## Node input interpretation and generic sink contracts

`source.node-input-v1` is selected only for Node candidates carrying versioned shared input facts.
It interprets transport-neutral origin, initial/sink type, transformations, lifecycle stages and
source-present controls. It does not supply source edges or security verdicts. Existing Python
material remains unchanged. Fresh Mongoose lookups use `mongoose-find-by-id-objectid-v1` for the
verified pinned default-ObjectId operation; the historical Express-coupled contract remains readable.
Neither a framework name nor a schema declaration establishes protection.

Acquisition adapters lower bounded syntax/configuration into common evidence. The judge reasons
about supplied application logic; Go requires complete witnesses and consistent outcomes. The
separate `node-route-discovery-v1` protocol selects source-backed binding proposals under an explicit
additional cap. It is not a security pack or an alternate vulnerability pipeline. The engine checks
source snapshots and dispatch; unknown suggestions remain provisional coverage. See the
[Node input contract](../specifications/node-http-input-refactor.md) and
[public guidance](../../docs/analysis/node-inputs.md).

## Current implementation status

The SQL Injection, JS/TS NoSQL Injection, Input Validation, XSS and Command Injection Analyzers
use the shared embedded catalog, deterministic selection and schema-4 provenance. Outbound
observations also select catalog components, without implementing SSRF security assessment.
Static adapters establish source facts;
components select relevant guidance, contracts, questions and evidence obligations; evidence validation
enforces completeness and consistency requirements. Outbound is observation-only, with no model
questionnaire, model calls or SSRF verdict.

The SQL-first MVP and migration sessions 01–03 are implemented. The Sensitive Data Logging
Analyzer still uses its working judge-owned questions and `log-use-v1` protocol outside component selection. It is the remaining
migration of an existing analyzer. The Command Injection Analyzer is delivered as a new capability on this structure (see the command ledger below);
complete SSRF assessment, general Inspect, public pack loading and executable plugins remain future
capabilities.

The [fresh paid verification](#fresh-paid-component-e2e-2026-11-06) and
[static baseline comparison](#merge-readiness-recheck-2026-11-06) record actual results and limits.
Dated checkpoints below preserve implementation history; their former next-session instructions
do not supersede this status or authorize new work.

### Fresh paid component E2E, 2026-11-06

The user explicitly authorized live OpenAI Decisions `gpt-6-luna` scans of both complete pinned
checkouts. Current runtime `d33d215` completed all 944 eligible fresh requests with no provider
failures, retries, fallback or reused historical answers. The runner used the same parse, component,
judge and report packages as the CLI, preserving exact request/response traces and source snapshots.
These are live judgments; earlier stub runs remain separately identified offline evidence.

| Application | Entries / uses | Fresh paid completed / eligible | Confirmed / poor practice / Review / Protected |
| --- | --- | --- | --- |
| Juice Shop | 167 / 208 | 117 / 117 | 9 / 1 / 198 / 0 |
| VulnPy | 564 / 827 | 827 / 827 | 28 / 0 / 799 / 0 |

All seven historical Juice Shop and 28 historical VulnPy confirmed source contexts remain confirmed.
The two additional Juice Shop confirmations are raw email interpolation at `routes/login.ts:34`
and query input passed through `bypassSecurityTrustHtml` to the search component's `innerHTML` sink
at template line 11. Both were checked against source; changed model outcomes are not proof of a
general accuracy gain. VulnPy retains 21 SQL and seven raw-HTML contextual findings, including the
12 required main-path framework/method combinations. The separate Jinja path remains Review.

Every migrated candidate's paid request carries the same selected pack/components, versions and
digests as its source evidence, with the correct JS/TS or Python language projection. The 942
registered-family requests comprise 877 standalone-validation, 23 SQL, 11 NoSQL and 31 XSS
assessments; two additional logging requests retain the active unmigrated protocol. Target exercise
comments are absent from model input. Outbound observations make zero model requests. Juice Shop
still has 66 outbound and 20 JSON-only observations `not_run`, plus five explicit binding failures;
completing its eligible judgments does not make those coverage limits complete assessments.

Independent fresh-source exact replay passes for all 944 paid responses without additional calls.
Saved/re-exported HTML and SARIF match, JSON raw answers remain unchanged, and source/entry facts
match the freshly parsed checkouts. Both targets remain clean with pinned revisions and all 156
reference hashes verified before/after. Maximum bodies are 64,648 bytes for Juice Shop and 48,332
for VulnPy, below 65,536. Provider-reported usage totals 8,451,642 input tokens and zero output
tokens; no currency charge is inferred.

Evidence root: `_test-findings/run-xhndoag7/`, including `audit.json`, `component-audit.json`,
`baseline-and-exports.json`, integrity manifests and per-candidate raw traces. Live report bundles:
`juice-shop/assessed/juice-shop/run-3161010206/` and
`vulnpy/assessed/vulnpy/run-2718109530/`. Historical reports and sample apps were preserved.
The obsolete test-only `Client.decode` wrapper was removed before this runtime checkpoint; its
duplicate-answer regression uses the current decoder. No additional unreferenced migration
functions were identified in the production-reference review. Logging remains active and separately
scoped; this validation does not authorize another family migration or further paid runs.

### Merge-readiness recheck, 2026-11-06

A fresh whole-checkout Juice Shop scan after documentation reconciliation and removal of the unused
`Client.decode` wrapper retains 167 entries (154 HTTP, 13 browser), 208 uses, eight construction
findings and 200 Review records. It is exactly equal to the original pre-componentization
`f8b7dbd` report after excluding component selections and the schema3-to-schema4 version change.
The baseline was built from a temporary Git source archive; no worktree or integration changes
were made. This checks the whole refactor's static source/report behavior, beyond session03 alone.

Against pre-outbound `dc309cd`, removing only 66 outbound selection records yields exact structural
equality. Both provider stubs preserve all 117 effective request hashes, 117 exact replays and all
142 non-outbound full CLI candidate records, including original-source request digests. Each makes
117 calls with zero outbound calls; two source-reviewed raw XSS controls remain findings. Full CLI
runs retain the expected exit1 with five binding failures and 86 `not_run` observations. Saved and
re-exported JSON/HTML/SARIF preserve raw answers, source associations and counts. Stub outcomes
verify mechanics and preservation, not live-model accuracy or complete security coverage.

Current evidence: `_test-findings/juice-shop-closeout/juice-shop/run-1110679670/`; original-base
report: `_test-findings/juice-shop-precomponents-closeout/juice-shop/run-503065659/`.
The pinned target and all 27 source hashes remain clean and unchanged. Full race tests (nine
packages), vet, build, changed-Go formatting and scoped documentation/link checks pass. The
duplicate-answer regression now exercises the current decoder directly; no request or policy
semantics changed. The local report server serves these snapshots for review.

## Session 02 closeout and session 03 starting point

Runtime checkpoint `4e0be3e` on the existing `analysis-pack-mvp` feature branch includes the
session01 foundation (`7610193`), XSS component migration (`30fada9`) and authorized minor cleanup.
SQL, NoSQL, standalone validation and XSS are working component consumers. Their protocols are
`sql-components-v2`, `nosql-components-v1`, `validation-components-v1` and `xss-components-v1`;
report schema4, evidence-version3 and route-inventory schema1 are independent contracts.
Schemas1–4 still read/export with original historical answers; changed requests reject replay.

The post-push Juice Shop check used clean pinned revision
`f189f521266f42c6bd05884468292000cee852ed`, with all 27 reference hashes verified before/after.
Accepted pre-XSS `7610193` and current `30fada9` scans have exact canonical equality after removing
only the 23 new XSS selection records: 165 entries (152 HTTP, 13 browser), 208 uses, 8 construction
findings and 200 Review records. DOM search and cross-tier track-order remain the two XSS
construction findings. Stored/JWT/model-setter/collection/dialog origin gaps remain Review.
Both provider encoders construct all 23 rendering requests; localhost stubs verify the two
source-reviewed raw controls plus replay; all 20 JSON-only observations remain unassessed. Largest bodies are
62,738 bytes (OpenAI) and 62,108 (Jev), below 65,536. These are offline preservation checks, not
live-model accuracy or resolution of the known coverage misses. Raw report/verification artifacts:
`_test-findings/juice-shop/run-3290785101/`; accepted pre-XSS run: `run-3975911309`.
The small cleanup removes an unreachable XSS protocol fallback, a test-only production constant
and SQL-specific wording in the shared replay error. Full race, vet, build, formatting and docs
checks passed after cleanup; no source facts, protocols or successful judgments changed.

This records the historical session02 checkpoint. [Session03](../specifications/components-03-outbound.md)
subsequently implemented observation-only `not_run`, zero model calls and Preview rejection from
clean `dc309cd`. The [outbound verification](#outbound-observation-verification-2026-11-06) separates
that eligibility correction from source/report parity and records the changed requested-scan exit.
Logging migration and complete SSRF/exfiltration/browser-security assessment remain separate work.

## Boundary and ownership

`internal/analysispacks` owns scanner-authored component descriptors, dependency validation,
deterministic selection and bounded interpretation material. Components describe existing compiled
capabilities; they do not load or execute adapters. The package does not import parse, judge or report.
Shared serializable references live in `internal/analysis`; extraction remains in `internal/parse`,
transport and mandatory claim gates in `internal/judge`, and presentation in `internal/report`.

| Knowledge | Baseline owner | Component responsibility and remaining owner |
| --- | --- | --- |
| JS/TS syntax, Express, dynamic HTTP, GraphQL, unary gRPC, browser entry/flow | `internal/parse/` adapter and flow files | Reference supported compiled subsets and their limits; extraction remains in parse |
| Python Flask/Blueprint, RESTX, FastAPI, DB-API flow | `internal/parse/python_*.go` | Reference supported compiled subsets; no new Python framework/heap/async support |
| Language interpretation | `internal/guidelines/javascript.md`, `python.md`, `go.md` | Registered families select validated existing sections; unmigrated families retain full language documents; Go guidance does not establish Go support |
| Sequelize raw SQL | `internal/parse/checks.go` | Catalog owns the verified operation contract; parse still proves receiver/import/slot bindings |
| Python SQL drivers | `internal/parse/python_dbapi.go` | Catalog owns sqlite3, Psycopg 2/3, PyMySQL and MySQL Connector operation contracts; parse still proves connection/cursor provenance |
| SQL questions and choices | `internal/judge/client.go`, `injection.go` | SQL components own the selected question/answer material; judge encodes, decodes and applies evidence validation |
| Required SQL evidence | `internal/parse/checks.go`, `python_sql.go`; `internal/judge/policy.go` | Components declare obligations; core input-source, sink-binding, invoked-callable and control-flow roles remain mandatory |
| NoSQL contracts | `internal/analysispacks/nosql.go` (catalog owner); parse proves collection/model bindings | Migrated: MarsDB collection and Mongoose query/casting contracts are catalog components; selector, `$where`, schema/version and all-path semantics preserved |
| XSS contracts/questions | `internal/analysispacks/xss.go` and `xss_selection.go`; validated guideline projections | Migrated: catalog owns primary rendering contracts, five questions and supplementary context/protection/storage/browser/response material; parse retains source facts and judge retains mandatory gates |
| Standalone validation | `internal/analysispacks/validation.go` (questions/choices); policy assembly stays in parse; gates in `internal/judge/validation.go` | Migrated: requirement/enforcement questions are catalog components; established/absent policies, enforced/bypassed/missing guards and API-less field claims preserved |
| Logging | Logger/source extraction in parse; `internal/judge/logging.go` | Inventoried, not migrated; retain sensitive content, emission and redaction gates |
| Outbound requests | Destination/source extraction in parse; `internal/analysispacks/outbound.go` owns Python contract and observation descriptors | Migrated: JS/TS shapes remain unverified, Python URL/body/response roles preserved; no security questionnaire, model request or SSRF verdict |
| Findings and exports | `internal/report/`, `cmd/scan/` | Existing presentation counts/statuses remain; canonical JSON carries detailed selection provenance |

A material item has one runtime owner. Family integration reuses selected shared language sections
and moves operation/question knowledge rather than creating alternative legacy policy paths.
Logging retains its existing behavior until its own migration. Outbound is observation-only, with no
model protocol; selected scope/limits do not establish a completed security assessment.

Catalog identities are `pack.<family>`, `claim.<family>`, `evidence.<family>`, `flow.local`,
`language.javascript`, `language.python`, `language.nosql.javascript`,
`language.validation.javascript`, `language.validation.python`, `entry.http`, `entry.graphql`,
`entry.grpc` and `api.<operation-contract-id>`. A normal SQL or NoSQL candidate selects seven
components; a standalone validation claim selects five. Language versions follow the canonical
JavaScript/TypeScript v5 and Python v3 guidance; the SQL projection keeps the accepted
`language.javascript`/`language.python` identities, and each family projection has distinct
component identities because its selected bytes differ. Operation IDs remain
`sequelize-raw-query-v1`, `python-<driver>-dbapi-v1` for the five existing Python drivers,
`marsdb-collection-v1`, `mongoose-model-query-v1` and the pinned `mongoose-model-query-v2`.
A language version identifies the underlying guidance; the digest also covers the actual selected text.

## Descriptor and selection contract

Each embedded component has a stable ID, explicit version, kind, domains, applicability,
compatibility, pinned dependencies, compiled/source owner, required roles, limits and test references.
Its SHA-256 covers content and metadata, including compiled-owner references, so changing bytes
without bumping a version still changes identity. Ordered dependency closure produces a stable selection digest. Pack identity is versioned
independently of a target application or dependency version.

Language, entry framework, verified library operation and claim compose independently. Selection
uses supported source facts and scanner configuration. Installed packages, helper names and target
comments do not enable trusted contracts or define policy. Unknown application library versions
retain the contract's bounded assumptions; a scanner contract version is not an installed version.

Static registered-family assembly records its selection and effective obligations on the candidate. Existing
`completeness.required` and source gaps are preserved; `analysis_components.required` records selected
obligations. Evidence validation checks their union with core/claim roles and consumes that same
selection. Mandatory engine obligations are unioned with component roles;
component content cannot remove evidence gates, invent an edge or clear a blocker. Caller-specific
controls remain attached to invocation contexts, including shared callables exposed through several
entries. Protection cannot transfer from one caller, field, operand or branch to another.

Invalid embedded catalog configuration fails before model requests. Missing or ambiguous candidate
applicability retains the candidate and an explicit unresolved state, without generic fallback.
Selected-for-analysis provenance is distinct from a completed model assessment.

The model receives selected interpretation and the actual trace. Compiled-owner identifiers,
regression labels/test names and unrelated catalog entries are metadata, not model instructions.
No catalog-wide list or expected result is sent. Existing source deduplication and lossless compact
wire encoding are retained; neither removes controls or obligations.

## Bounds and compatibility

The selection closure is limited to 32 components and selected interpretation material to 16 KiB.
These bounds leave headroom for the small working SQL composition while preventing unrestricted
catalog expansion into a request. The existing 64 KiB final provider-body bound remains authoritative
for both provider encoders; source and selected material count toward it. Requests may use existing
lossless compaction. Excess material or a still-oversize body remains unresolved with no HTTP call;
required content is never truncated. Measurements are recorded under verification below.

Fresh analysis JSON uses schema 4. SQL requests use `sql-components-v2` (the NoSQL/validation
generalization changed component compatibility metadata and therefore SQL provenance bytes; guidance,
questions, choices and outcomes are unchanged), NoSQL uses `nosql-components-v1` and standalone
validation `validation-components-v1`. The accepted foundation used schema 3 with
`candidate-injection-v1` SQL/NoSQL requests and `validation-use-v2` validation requests; saved
reports keep those answers but cannot replay onto changed requests. XSS uses `xss-components-v1`,
logging `log-use-v1`, and generic candidates `candidate-use-v10`. Evidence-version 3 and
route-inventory schema 1 are independent contracts.

The candidate's `analysis_components` records pack/component IDs, versions, digests, effective
required roles, limits and optional `failure` coverage provenance, separately from original source
gaps. `assessment.request_digest` records the effective request for assessed registered-family claims. Decision traces carry
`analysis_components` and `request_digest` alongside the exact request/response bodies. Exact effective provider-body matching and protocol checks still gate Replay. Changing
selected content/metadata, evidence, instructions, questions/choices or model rejects an old response,
even if someone forgot to bump a material version. No automatic persistent decision cache is added.

Saved schema-1/2/3 reports remain exportable through the existing compatibility boundary. Export
preserves original answers and source-schema provenance; it does not invent a component selection or
claim that a saved result was freshly judged. JSON is canonical provenance. HTML/SARIF retain existing
issue counts and status semantics, including a construction-practice concern beside protected SQL.

## Migration ledger

| Analyzer / supporting observations | Status | Next bounded task and acceptance controls |
| --- | --- | --- |
| SQL Injection Analyzer with query validation/construction facets | Migrated / offline verification passed | Catalog/selection, request composition, provenance and actual JS/TS/Python pipeline parity; raw, bound, constrained, unknown and context-isolation controls; `sql-components-v2` provenance after family generalization with frozen discovery hashes and outcomes |
| Command Injection Analyzer | Implemented; offline checks and full judged scans passed | `pack.command`/`claim.command`/`evidence.command`/`flow.command`, `language.command.{javascript,python}` and four `api.*` operation contracts; four shell/executable/argument/coverage questions under `command-components-v1`; evidence validation checks; predecessor requests and identities unchanged ([results](../evaluation/command-injection-results.md)) |
| Path Traversal Analyzer | Implemented; offline checks, full 8-app matrix and live controls passed | `pack.path`/`claim.path`/`evidence.path`/`flow.path`, `language.path.{javascript,python}`, eleven `api.*` operation contracts (`node-fs-file-v1`, `express-send-file-v1`, `adm-zip-extract-v1`, `unzipper-entry-write-v1`, `hbs-render-layout-v1`, `python-open-file-v1`, `python-pathlib-file-v1`, `python-archive-open-v1`, `python-os-file-v1`, `flask-send-file-v1`, `werkzeug-file-save-v1`) and path-only `source.node-input-path-v1`; three questions under `path-components-v1` (traversal, containment control, coverage); AST-polarity and order-sensitive evidence validation checks; shared node-input component and predecessor requests unchanged ([results](../evaluation/path-traversal-results.md)) |
| XSS Analyzer (reflected, stored and client-side/DOM/framework) | Migrated / offline verification passed | Selected rendering/context/protection/storage/browser/response material; five unchanged named questions, mandatory origin/context/path gates, JSON-only observations, exact replay and separate bounded fetch-method correction |
| Input Validation Analyzer | Migrated / offline verification passed | Requirement/enforcement questions and field-policy guidance selected per claim; established/absent policies, enforced/bypassed/missing guards, client-only policy, unknown helpers, API-less claims, JS/Python parity and claim isolation; no invented standards |
| Sensitive Data Logging Analyzer | Implemented; catalog migration pending | Move sensitive-content/emission/redaction contracts and questions; paired leaks, metadata/constants, redaction and unknowns |
| NoSQL Injection Analyzer (JS/TS) | Migrated / offline verification passed | MarsDB/Mongoose contracts, selector/`$where` guidance and all-path/coverage questions selected per claim; raw selector, constrained scalar, conditional alternatives, Mongoose schema/version, unknown helper/API, shared-caller isolation and replay controls; Python NoSQL stays unsupported |
| Outbound observations (supporting future SSRF Analyzer) | Migrated / offline verification passed | Scoped observation components, unchanged source/report projections and Python operand contract; explicit zero-call not_run and incomplete requested scan; no SSRF verdict |

The user revised session grouping on 2026-11-05. Implementation order is
[01 NoSQL plus standalone validation](../specifications/components-01-nosql-validation.md),
[02 all XSS types including browser](../specifications/components-02-xss.md), then
[03 outbound observations](../specifications/components-03-outbound.md). Logging remains separate.
Sessions 01–03 are implemented and offline-verified; human review remains pending.
XSS uses coordinated server/template, stored and browser/cross-tier checkpoints. The plan tracks
actual future sequencing; the Command Injection Analyzer is delivered and Harden XSS analyzers is the next unfinished analyzer task.

### Extension risks recorded by source review

- Resolved by session 01: catalog compatibility, required roots, `Select`/`Attach`, material
  requirements and request-digest handling were SQL-specific. Family registrations now own candidate
  eligibility, question protocols, roots, roles, cardinality and policy owners, and required
  questions are validated by registered names and choices, not a universal count.
- Resolved by session 01: guidance projection relied on exact Markdown headings and silent literal
  phrase removal. Projections now declare required named sections; duplicate, renamed or missing
  sections and missing required phrase edits fail before scanning, and the SQL projection's effective
  bytes are frozen by test.
- Resolved by session 02: browser fetch uses actual literal methods/default GET; unresolved options,
  methods and Request objects keep a gap and cannot select a guessed server producer. The separate
  before/after table below records the only authorized detection correction. No runtime exploit or
  corpus-wide accuracy claim is made.
- [JS/TS outbound discovery](../../internal/parse/flow.go) uses fetch/axios-shaped names and retains
  unverified-binding/response gaps. It combines argument dependencies without the same destination
  precision as the existing Python adapter. Session 03 retains these limits, confers no trusted
  API contract by name, and keeps URL/body/response and browser/server evidence separate.
- Generic SQL construction questions do not establish outbound destination security. Session 03
  makes observation-only model eligibility explicit; full SSRF requires its own later questions,
  evidence gates and evaluation. Client-side requests must not be labeled server SSRF.

These are maintenance/extension constraints and bounded correctness concerns, not evidence that the
SQL refactor regressed. Existing offline checks preserve the measured SQL baseline; they do not
establish general live accuracy or coverage of every browser vulnerability.

Scan, Inspect, Audit and Fix remain independent product goals. Existing validation and construction
practice can share components without establishing a general quality engine. A team standard requires
explicit trusted selection and claim-specific evidence. This repository's `.zazz/` development rules
are not automatic policy for targets. General standards ingestion, downloaded packs, plugins,
independent Findings Review and automated remediation remain outside this MVP.

## Verification and limits

Verification uses existing source fixtures and local provider stubs. It compares discovery, bindings,
source spans/hashes, invocation contexts, blockers, coverage, raw answers and final report outcomes
against the accepted foundation. Only explicitly versioned schema/provenance/envelope changes are
allowed. Existing unmigrated-family controls remain regression coverage. Expected labels remain in
test assertions/stubs, outside judgment input.

Offline tests demonstrate composition, transport, policy and reporting behavior. They do not measure
live-model accuracy, general precision/recall, custom-validator generalization or paid-call savings.
No live requests, target execution or sample-application edits are needed for this migration.

### SQL migration verification, 2026-11-05

On native Go 1.27.3 darwin/arm64 (module minimum 1.27.2), uncached scoped tests pass for parse,
judge, analysis, report and CLI. SQL-specific evidence includes:

- `TestSQLDiscoveryBaseline`: frozen accepted-foundation hashes across nine fixture sets, allowing
  only schema 4 and `analysis_components` fields to differ; source facts and existing gaps are preserved.
- `TestCatalogValidation`, `TestSelectionDeterminism`, `TestSQLApplicability` and
  `TestSQLMaterialAndSelectionLimits`: closure, dependency/version/applicability conflicts, byte changes
  without version bumps, additive obligations and explicit limits.
- `TestSQLComponentPayload`: selected SQL assessment, decoding and exact replay through both OpenAI
  and Jev localhost transports; unrelated guidance/catalog/test metadata excluded.
- `TestSQLComponentPipelineParity`: six SQL controls each in JavaScript/TypeScript GraphQL/gRPC,
  expected per-entry outcomes and JSON/HTML/SARIF count/status/source/raw-assessment parity.
- `TestSQLPythonComponentPipeline`: five drivers × raw, bound, dynamic-identifier and unresolved
  transformation controls (20 cases), with selected contracts, policy/replay and cross-format checks.
- `TestSQLHTTPComponentAnswers`, `TestSQLSelectionFailurePipeline`, `TestSQLComponentLimits` and
  `TestSQLComponentReplay`: independent facets, unknown/not-applicable answers, zero-call failures,
  oversize rejection and stale-request controls. Existing injection/context/hex/conditional tests remain.
- `TestComponentReportCompatibility` plus existing schema-1/2 tests: old answers/protocols stay
  historical; schema-3 export does not fabricate component or request provenance.

Measured selection material is 6,074 bytes for JS/TS and 5,293 bytes for Python sqlite3; each uses seven
components. Across 35 valid SQL fixture candidates, final provider bodies range from 22,668 to 48,318
bytes. The same baseline fixture set's largest body was 48,138 bytes: the observed maximum increases
by 180 bytes, remaining below 65,536. Material stays well below the 16,384-byte cap; no content is
truncated to fit. These fixture measurements are not whole-repository payload guarantees.

`BenchmarkSQLComponentSelection` on Apple M6 measured 2,493 ns/op, 2,765 B/op and 20 allocations/op.
The old path had no component selection, so this is added local selection work, not a scanner-wide
speedup. Timing is host-specific evidence, not a correctness threshold or live-model cost estimate.

Final independent checks after the required-root configuration fix all pass:

```bash
GOTOOLCHAIN=local GOPROXY=off GOFLAGS='-mod=readonly -buildvcs=false' \
  GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test -race ./... -count=1
GOTOOLCHAIN=local GOPROXY=off GOFLAGS='-mod=readonly -buildvcs=false' \
  GOCACHE="$PWD/.zazz/ephemeral/go-cache" go vet ./...
GOTOOLCHAIN=local GOPROXY=off GOFLAGS='-mod=readonly -buildvcs=false' \
  GOCACHE="$PWD/.zazz/ephemeral/go-cache" go build ./...
```

All nine packages pass the race suite. Changed/new Go files pass the format gate; the diff passes
whitespace/conflict checks, and new/changed documentation links resolve. The obsolete parse-owned
Python DB-API contract file was removed after moving its sole owner to the catalog. No paid calls,
sample edits, feature commit/push or integration merge were performed as part of this refactor.
The user-requested local branch synchronization was a fast-forward to the already merged foundation.

### NoSQL and standalone validation migration verification, 2026-11-05

Second/third consumer migration under the [combined contract](../specifications/components-01-nosql-validation.md),
implemented on the accepted (uncommitted) SQL tree recorded in the session run log. On native Go
1.27.3 darwin/arm64, uncached scoped tests and the full race/vet/build suite pass. Evidence:

- `TestFamilyComponentSelection`, `TestFamilyCatalogValidation`, `TestFamilyGuidanceCompleteness`:
  independent family registrations; missing family roots, unknown protocols, drifted claim questions,
  contradictory language applicability and renamed/missing/duplicate guidance sections fail before
  scanning; API-less validation selects; Python NoSQL and unregistered kinds gain no selection.
- `TestNoSQLComponentPipelineParity`: raw selector, constrained scalar (protected and
  optimistic-vulnerable), `$where` numeric-only vs raw-sibling alternatives, Mongoose pinned
  4.2.4 schema/version (`mongoose-model-query-v2`), unknown helper, fake collection API and shared
  caller with per-invocation guard isolation; per-route outcomes, blockers, replay and
  JSON/HTML/SARIF parity through actual parsed fixtures.
- `TestValidationComponentPipelineParity`: free text, absent policy and ignored type-only guards
  (JS), required-only enforced, source-backed format unenforced, client-only policy and unknown
  helpers (Python); optimistic answers cannot bypass missing field-policy roles; no API contract
  in any validation payload.
- `TestNoSQLValidationClaimIsolation`: one Python field simultaneously SQL-protected and
  policy-invalid; one JS selector field injection-protected beside an unresolved standalone record;
  no duplicate issue counts across JSON/HTML/SARIF.
- `TestFamilyComponentPayloads`, `TestFamilyComponentFailures`, `TestFamilyComponentReplay`: both
  provider encoders carry only selected material with exact question sets and provenance; zero HTTP
  calls on selection failures; stale-request/protocol/evidence mutations reject replay.
- `TestComponentReportCompatibility` extended: schema-3 exports keep historical
  `candidate-injection-v1`/`validation-use-v2` answers and absent provenance (including display);
  schema-4 exports keep `pack.nosql`/`pack.validation` provenance and request digests.
- Existing NoSQL/validation regressions (`TestNoSQLAllPathProtectionGate`,
  `TestMongooseQueryProtectionControls`, `TestConditionalQueryOutputConstraints`,
  `TestAutomaticCollectionProvenance`, `TestValidationPolicyRequiresIndependentEvidence`,
  `TestValidationRespectsAdditionalRequiredRoles`, `TestPythonValidationPolicyClaims`,
  `TestPythonFormPolicyIsNotEnforcement`) and the frozen SQL discovery baseline all pass unchanged;
  `string-flow` goldens are byte-identical to the accepted SQL tree.

Measured on fixtures: NoSQL selects 7 components / 11,092 bytes of material with final bodies of
28,755 (jev) and 29,451 (openai) bytes; validation selects 5 components / 4,358 (JS) and 3,646
(Python) bytes with bodies of 16,031 and 16,265 bytes. All remain inside the 32-component,
16 KiB material and 64 KiB request bounds with no truncation. SQL bodies stay in the recorded
22,668–48,318 byte range. `BenchmarkSQLComponentSelection` measures 2,767 ns/op, 4,200 B/op and
34 allocations/op on Apple M6 (accepted SQL baseline: 2,493 ns/op, 2,765 B/op, 20 allocs/op);
host-specific timing evidence, not a correctness threshold.

No paid calls, sample edits, target execution, feature commit/push or integration merge were
performed. JS standalone field records now use the field-policy protocol instead of the generic
practice pair whose sink-protection question they could not answer; their outcomes remain
Review/needs_evidence, now for the honest missing-policy reason.

### XSS migration verification, 2026-11-05

Accepted predecessor: clean `7610193`, containing session-01 implementation `9c83a07` and its
cleanup. The ignored run log records the complete tracked-blob manifest and passing baseline.
One agent used the existing `analysis-pack-mvp` worktree; no predecessor work was discarded.

`pack.xss`, `claim.xss` and `evidence.xss` register `xss_candidate`. The catalog owns the three
existing Express, browser and Python rendering contracts and the unchanged five named questions
and choices. `render.*` is a singleton primary rendering role; `context.xss`, `protection.xss`,
`storage.xss`, `browser.xss` and `response.xss` are supplementary interpretation roles selected by
actual rendering/type facts. `flow.xss` references existing compiled extraction without changing
SQL/NoSQL/validation descriptors or requests. Template sinks retain their actual spans/files;
rendering contracts identify their source adapter for language selection. The browser contract is
rendering interpretation, not an invented server API. Data-only JSON records acquire no selection
and make no decision request. Existing compiled encoder/sanitizer binding/version/options logic,
independent writing paths and source/coverage limits remain authoritative.

The staged server/template, stored, browser/framework/event/inline-script and cross-tier checks pass:

- `TestXSSComponentSelection`, `TestXSSMaterialBoundsAndConflicts`, `TestXSSComponentInventory`:
  browser-only selection, required roots, incompatible primary contracts, stale bytes without a
  version bump, bounds and actual Python/browser fixture inventory.
- `TestXSSServerComponentParity`, `TestXSSStoredComponentParity`, `TestXSSBrowserComponentParity`,
  `TestXSSCrossTierComponentParity`: parsed source through both OpenAI/Jev localhost transports
  to JSON/HTML/SARIF, with independent expected raw/protected/unknown results; EJS/Handlebars/Pug,
  Jinja, Mongoose/Sequelize, DOM/jQuery, React/Vue/Angular and Python inline scripts.
- Existing response/template/compile/sanitizer, stored sibling-path, framework, event/limit and
  Python-inline regression matrices pass. Frozen SQL discovery projections and non-XSS suites pass.
- `TestXSSComponentPayloadsAndPolicy`, `TestXSSDataOnlyNotAssessed`, `TestXSSComponentFailures`,
  `TestXSSComponentReplay`: correct selected questions, no unrelated policy/test labels, optimistic
  answer rejection, required-role union, unresolved origins, zero-call selection/body failures,
  exact replay and changed method/evidence/material/model/protocol rejection.
- `TestXSSComponentReportParity`: six real event registrations, four independent use contexts,
  two raw, one protected and one unknown outcome; JSON/SARIF keep zero-use coverage and HTML
  keeps browser grouping/source locations. `TestXSSComponentHistory` retains original XSS answers
  and versions through schema1–4 read/export; fresh reports remain schema4.

The fetch exception is separate from organizational parity. The pre-fix GET-hardcoded control was
run against the same fixtures and failed; the corrected implementation passes. GET supplies raw
`req.query.get`, while POST supplies independently constrained `req.body.post` at the same `/item`.

| Browser request | Before | After |
| --- | --- | --- |
| Absent/undefined options, `{}`, explicit GET | GET origin; raw | Same GET origin/protection |
| Literal lower-case `post` | Wrong GET origin; raw | POST origin only; sanitized on its own path |
| Dynamic method/options or alias | Guessed GET origin; raw | Empty unresolved method; explicit method gap; no linked producer |
| Spread, duplicate or computed property | Guessed GET origin; raw | Method gap; no linked producer |
| Request object | Unsupported endpoint; no demonstrated origin | Explicit unresolved method; no guessed producer; rendering record retained |

`TestBrowserFetchMethodIsolation`, `TestBrowserFetchRequestObjectRetainsGap`, `TestPythonInlineFetchMethodGap` and existing
`TestCrossTierResponseFieldLinks` cover literal/default methods, wrong fields, ambiguous routes and
unresolved producers. New origin/method evidence cannot reuse a saved request. No other detector
behavior correction, framework/flow expansion or vulnerability family was introduced.

Measured selected material: reflected JS 8 components / 8,115 bytes; stored Python 9 / 7,394 bytes;
cross-tier JS/TS 10 / 8,836 bytes, below 32 / 16,384. The 88 measured pipeline/inventory provider bodies
range from 16,961 to 38,293 bytes, below 65,536; source evidence is never truncated to fit. Local selection benchmark:
6,437 B/op, 44 allocations/op (Apple M6, Go1.27.3); no timing threshold or scanner-wide speedup claim.
Test output lives outside the worktree under `_test-findings/components-xss/20261105-offline/`.

Full contributor checks pass: `go test -race ./... -count=1` (nine packages), `go vet ./...`,
`go build ./...`, `gofmt -l .` (empty), whitespace/conflict and scoped manual documentation/link
checks. X1–X8 are covered; no unmet criterion remains in this contract. Subsequent user-authorized
feature commits/pushes and minor cleanup are recorded in the checkpoint above. No paid calls,
sample edits, target execution, new worktrees/agents, PR creation or integration merge were performed. Live-model accuracy,
broader browser security and general Python API-to-browser linkage remain outside this contract.


### Outbound observation verification, 2026-11-06

Accepted predecessor: clean `dc309cd` in the assigned `analysis-pack-mvp` worktree, preserving
runtime `4e0be3e` and sessions01/02. The ignored run log retains the tracked-blob manifest and
baseline experiments. One agent implemented the bounded observation migration; no commits, pushes,
PRs, extra agents/worktrees, target requests, sample changes, paid calls or integration merges.

`pack.outbound`, `observation.outbound`, `evidence.outbound` and `flow.outbound` describe existing
observations. JS/TS selections retain combined argument dependencies and unverified binding/response
gaps, including fake/shadowed fetch/axios. No JS API contract or URL-slot precision is invented.
Python's unchanged `python-http-destination-v1` has one catalog owner, selected only for existing
bound supported calls; method-first, positional/keyword URL and fixed-URL/body-only controls pass.
The source adapter still proves binding and roles. Runtime context comes from entry/binding facts,
not file names; browser request sources and XSS response producer links remain independent.

Catalog compatibility is `outbound-observation-v1`, with no outbound model protocol and no schema
change. Schema4 selection provenance describes static capability only. Assess/AssessTrace return
`not_run` with the reason that outbound security assessment is not implemented, no request digest or
question version; Preview errors with no body. Missing/malformed catalog roots/material fail explicitly.
Existing component/material/request bounds remain, without truncation or an outbound payload.

**Eligibility correction, separate from parity:** on the same five-observation synthetic fixture,
both predecessor provider stubs completed five generic `candidate-use-v10` assessments, five HTTP
calls and exit0. The new path retains five Review records, returns five explicit `not_run`, makes
zero HTTP calls and exits1 for requested-assessment incompleteness. This is the intended eligibility
and exit-result delta, not a new detector or SSRF judgment. Conservative candidate-index scheduling
is unchanged: observations can occupy capped positions; HTTP calls never exceed the configured cap.
Structural-only scans still complete normally. Historical generic answers remain intact on export.

Acceptance evidence:

- O1/O2: `TestOutboundComponentSelection`, `TestOutboundBindingScope`, frozen
  `TestOutboundComponentEvidenceParity` and existing `TestPythonOutboundOperandRoles`,
  `TestPythonBindingControls`, `TestPythonEvidence`. JS and TS each retain five observations;
  Python retains three URL-dependent uses, excluding fixed URL/body-only and response-body controls.
  Removing only outbound selection metadata yields exact accepted enriched-report hashes.
- O3/O4: `TestOutboundObservationNotAssessed`, `TestOutboundObservationCLI` and
  `TestMixedAssessmentWithOutboundObservations`: both localhost providers, direct/trace/preview,
  saved incomplete bundles, all four supported claim families, caps1/3/100, explicit status/reason
  and exit1. Target fixture hosts never enter transport.
- O5: `TestBrowserServerRequestIsolation`, unchanged `TestBrowserFetchMethodIsolation`,
  `TestCrossTierResponseFieldLinks` and browser/Angular/XSS regression matrices retain independent
  request, body, response, method, field and producer relationships. Browser HTTP is not server SSRF.
- O6: `TestOutboundComponentReportParity`, `TestOutboundComponentHistory`, saved CLI HTML/SARIF
  re-export and schema1–4 controls preserve source, gaps, coverage, Review counts, raw answers and
  provenance. No SSRF/exfiltration/browser-security vulnerability is added.
- O7: `TestOutboundPredecessorRequests` freezes eight exact provider-body hashes for SQL, NoSQL,
  validation and XSS, compared with a temporary source snapshot of `dc309cd` (not a Git worktree).
  All earlier family replay/staleness tests and catalog configuration/bounds controls pass.

Selection measures five components / 351 material bytes for JS/TS and six / 590 for Python;
provider request bytes are zero. Local benchmark: 2691 ns/op, 4876 B/op, 34 allocations/op
(Apple M6, Go1.27.3). This is added static selection overhead, not a whole-scan speedup or live-model
accuracy/cost measurement. Full offline race, vet, build, formatting and scoped manual doc/link
checks pass. O1–O7 have evidence; no unmet implementation criterion remains. Human acceptance,
complete SSRF/exfiltration/browser-security analysis and general JS URL-operand verification remain
outside this bounded delivery.


### Juice Shop full E2E follow-up, 2026-11-06

The user authorized full Juice Shop E2E validation, fixes if needed, then commit and push of
`analysis-pack-mvp`. No scanner defect was found by this comparison. The orientation's obsolete
next-session pointer was corrected; implementation scope and detector behavior remain unchanged.

Target revision `f189f521266f42c6bd05884468292000cee852ed` is clean including ignored files;
all 27 reference hashes match before/after. Complete CLI discovery without `--entry` produces
167 entries (154 HTTP, 13 browser), 208 uses, eight construction findings and 200 Review records.
The earlier 165-entry report selected `server.ts`; the complete scan additionally retains the
GET/POST zero-use registrations in `routes/dataErasure.ts`. Current structural bundle
`_test-findings/juice-shop/run-860097900/` and accepted `dc309cd` source-snapshot bundle
`run-3156486993/` are exactly canonically equal after removing only 66 new outbound selections.

Both local provider probes cover every candidate and preserve all 117 non-outbound request hashes
and raw assessments per provider. Predecessor: 183 completed stub calls, including 66 outbound;
current: 117 completed calls, zero outbound calls, 86 `not_run` (66 outbound, 20 JSON-only), and
five unchanged failed assessments (two SQL and three NoSQL missing verified binding). Both providers
replay all 117 current completed answers exactly and retain the two independently source-reviewed
DOM-search/track-order raw XSS controls. Largest bodies are 64,651 bytes (OpenAI), 64,345 (Jev),
below 65,536; no source/material is truncated. Unknown stub answers test mechanics, not live accuracy.

Full CLI requested-assessment runs use the same localhost stubs with cap208, preserve all entries,
source/provenance and expected statuses, make 117 calls per provider, save their incomplete bundles
and exit1 as required. Saved JSON/HTML/SARIF and independent re-exports retain exact raw answers,
source associations and counts. Stub-assessed presentation has eight construction findings and
200 Review records (91 `needs_review`, 109 `needs_evidence`). The existing five binding failures
and JSON-only/outbound incompleteness are supported limits, not claimed complete security coverage.
Synthetic cap1/3/100 regressions and the full contributor race/vet/build/doc checks also pass.
Raw assessment traces, body-hash summaries and CLI bundles are retained under the current run's
`assessment-checks/` and `cli-verified/`; temporary target-bound probes are retained in ignored
execution scratch rather than adding external-checkout dependencies to normal unit tests.

No paid provider call, target request/application execution, sample edit, extra agent/worktree,
PR creation or integration merge was performed. Human review and broader accuracy/coverage work
remain pending; all outbound migration criteria remain met.

## Command execution components (2026-11-07)

The command family adds components without touching existing descriptors: command-only embedded guidance
(`internal/guidelines/command*.go`, never in default language selection), the catalog-owned operation contracts
(Node shell and argv, Python `os`, Python `subprocess`) selected only after a verified binding, and reused
`entry.http/graphql/grpc` descriptors. Parse attaches the same selection the judge revalidates with `ForUse`;
`CommandFacts` (operation, shell modes, ordered operands, per-path protection and controls, with index-validated
references into the deduplicated evidence table) travel in the wire bundle. Control-kind evidence in a command use is
namespaced so invocation identity, and therefore every existing candidate ID, is unchanged. Limits: POSIX assumption,
bounded transfers, adapter-specific entry models (see the [public guide](../../docs/analysis/command-injection.md)).

## Path traversal components (2026-11-14)

The path family follows the command pattern: path-only embedded guidance (`internal/guidelines/path*.go`, never in
default language selection), catalog-owned contracts selected only after a verified `fs`/`open`/`pathlib` binding,
reused `entry.http/graphql/grpc` descriptors, and `PathFacts` (operation, role, operand slots, per-flow protection,
transformations, base, classified guards) in the wire bundle. Two decisions are architectural. First, the shared
`source.node-input-v1` component is not widened: adding the path kind to its applicability would change its digest and
therefore every existing Node family's selected request, so a path-only twin `source.node-input-path-v1` shares the
same material constant. Second, claim assembly (entry scoping, supplied route/middleware context, handler control flow,
guards, completeness) is now one hook-driven routine (`internal/parse/claim_assembly.go`) used by the command and path
families; the command tests, including the source cases on the pinned targets, are unchanged by the refactor. Only request
`input_source` dependencies are path flows; stored, file, API and browser values are not. Path-scoped second-pass URL/file
members (`req.path`/`url`/`originalUrl`/`file(s)`), non-final Express route-chain handlers, explicit local export lists and
mounted router parameters extend path coverage without altering any existing analyzer's evidence (see the [results](../evaluation/path-traversal-results.md)).
