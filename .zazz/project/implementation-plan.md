# Implementation plan

**Reconciled: 2026-11-14.** This document owns the functionality roadmap. **Implemented** means
bounded code and verification exist in this checkout; it does not mean complete ecosystem coverage,
a released version, or a merged feature branch. Contracts and evaluation records own detailed
acceptance evidence. This roadmap does not authorize implementation or live model calls.

## Product goals and capability boundaries

| Capability | Function | State |
|---|---|---|
| **Scan** | Assess source-code vulnerabilities, controls, and supported validation/construction practices | Implemented for bounded JavaScript, TypeScript, and Python cases |
| **Inspect** | Assess correctness, maintainability, and selected engineering standards | Planned as a distinct workflow; existing practice checks provide a foundation |
| **Audit** | Assess dependency vulnerabilities and retain advisory evidence | Planned |
| **Fix** | Turn findings or a specified issue into tested repairs and reviewable pull requests | Planned |

The capabilities are intended to work independently or in combination. Fix may start from an
existing report or user-specified issue. Review is an unresolved report outcome, not an Inspect
workflow or an independent review service. See [product responsibilities](../project.md#four-product-capabilities).

## Delivery priorities

1. Strengthen native Scan and build the distinct Inspect workflow on the shared engine.
2. Add dependency Audit through ecosystem tooling: npm/pnpm for JS/TS and pip-audit for Python.
3. Add on-demand and scheduled execution, agent-driven Fix, verification, and pull-request preparation.
4. Import external SAST and code-quality findings while preserving their provenance.

These are delivery priorities, not a mandatory sequence for users. The tables below distinguish
implemented functionality from planned work; proposed features still need bounded contracts.

<a id="supported-capability-checklist"></a>
<a id="complete-delivery-list"></a>
<a id="analysis-pack-mvp-initiative"></a>

## Completed functionality

Every row describes an implemented subset. A supported language or framework is not a claim that
all its syntax, APIs, or vulnerable paths are covered.

| Functionality | Implemented behavior and boundary | Owning reference |
|---|---|---|
| **SQL injection** | JS/TS and Python query construction, verified API operand/binding models, and separate injection judgments | [Database rules](../../docs/analysis/database-injection.md#sql-rules) |
| **NoSQL injection** | JS/TS MongoDB/Mongoose and MarsDB-compatible selectors and executable expressions; Python and other engines remain planned | [Database-specific scope](../../docs/analysis/database-injection.md#database-specific-nosql-scope) |
| **Input validation** | JS/TS/Python source-established field requirements and enforcing controls, separate from destination protection; missing business policy stays unresolved | [Validation rules](../../docs/analysis/input-validation.md) |
| **Sensitive-data logging** | JS/TS/Python supported logger calls and access-log credential exposure; data class, content, and redaction assessed separately | [Logging contract](../specifications/sensitive-data-logging.md) |
| **Cross-site scripting** | Supported server/template and stored-value claims, browser/DOM/framework sinks, and selected JS/TS API-to-browser links; general Python-to-browser linkage remains planned | [XSS rules](../../docs/analysis/xss.md), [hardening results](../evaluation/xss-hardening-results.md) |
| **Command injection** | Node `child_process` and Python `os`/`subprocess` contracts; shell syntax, executable selection, arguments, and control coverage | [Command results](../evaluation/command-injection-results.md) |
| **Path traversal** | Supported Node/Python file operands (including `fs.open`/`copyFile`/`rename`, Starlette/FastAPI `FileResponse`/`UploadFile`, `shutil` copy/move, `tarfile.extractall` with filter facts), file serving, archive opens/extraction, Zip Slip, and render-layout paths; dual-path independence; containment, branch polarity, mutation, and ordering checks | [Path rules](../../docs/analysis/path-traversal.md), [results](../evaluation/path-traversal-results.md), [E4 contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Outbound observations and SSRF** | Destination-origin classification and grouped observations; SSRF claims for verified `fetch`/`axios`/Node `http`/`https`/`node:http`/`node:https` and Python `requests`/`httpx`/`urllib` calls with a request-derived destination | [Outbound contract](../specifications/components-03-outbound.md), [assessment coverage](../specifications/analyzer-assessment-coverage.md), [E4 contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Entry discovery and bounded flow** | Source inventory; shared entry/registration/dispatch/callable records; supported HTTP, browser events, finite dynamic routes, Node Apollo GraphQL, and Node unary gRPC | [Entry acceptance](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05) |
| **JavaScript conditional flow** | Precise JS/TS `if`/`else if`/`else`: arm polarity, exits including `process.exit`, isolated joins, block scoping. A guard on one arm never protects a sibling arm or later code. Loops, `switch`, `try`/`finally` and request rebinding keep a conservative fallback | [Analysis rules](../../docs/analysis/README.md#javascript-conditional-flow), [contract](../specifications/javascript-if-flow.md) |
| **Evidence wire v7** | Always-compact requests with evidence IDs, character-column locators, one obligation ledger, a role budget with visible omissions and an `evidence_too_large` floor. Transparent wrappers and header-only middleware summaries. Guidance-owned fact codes. Largest sample request about 59 KB | [Wire v7 contract](../specifications/wire-bundle-v7.md), [verification](../evaluation/wire-bundle-v7-results.md) |
| **Node input acquisition** | Bounded Express/Fastify/Hapi adapters supply shared input origins (including URL path/url/originalUrl/baseUrl and verified upload filename/content), types, transfers, controls, lifecycle stages, and Express non-final middleware-chain sibling entries; Python remains on its existing adapters | [Node refactor results](../evaluation/node-input-refactor-results.md), [E4 contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Optional model-assisted route discovery** | Explicitly enabled, separately capped proposals with source/binding verification; unfamiliar wrappers remain provisional coverage, not trusted flow | [Node input/discovery contract](../specifications/node-http-input-refactor.md) |
| **Decision-model assessment** | OpenAI Luna Decisions is primary; optional Gemini and stub-tested Jev adapters use the shared evidence gates and one model selection per scan, without fallback | [Model setup](../../docs/decision-models.md) |
| **Assessment scheduling and family selection** | Primary security sinks precede standalone validation; zero-call observations consume no request slots; canonical `--only-family` / `--skip-family` flags and environment defaults | [E1 contract](../specifications/analyzer-engine-hardening.md) |
| **Equivalent-context reuse** | Scan-local reuse only for conservatively equivalent requests; retain each entry's finding, provenance, policy evaluation, and existing exact-request identity; derived records add no usage | [E1 contract and measured limits](../specifications/analyzer-engine-hardening.md#6-acceptance-criteria-slice-e1) |
| **Request and rate controls** | Per-run assessment cap and optional shared RPM/TPM pacing; disabled pacing skips clock/window work. Spending is managed in the provider console; local dollar budgets/pricing are removed | [Limits contract](../specifications/decision-model-limits.md) |
| **Embedded analysis knowledge** | Versioned catalog selection and provenance for SQL, NoSQL, validation, XSS, command, path, logging and outbound observations; fixed query/middleware fact interpretation in `internal/guidelines/facts.md` | [Catalog architecture](../architecture/analysis-packs.md), [path contract](../specifications/path-traversal.md) |
| **Evidence validation and exact replay** | Source-backed completeness/consistency gates, request traces, and exact-match offline replay; confidence cannot supply missing evidence | [Trace architecture](../architecture/trace-judgment.md), [report contract](../architecture/reporting-and-sarif.md) |
| **Reports and artifacts** | Canonical JSON, standalone HTML, SARIF, entry selection, findings/Review/Protected presentation, saved-report export, and historical schema compatibility; artifacts can be retained in CI | [Running guide](../../docs/running-scans.md), [CI artifacts](../../docs/ci.md) |

## Active delivery: analyzer engine hardening

E1 (scheduling, family filters, context reuse), E2 (shared guard and workspace-manifest
engine), and E3 (evidence wire v7, assessment coverage, JavaScript conditional flow and
fact-code consolidation) are merged into `stage` via [PR #14](https://github.com/zazzcode/zazzles/pull/14)
(`6e815ec`).

**E4 complete on branch `node-inputs-and-file-apis` (base `6e815ec`).** Shared Express
middleware-chain / URL/upload inputs, path second-pass retirement, phase-2 file APIs, and Node
`http`/`https` SSRF are implemented; Node sample reports republished under a 350-request
`gpt-6-luna` cap (250 charged, 250 exact replays). Draft PR targeting `stage` is the remaining
integration step. Contract:
[shared-node-inputs-and-file-apis.md](../specifications/shared-node-inputs-and-file-apis.md).

Deferred with recorded decisions: S1 data-path slicing and S2/S5 relevance filtering. Size pressure
is one record near the soft threshold and none over the limit. The full v7 re-recording of the 260
historical VulnPy path contexts needs its own owner cap.

<a id="future-capability-branches"></a>
<a id="ordered-specification-backlog"></a>

## Planned functionality

### Sequenced engine follow-ons

The [hardening milestone](../specifications/analyzer-engine-hardening.md#0-capability--milestone-roadmap)
sets the dependency order. Each remaining slice requires its dedicated executable contract before coding.

| Slice | Planned outcome | State |
|---|---|---|
| **E2 — Shared guards and workspace manifests** | One lexical guard engine for Command and Path (branch polarity, terminators including exiting else-if links, derived values, reassignment, helper callers); nearest-workspace manifest and lockfile resolution for Path, XSS and NoSQL | Merged; [contract](../specifications/shared-guard-and-manifest-engine.md) |
| **E3 — Wire bundle and catalog consolidation** | Compact v7 wire, evidence references, logging catalog, wrappers and middleware summaries, precise JS conditionals, fact codes | Merged via [PR #14](https://github.com/zazzcode/zazzles/pull/14); [contract](../specifications/wire-bundle-v7.md) |
| **E4 — Shared Node inputs and file APIs** | Promote middleware-chain and URL/upload inputs across Node analyzers; extend verified Python/Node file and archive operation coverage; add Node core `http`/`https` client SSRF contracts (vuln-demo-app `/fetch` confirmed) | Complete on `node-inputs-and-file-apis` (paid Node rebuild 250/350 `gpt-6-luna`, exact replay 250/250); draft PR to `stage` pending; [contract](../specifications/shared-node-inputs-and-file-apis.md) |

The [proposal](analyzer-hardening-and-wire-efficiency-proposal.md) owns the detailed rationale and
boundaries. Token and call savings remain measurements to establish, not guaranteed outcomes.

### Analyzer expansion and product workflows

The following work remains planned; rows are functional goals rather than reserved branches or
approved implementation assignments.

| Planned functionality | Intended outcome / remaining boundary |
|---|---|
| **Python coverage completion** | Python NoSQL models and general API-to-browser XSS linkage; shared Python input facts remain a separate migration |
| **NoSQL engine expansion** | Additional MongoDB-style coverage and separately verified contracts for other databases; no implied DynamoDB or universal NoSQL support |
| **Code injection and XXE** | Request-to-evaluation/code-generation and request-to-XML paths with verified operation/configuration contracts |
| **Open redirect and SSRF** | Destination policies, verified URL slots, and complete security judgments beyond current outbound observations |
| **Weak randomness and cookie/session/header configuration** | Security-sensitive randomness and source-established configuration requirements with appropriate negative controls |
| **Prototype pollution** | JS/TS object/prototype operations and verified library behavior; no invented Python equivalent |
| **Secret scanning** | Distinguish private material from public keys, placeholders, and test data |
| **Stronger claim evidence** | Improve remaining unresolved helper, guard, dispatch, and API cases within explicit analysis bounds; [targeted direction](analysis-certainty-improvements.md) |
| **Independent Findings Review** | Separate review conclusions, disagreements, evidence, and completion state; distinct from the current Review category |
| **Inspect workflow** | Select applicable engineering standards and present quality/maintainability findings separately from vulnerability claims |
| **Dependency Audit** | npm/pnpm and pip-audit adapters, dependency/advisory provenance, SBOM artifacts, and explicit failure/reachability limits; [design](../architecture/sca-design.md) |
| **Automation and Fix** | Scheduled/on-demand assessments, scoped repair agents supplied with findings and standards, tests/reassessment, and reviewable pull requests; [workflow proposal](user-agent-skills.md) |
| **External finding imports** | SAST/code-quality adapters retaining source, provenance, and uncertainty within the remediation workflow |
| **Baselines and incremental analysis** | Stable finding identity, correct invalidation, comparison and explicit severity gates; current exit codes are not severity gates |
| **Public analysis packs and standards** | Public pack loading and broader user-selected standards; embedded components do not imply an executable plugin system |
| **Additional acquisition and languages** | Queue inputs and further source-language/framework adapters under separate coverage contracts |
| **External generalization evaluation** | Bounded checks on fresh JS/TS and Python services against source-reviewed expectations; prior sample results do not establish general accuracy |

### Deferred analysis boundaries

Windows path/shell semantics, runtime symlink/TOCTOU state, whole-program or greater-than-one-hop
summaries, a full CFG/SSA rewrite, second-order database-to-path/command flows, and uncommon custom
archive/template engines are deferred. The [proposal's non-goals](analyzer-hardening-and-wire-efficiency-proposal.md#tier-3--high-effort--low-or-narrow-impact-future-work--do-not-implement-now)
own the rationale. Unsupported behavior must remain explicit rather than being reported as safe.

## Structural analysis and semantic judgment

Static analysis supplies bindings, operand roles, value transfers, controls, snapshots, and gaps.
The decision model assesses the named claim; deterministic gates check required evidence and
consistency. A protected operation does not certify its entire entry or application. Questions can
share one candidate request, but whole-subgraph cross-analyzer batching is not implemented.
See [claim gates](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes).

## Acceptance targets

The [sample catalog](vulnerable-sample-apps.md#applications) owns target pins and source-expectation
references. Analyzer evaluation records own measured positives, protected controls, unresolved cases,
and known misses; historical counts and old reports are not automatically current results.

Verification uses source-reviewed vulnerable, protected, and unresolved controls, with answer keys
kept outside model input. Keep pinned targets unchanged and write reports outside their trees.
See the [baseline policy](../../docs/samples/reference-policy.md). The current worktree's E1 evidence
includes full race checks, request-byte compatibility, historical exact replay, and report parity;
future work needs evidence appropriate to its changed behavior.

<a id="how-a-phase-becomes-agent-manageable-work"></a>

## Maintaining this plan

Update a row when functionality is implemented, verification changes its supported boundary, or
an owner changes the roadmap. Link detailed contracts and results instead of copying their test
counts or session checklists. Record implementation/review/release state separately; do not mark
future slices complete merely because an earlier slice in the same milestone shipped.

Explicit user requests authorize assigned work under [AGENTS.md](../../AGENTS.md#authorization-and-delivery).
Specifications own bounded scope and acceptance; ignored `.zazz/ephemeral/` logs own execution
history. This document is the single functionality status list, not a second execution tracker.

## Historical references

These anchors preserve older links; the completed and planned tables above own current status.

<a id="active-delivery-shared-gemini-then-path-traversal"></a>
<a id="delivered-foundation-optional-gemini-adapter-and-path-traversal"></a>
**Provider/path foundation:** [optional Gemini verification](../evaluation/gemini-decisions-results.md),
[path results](../evaluation/path-traversal-results.md), and
[Tier-1 hardening](../specifications/path-traversal-hardening.md).

<a id="first-build"></a>
<a id="phase-0--foundation-audit-and-tooling-decision"></a>
<a id="route-string-validation-delivery-sequence"></a>
**Parser and route/string foundations:** [route MVP](../specifications/tree-sitter-route-identification-mvp.md),
[assessment contract](../specifications/route-string-validation.md), and
[historical verification](06-route-validation-assessment.md#route-verification).

<a id="phase-11--python-adapter"></a>
**Python foundation:** [contract](../specifications/python-support.md) and
[results/limits](../evaluation/python-support-results.md).

## Evidence wire v7

The [E3 contract](../specifications/wire-bundle-v7.md) coordinates compact requests, evidence references, catalog-backed logging and transparent wrapper dispatch in `analyzer-assessment-coverage`. Its checklist records the completed JavaScript conditional flow, broader W6, the citation decision (retention proxy accepted) and the measured S1/S2/S5 deferrals.
