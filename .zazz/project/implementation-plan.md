# Implementation plan

**Reconciled: 2026-11-16.** This document owns the functionality roadmap. **Implemented** means
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
| **Node input acquisition** | Bounded Express/Fastify/Hapi adapters supply shared input origins (including URL path/url/originalUrl/baseUrl and verified upload filename/content), types, transfers, controls, lifecycle stages, and Express non-final middleware-chain sibling entries | [Node refactor results](../evaluation/node-input-refactor-results.md), [E4 contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Next.js acquisition** | App Router route handlers, Server Component pages and `generateMetadata`, Server Actions, middleware matcher stages; Pages Router API routes (including CommonJS handler factories) and `getServerSideProps` pages whose props feed the server render; Web Request API origins, zod evidence, `"use client"` React flow; `prisma-raw-v1`, `prisma-filter-object-v1`, `better-sqlite3-v1`, `pglite-v1`; raw-SQL and Prisma stored-XSS links; model-free NX-BP practice observations. Verified on OopsSec Store (`2d530ef`) and the owner-maintained vuln-nextjs lab (`ea10efb`; full sample reports published). [PR #18](https://github.com/zazzcode/zazzles/pull/18) merged; phase 2 follows the [combined contract](../specifications/nextjs-phase-2-and-code-redirect.md) | [Next.js support](../../docs/nextjs-support.md), [rules](../../docs/analysis/nextjs.md), [contract](../specifications/nextjs-support.md) |
| **Python input acquisition** | Existing bounded Python HTTP adapters emit the same optional origin/type/transfer schema as Node, with invocation-local acquisition and separate `source.python-input-v1` interpretation; runtime types remain unknown, existing sink contracts and behavior preserved; new dependency/lifecycle/discovery coverage remains deferred | [Python refactor contract](../specifications/python-input-refactor.md), [verification](../evaluation/python-input-refactor-results.md) |
| **Optional model-assisted route discovery** | Explicitly enabled, separately capped proposals with source/binding verification; unfamiliar wrappers remain provisional coverage, not trusted flow | [Node input/discovery contract](../specifications/node-http-input-refactor.md) |
| **Decision-model assessment** | OpenAI Luna Decisions is primary; optional Gemini and stub-tested Jev adapters use the shared evidence gates and one model selection per scan, without fallback | [Model setup](../../docs/decision-models.md) |
| **Assessment scheduling and family selection** | Primary security sinks precede standalone validation; zero-call observations consume no request slots; canonical `--only-family` / `--skip-family` flags and environment defaults | [E1 contract](../specifications/analyzer-engine-hardening.md) |
| **Equivalent-context reuse** | Scan-local reuse only for conservatively equivalent requests; retain each entry's finding, provenance, policy evaluation, and existing exact-request identity; derived records add no usage | [E1 contract and measured limits](../specifications/analyzer-engine-hardening.md#6-acceptance-criteria-slice-e1) |
| **Request and rate controls** | Per-run assessment cap and optional shared RPM/TPM pacing; disabled pacing skips clock/window work. Spending is managed in the provider console; local dollar budgets/pricing are removed | [Limits contract](../specifications/decision-model-limits.md) |
| **Embedded analysis knowledge** | Versioned catalog selection and provenance for SQL, NoSQL, validation, XSS, command, path, logging and outbound observations; fixed query/middleware fact interpretation in `internal/guidelines/facts.md` | [Catalog architecture](../architecture/analysis-packs.md), [path contract](../specifications/path-traversal.md) |
| **False positives and Review noise** | Validation records that no answer could decide are not sent; own-API response fields take their handler's origin; a closed constant type map resolves the response type; stored-origin records carry their write set; records are grouped by kind, sink span and status; the model judges command guard adequacy with each guard's contract | [Contract](../specifications/accuracy-false-positive-noise.md), [precision baseline](../evaluation/precision-noise-baseline.md) |
| **Evidence validation and exact replay** | Source-backed completeness/consistency gates, request traces, and exact-match offline replay; confidence cannot supply missing evidence | [Trace architecture](../architecture/trace-judgment.md), [report contract](../architecture/reporting-and-sarif.md) |
| **Reports and artifacts** | Canonical JSON, standalone HTML, SARIF, entry selection, findings/Review/Protected presentation, saved-report export, and historical schema compatibility; artifacts can be retained in CI | [Running guide](../../docs/running-scans.md), [CI artifacts](../../docs/ci.md) |

## Active delivery: analyzer engine hardening

E1 (scheduling, family filters, context reuse), E2 (shared guard and workspace-manifest
engine), and E3 (evidence wire v7, assessment coverage, JavaScript conditional flow and
fact-code consolidation) are merged into `stage` via [PR #14](https://github.com/zazzcode/zazzles/pull/14)
(`6e815ec`).

**E4 merged into `stage` via [PR #15](https://github.com/zazzcode/zazzles/pull/15)
(`eafabcc`, base `6e815ec`).** Shared Express middleware-chain / URL/upload inputs, path
second-pass retirement, phase-2 file APIs, and Node `http`/`https` SSRF are in `stage`; Node
sample reports republished under a 350-request `gpt-6-luna` cap (250 charged, 250 exact
replays). Contract:
[shared-node-inputs-and-file-apis.md](../specifications/shared-node-inputs-and-file-apis.md).

Deferred with recorded decisions: S1 data-path slicing and S2/S5 relevance filtering. Size pressure
is one record near the soft threshold and none over the limit. The user-authorized full Python
validation below includes the 260 VulnPy path contexts and standalone input validation.

**Next.js support is implemented on `nextjs-support-mvp`, draft
[PR #18](https://github.com/zazzcode/zazzles/pull/18) into `stage`.** It covers proposal slices N0–N5,
partial N6 (model-free practice checks) and a second iteration for the vuln-nextjs lab. Every required
positive in a supported family is Confirmed on both Next.js samples, no safe control is red, and both
fresh full paid runs replay exactly (149/149 assessments, including standalone input validation);
both [sample reports](../../docs/samples/README.md) and detection guides are published in this branch. [Contract](../specifications/nextjs-support.md).

**Model-assisted evidence resolution is implemented on `model-evidence-resolution`, draft PR into
`stage` pending.** The scanner asks the decision model specific questions about the points it could
not resolve (flow gaps, stored origin, a missing witness, a command guard bypass, one missing
definition) and an answer counts only when its cited evidence chain verifies against the request.
A model-resolved fact can move a record to a finding with a visible mark, never to Protected without
a scanner-held coverage fact; records no answer could change are not sent; follow-ups are capped at
25% of requests; a protocol bump re-judges only its family. Offline gates and the recall floor hold;
the W3a write census covers 29 of 45 stored-origin records (AC3 asks 40); the authorized live runs
and their source review (AC6) are pending. [Contract](../specifications/model-assisted-evidence-resolution.md).

<a id="next-up"></a>

### Next up (owner order, 2026-11-16)

| Order | Planned functionality | Notes |
|---|---|---|
| 1 | **Code injection (CWE-94/95) and open redirect (CWE-601)** | Implemented with Next.js B–D in `nextjs-support-phase-2`; human review pending. [Contract](../specifications/nextjs-phase-2-and-code-redirect.md), [results](../evaluation/nextjs-phase-2-results.md). Prototype pollution remains the next implementation assignment |
| 2 | **Prototype pollution (CWE-1321)** | JS/TS recursive merge and library `merge`/`set`/`defaultsDeep` sinks, computed key writes, key deny-list and null-prototype controls |
| 3 | **PHP support (DVWA MVP), then Drupal** | Plain-PHP adapter implemented on `php-dvwa` (server-mapped entries, include dispatch, superglobal input facts, SQL/command/XSS/path/code/redirect/validation families) with offline DVWA `a1978a2` ACs green and the paid AC14 `gpt-6-luna` pass complete (292/296 assessed, 292/292 exact replay, sample published): [contract](../specifications/php-support.md), [results](../evaluation/php-support-results.md), [guide](../evaluation/dvwa-detection-guide.md), [sample](../../docs/samples/dvwa/README.md). Draft PR #23 into `stage`; then Drupal routing/controllers, Symfony `Request`, Form API, database API, Twig and render arrays as a separate follow-up deliverable |
| 4 | **Agent skills fixes, scan/fix loop, external SAST findings import** | Fix-workflow skills, the scheduled/on-demand loop, and provenance-preserving import of third-party SAST findings |
| Deferred | **XXE; SCA / dependency Audit** | Owner deferred, 2026-11-16 |

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
| **E4 — Shared Node inputs and file APIs** | Promote middleware-chain and URL/upload inputs across Node analyzers; extend verified Python/Node file and archive operation coverage; add Node core `http`/`https` client SSRF contracts (vuln-demo-app `/fetch` confirmed) | Merged via [PR #15](https://github.com/zazzcode/zazzles/pull/15) (`eafabcc`); paid Node rebuild 250/350 `gpt-6-luna`, exact replay 250/250; [contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Shared Python input/acquisition refactor** | Migrate existing Python HTTP adapters to language-neutral acquisition/origin/type/transfer facts; retain flow, sink contracts and coverage; refresh complete Python sample reports and metrics | Implemented on `python-input-refactor`; full test/race/vet/build and four-app structural parity passed. Full all-family Python validation completed: 3,354/3,354 paid assessments and exact replays, zero failures/mismatches; all four Python samples republished with metrics. Future routine runs skip standalone input validation; [contract](../specifications/python-input-refactor.md), [results](../evaluation/python-input-refactor-results.md). Human PR review/merge pending |

The [proposal](analyzer-hardening-and-wire-efficiency-proposal.md) owns the detailed rationale and
boundaries. Token and call savings remain measurements to establish, not guaranteed outcomes.

### Analyzer expansion and product workflows

The following work remains planned; rows are functional goals rather than reserved branches or
approved implementation assignments.

| Planned functionality | Intended outcome / remaining boundary |
|---|---|
| **Python coverage completion** | Python NoSQL models and general API-to-browser XSS linkage; expanded dependency/lifecycle/discovery coverage remains a separate feature beyond shared Python input facts |
| **NoSQL engine expansion** | Additional MongoDB-style coverage and separately verified contracts for other databases; no implied DynamoDB or universal NoSQL support |
| **Code injection and open redirect** | Implemented in the assigned phase-2 worktree; [contract](../specifications/nextjs-phase-2-and-code-redirect.md) and [evaluation](../evaluation/nextjs-phase-2-results.md); review pending |
| **XXE** | Request-to-XML parser paths with verified parser configuration contracts (deferred by the owner) |
| **Weak randomness and cookie/session/header configuration** | Security-sensitive randomness and source-established configuration requirements with appropriate negative controls |
| **Prototype pollution** | Next up, order 2. JS/TS object/prototype operations and verified library behavior; no invented Python equivalent |
| **Secret scanning** | Distinguish private material from public keys, placeholders, and test data |
| **Stronger claim evidence** | Improve remaining unresolved helper, guard, dispatch, and API cases within explicit analysis bounds; [targeted direction](analysis-certainty-improvements.md) |
| **Independent Findings Review** | Separate review conclusions, disagreements, evidence, and completion state; distinct from the current Review category |
| **Inspect workflow** | Select applicable engineering standards and present quality/maintainability findings separately from vulnerability claims |
| **Dependency Audit** | Deferred by the owner (2026-11-16). npm/pnpm and pip-audit adapters, dependency/advisory provenance, SBOM artifacts, and explicit failure/reachability limits; [design](../architecture/sca-design.md) |
| **Automation and Fix** | Next up, order 4, with agent skills fixes. Scheduled/on-demand assessments, scoped repair agents supplied with findings and standards, tests/reassessment, and reviewable pull requests; [workflow proposal](user-agent-skills.md) |
| **External finding imports** | Next up, order 4. SAST/code-quality adapters retaining source, provenance, and uncertainty within the remediation workflow |
| **Baselines and incremental analysis** | Stable finding identity, correct invalidation, comparison and explicit severity gates; current exit codes are not severity gates |
| **Public analysis packs and standards** | Public pack loading and broader user-selected standards; embedded components do not imply an executable plugin system |
| **Additional acquisition and languages** | PHP is next up (order 3) via the [DVWA MVP contract](../specifications/php-support.md); Drupal follows as its own deliverable; queue inputs and further source-language/framework adapters under separate coverage contracts |
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
