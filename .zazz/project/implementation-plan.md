# Implementation plan

Current capability and deliverable roadmap. A checked item means a bounded implementation exists;
it does not establish universal coverage or integration status. Contracts and evaluation records own
acceptance details. This plan is not blanket implementation or live-call authorization.

## Product goals and capability boundaries

**Scan** assesses source-code security. **Inspect** will assess correctness, maintainability and
selected engineering standards. **Audit** will assess dependencies. **Fix** will support agent
remediation with verification. Scan exists in bounded form; distinct Inspect/Audit/Fix workflows
remain planned. They can eventually run independently; usage order does not dictate delivery order.
The broader goal is to turn findings and applicable standards into verified changes and reviewable
pull requests. See [product responsibilities](../project.md#four-product-capabilities).

## Delivery priorities

1. **Native Scan and Inspect:** strengthen source-code security assessment and develop code-quality/
   standards assessment on the shared engine. Current Scan/analyzer work, including path traversal,
   belongs here; a distinct Inspect workflow is still planned.
2. **SCA Audit:** use per-language ecosystem tooling rather than building an advisory scanner from
   scratch: npm/pnpm for JavaScript/TypeScript and pip-audit for Python, with separate adapters for
   later languages. Preserve advisory provenance and dependency evidence.
3. **Automation and Fix:** add on-demand and cron/scheduled-CI orchestration, scoped remediation
   agents supplied with findings and standards, tests/reassessment, and focused pull requests.
4. **External SAST findings:** add imports/adapters for other security and code-quality scanners,
   preserving their provenance and limits within the established remediation workflow.

This is implementation order, not a required usage pipeline. Each capability remains independently
usable once delivered. Ecosystem SCA adapters in stage 2 are distinct from external SAST finding
integration in stage 4. The detailed branch checklist below retains existing delivered work and
bounded follow-on contracts.

## Supported capability checklist

| Analyzer / infrastructure | JavaScript | TypeScript | Python | Key limits / evidence |
| --- | --- | --- | --- | --- |
| Input Validation | [x] | [x] | [x] | Source-backed requirements and enforcing guards; missing business policy stays Review |
| SQL Injection | [x] | [x] | [x] | Verified SQL APIs, operand/binding and construction claims; [database rules](../../docs/analysis/database-injection.md#sql-rules) |
| NoSQL Injection — MongoDB-style | [x] | [x] | [ ] | Bounded MongoDB/Mongoose and MarsDB-compatible selectors/expressions; other engines unsupported |
| Sensitive Data Logging | [x] | [x] | [x] | Sensitive content, emission and redaction; unknown sensitivity stays Review |
| XSS — server/template, stored, DOM/framework | [x] | [x] | [x] | Bounded render/origin contracts; Python includes selected inline template scripts |
| XSS — API-to-browser linkage | [x] | [x] | [ ] | General Python linkage remains pending |
| Command Injection | [x] | [x] | [x] | Process operands, shell/executable/argument claims; [results](../evaluation/command-injection-results.md) |
| Common entry/dispatch | [x] | [x] | [x] | HTTP/browser foundations; bounded dynamic HTTP, Node GraphQL/unary gRPC; [acceptance](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05) |
| Outbound observations | [x] | [x] | [x] | Observation only; requested security judgment stays not_run/Review, not SSRF support |
| JSON / HTML / SARIF | [x] | [x] | [x] | Fresh schema4; schemas1–4 remain readable; [report contract](../architecture/reporting-and-sarif.md) |

NoSQL is an analyzer category intended to cover multiple database engines. MongoDB-style operations
are the initial implementation, not a generic contract for all NoSQL databases. Each additional
engine (for example DynamoDB) needs distinct verified API/operand models, rules, guidance and
controls. Findings must identify the actual database/driver supported by source evidence: MongoDB
through Mongoose, MarsDB for its compatible in-process operations, or an explicitly unknown engine.
Do not label MarsDB as a MongoDB server or imply DynamoDB support. See
[database-specific scope](../../docs/analysis/database-injection.md#database-specific-nosql-scope).

The [sample catalog](vulnerable-sample-apps.md#applications) and analyzer-specific evaluation records
own exact pins, expected positives, controls and known misses. Historical counts do not imply that
all later scans or providers achieved the same results. XSS hardening confirmed its 28 required
cases; [results and controls](../evaluation/xss-hardening-results.md) retain the scope. Python's
bounded adapter has known SQL coverage gaps; Python NoSQL and general browser linkage remain open.

## Future capability branches

### Complete delivery list

Each new deliverable uses its named feature worktree/branch and a bounded tracked contract, then
human-reviewed integration into `stage`. Completed rows retain their historical branch/capability
IDs; verify actual Git history before resuming one. Related phases explicitly assigned to one
worktree stay together, including shared Gemini support and later path analysis in `path-traversal`.

| Status | Analyzer / supporting capability | Branch / capability ID | Acceptance target or delivered reference |
| --- | --- | --- | --- |
| [x] | Input Validation | `input-validation` | Bounded source-backed policy/enforcement judgments; retain separate destination protection |
| [x] | SQL Injection | `sql-injection` | Bounded SQL construction, binding and injection judgments on verified APIs |
| Partial | NoSQL Injection — MongoDB-style | `nosql-injection` | Bounded MongoDB/Mongoose and MarsDB-compatible JS/TS operations; Python and other database engines pending |
| [x] | Sensitive Data Logging | `logger-leak` | Explicit sensitive logger calls, access-log URL credentials and logging-specific judgment; see the contract |
| [x] | XSS | `xss-response` | Delivered bounded reflected, stored, browser and cross-tier analysis; retain hardening gaps rather than claiming universal coverage |
| [x] | Python adapter (shared infrastructure) | `python-support` | Delivered adapter and shared trace/report guardrails; same claim architecture as JS/TS |
| [x] | Common entry/dispatch (shared infrastructure) | `common-entry-dispatch` | Shared entry/registration/dispatch/callable model; migrate HTTP/browser consumers and add bounded dynamic-route, GraphQL resolver and gRPC handler adapters with explicit unknown controls |
| [x] | Analysis-pack catalog (shared knowledge infrastructure) | `analysis-pack-mvp` | SQL-first embedded selection, bounded judge composition, report provenance and exact-request replay; [contract](../specifications/analysis-pack-mvp.md), [architecture/ledger](../architecture/analysis-packs.md) |
| [x] | Command Injection | `command-injection` | Delivered: verified Node/Python process contracts, shell/executable/argument facets, 11 Python framework adapters, GraphQL/gRPC contexts; four full judged scans with every independent positive confirmed ([results](../evaluation/command-injection-results.md)) |
| [x] | Harden XSS analyzers | `xss-hardening` | Delivered: all 28 source-reviewed XSS cases confirmed across five apps with every control held, including VulnPy's Jinja case and sql.js SQL injection; [contract](../specifications/xss-hardening.md), [results](../evaluation/xss-hardening-results.md), [sample applications](vulnerable-sample-apps.md) |
| [x] | Shared Gemini Decisions provider | `path-traversal` (interactive prerequisite) | [Provider contract](../specifications/gemini-decisions.md); [verified two-request live sample](../evaluation/gemini-decisions-results.md), shared protocols and single-model selection |
| [ ] | Path Traversal | `path-traversal` | Verified checkpoint: Node `fs`/Express send, Python `open`/`pathlib`/archive opens/Flask file APIs and `adm-zip` extraction (Zip Slip) with traversal/containment/coverage assessment, poor-practice outcome and `req.path` sources; 116 positive sample contexts judged, 85 positive contexts unjudged, two Juice Shop operations uncovered and one protected fixture unresolved ([results](../evaluation/path-traversal-results.md)); uncovered shapes are documented limits |
| [ ] | Code Injection | `code-injection` | Request-to-eval/code-generation paths, starting with `/api/calculate`, across supported languages |
| [ ] | XXE | `xxe` | Request-to-XML parsing and verified parser configuration across supported languages |
| [ ] | Open Redirect | `open-redirect` | Request-influenced redirect targets and actual destination policy |
| [ ] | Weak Randomness | `weak-randomness` | Randomness used for security-sensitive tokens; ordinary non-security randomness stays a negative |
| [ ] | Cookie/Session/Header Configuration | `cookie-session-headers` | httpOnly, secure, session configuration and source-backed baseline header requirements |
| [ ] | SSRF | `ssrf-destination` | Complete judgment of existing outbound candidates, including axios.default.get; verify URL slots and restrictions |
| [ ] | Prototype Pollution | `prototype-pollution` | JS/TS object/prototype operations such as _.merge; test Python's non-applicability rather than inventing equivalent prototype semantics |
| [ ] | Python analyzer coverage completion | `python-coverage-completion` | Complete Python NoSQL and API-to-browser XSS linkage coverage immediately before SCA; retain separate binding, origin and rendering claims with paired controls |
| [ ] | Dependency Audit (planned Audit capability) | `sca-library-audit` | Resolved dependency/advisory auditing for JS/TS npm/pnpm and Python pip-audit, with failures and reachability separate |
| [ ] | Secret Scanning | `hardcoded-secrets` / secret scanning | Private material in source; public verification keys and placeholders remain controls |


Additional follow-on deliverables require bounded contracts; their placement follows the delivery
priorities above:

| Status | Deliverable | Proposed worktree/branch | Outcome |
| --- | --- | --- | --- |
| [ ] | NoSQL engine expansion | `nosql-engine-<database>` | Separate MongoDB coverage expansion and each new engine's API models/guidance; database identity in findings |
| [ ] | Logging component migration | `logging-components` | Move existing logger knowledge into catalog without claiming broader detection |
| [ ] | Stronger claim evidence | `analysis-certainty` | [Targeted plan](analysis-certainty-improvements.md); helper/guard/API evidence and false-protection controls |
| [ ] | Independent Findings Review | `findings-review` | Separate reviewer, disagreements and completion state; not the judge or Review report category |
| [ ] | Inspect workflow | `inspect-workflow` | Selected standards, applicability and presentation separate from vulnerability counts |
| [ ] | Automation, Fix workflow and user-agent skills | `agent-remediation` | Stage 3: scheduled assessments, scoped agents, verified repairs and focused PRs; [workflow proposal](user-agent-skills.md) |
| [ ] | External SAST/code-quality finding integrations | `external-scanner-findings` | Stage 4: scanner-specific imports, source/provenance retention and reuse of the remediation workflow |
| [ ] | Baselines, CI severity gate, incremental analysis | `scan-baselines` | Stable identity, invalidation correctness and explicit severity gating |
| [ ] | Additional source languages | `language-<name>` | Separate language contract; no fixed position or automatic framework parity |

## Active delivery: shared Gemini, then path traversal

The [provider contract](../specifications/gemini-decisions.md#capability-and-boundary) owns interactive
Gemini setup and verification. The separate [path contract](../specifications/path-traversal.md#1-capability-and-prerequisite)
owns analyzer implementation and its remaining coverage improvements. The shared provider prerequisite is verified.

- [x] Add `gemini` as one scan-wide provider using only `gemini-decision-1` and v1beta Decisions.
- [x] Configure `JUDGE_DECISION_MODEL`; reject conflicting CLI settings and model lists.
- [x] Verify existing analyzers through HTTP stubs; preserve old provider/replay behavior.
- [x] Run a small authorized Gemini sample scan, recording model, scope, calls and results.
- [x] Implement path operands, containment evidence, selected components and evidence validation.
- [ ] Close the live protected-control discrepancy: Python prefix-boundary remains Review (40/40 vulnerable, 14/15 protected, 13/13 unknown/weak controls match; offline gates and report parity pass).
- [x] Run the [unattended correction loop](../specifications/path-traversal.md#11-copypaste-prompt-unattended-implementation-testing-and-correction-loop) across all eight sample apps; see the [results](../evaluation/path-traversal-results.md).
- [x] Widen scope (user-approved) to the source-documented traversals in the eight samples: send wrappers, `req.path`, upload save, archive opens, adm-zip extraction, delete.
- [ ] Final live verification of implemented general chain/export/mount/immediate-invocation, unzipper entry-name and `hbs` layout models; scoped portable parser/policy/report tests pass.
- [x] Judge all VulnPy contexts: 196 file-open contexts confirmed and all 64 WSGI templates Review; final replay onto the latest code pending.
- [x] Implement [shared decision-model controls](../specifications/decision-model-limits.md): per-scan dollar budget with explicit pricing/pre-call reservation, RPM/TPM pacing and flag/environment configuration covering discovery and assessment; update README/setup/output docs. Sample and both local environments are configured; older stage binaries ignore new settings until integration.
- [ ] Further archive libraries and dynamic entry/engine contracts beyond those explicitly modeled remain future coverage.
- [ ] Final full race/source/replay/compatibility verification after the last changes (paused at owner request), then human review.

No live Jev evaluation is included. Credentials stay in ignored local `.env` files; all analyzers
use the same selected provider/model, with no fallback. [Setup](../../docs/decision-models.md#credentials-and-local-environment)
owns user instructions; the spec owns the official Google references and Go REST decision.

## Analysis pack MVP initiative

The shared embedded catalog is implemented for SQL, JS/TS MongoDB-style NoSQL, standalone validation,
XSS, command execution and outbound observations. Static adapters select versioned interpretation
material; the engine enforces mandatory evidence validation checks. Logging migration, public pack loading, downloadable
plugins and general standards ingestion remain separate work. See the
[implementation ledger](../architecture/analysis-packs.md#current-implementation-status),
[selection contract](../architecture/analysis-packs.md#descriptor-and-selection-contract) and
[bounds](../architecture/analysis-packs.md#bounds-and-compatibility).

## Structural analysis and semantic judgment

Go establishes bindings, operand roles, values, invocation/control relationships, snapshots and gaps.
The judge assesses the named claims using each candidate's source-backed slice and applicable
questions. Several questions share one candidate request; analyzers are not combined into a single
whole-subgraph request. Model confidence never closes missing structural evidence. Full SSRF,
whole-program soundness and independent Findings Review are not implemented.
See [claim gates](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes)
and [provider boundary](../architecture.md#provider-neutral-judge-boundary).

## Acceptance targets

Use independent source-reviewed vulnerable, protected and unknown controls across applicable
JS/TS/Python coverage. Pin sample revisions; keep answer keys out of model input. Compare positive
coverage with false findings and false protection, not only agreement with another scanner.
Sample checkouts are read-only and reports go outside targets/worktrees. See
[sample policy](../../docs/samples/reference-policy.md) and
[available apps](vulnerable-sample-apps.md#applications).

## How a phase becomes agent-manageable work

A contract fixes scope, branch, dependencies, acceptance tests, evaluation references and review
shape before implementation. Explicit user requests authorize assigned work under
[AGENTS.md](../../AGENTS.md#authorization-and-delivery). Track execution in ignored
`.zazz/ephemeral/`; keep durable outcomes in contracts, architecture and evaluation docs.
No automatic extra worktree, stack, merge or release step is required.

## Delivered foundation references

Older phase/backlog links below are retained for existing contracts. The redundant thirteen-phase
proposal and S01–S34 backlog have been replaced by the capability matrix and deliverable list above;
they are not a second implementation sequence.

<a id="first-build"></a>
<a id="phase-0--foundation-audit-and-tooling-decision"></a>
**Parser foundation:** [route MVP](../specifications/tree-sitter-route-identification-mvp.md),
[verification limits](06-route-validation-assessment.md#route-verification).

<a id="route-string-validation-delivery-sequence"></a>
**Route/string assessment:** delivered bounded resolution, SQL/input-policy evidence, judge transport
and reporting under the [contract](../specifications/route-string-validation.md). Independent
Findings Review remains planned. [Two-case results](../evaluation/juice-shop/results.md) own history.

<a id="phase-11--python-adapter"></a>
**Python adapter:** [contract](../specifications/python-support.md),
[results/limits](../evaluation/python-support-results.md).

<a id="ordered-specification-backlog"></a>
**Replacement backlog:** use the [complete delivery list](#complete-delivery-list).
