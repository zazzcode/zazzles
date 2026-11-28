# Implementation plan

**Reconciled: 2026-11-27.** This document owns the functionality roadmap. **Implemented** means
bounded code and verification exist on `stage` (through PR #56) or in the named draft PR; it does
not mean complete ecosystem coverage or a released version. Contracts and evaluation records own
detailed acceptance evidence. This roadmap does not authorize implementation or live model calls.

## Product goals and capability boundaries

| Module | Function | State |
|---|---|---|
| [**Code Scan**](../../scan/README.md) (`scan/`) | Assess source-code vulnerabilities, controls, evidence gaps, and code smells or poor coding practices that can impact security or performance | Implemented for bounded JavaScript, TypeScript, Python, and PHP cases |
| [**Fix**](../../fix/README.md) (`fix/`) | Agent skills, remediation standards, and playbooks for findings from Zazzles modules and external scanners (SAST, dependency audit, DAST, and endpoint probe / TLS & certificate scanners such as Nuclei) | Planned, expected before Endpoint Probe |
| [**Endpoint Probe**](../../probe/README.md) (`probe/`) | Check authorized endpoints for externally observable issues, starting with TLS and certificates, with evidence and remediation guidance | Planned |

These modules can work independently or in combination. Fix accepts finding details even when
another tool performed the assessment. [Project overview](../../README.md#modules)

The [repository layout contract](../specifications/scan-fix-probe-repository-layout.md) moved
Code Scan under `scan/` and organized user docs under `docs/scan/`, `docs/fix/`, and `docs/probe/`
([PR #37](https://github.com/zazzcode/zazzles/pull/37), merged into `stage`).

<a id="detection-generalization-direction"></a>

## Direction: generalize detection, let the judge decide

Code Scan should not need a new hand-written analyzer, contract or rule for every driver, ORM,
framework, validator or library version. **The aim (owner, 2026-11-25):** a new driver version, ORM
or validation library needs no scanner change, or as little as possible. The scanner records an
operation by what it does and where its data comes from: SQL statement text reaching a call, a
receiver that traces back to a database package import. The decision model then answers bounded
questions about that evidence, such as whether the call runs SQL and whether a request can change
it. Rule-pack scanners grow by adding rules; Code Scan grows by sending better evidence to the judge.

The guard rails do not change. Recording stays source-backed and additive, so a record a contract
already makes is unchanged. Code the scanner could not read is shown to the model and bars
Protected. No scanner rule decides a verdict, and every new question is measured on paid runs,
including a held-out application, before it is called accurate. Explicit contracts stay where they
add evidence a general recorder cannot read.

Merged so far: SQL text records with no driver contract (spec 21, PR #56), native MongoDB driver
operations by package origin (spec 19, PR #54) and computed facts for PHP SQL operands (spec 17,
PR #52). [Series index](../specifications/detection-generalization/README.md) ·
[Strategy](../evaluation/detection-generalization-strategy.md) ·
[Learnings](../learnings/detection-generalization/README.md)

## Delivery priorities

1. Continue work on Code Scan and its evidence, coverage, and reporting.
2. Build Fix with remediation skills, standards, playbooks, verification, and reviewable changes.
3. Build Endpoint Probe, starting with TLS and certificate findings on authorized endpoints.

The detailed roadmap below also tracks longer-term proposals (Inspect, dependency audit, etc.).
Proposed features need bounded contracts before implementation.

<a id="supported-capability-checklist"></a>
<a id="complete-delivery-list"></a>
<a id="analysis-pack-mvp-initiative"></a>

## Completed functionality

Every row describes an implemented subset merged into `stage` (through PR #56). A supported
language or framework is not a claim that all its syntax, APIs, or vulnerable paths are covered.

| Functionality | Implemented behavior and boundary | Owning reference |
|---|---|---|
| **SQL injection** | JS/TS, Python, and PHP query construction, verified API operand/binding models, and separate injection judgments. A call no driver contract covers is recorded when an argument is SQL statement text and judged with the driver-free `sql-text-operation-v1` request ([PR #56](https://github.com/zazzcode/zazzles/pull/56)); PHP operands carry computed escape, hash, integer and digit facts ([PR #52](https://github.com/zazzcode/zazzles/pull/52)) | [Database rules](../../docs/scan/analysis/database-injection.md#sql-rules) |
| **NoSQL injection** | JS/TS MongoDB/Mongoose, MarsDB, and Prisma filter-object selectors and executable expressions; native `mongodb` driver calls recorded by package origin with no list of driver methods ([PR #54](https://github.com/zazzcode/zazzles/pull/54)); Python and other engines remain planned | [Database-specific scope](../../docs/scan/analysis/database-injection.md#database-specific-nosql-scope) |
| **Input validation** | JS/TS, Python, and PHP source-established field requirements and enforcing controls, separate from destination protection; missing business policy stays unresolved | [Validation rules](../../docs/scan/analysis/input-validation.md) |
| **Sensitive-data logging** | JS/TS and Python supported logger calls and access-log credential exposure; data class, content, and redaction assessed separately | [Logging contract](../specifications/sensitive-data-logging.md) |
| **Cross-site scripting** | Supported server/template and stored-value claims (JS/TS, Python, PHP), browser/DOM/framework sinks, and selected JS/TS API-to-browser links; general Python-to-browser linkage remains planned | [XSS rules](../../docs/scan/analysis/xss.md), [hardening results](../evaluation/xss-hardening-results.md) |
| **Command injection and bypass support** | Node `child_process`, Python `os`/`subprocess`, and PHP process-execution contracts; shell syntax, executable selection, arguments, regex capture facts, and guard-reach bypass validation (`command-components-v5`, [PR #34](https://github.com/zazzcode/zazzles/pull/34)) | [Command rules](../../docs/scan/analysis/command-injection.md), [bypass results](../evaluation/command-bypass-support-results.md) |
| **Path traversal** | Supported Node, Python, and PHP file operands, file serving, archive opens/extraction, Zip Slip, and render-layout paths; dual-path independence; containment, branch polarity, mutation, and ordering checks | [Path rules](../../docs/scan/analysis/path-traversal.md), [results](../evaluation/path-traversal-results.md) |
| **Unrestricted file upload (CWE-434)** | Verified PHP `move_uploaded_file` and Python Werkzeug upload writes with stored-name, type-control, and served-destination facts ([PR #31](https://github.com/zazzcode/zazzles/pull/31)); Express `multer` middleware with disk and memory storage ([PR #48](https://github.com/zazzcode/zazzles/pull/48)); `express-fileupload` and Starlette upload adapters remain planned | [Upload rules](../../docs/scan/analysis/file-upload.md), [results](../evaluation/close-findings-gaps-results.md) |
| **Code and template injection (CWE-94/95, CWE-1336)** | Verified JS/TS, Python, and PHP interpreter sinks ([PR #19](https://github.com/zazzcode/zazzles/pull/19)) and Jinja2/Flask/Mako, Twig, and Node EJS template-source operands ([PR #31](https://github.com/zazzcode/zazzles/pull/31)) | [Code/template rules](../../docs/scan/analysis/code-injection.md), [phase 2 results](../evaluation/nextjs-phase-2-results.md) |
| **Unsafe deserialization (CWE-502)** | Verified deserializers in Python, JS/TS and PHP ([PR #38](https://github.com/zazzcode/zazzles/pull/38)). Offline fixtures and pinned samples verified. Lab scenarios and live evaluation are open | [Rules](../../docs/scan/analysis/deserialization.md), [verification](../evaluation/deserialization-results.md) |
| **Open redirect (CWE-601)** | Verified JS/TS, Python, and PHP redirect destinations and effective origin restrictions ([PR #19](https://github.com/zazzcode/zazzles/pull/19), [PR #23](https://github.com/zazzcode/zazzles/pull/23)) | [Redirect rules](../../docs/scan/analysis/open-redirect.md), [phase 2 results](../evaluation/nextjs-phase-2-results.md) |
| **Prototype pollution (CWE-1321)** | JS/TS application writes through affected Lodash versions and bounded source-visible recursive, split-path, nested, and walk-start writes ([PR #35](https://github.com/zazzcode/zazzles/pull/35), [PR #36](https://github.com/zazzcode/zazzles/pull/36)); library-export mode remains planned at W3/W4 | [Pollution rules](../../docs/scan/analysis/prototype-pollution.md), [write shapes](../evaluation/pollution-write-shapes-results.md), [walk start](../evaluation/pollution-walk-start-results.md) |
| **Outbound observations and SSRF** | Destination-origin classification and grouped observations; SSRF claims for verified `fetch`/`axios`/Node `http`/`https`, Python `requests`/`httpx`/`urllib`, PHP URL-open and Symfony HttpClient calls, plus `curl` and `wget` shell URL arguments (`api.php-shell-url-client-v1`) | [SSRF rules](../../docs/scan/analysis/ssrf.md), [E4 contract](../specifications/shared-node-inputs-and-file-apis.md) |
| **Insecure configuration** | Allow-listed framework and deployment files. Directory listing, disabled CSRF, session-cookie flags, debug settings and a privileged schedule of a writable file, each joined to application facts (`configuration-components-v4`) | [Configuration rules](../../docs/scan/analysis/configuration.md), [design](../architecture/configuration-analysis.md) |
| **Next.js acquisition and practice checks** | App Router & Pages Router entries, Server Actions, middleware matchers, Web Request API origins, zod evidence, `"use client"` React flow, Prisma/better-sqlite3/PGlite contracts, and model-free NX-BP practice observations ([PR #18](https://github.com/zazzcode/zazzles/pull/18), [PR #19](https://github.com/zazzcode/zazzles/pull/19), [PR #20](https://github.com/zazzcode/zazzles/pull/20), [PR #21](https://github.com/zazzcode/zazzles/pull/21)) | [Next.js support](../../docs/scan/nextjs-support.md), [rules](../../docs/scan/analysis/nextjs.md) |
| **PHP support (DVWA MVP)** | Plain-PHP adapter with server-mapped entries, include dispatch, superglobal input facts, class/method binding, and SQL/command/XSS/path/upload/code/redirect/validation families ([PR #23](https://github.com/zazzcode/zazzles/pull/23), [PR #31](https://github.com/zazzcode/zazzles/pull/31)); Drupal remains planned | [PHP support](../../docs/scan/php-support.md), [results](../evaluation/php-support-results.md) |
| **Node and Python input acquisition** | Shared transport-neutral acquisition/origin/type/transfer facts for Express/Fastify/Hapi ([PR #15](https://github.com/zazzcode/zazzles/pull/15)) and Python HTTP adapters ([PR #17](https://github.com/zazzcode/zazzles/pull/17)), plus opt-in provisional model-assisted route discovery | [Node input rules](../../docs/scan/analysis/node-inputs.md), [Python refactor results](../evaluation/python-input-refactor-results.md) |
| **Architecture engine foundation (phases 0–4)** | Compatibility golden baseline, layered source index and bounded callable summaries ([PR #24](https://github.com/zazzcode/zazzles/pull/24)), single-walk concurrent language runners ([PR #25](https://github.com/zazzcode/zazzles/pull/25)), isolated `langjs`/`langpy`/`langphp` packages ([PR #26](https://github.com/zazzcode/zazzles/pull/26)), and parallel judge scheduling ([PR #27](https://github.com/zazzcode/zazzles/pull/27)) | [Architecture README](../architecture/README.md), [baseline measurements](../evaluation/architecture-baseline.md) |
| **Model-assisted evidence resolution & noise reduction** | Verified citation follow-ups for resolvable scanner blockers ([PR #30](https://github.com/zazzcode/zazzles/pull/30)), undecidable-validation and unresolvable-blocker gates ([PR #29](https://github.com/zazzcode/zazzles/pull/29)), compact wire & request size reduction ([PR #14](https://github.com/zazzcode/zazzles/pull/14), [PR #33](https://github.com/zazzcode/zazzles/pull/33)), and exact-request offline replay | [Resolution results](../evaluation/model-resolution-results.md), [size reduction results](../evaluation/judge-request-size-reduction-results.md) |
| **Decision-model controls, packs, and reports** | OpenAI (`gpt-6-luna`) and Google Gemini (`gemini-decision-1`) for judged scans, plus a stub-tested Jev adapter; `--only-family`/`--skip-family`, RPM/TPM pacing, context deduplication; embedded analysis packs & `facts.md`; canonical JSON, standalone HTML, SARIF, and saved-report export | [Decision models](../../docs/scan/decision-models.md), [running scans](../../docs/scan/running-scans.md), [catalog architecture](../architecture/analysis-packs.md) |

<a id="next-up"></a>

## Next up

Each item starts on owner assignment. Earlier items (Close findings gaps PR #31, Judge size
reduction PR #33, Command bypass PR #34, Prototype pollution stage 1 + write shapes PR #35, and
Prototype pollution walk start PR #36) are merged into `stage`.

| Order | Planned functionality | Notes |
|---|---|---|
| Done | **Scan / Fix / Endpoint Probe repository layout** | Merged into `stage` ([PR #37](https://github.com/zazzcode/zazzles/pull/37)). [Contract](../specifications/scan-fix-probe-repository-layout.md). Code Scan lives under `scan/` and user docs are organized by module |
| Done | **PHP Symfony support** | Merged into `stage` ([PR #39](https://github.com/zazzcode/zazzles/pull/39)). [Contract](../specifications/php-symfony-support.md) (supersedes architecture phase 6). Routes, argument binding, `Request` sources, Doctrine, Twig, services, URL-open SSRF. The `vuln-symfony` key at `086f81f` has 14 required positives, all Confirmed ([results](../evaluation/symfony-results.md)) |
| Done | **Close Symfony website support: application-security analyzers** | Merged into `stage`: branches 1 to 4 (PRs #42, #43, #45, #46) and the DVWA follow-up ([PR #47](https://github.com/zazzcode/zazzles/pull/47)). Branch 4 added configuration, the shell URL client and the lane acceptance run. [Lane contract](../specifications/symfony-more-analyzers.md). See [the lane table below](#symfony-application-security-lane). Every analyzer is a general PHP capability; `vuln-symfony` is the measuring sample only |
| Done | **Juice Shop and Next.js hardening: existing analyzers on JavaScript** | Merged into `stage` ([PR #48](https://github.com/zazzcode/zazzles/pull/48), [PR #49](https://github.com/zazzcode/zazzles/pull/49), [PR #50](https://github.com/zazzcode/zazzles/pull/50)). The `exposure`, `mass-assignment`, `authorization`, `account` and `configuration` families read Express applications with Sequelize, Mongoose or a Mongo-style collection; every Express entry records its middleware-chain access. No new analyzer, kind, finding type or question. The Juice Shop key has ten required positives, all Confirmed, and the guarded controls Protected ([results](../evaluation/juiceshop-hardening-results.md)). The `upload` family records `multer` middleware on Express routes; that family has not had a judged run. [Specification](../specifications/juiceshop-nextjs-hardening-1.md) |
| 1 | **Detection generalization** | The [generalization direction](#detection-generalization-direction). Merged: spec 17 ([PR #52](https://github.com/zazzcode/zazzles/pull/52)), spec 19 ([PR #54](https://github.com/zazzcode/zazzles/pull/54)) and spec 21 ([PR #56](https://github.com/zazzcode/zazzles/pull/56)); spec 20 ([PR #55](https://github.com/zazzcode/zazzles/pull/55)) was closed unmerged. Specs 22 (owner references in the mass-assignment census) and 23 (source references into a listed directory) are implemented and measured on `docs-cleanup`, unmerged: Gemini now finds all 41 rows of Code Scan's Juice Shop key and 45 of 75 in the comparison, as `gpt-6-luna` does. Held-out runs are no longer required (owner, 2026-11-27). Next: a held-out application with an uncontracted driver, then the remaining specs in the [series order](../specifications/detection-generalization/README.md). |
| Done | **Detection generalization 19: database package operations** | Merged ([PR #54](https://github.com/zazzcode/zazzles/pull/54)). A native MongoDB driver call (npm `mongodb`) that receives request data becomes a NoSQL record, found by following its receiver back to the package import, with no list of driver methods or client forms. Recording is met: 57 of 57 vulnerable lab routes; NodeGoat goes from 1 entry to 20. Judged precision on the lab is 93% with Gemini and 75% with gpt-6-luna against the series bar of 95%. [Specification](../specifications/detection-generalization/19-database-package-operations.md), [results](../evaluation/detection-generalization-results/19.md), [learnings](../learnings/detection-generalization/README.md) |
| Done | **Unsafe deserialization analyzer (CWE-502)** | **Merged into `stage` ([PR #38](https://github.com/zazzcode/zazzles/pull/38)).** [Contract](../specifications/unsafe-deserialization.md) and [verification status](../evaluation/deserialization-results.md). The `deserialization` family for Python `pickle`, PyYAML and `jsonpickle`, PHP `unserialize` and Symfony `Yaml::parse`, Node `node-serialize`, `funcster` and `js-yaml`. No prerequisite; the `vuln-symfony` row stays blocked on order 1 and is not part of the deliverable |
| 3 | **npm library RCE scanning** | Architecture [phase 7](../specifications/architecture-phase-7-npm-corpus.md) (corpus and direct-model baseline) and [phase 8](../specifications/architecture-phase-8-npm-library-mode.md) (library mode on existing command and code analyzers), then compile-to-JS sinks and library prototype pollution per the [waypoints below](#before-library-scanning) |
| 4 | **Fix module (agent skills, standards, playbooks & external findings import)** | Remediation skills, standards, and playbooks for findings from Zazzles modules and external SAST, dependency audit, DAST, and endpoint probe scanners; [workflow proposal](user-agent-skills.md) |
| 5 | **Endpoint Probe module** | Authorized read-only endpoint checks starting with TLS versions, certificates, and trust chains, with remediation guidance |
| Deferred | **XXE; SCA / dependency Audit** | Owner deferred, 2026-11-16 |

<a id="symfony-application-security-lane"></a>

### Closing Symfony website support (stacked lane)

The independent review of PR #39 found that 11 of the 21 defects the `vuln-symfony` README
documents belong to classes no analyzer covered. This lane closes them. Each branch is one draft
PR, stacked with `gh-stack` in one worktree ([guide](../docs/using-gh-stack.md)), implemented in
its own session, and validated by paid judged runs at each checkpoint. Existing analyzers are
extended where a claim fits them; a new family is added only for a new question.

| Order | Branch and contract | Delivers | README entries closed | State |
|---:|---|---|---|---|
| 1.1 | [`symfony-more-analyzers-1`](../specifications/symfony-more-analyzers-1.md) | `exposure` (CWE-200, CWE-215) and `mass-assignment` (CWE-915) families; the security-field census (credential, login identifier and role-source fields from framework contracts) | 17, 19 | Merged ([PR #42](https://github.com/zazzcode/zazzles/pull/42)) |
| 1.2 | [`symfony-more-analyzers-2`](../specifications/symfony-more-analyzers-2.md) | Entry access from `access_control`, firewalls and `#[IsGranted]`; `authorization` family (CWE-862, CWE-639, CWE-285) with ownership, role and address-based guard kinds (CWE-291); state changes per entry | 7, 9, 10, 13, 16. Entry 8 recorded as not present in source | Merged ([PR #43](https://github.com/zazzcode/zazzles/pull/43)) |
| 1.3 | [`symfony-more-analyzers-3`](../specifications/symfony-more-analyzers-3.md) | `account` family: enumeration (CWE-204), recovery-secret delivery (CWE-640) with the mail sink, weak password hashing (CWE-916) | 6, 20 | Merged ([PR #45](https://github.com/zazzcode/zazzles/pull/45)) |
| 1.4 | [`symfony-more-analyzers-4`](../specifications/symfony-more-analyzers-4.md) | `configuration` family over allow-listed framework and deployment files (directory listing, disabled CSRF, session cookie flags, debug, privileged scheduled commands); SSRF through `curl` and `wget` as a new `ssrf` contract; whole-sample judged acceptance and closing documentation | 18, 21, and the SSRF half of 1 | Merged ([PR #46](https://github.com/zazzcode/zazzles/pull/46)). Acceptance run recorded in [symfony-results.md](../evaluation/symfony-results.md) |

After 1.4 the sample's closing state is 20 of 21 README entries detected, entry 8 recorded as not
reproducible at the pin, and committed secrets left to the planned secret-scanning work.

<a id="before-library-scanning"></a>

### Before library scanning (waypoints)

| Waypoint | Work | Spec | State | Needed before |
|---|---|---|---|---|
| W0 | **Command bypass support** | [Contract](../specifications/command-bypass-support.md) | Merged into `stage` ([PR #34](https://github.com/zazzcode/zazzles/pull/34)) | W4 |
| W1 | **Re-judge the JS command samples** under `command-components-v5` (Node.js Goof, vuln-nextjs) | None needed: a live check | Owner's call | W4, so library mode starts from a measured JS command baseline |
| W2 | **npm corpus, answer keys and direct-model baseline** | [Phase 7](../specifications/architecture-phase-7-npm-corpus.md) | Ready to assign. Offline steps need no cap; baseline needs a model and numeric cap | W3 (stage 2), W4, and W5 |
| W3 | **Prototype pollution analyzer (CWE-1321)** | [Contract](../specifications/prototype-pollution.md), [write shapes](../specifications/pollution-write-shapes.md) | Stage 1 application writes + write shapes merged into `stage` ([PR #35](https://github.com/zazzcode/zazzles/pull/35)). Stage 2 library writes follow W2 and W4; access and gadget claims follow corpus keys | The six pollution corpus rows |
| W3.1 | **Prototype pollution walk start** | [Contract](../specifications/pollution-walk-start.md) | Merged into `stage` ([PR #36](https://github.com/zazzcode/zazzles/pull/36)) | Completed |
| W4 | **Library mode on the existing analyzers** | [Phase 8](../specifications/architecture-phase-8-npm-library-mode.md) | Starts after W2 merges (W0 is merged) | Every library result |
| W5 | **Utility option contracts for argument arrays**, `git` first | **Not written** | Decide after W2: write only if `simple-git` is outside W4's reach | `simple-git` row |
| W6 | **Library judge contract**: parameter-trust question, caller-argument protocol, feasibility consumer | **Not written** | After W4 reports candidates per library | Paid library judgment |
| W7 | **Code-execution sinks for libraries**: compile-to-JS, deserialization-to-code, dynamic `require` | **Not written** | After W4; reuse Node contracts of [unsafe deserialization](../specifications/unsafe-deserialization.md) | `ejs`, `pug`, `lodash`, `ajv`, `node-serialize` |

Orders 1 and 2 (Symfony, unsafe deserialization) are not prerequisites for W2–W4 and may run
beside them.

<a id="future-capability-branches"></a>
<a id="ordered-specification-backlog"></a>

## Planned functionality

The following work remains planned; rows are functional goals rather than reserved branches or
approved implementation assignments.

| Planned functionality | Intended outcome / remaining boundary |
|---|---|
| **PHP Symfony & Drupal** | Symfony injection-family support is merged (PR #39; [contract](../specifications/php-symfony-support.md), [results](../evaluation/symfony-results.md)). Authorization, mass assignment, information exposure, account-flow and configuration analyzers are merged as the [Symfony application-security lane](#symfony-application-security-lane). Drupal routing and render arrays remain planned ([phase 9](../specifications/architecture-phase-9-drupal.md)) |
| **Authorization, mass assignment, information exposure, account security, configuration** | General PHP analyzers delivered by the [Symfony application-security lane](#symfony-application-security-lane). Voters and custom authenticators, Symfony Form and serializer mass assignment, plain-PHP object-level authorization, and infrastructure files outside the allow-lists stay explicit gaps |
| **Unsafe deserialization (CWE-502)** | Merged ([PR #38](https://github.com/zazzcode/zazzles/pull/38); [contract](../specifications/unsafe-deserialization.md), [verification](../evaluation/deserialization-results.md)). Lab scenarios and live evaluation remain |
| **Unrestricted upload adapter expansion** | PHP and Werkzeug uploads are merged (PR #31); Express `multer` is merged (PR #48); `express-fileupload` and Starlette upload adapters remain |
| **Prototype pollution in libraries** | Application writes and walk starts are merged (PR #35, PR #36); library export coverage follows W2/W4 |
| **Python coverage completion** | Python NoSQL models and general API-to-browser XSS linkage; expanded dependency/lifecycle/discovery coverage beyond shared Python input facts |
| **NoSQL engine expansion** | Native MongoDB driver calls are merged (PR #54). Other databases join by adding a package and its query-language notes to the same origin table, each with its own measured run |
| **Weak randomness and cookie/session/header configuration** | Security-sensitive randomness and source-established configuration requirements with negative controls |
| **Secret scanning** | Distinguish private material from public keys, placeholders, and test data. The Symfony lane leaves committed `.env` secrets to this item |
| **Stronger claim evidence** | Improve remaining unresolved helper, guard, dispatch, and API cases within explicit analysis bounds; [targeted direction](analysis-certainty-improvements.md) |
| **Independent Findings Review** | Separate review conclusions, disagreements, evidence, and completion state; distinct from the current Review category |
| **Fix & external finding imports** | Next up order 4: agent remediation skills, standards, playbooks, and provenance-preserving import from SAST, dependency audit, DAST, and endpoint probe scanners; [workflow proposal](user-agent-skills.md) |
| **Endpoint Probe** | Next up order 5: authorized read-only endpoint checks starting with TLS and certificates, with remediation recommendations |
| **Inspect workflow** | Select applicable engineering standards and present broader quality/maintainability findings separately from vulnerability claims |
| **Baselines and incremental analysis** | Stable finding identity, invalidation, comparison, and explicit severity gates |
| **Public analysis packs and standards** | Public pack loading and user-selected standards; embedded components do not imply an executable plugin system |
| **Additional acquisition and languages** | Queue inputs and further source-language/framework adapters under separate contracts |
| **XXE; Dependency Audit (SCA)** | Deferred by the owner (2026-11-16); [SCA design](../architecture/sca-design.md) |
| **External generalization evaluation** | Bounded checks on fresh applications against source-reviewed expectations |

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
See the [baseline policy](../../docs/samples/reference-policy.md).

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
**Provider/path foundation:** [Gemini verification](../evaluation/gemini-decisions-results.md),
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
