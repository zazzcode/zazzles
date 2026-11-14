# Analyzer Hardening, Shared Engine Architecture, and Wire-Efficiency Proposal

**Date:** 2026-11-14  
**Context:** Independent review of the Path Traversal Analyzer ([contract](../specifications/path-traversal.md#1-capability-and-prerequisite), [checkpoint results](../evaluation/path-traversal-results.md#scope-and-outcome)) and cross-cutting audit of the shared parse/catalog/judge/CLI architecture across **Command Injection**, **XSS**, **SQL**, **NoSQL**, **Input Validation**, **Sensitive Data Logging**, and **Outbound Observations**.

See [AGENTS.md](../../AGENTS.md#authorization-and-delivery), [architecture](../architecture.md#2-pipeline), [agent orientation](../docs/zazzles-agent-orientation.md#documentation-map), [analysis-pack bounds](../architecture/analysis-packs.md#bounds-and-compatibility), and [certainty roadmap](analysis-certainty-improvements.md#prioritized-increments).

---

## 1. Architectural Structure: Approved Two-Document Split

Confirmed with the Project / Deliverable Owner (2026-11-14):

1. **Implemented & Live-Verified via Bounded Deliverable Specification ([path-traversal-hardening.md](../specifications/path-traversal-hardening.md)):**
   Covers **Tier 1 (Straightforward, High-Impact, `[Path-Only]` + shared Python monkey-patch detection)**: soundness, branch-polarity (`PathGuardInverted`), normalization-sensitive substring policy, 5 false-protection closures, guarded `ROOT`/`ALLOWED` excerpt injection, determinism, and file-size splits. Implemented and verified across all 8 sample apps, 78 portable controls, 11 live adversarial controls, and 360 exact replays (`0` non-path use changes).
2. **Drive Cross-Analyzer Engine & Wire Evolution via This Proposal + Milestone Spec ([analyzer-engine-hardening.md](../specifications/analyzer-engine-hardening.md)):**
   Covers **Tier 2 (`[All Analyzers]`, `[Command + Path + Validation]`, `[XSS + SQL + NoSQL]`)** architectural improvements. Slice `E1` (`scan-scheduling-and-context-dedupe`) now has a full executable deliverable specification ready to launch after `path-traversal` merges to `stage`, with explicit baseline-compatibility rules for frozen tests (`components-03-outbound.md` O4, `TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests`).
3. **Explicitly Park Tier 3 (High-Effort, Low/Narrow Impact) as Future Work:**
   Recorded below and in the spec's Out-of-Scope section so contributor agents do not spend engineering time or model budget on low-ROI surface area.

---

## 2. Cross-Analyzer Architectural Audit: Where Analyzer Silos Are Hurting Accuracy & Cost

Auditing `cmd/scan/` and `internal/{parse,analysispacks,judge}/` shows that Command Injection and Path Traversal introduced cleaner patterns (`claimHooks`, typed `CommandFacts`/`PathFacts`, `APIModel` contracts, per-flow witness isolation) while older families and shared glue still carry **eight structural bottlenecks**:

| # | Architectural Bottleneck | Code Evidence | Affected Analyzers | Concrete Impact |
| ---: | --- | --- | --- | --- |
| **A-1** | **Observation-only / unassessable candidates burn `--judge-limit` slots AND XSS/Logging are deprioritized behind unassessable uses** | `cmd/scan/analysis.go:72-86` (`queryUse` at line 151 omits `xss_candidate` & `log_sink_candidate`; `requestIndex++` runs *before* checking `ObservationOnly` or `xss_data_candidate`) | `[All Analyzers]` (hurts **XSS** & **Logging** directly) | With default `--judge-limit 10`, a repo with 10 `outbound_http_candidate` or `xss_data_candidate` uses consumes slots 1–10 with zero HTTP calls (`not_run`) while real reflected/stored **XSS** and **Logging** vulnerabilities are skipped as `"judge request limit reached"`! |
| **A-2** | **`--skip-family` / family selection is hardcoded to `"input-validation"` only** | `cmd/scan/analysis.go:155-180` (`parseSkipFamilies` rejects every family except `"input-validation"`) | `[All Analyzers]` | Every analyzer evaluation required custom throwaway harnesses (`.zazz/ephemeral/patheval`) because the CLI has no `--only-family` or general `--skip-family` support across `sql`, `nosql`, `xss`, `command`, `path`, `logging`, `input-validation`. |
| **A-3** | **Repeated framework/route contexts re-judge identical sink/guard subgraphs N times** | `cmd/scan/analysis.go:74-99` (judges every `CandidateUse` independently even when `callable_id`, sink, transfers, and entry controls are identical) | `[All Analyzers]` (**Path**, **Command**, **SQL**, **XSS**) | VulnPy judges 8 unique path sinks across 260 framework contexts (~4.41M tokens); Command Injection and SQL Injection pay the exact same 11-adapter multiplier on shared callables. *(Owner approved default-on Fact-Signature Deduplication with `derived_from` provenance.)* |
| **A-4** | **4-way duplicated, asymmetric guard climbing & termination across JS & Python** | `command_claims.go:326` (`else`-branch bug, no helper call-site climb, no derived-var closure), `python_command.go:365` (branch preconditions only — misses `if bad: abort(400)` terminating siblings!), `path_guards.go:213`, `python_path.go:493` | **Command**, **Path**, **Validation**, **SQL/NoSQL** | **Command Injection has real false-negative / false-protection gaps today:** JS `commandGuards` has the same `child.StartByte() >= cond.EndByte()` `else`-branch bug found in Path; Python `command` misses dominating `if ...: flask.abort(403)` guards and 1-hop helper guards that `python_path.go` already handles! |
| **A-5** | **Three fragmented claim-assembly pipelines instead of one unified engine pass** | `claim_assembly.go` (JS Command + Path only), `python_command.go` / `python_path.go` (inline during AST walk), `automatic_queries.go` -> `checks.go` (`buildEntryChecks` cloning synthetic `analysis.Check` structs for SQL/NoSQL), `xss_claims.go` (minimal loop, no `ControlEdges` or `chainEvidence`) | **SQL**, **NoSQL**, **XSS**, **Command**, **Path**, **Logging** | SQL/NoSQL allocate temporary single-use `AnalysisReport` structs per candidate (`automatic_queries.go:69`); **XSS** candidates never receive `ControlEdges` or route-level `chainEvidence` (`xss_claims.go:9-54`); `analysis.go:138` has to stash `commandUses` aside so `buildChecks` doesn't wipe them out. |
| **A-6** | **Path-only `req.path`/`url`/`files` second pass & `pathOnly` Express middleware-chain entries** | `path_url_sources.go:19`, `path_chain.go:13`, `flow.go:640-715` (`evalCall` is a 120-line waterfall of ad hoc family hooks) | **XSS**, **Command**, **SQL/NoSQL**, **Logging**, **Validation** | Non-final Express middleware handlers (`app.post('/upload', unzipMiddleware, finalHandler)`) can execute SQL queries, commands, or XSS renders, and `req.originalUrl`/`req.path` is a classic **reflected XSS** and **Open Redirect / SSRF** source — currently invisible outside `path_traversal_candidate`. |
| **A-7** | **Verbose <64 KiB wire payloads, duplicate role ledgers, and raw `context_evidence` integer offsets** | `judge/client.go:140` (`compactBundle` only if `>64 KiB`), `judge/bundle.go:77,86` (`evidence_coverage` + `evidence_roles`), `path_claims.go:44` & `command_claims.go:67` (claim indices point to `evidence` when they actually index `context_evidence`) | `[All Analyzers]` (`[Command + Path]` for index bug) | Wastes ~9.5–11.5 KB (~25–35% input tokens) on every call across all 7 analyzers; **Command Injection** and **Path Traversal** both tell the LLM the wrong array (`evidence` vs `context_evidence`) for operand/guard indices! |
| **A-8** | **Unmigrated Logging analyzer, JS-only `InputFacts`, and root-only `packageVersion` / `commandTampered`** | `judge/logging.go` (`log-use-v1` outside `analysispacks`), `parse/node_input_facts.go` (no Python `InputFacts`), `xss_versions.go:8` (root `package.json` only), `python_command.go:48` (`commandTampered` caches patches only for `os`/`subprocess`, missing `io`/`pathlib`/`flask`/`tarfile`!) | **Logging**, **Python NoSQL/SQL/XSS**, **Path + XSS + NoSQL** | **Real cross-family bug found in `python_command.go:48`:** `python_path.go` calls `f.set.commandTampered(m, "io"|"flask"|"pathlib"|"tarfile")`, which checks `s.tampered["patch:"+module]` — but `commandTampered` only populates `s.tampered` for `imp.module == "os" || imp.module == "subprocess"`! Monkey-patches on `io.open`, `tarfile.open`, or `flask.send_file` are silently ignored! |

---

## 3. Master Ranked Improvement Matrix (Separated by Effort vs. Impact & Analyzer Scope)

### Tier 1 — Straightforward & High Impact (Implemented & Verified in `path-traversal-hardening.md`)

| Rank | ID | Improvement | Analyzer Scope | Effort | Impact |
| ---: | --- | --- | --- | --- | --- |
| 1 | **T1-1** | **Receiver-scoped `PathGuardSubstring` + normalization-sensitive policy (`confirmed` vs `poor_practice`) + `PathFacts.Validate`** *(Owner-approved)* | `[Path-Only]` | XS | Stops false-confirmed vulns on imported/DB allow-lists (`!ALLOWED.includes(f)`); accurately distinguishes unnormalized `/uploads/../../etc/passwd` (`confirmed_vulnerability`) from resolved sibling collision (`poor_practice`). |
| 2 | **T1-2** | **AST branch polarity (`consequence` vs `alternative`, `!`/`not`) & `&&`/`||` guard soundness** | `[Path-Only]` (blueprint for Command) | S | Unblocks true positives & closes false-protection gates on `else` branches, negated `if (!startsWith)`, and `if (!isAdmin && !ALLOWED.has) return 403`. |
| 3 | **T1-3** | **Supply module-level `ROOT` / `ALLOWED` declaration spans & deduplicate Python `ModelFacts`** | `[Path-Only]` | S | Resolves live Python `/p/prefix-boundary` discrepancy (`0.51 unknown`) with zero gate weakening. |
| 4 | **T1-4** | **Close 5 false-protection + monkey-patch holes** (`send_from_directory` constant root, dict `**splat` / mutated collections, `RealpathBeforeGuard`, helper-order `DecodedAfterGuard`, multi-caller guard intersection, and generalize `commandTampered` monkey-patch scan beyond `os`/`subprocess`) | `[Path + Python Command]` | S | Closes 6 verified soundness holes with zero non-path wire-digest changes. |
| 5 | **T1-5** | **Sort `defs` map keys + pre-filter `path_chain` Express middlewares** | `[Path-Only]` | XS | Restores 100% deterministic guard classification and skips redundant handler passes on non-path routes. |
| 6 | **T1-6** | **Small high-frequency bindings & catalog sync** (`require('fs').promises` destructuring, `Path.unlink`, helper-nested `req.path`/`req.url`, 11-op `NodeFSContract` + guidelines sync) | `[Path-Only]` | S | Closes common false negatives and aligns contract prose with parser bindings. |
| 7 | **T1-7** | **Split `python_path.go` (763 lines) into 3 cohesive files <= 450 lines** | `[Path-Only]` | S | Restores `code-structure.md §2` compliance. |

---

### Tier 2 — Medium Effort & High Cross-Analyzer Architectural Impact (Slice into Sequenced Specs)

| Rank | ID | Architectural Improvement | Analyzer Scope | Effort | Why High Impact Across Analyzers |
| ---: | --- | --- | --- | --- | --- |
| 8 | **T2-1** | **CLI Scheduling Fix + General `--only-family` / `--skip-family` + Default-On Fact-Signature Context Deduplication** *(Owner-approved)* | `[All Analyzers]` | S–M | **(1)** Never burn `--judge-limit` slots on `ObservationOnly`/`xss_data_candidate` uses, and rank **XSS** + **Logging** ahead of standalone field validation in `queryUse`. **(2)** Support `--only-family` / `--skip-family` for all registered families (retiring throwaway eval harnesses). **(3)** Judge 1 canonical context per distinct `(pack_digest, callable, sink, contract, claim_facts, transfers, entry_controls, blockers)` signature and mark siblings `derived_equivalent_context` with `derived_from` provenance (**cuts VulnPy 260 -> 8 calls, -96.9% tokens**, across Path, Command, SQL, and XSS). |
| 9 | **T2-2** | **Wire Bundle v7 (`evidence_version: 7`) & Direct `eN` Fact References** | `[All Analyzers]` (`[Command + Path]` for index fix) | M | Always-on `compact_wire`, drop duplicate `evidence_roles`, omit 64-hex component SHA-256s from prompt, deduplicate `instruction`/`guidelines`/`questions`, and project `CommandFacts`/`PathFacts` context indices to `eN` refs (fixing the `context_evidence` vs `evidence` bug in **both Command and Path**). **Saves ~25–35% input tokens on every call across all analyzers** and pulls 64.6 KB payloads safely away from the 64 KiB cap. |
| 10 | **T2-3** | **Shared AST Guard, Polarity & Terminator Engine (`internal/parse/guards_*.go`)** | **Command**, **Path**, **Validation**, **SQL/NoSQL** | M | Extracts ~350 lines of duplicated JS/Python guard climbing into one shared engine. **Directly upgrades Command Injection:** fixes JS `commandGuards` `else`-branch bug, adds Python dominating `if bad: abort()` / `HTTPException` guards to `python_command.go`, and brings 1-hop helper call-site guard attribution + derived-variable closure to Command and Validation. |
| 11 | **T2-4** | **Nearest-Ancestor Workspace Manifest & Lockfile Resolver** | **Path**, **XSS**, **NoSQL** (`adm-zip`, `hbs`, `marked`, `sanitize-html`, `mongoose`) | S | Upgrades `packageVersion` (`xss_versions.go`) to resolve nearest `packages/*/package.json` + root `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` (`dependencies`), fixing version-gated advisories and contracts in monorepos for Path, XSS, and Mongoose NoSQL. |
| 12 | **T2-5** | **General Express Middleware-Chain Entries & Unified Node URL/Upload Input Facts** | **XSS**, **Command**, **SQL**, **NoSQL**, **Path**, **Logging** | M | Promotes `analyzePathChainHandlers` and `req.path`/`url`/`originalUrl`/`file(s)` from path-only workarounds into the shared Node HTTP adapter (`source.node-input-v2`), eliminating the double handler pass (`withRequestURLPaths`) AND enabling **XSS** (reflected URL path XSS), **Command**, **SQL/NoSQL**, and **Logging** detection inside upload/auth middleware chains. |
| 13 | **T2-6** | **Phase-2 Path & Outbound/SSRF Contracts** (`FileResponse`, `UploadFile.filename`, `fs.open/copyFile/rename`, `shutil`, `tarfile.extractall` CVE-2007-4559) | **Path** (+ FastAPI `UploadFile` input source for **Command / XSS**) | M | High-prevalence modern FastAPI/Starlette and dual-slot (`src` + `dst`) file operations backed by official runtime contracts. |
| 14 | **T2-7** | **Catalog Migration Completion (Sensitive Data Logging) & Unified Claim-Assembly Registry** | **Logging**, **XSS**, **SQL**, **NoSQL** | M | Migrates `log-use-v1` (`judge/logging.go`) onto `analysispacks` (the last unmigrated analyzer!), attaches `ControlEdges` + `chainEvidence` to **XSS** claims (`xss_claims.go`), and replaces `evalCall`'s hardcoded waterfall + `automatic_queries.go`'s synthetic `Check` cloning with a declarative sink-observer table. |
| 15 | **T2-8** | **Transport-Neutral Python `InputFacts` (`source.python-input-v1`)** | **Python SQL**, **Python NoSQL (planned)**, **Command**, **Path**, **XSS** | M–L | Brings Python parity with Node's `InputFacts` (distinguishing FastAPI Pydantic scalar types / Flask `<int:id>` route converters from raw query strings), unlocking **Python NoSQL Injection** and eliminating false Review records on typed integer route params across SQL, Command, and Path. |

---

### Tier 3 — High Effort / Low or Narrow Impact (Future Work — Do NOT Implement Now)

| ID | Deferred Item | Analyzer Scope | Why Deferred (Effort vs. Impact) |
| --- | --- | --- | --- |
| **T3-1** | **Windows path/UNC/drive/ADS & `cmd.exe`/PowerShell command semantics** | **Path**, **Command** | Doubles path and shell quoting state machines (`C:foo` vs `C:\foo`, `%VAR%`, `^` escaping) without knowing target deployment OS; high false-positive risk unless target platform is configured. |
| **T3-2** | **Symlink / TOCTOU race & OS fd-containment (`O_NOFOLLOW`, `openat2`)** | **Path** | Runtime/environment properties that static source cannot establish without OS-specific descriptor tracking. |
| **T3-3** | **Whole-program / multi-hop (>1 cross-module) interprocedural summaries** | `[All Analyzers]` | High complexity (context-sensitive summary caching + cycle handling); keep scoped to the dedicated `analysis-certainty` roadmap slice rather than ad hoc per-analyzer recursion. |
| **T3-4** | **Second-order DB/cache-to-path or DB-to-command flows** | **Path**, **Command** | Unlike Stored XSS (where rendering user text from DB is ubiquitous), DB-stored paths/commands are overwhelmingly admin/config columns; tracing them without column-trust provenance creates heavy `Review` noise. |
| **T3-5** | **Full Repository CFG / SSA IR Rewrite (`flow.go` 991 lines -> SSA)** | `[All Analyzers]` | Tempting refactor, high regression risk across 7 calibrated analyzers; incremental extraction (`guards`, sink registry, `python_path` split) delivers 80% of the maintainability at 15% of the cost. |
| **T3-6** | **Unmodeled dynamic template `include` engines & custom streaming archive state machines (`yauzl`, raw `zlib`)** | **Path**, **XSS** | Low ecosystem frequency vs. high per-engine parser effort. |

---

## 4. Concrete Cross-Analyzer Blueprints (Tier 2)

### 4.1 Fact-Signature Context Deduplication & CLI Scheduling (`T2-1` — Owner-Approved Direction)

1. **Eligibility & Priority Fix (`cmd/scan/analysis.go`):**
   - Skip `analysispacks.ObservationOnly(u.Kind)` and `u.Kind == "xss_data_candidate"` *before* incrementing `requestIndex` against `--judge-limit` (still setting their `not_run` status explicitly).
   - Expand priority ordering from `queryUse` (`sql`, `nosql`, `command`, `path`) to `securitySinkUse` (`sql`, `nosql`, `command`, `path`, `xss_candidate`, `log_sink_candidate`) ahead of `input_validation_candidate`, so small `--judge-limit` runs always judge primary vulnerability sinks before standalone field-policy checks.
   - Generalize `--skip-family` and add `--only-family` accepting comma-separated registered family names (`sql,nosql,xss,command,path,logging,input-validation`).
2. **Default-On Fact-Signature Deduplication:**
   - Compute deterministic `FactSignature` = SHA-256 of `(pack_digest, protocol_version, callable_id, sink.sha256, sink.span, api_model_id, canonical_claim_facts, dependency_transfer_spans_and_kinds, applicable_entry_controls_and_route_converters, blocking_gaps)`.
   - Entry-specific differences (e.g., Flask `<int:id>` vs `<path:p>`, auth/validator middleware on one route but not another, or VulnPy WSGI `PATH_INFO` comprehension vs Flask `request.args`) produce **distinct** signatures and are judged independently.
   - Identical signatures judge the first candidate canonically and populate siblings with `assessment.DeduplicatedFrom = canonicalUse.ID` (`status: "completed"`), preserving per-entry findings in JSON/HTML/SARIF while surfacing `"Judged M distinct candidate signatures across N total entry contexts"` in scan accounting.

### 4.2 Shared AST Guard, Polarity & Terminator Engine (`T2-3` — Command + Path + Validation)

Extract a small, language-adapter-backed guard package inside `internal/parse/` (`guard_climb.go`):
- **Shared concepts:** `guardPolarity` (`rejectsWhenTrue` vs `enforcesWhenTrue`), boolean root unwrapping (`!` / `not`, `&&` / `and`, `||` / `or`), terminating block detection (JS `return`/`throw`/`process.exit`, Python `return`/`raise`/`flask.abort`/`werkzeug.exceptions.abort`/`fastapi.HTTPException`/`sys.exit`), intra-scope reassignment invalidation (`assignedBetween`), bounded 4-round derived-variable closure (`const rel = path.relative(...)`, `ok = ALLOWED.has(...)`), and 1-hop local helper call-site intersection.
- **Immediate Command Injection payoff:**
  - Fixes `commandGuards` (`command_claims.go:391`) attaching `if` conditions to `else` branches.
  - Upgrades Python `command` (`python_command.go:365`) to recognize dominating `if not ALLOWED: abort(403)` guards and local helper call-site guards without duplicating `python_path.go`.

### 4.3 Wire Bundle v7 (`T2-2` — All Analyzers)

Batch all prompt-byte changes into **one** coordinated protocol bump (`evidence_version: 7`, `*-components-v2`/`v3`):
- Always run `compactBundle` (saves ~5.5–7.0 KB of repeated 64-char SHA-256s and span keys per call; removes unused `compact_wire` instructions on uncompacted requests).
- Drop `use.evidence_roles` in favor of `use.evidence_coverage` (-1.0 KB).
- Strip 64-hex `digest` strings from model-facing `analysis_components` while keeping full digests on `CandidateUse.Components` and `DecisionTrace` for Go replay verification (-1.4 KB).
- Convert `CommandFacts` and `PathFacts` integer context offsets into `eN` wire IDs inside `wireBundle` (fixing the `context_evidence` vs `evidence` mismatch in both analyzers).
- Keep static fields (`analysis_components`, `instruction`, `analysis_guidelines`) serialized before `use` in `input` to maximize provider prefix-cache hits.

---

## 5. Recommended Delivery Sequence

1. **[x] Completed `path-traversal` coverage + `decision-model-limits` + [path-traversal-hardening.md](../specifications/path-traversal-hardening.md) (Tier 1)** — all 8 sample apps (including Juice Shop `unzipper` Zip Slip and both `hbs` layout call sites), shared rate/spend limits, `PathGuardSubstring` normalization policy, `PathGuardInverted` polarity, 5 false-protection closures, `commandTampered` generalization, Python `/p/prefix-boundary` `ROOT` excerpt (`16/16` protected controls), and `python_path*.go` / `path_guard*.go` splits are implemented and live-verified.
2. **Slice E1 ([analyzer-engine-hardening.md](../specifications/analyzer-engine-hardening.md), Tier 2 `T2-1` — Spec Authored & Ready)** — CLI `--only-family`/`--skip-family`, `--judge-limit` slot fix for XSS/Logging (superseding `components-03-outbound.md` O4's conservative candidate-index counting while preserving `exit 1` incompleteness), and default-on normalized-wire-bundle Context Deduplication (`deduplicated_from` provenance, `Usage == 0` on derived siblings, `-96.9%` multi-adapter token spend, zero `request_digest` byte changes).
3. **Slice E2 (`shared-guard-engine`, Tier 2 `T2-3` + `T2-4`)** — unify JS/Python guard polarity + `abort()` termination across Command, Path, and Validation, plus workspace `packageVersion` lookup for Path, XSS, and NoSQL.
4. **Slice E3 (`wire-bundle-v7`, Tier 2 `T2-2` + `T2-7`)** — single batched wire compaction + `eN` ref fix + `NodeFSContract`/`path_*.md` prose sync + `log-use-v1` catalog migration across all families (updating `TestOutboundPredecessorRequests` and `TestCommandPredecessorRequests` once).
5. **Slice E4 (`node-middleware-and-url-inputs` / `path-traversal-phase2`, Tier 2 `T2-5`, `T2-6`)** — promote Express chain handlers & `req.path` to XSS/Command/SQL/NoSQL and add FastAPI `FileResponse`/`UploadFile` + `shutil`/`tarfile.extractall`.
6. **External Generalization Check (from review handoff §3.6)** — run bounded out-of-sample evaluation on 2–3 fresh open-source JS/TS and Python microservices once `E1` context deduplication is active.
