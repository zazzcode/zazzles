# Path Traversal Hardening — Deliverable Specification

**Worktree / branch:** `path-traversal`  
**Feature:** Path Traversal Analyzer (CWE-22)  
**Milestone:** Native Scan — Analyzer Hardening (`N/A` calendar milestone)  
**Deliverable:** Path Traversal Tier-1 Correctness, Determinism, and Performance Hardening  
**Project Owner:** Human Project Owner  
**Deliverable Owner:** Human Deliverable Owner  
**Delivery topology:** Milestone branch (executes after the active Juice Shop coverage and shared `decision-model-limits` slice commits in `path-traversal`)  
**Review artifact:** One milestone PR into `stage` (or focused follow-up PR if `path-traversal` has already opened for review)  
**Approved review shape:** Milestone PR slice (focused commit(s) `[PARSE+JUDGE+DOC]` in `path-traversal`)  
**Decomposition rationale:** All Tier-1 fixes target path-specific soundness, determinism, live fixture accuracy, and file-size hygiene without altering any other analyzer's wire bytes or entries; splitting into stacked branches adds rebase churn over the same `internal/parse/*path*` files. Cross-analyzer wire/entry changes are separated into the [hardening and wire-efficiency proposal](../project/analyzer-hardening-and-wire-efficiency-proposal.md#1-architectural-structure-approved-two-document-split).  
**Integration branch:** `stage`  
**Merge policy:** PR review required — agents commit/push feature branches only; never merge to `stage`  
**Drafted:** 2026-11-14  
**Shared run log:** `.zazz/ephemeral/path-traversal-run-log.md` (`Tier-1 Hardening` section)  
**Execution tracking:** Local run log only (Zazz Board is not used)  
**Implementation coordination:** Lead Agent working alone (serialized after the active coverage/limits agent completes its checkpoint)  
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability

Eliminate verified false-positive, false-protection, nondeterminism, and missing-context defects in the Path Traversal Analyzer (`internal/parse`, `internal/analysis`, `internal/judge`, `internal/analysispacks`, `internal/guidelines`) while preserving byte-identical behavior and request digests across all non-path analyzers. Specifically: fix `.includes()`/`.indexOf()` allow-list misclassification (`PathGuardSubstring`), enforce AST branch polarity and compound-boolean soundness on path guards, include module-level root/allow-list definitions in candidate context (resolving the live Python `/p/prefix-boundary` Review discrepancy without weakening Go gates), close five concrete false-protection holes (`send_from_directory` unresolved roots, dict-splat/mutated allow-lists, `realpath`-after-guard, helper-nested decode order, multi-caller helper guard merging), close three small high-frequency binding gaps (`require('fs').promises` destructuring, `pathlib.Path.unlink`, helper-nested `req.path`/`req.url`), restore map-iteration determinism and fast-skip non-path Express middlewares, and split `internal/parse/python_path.go` inside repository file-size thresholds.

---

## 1. Required Reading For The Implementor

### 1.a This Specification

Read this specification end to end first, after confirming no concurrent agent is actively editing `path-traversal`.

### 1.b Feature / Milestone Context

- [.zazz/project/analyzer-hardening-and-wire-efficiency-proposal.md §3 Master Ranked Improvement Matrix](../project/analyzer-hardening-and-wire-efficiency-proposal.md#3-master-ranked-improvement-matrix-separated-by-effort-vs-impact--analyzer-scope) — Tier 1 vs. Tier 2/3 boundary.
- [.zazz/architecture/analysis-packs.md §Descriptor and selection contract](../architecture/analysis-packs.md#descriptor-and-selection-contract) and [§Bounds and compatibility](../architecture/analysis-packs.md#bounds-and-compatibility) — digest and replay rules.
- [docs/analysis/path-traversal.md](../../docs/analysis/path-traversal.md) — public product rules that MUST match behavior.

### 1.c Prior Specifications In This Delivery Effort

- [.zazz/specifications/path-traversal.md §3 Invariants and decisions](path-traversal.md#3-invariants-and-decisions) and [§5 Acceptance criteria](path-traversal.md#5-acceptance-criteria).
- [.zazz/specifications/decision-model-limits.md](decision-model-limits.md) — shared runtime rate/spend controls in the same worktree.

### 1.d Standards

Per `.zazz/standards/index.yaml`, load and verify these standards before editing:

| Standard | What it governs here |
| --- | --- |
| [.zazz/standards/code-structure.md](../standards/code-structure.md) | 400/700-line file and 60/100-line function thresholds, contextual splitting, compute-once, sorted map keys, no spec/AC IDs in code comments |
| [.zazz/standards/testing.md](../standards/testing.md) | Table-driven failing-first Go regressions, HTTP stubs, deterministic offline checks |
| [.zazz/standards/docs-hygiene.md](../standards/docs-hygiene.md) | Relative links, RFC-2119 voice, zero working-doc tokens (`AC-`, `D-`, `OQ-`, `INVARIANT`) in committed Go/test files |
| [.zazz/standards/spec-hygiene.md](../standards/spec-hygiene.md) | Repo-relative paths, explicit exclusions, in-place contract updates |

### 1.e Existing Code References

- `internal/parse/path_guards.go`, `internal/parse/path_modeled.go`, `internal/parse/path_claims.go`, `internal/parse/path_node.go` — JS/TS path extraction and guard classification.
- `internal/parse/python_path.go` — Python path extraction, guards, and completeness (to be split by concern).
- `internal/judge/path.go` and `internal/judge/path_policy_test.go` — deterministic evidence-validation gates and policy matrix.

### 1.f Project Orientation

- [AGENTS.md](../../AGENTS.md#authorization-and-delivery) and [.zazz/docs/zazzles-agent-orientation.md](../docs/zazzles-agent-orientation.md#working-protocol).

---

## 2. Invariants

1. **Zero target leakage.** No sample name, route, challenge identifier, file name, or answer-key label may appear in production code, embedded contracts, guidelines, or model-bound evidence.
2. **Non-path analyzer byte preservation.** Every non-path `CandidateUse`, non-path entry, and non-path provider request digest across SQL, NoSQL, Validation, XSS, Command, Outbound, and Logging MUST remain byte-identical (except explicitly enumerated `pathOnly` chain entries already authorized in `path-traversal.md`).
3. **Go gates never weaken for model convenience.** Fixing Python `/p/prefix-boundary` MUST work by supplying missing source-backed `ROOT`/import evidence and clearing false `coverage_gaps`, never by relaxing `applyPathPolicy` when `path_traversal == "unknown"`.
4. **Unverified controls stay `needs_evidence`, never `confirmed_vulnerability` or `protected_for_claim`.** An imported, runtime, or negated collection/helper check whose semantics are not proven in local source MUST classify as `PathGuardUnclassified` (`Review`), never as a `KnownNonEnforcingPathGuard` witness or an `EnforcingPathGuard`.
5. **Deterministic output.** Every map iteration that feeds slice order, string construction, guard classification, or wire serialization MUST sort keys first.

---

## 3. Scope

### Approved Review Shape

One coherent slice inside the `path-traversal` milestone branch (targeting `stage` via draft PR). If `path-traversal` has already been merged to `stage` when this specification is launched, create sibling branch/worktree `path-traversal-hardening` from `stage` only after Deliverable Owner confirmation and record the update in §13.

### Strict Scope Constraint

Every modified file MUST live under `internal/analysis/`, `internal/analysispacks/`, `internal/guidelines/`, `internal/parse/`, `internal/judge/`, `docs/analysis/`, or `.zazz/`. Do NOT modify `cmd/`, `internal/walk/`, `internal/lang/`, non-path family descriptors, or `.env` files.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `internal/analysis/path.go` | Modified | Add `RealpathBeforeGuard`, `NormalizedBeforeGuard` and `PathGuardInverted` (`KnownNonEnforcingPathGuard`); include `PathGuardSubstring` and `PathGuardInverted` in `Validate()`; add `"delete"` to `Role` doc comment |
| `internal/parse/path_guard_classify.go` | New | Extracted from `path_guards.go` (<= 400 lines): deterministic `sortedRelated`, `classifyPathGuardAST`, polarity/conjunction evaluation, `PathGuardInverted` and receiver-scoped `PathGuardSubstring` |
| `internal/parse/path_guards.go` | Modified | AST branch-polarity climbing (`consequence` vs `alternative`), multi-caller enforcing-guard intersection, module constant/allowlist excerpt capture, and helper functions <100 lines |
| `internal/parse/path_modeled.go` | Modified | Emit top-level `constant_base` / `allowlist_definition` declaration spans on guarded candidates; reject mutated module collections (`.push`, `.add`, `Object.assign`, subscript assignment) |
| `internal/parse/path_claims.go` | Modified | Fix `DecodedAfterGuard` across helper call sites; set `RealpathBeforeGuard` and `NormalizedBeforeGuard` |
| `internal/parse/path_node.go` | Modified | Support `const { readFile } = require('fs').promises` destructuring |
| `internal/parse/path_url_sources.go`, `internal/parse/helper_flow.go` | Modified | Detect and propagate `req.(path\|url\|originalUrl\|baseUrl\|file\|files)` inside reachable local helper bodies |
| `internal/parse/path_chain.go` | Modified | Fast-skip non-final Express middlewares (`mayContainPathSink`) whose reachable AST lacks filesystem, archive, or `render` calls |
| `internal/parse/python_path.go` | Modified | Keep verified Python bindings and operand extraction (<350 lines); add `"unlink"` (`delete` role) to `pyPathlibOps`; require `safeSendDirectory` on `send_from_directory` directory |
| `internal/parse/python_path_guards.go` | New | Extracted from `python_path.go`: `pyConstantCollection` (rejecting `dictionary_splat` and mutations), `pyConstantPath`, `safeSendDirectory`, `pyAlwaysExits`, `pythonPathGuards` with polarity/conjunction checks |
| `internal/parse/python_path_claims.go` | New | Extracted from `python_path.go`: `completePythonPath` and `modeledPathGap` emitting module-level `constant_base` / import evidence on guarded claims and deduplicating `transfers` |
| `internal/parse/python_command.go` | Modified | Generalize `commandTampered` monkey-patch scan beyond `os`/`subprocess` to any imported Python module |
| `internal/parse/path_source_test.go` | Modified | Accept non-enforcing `KnownNonEnforcingPathGuard` unsafe witnesses alongside `raw` flows on positive matrix rows |
| `internal/judge/path.go` | Modified | Require `RealpathBeforeGuard` for `resolved_boundary`; treat `PathGuardSubstring` as `unsafeWitness` when unnormalized and `poor_practice` (`weakControlsOnly`) when normalized |
| `internal/parse/path_test.go`, `internal/judge/path_policy_test.go`, `internal/judge/path_payload_test.go` | Modified | Table-driven adversarial regressions for all ACs |
| `README.md`, `docs/analysis/path-traversal.md`, `.zazz/architecture/analysis-packs.md`, `.zazz/evaluation/path-traversal-results.md`, `.zazz/project/implementation-plan.md`, `.zazz/docs/zazzles-agent-orientation.md`, `.zazz/specifications/{README,path-traversal,decision-model-limits}.md` | Modified | Sync delivered capabilities, live verification outcomes, and Tier-2/Tier-3 architecture pointers |

### Out Of Scope (Including Explicitly Deferred Future Work)

- **Cross-analyzer Wire Bundle v7 & Fact-Signature Context Deduplication** — tracked in [proposal §4](../project/analyzer-hardening-and-wire-efficiency-proposal.md#4-concrete-cross-analyzer-blueprints-tier-2); requires coordinated multi-family trace migration.
- **Additional file/archive APIs** (`FileResponse`, `UploadFile`, `fs.open/copyFile/rename`, `shutil`, `tarfile.extractall`, `node-tar`, `extract-zip`, Multer storage) — deferred to Tier-2 follow-on spec `path-traversal-phase2`.
- **Shared JS+Python AST guard engine & general Express middleware-chain entries for non-path analyzers** — deferred to Tier-2 cross-analyzer specs.
- **High-effort / low-impact future work (NOT to be implemented):**
  - Windows drive-letter, UNC, ADS, and backslash path semantics (`path.win32`, `ntpath`).
  - Runtime symlink/TOCTOU race state or `openat2`/`O_NOFOLLOW` OS modeling.
  - Cross-module (>1 hop) general interprocedural path/guard summaries.
  - Second-order DB/cache-to-path traversal flows.
  - Unmodeled template engines (dynamic `pug`/`ejs` includes, custom Jinja loaders) and hand-written event-stream archive loops (`yauzl`, `zlib`).

---

## 4. Decisions

### D-1 — Receiver-Scoped `PathGuardSubstring` and Normalization-Sensitive Policy

**Decision.** Classify `.includes(...)` / `.indexOf(...)` as `PathGuardSubstring` ONLY when the call receiver mentions a path-derived variable (`mentionsAny(receiver, names)` and `!mentionsAny(arg, names)`). When a path-derived variable is the argument to `.includes`/`indexOf` on an unverified receiver (`!ALLOWED_IMPORTED.includes(f)`), classify as `PathGuardUnclassified`. In `internal/judge/path.go`, treat `PathGuardSubstring` as an `unsafeWitness` (`confirmed_vulnerability`) when no `resolve`/`normalize`/`abspath`/`normpath`/`realpath` transform precedes the guard, and as a weak control (`poor_practice` via `weakControlsOnly`, matching `PathGuardPrefixBare`) when lexical normalization precedes the guard.  
**Why.** `str.includes(sub)` tests a substring of the path, whereas `arr.includes(item)` tests collection membership. On an unnormalized string, `'/uploads/' + '../../etc/passwd'` contains `'/uploads/'` and climbs out directly (`confirmed_vulnerability`); on a resolved/normalized string, `..` is collapsed before `.includes(root)`, reducing the weakness to sibling-prefix/substring collision (`poor_practice`). Treating unverified `arr.includes(f)` as `PathGuardSubstring` would falsely confirm vulnerabilities on imported or database-backed allow-lists.  
**Rejected alternative.** Resolving cross-module `ALLOWED` arrays in Tier 1 — rejected because runtime/DB arrays would still exist and MUST safely remain `Review` (`PathGuardUnclassified`).

### D-2 — Structural Polarity & Boolean Conjunction Awareness in Guard Climbing

**Decision.** Pass explicit branch polarity into `consider` (`rejectsWhenTrue = true` for `if (cond) { return/throw/abort }`, `enforcesWhenTrue = true` for `if (cond) { sink }` in `consequence` only, never `alternative` unless `consequence` did not exit and condition is inverted) and inspect the AST boolean root (`!`, `not`, `&&`/`and`, `||`/`or`) before labeling a guard with an enforcing `PathGuard*` kind.  
**Why.** Regex matching over raw condition text ignores negation and branch placement, letting `if (!full.startsWith(ROOT + sep)) { fs.readFileSync(full); }`, `else` branches of allow-lists, and `if (!isAdmin && !ALLOWED.has(f)) return 403` acquire enforcing guard kinds (`unsafeWitness = false`, `guardedAll = true`).  
**Rejected alternative.** Leaving polarity entirely to the LLM — rejected because `unsafeWitness` in Go (`internal/judge/path.go:89`) blocks confirming `vulnerable` whenever an enforcing guard kind is attached, even when the LLM correctly answers `vulnerable`!

### D-3 — Supply Module Constant & Import Definitions Instead of Weakening Gates

**Decision.** When `constantPathValue` (JS/TS) or `pyConstantPath` / `pyConstantCollection` (Python) validates a module-level identifier (`ROOT`, `ALLOWED`), append its declaration node (`topVariable` / `m.vars`) as `constant_base` or `allowlist_definition` evidence in `u.Context`, attach verified `os`/`path`/`abort` import bindings in Python, and move covered `python_value_unresolved` / `python_call_unresolved` gaps to `Completeness.Resolved`.  
**Why.** Saved trace `candidate_v1_244fa01c...` proves `gemini-decision-1` answered `path_traversal = unknown` on Python `/p/prefix-boundary` because `ROOT = os.path.abspath("uploads")` was absent from `source_excerpts` while `coverage_gaps` declared `ROOT` unresolved. Supplying the verified source line fixes model certainty cleanly while keeping strict all-3-facet Go gates intact.

### D-4 — Pre-Filter Express Non-Final Middleware & Batch Catalog Text Updates Once

**Decision.** Gate `analyzePathChainHandlers` behind a fast AST scan checking whether the middleware body (or its local helpers) references any `fs`/archive/`sendFile`/`download`/`render` identifier before running `analyzeHTTPHandler`, and batch the `NodeFSContract` / `PythonPathlibContract` / `path_*.md` text sync into a single phase so path fixture traces are refreshed at most once.  
**Why.** Running full `analyzeHTTPHandler` on every `auth`/`rateLimit`/`cors` middleware wastes parse time on large Express apps, and batching prompt-affecting edits avoids repeated live trace invalidation.

---

## 5. Agent Implementation Rules

- **Concurrency & serialization:** Verify `git status --short --branch` shows the prior coverage/limits session is committed and idle before starting. Single Lead Agent working sequentially in `path-traversal/`.
- **Team integration:** Commit/push to `path-traversal` only when instructed; never merge to `stage`.
- **Command working directory & toolchain:** Run from `path-traversal/` with `GOFLAGS=-buildvcs=false`. Format **only** changed Go files (`gofmt -w <changed-files>`).
- **Live budget:** Offline tests and local HTTP stubs run first for all ACs. Live `gemini-decision-1` reassessment is permitted ONLY for path candidates whose `request_digest` changed (bounded to <= 80 live requests, using exact replay for unchanged traces, paced via configured limits, zero retries/fallback, never printing `.env`).
- **Run log:** Append phase progress, test outputs, and any deviations to `.zazz/ephemeral/path-traversal-run-log.md`.
- **Code comment hygiene:** Do NOT put `AC1`, `D-1`, `OQ-1`, `SPEC`, or `INVARIANT` tokens in Go comments or test names ([docs-hygiene.md](../standards/docs-hygiene.md#working-doc-identifiers-do-not-appear-in-committed-files)).

### Halt Conditions

1. Any §10 Open Question is unresolved before writing code.
2. Uncommitted edits from another active agent session are present in `git status`.
3. `compare_existing_families.sh` shows any non-path use or non-enumerated entry delta against `stage`.
4. Same test fails 3 consecutive iterations, or implementation requires touching files outside §3.
5. Any live Gemini call returns HTTP 401/403/429 or exceeds the session request/dollar cap.

---

## 6. Acceptance Criteria

- **AC1 — Unverified `.includes()` / `.indexOf()` stays `Review`, and path-receiver substring checks distinguish unnormalized bypasses from normalized weak prefixes.** An imported or dynamic collection check `if (!EXTERNAL_LIST.includes(req.query.f)) return res.status(403).end()` classifies as `PathGuardUnclassified` (`unsafeWitness == false`, `FindingStatus == "needs_evidence"` under both `honestRaw` and `optimisticAllowlist`). A path-receiver substring check `if (!p.includes('/uploads/')) return res.status(403).end()` classifies as `PathGuardSubstring`, passes `PathFacts.Validate()`, confirms `confirmed_vulnerability` (`unsafeWitness == true`) when `p` is NOT normalized/resolved prior to the check (because `/uploads/../../etc/passwd` trivially passes), and yields `poor_practice` (`weakControlsOnly == true`, `unsafeWitness == false`) when `resolve`/`normalize`/`abspath`/`normpath` precedes the check (neutralizing `..` climb while leaving sibling-directory `/uploads-secret` exposure, matching `PathGuardPrefixBare`). Verified by `TestPathGuardSubstringVsMembership` in `internal/parse/path_test.go` and `internal/judge/path_policy_test.go`.
- **AC2 — Branch polarity and compound boolean bypasses do not earn enforcing guard kinds.** Sinks inside (a) an `else` branch of `if (ALLOWED.has(f))`, (b) a negated `if (!full.startsWith(ROOT + path.sep))` consequence, (c) an inverted terminating guard `if (ALLOWED.has(f)) return res.status(403).end()`, or (d) a conditional bypass `if (!req.query.admin && !ALLOWED.has(f)) return res.status(403).end()` do NOT attach an `EnforcingPathGuard`; `honestRaw` confirms (a)–(c) and `optimisticAllowlist`/`optimisticBoundary` is rejected by `applyPathPolicy` on (a)–(d). Verified by `TestPathGuardPolarityAndBypass` in `internal/parse/path_test.go` and `internal/judge/path_policy_test.go`.
- **AC3 — Five false-protection holes closed.**
  1. Python `send_from_directory(unresolved_helper(), f)` does not attach `PathGuardFrameworkRoot`.
  2. Python `ALLOWED = {"a.txt": 1, **EXTRA}` and JS/Python module collections mutated via `.push`/`.add`/subscript assignment return `false` from constant-collection checks.
  3. `realpathSync`/`os.path.realpath` called *after* a lexical `startsWith` guard sets `RealpathBeforeGuard == false`, and `applyPathPolicy` rejects `containment_control == "resolved_boundary"` with `path_answers_inconsistent`.
  4. `decodeURIComponent`/`unquote` inside a local helper invoked *after* a guard sets `DecodedAfterGuard == true` even when the helper is declared earlier in the file.
  5. A local helper called from two sites where one site has `ALLOWED.has` and the other has only `includes('..')` sets `ambiguousCallers == true` (`flow.Protection == "unknown"`).
  Verified by `TestPathFalseProtectionControls` across `internal/parse/path_test.go` and `internal/judge/path_policy_test.go`.
- **AC4 — Module constant/import context supplied & Python `/p/prefix-boundary` resolved.** Both JS/TS and Python path candidates include module-level `constant_base` (`ROOT`) and `allowlist_definition` (`ALLOWED`) declaration spans in `source_excerpts`; Python candidates omit resolved `ROOT`/`os`/`os.path.abspath` entries from `coverage_gaps` and emit no duplicate `Supported transfer` strings in `ModelFacts`. Verified offline by `TestPathPayloadConstantDefinitions` in `internal/judge/path_payload_test.go` (and 15/15 live protected controls when live reassessment is authorized).
- **AC5 — High-frequency small bindings covered.** `const { readFile } = require('fs').promises`, `pathlib.Path(ROOT, f).unlink()`, and `req.path` read inside a local helper called from an Express handler each produce a valid `path_traversal_candidate` with verified contract and role (`read`, `delete`, `read`). Verified by `TestPathBindingsAndOptions` and `TestPathPythonOperands` in `internal/parse/path_test.go`.
- **AC6 — Determinism, middleware fast-skip, and file-size compliance.** `classifyPathGuardText` produces identical guard kinds across 100 randomized `defs` map constructions; Express routes with non-path middle handlers incur zero `analyzeHTTPHandler` runs in `analyzePathChainHandlers`; `python_path*.go` files are each <= 450 lines with extracted functions <= 100 lines. Verified by `TestPathGuardClassificationDeterminism` in `internal/parse/path_test.go`, `wc -l`, `go build ./...`, `go vet ./...`, `gofmt -l`, and `go test -race ./... -count=1`.
- **AC7 — Additive non-path parity & doc checks pass.** Existing-family comparison across pinned samples shows zero non-path use changes, and `python3 .zazz/ephemeral/path-tools/check-docs.py` exits 0.

---

## 7. Test Strategy

Reference data sources:
- Existing portable fixtures in `internal/parse/testdata/{typescript,javascript,python}/path-traversal/` and stubbed policy matrices in `internal/judge/path_policy_test.go`.
- Saved trace `candidate_v1_244fa01c...json` as the empirical baseline for `ROOT` excerpt inclusion on `/p/prefix-boundary`.

Automated tests (compact table-driven matrices, no duplicate per-case boilerplate):
- `TestPathGuardSubstringVsMembership` (`internal/parse/path_test.go` + `internal/judge/path_policy_test.go`) — covers AC1 (receiver vs. argument `.includes`/`.indexOf`, `PathFacts.Validate`).
- `TestPathGuardPolarityAndBypass` (`internal/parse/path_test.go` + `internal/judge/path_policy_test.go`) — covers AC2 (`else` branch, negated `consequence`, inverted terminating guard, `&&` bypass vs. `||` rejection in both TS and Python).
- `TestPathFalseProtectionControls` (`internal/parse/path_test.go` + `internal/judge/path_policy_test.go`) — covers AC3 (all 5 false-protection vectors in one table per layer).
- `TestPathPayloadConstantDefinitions` (`internal/judge/path_payload_test.go`) — covers AC4 (asserts `ROOT = os.path.abspath("uploads")` and `const ROOT = ...` appear in `Preview()` `source_excerpts`, `ROOT` absent from `coverage_gaps`, `ModelFacts` deduplicated).
- `TestPathBindingsAndOptions` / `TestPathPythonOperands` extensions (`internal/parse/path_test.go`) — covers AC5 (3 new rows added to existing tables rather than new fixture directories).
- `TestPathGuardClassificationDeterminism` (`internal/parse/path_test.go`) — covers AC6 (20-entry `defs` map with competing `startsWith(ROOT)` and `startsWith(ROOT + sep)` tested over 100 iterations).

Existing coverage intentionally reused:
- `TestPathSourceCases`, `TestPathComponentSelection`, and `TestPathPipelineParity` already verify pinned-sample structural expectations, catalog digests, and JSON/HTML/SARIF parity.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

### TDD Entry Point

Start by adding `TestPathGuardSubstringVsMembership` and `TestPathGuardPolarityAndBypass` in `internal/parse/path_test.go` and running:
```bash
GOFLAGS=-buildvcs=false go test ./internal/parse -run 'TestPathGuard(SubstringVsMembership|PolarityAndBypass)' -count=1
```
Confirm red failure (`!EXTERNAL_LIST.includes(f)` misclassified as `substring`; `else`-branch and negated `consequence` misclassified as `allowlist` / `prefix_boundary`).

### Prescriptive Execution Sequence

**Phase 1: Guard Soundness, Determinism & False-Protection Closures (AC1, AC2, AC3, AC6)**
1.1. Add failing table rows in `internal/parse/path_test.go` and `internal/judge/path_policy_test.go` for AC1–AC3 and determinism (AC6).
1.2. Split `internal/parse/python_path.go` into `python_path.go`, `python_path_guards.go`, and `python_path_claims.go` (pure move first; verify `go test ./internal/parse -run TestPath -count=1` stays green before behavior edits).
1.3. Update `internal/analysis/path.go`, `internal/parse/path_guards.go`, `internal/parse/python_path_guards.go`, `internal/parse/path_modeled.go`, `internal/parse/path_claims.go`, and `internal/judge/path.go` using the skeletons below.
1.4. Run `GOFLAGS=-buildvcs=false go test ./internal/parse ./internal/judge -run 'Path' -count=1`. Expect PASS.

**Phase 2: Constant-Definition Context, Small Bindings & Middleware Fast-Skip (AC4, AC5, AC6)**
2.1. Add failing payload/binding assertions in `internal/judge/path_payload_test.go` and `internal/parse/path_test.go`.
2.2. Update `internal/parse/python_path_claims.go` and `internal/parse/path_modeled.go` to emit declaration spans for verified module constants/allow-lists and deduplicate `transfers`; update `path_node.go` (`require('fs').promises` destructuring + `unzipper` declaration context), `path_url_sources.go` (helper body scan), and `path_chain.go` (fast-skip predicate).
2.3. Batch-update `internal/analysispacks/path.go` and `internal/guidelines/path_{javascript,python}.md` for full operation parity.
2.4. Run `GOFLAGS=-buildvcs=false go test ./internal/parse ./internal/analysispacks ./internal/judge ./internal/report -run 'Path' -count=1`. Expect PASS.

**Phase 3: Full Verification, Additive Proof & Documentation Sync (AC7)**
3.1. Run `TestPathSourceCases` and `.zazz/ephemeral/path-tools/compare_existing_families.sh origin/stage`.
3.2. If live reassessment of changed fixture digests is authorized (see §10), run `.zazz/ephemeral/patheval` with exact replay for unchanged requests and verify Python `/p/prefix-boundary` reaches `protected_for_claim` (15/15 protected controls).
3.3. Run `go build ./...`, `go vet ./...`, `gofmt -l` on changed Go files, `go test -race ./... -count=1`, and `python3 .zazz/ephemeral/path-tools/check-docs.py`. Update docs in §3.

### Skeleton: Guard Polarity & Deterministic Classification (`internal/parse/path_guards.go`)

```go
type guardPolarity int

const (
	guardRejectsWhenTrue  guardPolarity = iota // if (cond) { return/throw/abort }
	guardEnforcesWhenTrue                      // if (cond) { sink } inside consequence
)

// classifyPathGuard evaluates condition AST + sorted derived definitions with branch polarity.
// Unconditional enforcing status requires positive containment polarity without top-level
// bypass conjuncts/disjuncts; ambiguous polarity falls back to PathGuardUnclassified.
func classifyPathGuard(cond *sitter.Node, src []byte, polarity guardPolarity, names []string, defs map[string]string, collectionIs func(string) bool) string {
	// 1. Sort keys(defs) before building related string (determinism).
	// 2. Unwrap unary '!' / 'not' flipping polarity; reject enforcing promotion when
	//    guardRejectsWhenTrue is joined by '&&'/'and' with an unmodeled condition, or
	//    guardEnforcesWhenTrue is joined by '||'/'or'.
	// 3. Match substring (.includes/.indexOf) ONLY when mentionsAny(receiver, names).
	return analysis.PathGuardUnclassified
}
```

### Skeleton: `RealpathBeforeGuard`, `NormalizedBeforeGuard` & Helper-Order `DecodedAfterGuard` (`internal/analysis/path.go`, `internal/parse/path_claims.go`)

```go
// In analysis.PathFlow:
RealpathBeforeGuard   bool `json:"realpath_before_guard,omitempty"`
NormalizedBeforeGuard bool `json:"normalized_before_guard,omitempty"`

// In finishPathFlows (internal/parse/path_claims.go):
// Walk dep.Transfers in dataflow order: track whether an argument_to_parameter transfer
// at a call site >= guard.EndByte precedes a decode transfer (DecodedAfterGuard = true),
// whether a realpath transfer precedes all enforcing guards (RealpathBeforeGuard = true),
// and whether resolve/normalize/absolutize/realpath precedes substring guards (NormalizedBeforeGuard = true).
```

---

## 9. Definition Of Done

- [x] All §1 required reading consumed; `.zazz/standards/index.yaml` lookup verified.
- [x] All §10 Open Questions resolved with the Deliverable Owner and logged in `.zazz/ephemeral/path-traversal-run-log.md`.
- [x] Concurrent worktree changes from the prior coverage/limits session cleanly checkpointed (`eb5eddc`) before edits began.
- [x] Scoped tests green: `GOFLAGS=-buildvcs=false go test ./internal/parse ./internal/analysispacks ./internal/judge ./internal/report -run 'Path' -count=1`.
- [x] Full race suite green: `GOFLAGS=-buildvcs=false go test -race ./... -count=1` (all 9 packages), `go vet ./...`, `go build ./...`.
- [x] Changed Go files formatted (`gofmt -l` empty); zero transient spec tokens in code/tests.
- [x] `python_path*.go` and `path_guard*.go` splits verified (`wc -l` <= 450 lines per file).
- [x] Additive check passes against `86f5bc5` (`compare_checkpoint.sh`: zero non-path use changes; 2 path-only Juice Shop entries).
- [x] `python3 .zazz/ephemeral/path-tools/check-docs.py` exits 0.
- [x] All AC1–AC7 verified offline and live with `gemini-decision-1` (78/78 portable controls, 11/11 live adversarial controls, 204/204 sample positive contexts, 360/360 exact replays), recorded in `.zazz/ephemeral/path-traversal-run-log.md` and `.zazz/evaluation/path-traversal-results.md`.
- [ ] Human PR review completed.

---

## 10. Open Questions

All open questions resolved with the Deliverable Owner on 2026-11-14:
- **Document topology:** Two-document split confirmed (`path-traversal-hardening.md` for Tier 1 + `analyzer-hardening-and-wire-efficiency-proposal.md` for Tier 2/3).
- **`PathGuardSubstring` normalization policy:** Context-sensitive rule confirmed (unnormalized -> `confirmed_vulnerability`; normalized root substring -> `poor_practice`; unverified receiver membership -> `PathGuardUnclassified` / `needs_evidence`).
- **Live reassessment:** Authorized and completed with `gemini-decision-1` while keeping `NodeFSContract` / guideline text edits deferred to the single Tier-2 Wire Bundle v7 batch (`T2-2`) so 253/260 VulnPy and unguarded sample traces preserved exact replay without redundant token spend.

---

## 11. Run Log Protocol

Append execution records to `.zazz/ephemeral/path-traversal-run-log.md` under `## 2026-11-14 — Path Traversal Tier-1 Hardening` (Standards Verification, OQ Resolutions, Phase Completions, Deviations, Verification Summary, Verifier Report). Never rewrite earlier session history.

---

## 12. Agent Implementation Prompt

```text
Work in the existing `path-traversal/` worktree on branch `path-traversal`.
Your task is to implement `.zazz/specifications/path-traversal-hardening.md`.
Shared run log: `.zazz/ephemeral/path-traversal-run-log.md` (local run log only; Zazz Board is not used).
Implementation coordination: Lead Agent working alone. Companion skills: `spec-driven`, `doc-check`.

1. Verify `pwd`, `git branch --show-current`, and `git status --short --branch`. Halt immediately if another agent session has uncommitted in-flight edits or if any §10 Open Question is unresolved. Never read or print `.env`.
2. Read `AGENTS.md`, `.zazz/docs/zazzles-agent-orientation.md`, `.zazz/specifications/path-traversal-hardening.md` end to end, `.zazz/ephemeral/path-traversal-run-log.md`, and verify `.zazz/standards/index.yaml` against §1.d.
3. Follow §8 strictly: add the failing tests in Phase 1 first, confirm red failure for the right reason, split `python_path.go` cleanly before behavioral edits, then implement Phases 1–3 within §3 strict scope. Never place `AC`, `D-`, `OQ-`, `SPEC`, or `INVARIANT` identifiers in Go source or test files.
4. Run `GOFLAGS=-buildvcs=false` for `go build ./...`, `go vet ./...`, `go test -race ./... -count=1`, format only changed Go files, run `.zazz/ephemeral/path-tools/compare_existing_families.sh origin/stage`, and run `python3 .zazz/ephemeral/path-tools/check-docs.py`.
5. After your DoD checks pass, dispatch a fresh read-only Verifier sub-agent:
   "Verify `.zazz/specifications/path-traversal-hardening.md` in `path-traversal/`. Read the specification and `.zazz/ephemeral/path-traversal-run-log.md`. Independently run the verifying tests/commands for AC1–AC7, verify `wc -l` thresholds, check `git diff` stays strictly inside §3 with zero working-doc identifiers in code, and do not modify any files. Return PASS/FAIL per AC with evidence."
6. Report the checkpoint to the Deliverable Owner. Commit/push only if explicitly instructed; never merge to `stage`.
```

---

## 13. Implementation And Review Change Log

### 2026-11-14 — Live Verification Discovery: `PathGuardInverted` & Exact-Replay Preservation

**Source.** Deliverable Owner authorization of Tier-1 implementation + live `gemini-decision-1` validation.

**Changed Sections.** [§3 Scope](#3-scope), [§4 Decisions](#4-decisions), [§9 Definition Of Done](#9-definition-of-done), [§10 Open Questions](#10-open-questions).

**Rationale.** Live Gemini testing on `/v/else-branch` (`if (ALLOWED.has(f)) return ... else fs.readFileSync(...)`) showed Gemini truthfully answered `vulnerable` + `none`, which requires a verified `PathGuardInverted` (`KnownNonEnforcingPathGuard`) kind so `unsafeWitness` confirms the finding while still keeping unverified external allow-lists (`!EXTERNAL.includes(f)`) at `PathGuardUnclassified` (`needs_evidence`). Additionally, deferring prose-only catalog/guideline edits to the Tier-2 Wire Bundle v7 batch preserved exact replay across 315 unchanged traces while supplying `ROOT`/`ALLOWED` excerpts only on guarded candidates.

**Summary.** Added `PathGuardInverted`, split `path_guards.go` into `path_guards.go` + `path_guard_classify.go` alongside the 3-file `python_path*.go` split, generalized `commandTampered`, and verified all 11 adversarial controls live with `gemini-decision-1`.

**Verification Impact.** Full 9-package `go test -race ./... -count=1`, 11/11 live adversarial Gemini checks, 78/78 portable controls, 204/204 sample positive contexts, and 360/360 zero-call exact replays pass.

