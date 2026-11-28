# Shared AST Guard & Workspace Manifest Engine — Slice E2 Contract

**Worktree / branch:** `analyzer-engine-hardening` (same assigned worktree and branch as E1; E3 and E4 get their own worktrees)
**Milestone:** [Cross-Analyzer Engine Hardening](analyzer-engine-hardening.md#0-capability--milestone-roadmap), slice `E2`
**Deliverable:** `shared-guard-and-manifest-engine`
**Drafted:** 2026-11-14
**Review artifact:** The existing draft PR for `analyzer-engine-hardening` targeting `stage`; never merge to `stage`
**Execution record:** Local run log `.zazz/ephemeral/analyzer-engine-hardening-run-log.md`
**Companion skills:** `spec-driven`, `doc-check`

---

## 1. Capability

One lexical guard engine decides, for a sink call, which dominating or enclosing controls apply, with
which polarity, and whether they terminate. Today four copies of that logic exist and they disagree
([proposal A-4](../project/analyzer-hardening-and-wire-efficiency-proposal.md#2-cross-analyzer-architectural-audit-where-analyzer-silos-are-hurting-accuracy--cost)):

| Defect (verified in source) | Location | Effect |
| --- | --- | --- |
| JS Command records an `if` condition as `enclosing_guard` when the call is in the `else` branch | `commandGuards` in `internal/parse/command_claims.go` | The model reads a *rejected* condition as an enforced one; protected/vulnerable verdicts invert for `if (isSafe(x)) … else exec(x)` |
| Python Command never sees a dominating `if bad: abort(403)` | `commandCall` in `internal/parse/python_command.go` | `abort()` is not a flow terminator, both branches merge, the branch precondition is dropped, and the path is reported `raw` although it is guarded |
| Command guards ignore reassignment between guard and call and ignore derived values (`const clean = x.trim(); if (!OK.has(clean)) return`) | both Command adapters | A stale guard is credited, or a real guard on a derived value is missed |
| Command has no helper call-site attribution | both Command adapters | A guard in the caller of a local helper is invisible |
| Path owns the correct engine privately | `path_guards.go`, `python_path_guards.go` | Duplicated code; JS terminators omit `process.exit` |

Dependency-version facts have a second root-only defect: `packageVersion` reads the repository-root
`package.json` and `package-lock.json` only. A monorepo workspace (`packages/api`) that pins a vulnerable
`marked`, `sanitize-html`, `adm-zip`, `hbs` or `mongoose`, or that is locked by a workspace lockfile, resolves
to the wrong version or to none.

E2 extracts the engine, routes Command and Path through it, and replaces `packageVersion` with a
nearest-ancestor, workspace-lockfile-aware resolver used by Path, XSS and NoSQL.

## 2. Required reading

- [Milestone index §0–§4](analyzer-engine-hardening.md#0-capability--milestone-roadmap) and the [proposal §4.2 and T2-4](../project/analyzer-hardening-and-wire-efficiency-proposal.md#42-shared-ast-guard-polarity--terminator-engine-t2-3--command--path--validation).
- [Path hardening contract](path-traversal-hardening.md) — the polarity, conjunction and helper-caller rules this slice extracts without changing path outcomes.
- [Command injection contract](command-injection.md) and [command analysis rules](../../docs/scan/analysis/command-injection.md) — guard and protection semantics.
- Standards: [code structure](../standards/code-structure.md), [testing](../standards/testing.md), [docs hygiene](../standards/docs-hygiene.md), [spec hygiene](../standards/spec-hygiene.md).
- Code: `internal/parse/path_guards.go`, `path_guard_classify.go`, `python_path_guards.go`, `command_claims.go`, `python_command.go`, `xss_versions.go`.

## 3. Invariants

1. **Provider request bytes change only for candidates whose static guard or version facts change.** `TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests`, every existing parser test and all saved path-traversal exact replays pass without modification; a candidate with no changed guard/version fact keeps its `request_digest`.
2. **Path outcomes are preserved.** The refactor moves Path onto the shared engine without altering guard selection, classification, `covered` dependencies or `ambiguousCallers`; the intended Path deltas are the new JS `process.exit` terminator and the shared reassignment rule (see the change log).
3. **A guard is credited only for the operand it mentions, in the polarity the code gives it.** A condition in the `else` branch is a false-branch fact, never an enforced one; a terminating `if` is credited only when no write to a mentioned name, or to a name a mentioned derived value was computed from, lies between the guard and the call (plain, member, destructuring, tuple, walrus and loop-header writes all count); a guard on a sibling operand, branch or invocation never covers another.
4. **Presence-only tests are never guards** (existing `presenceOnlyCondition` / `pathPresenceOnly` rules are unchanged).
5. **Helper call-site guards use intersection.** With one local call site its guards apply; with several, only guards present at every site apply (same kind, polarity and normalized condition text).
6. **Unknown never becomes known.** A version is established only by a lock entry matching the resolved workspace or by an exact literal manifest pin; ranges, ambiguous lock entries and unparseable files yield no version, and an unparseable workspace manifest stops resolution for its files instead of deferring to an ancestor. No filesystem access leaves the scan root or enters skipped directories.
7. **Root-only repositories using `package.json` and `package-lock.json` resolve exactly as before.** A root that has only a Yarn or pnpm lockfile now also resolves from it.

## 4. Scope

Only `internal/parse/`, `.zazz/`, `docs/analysis/`, and `docs/` pages that describe guard or version behavior may change. Do **not** change `internal/judge`, `internal/analysispacks`, `internal/guidelines`, wire-bundle fields, protocol versions, or CLI flags (E3 owns the wire bump).

| Path | Change | Reason |
| --- | --- | --- |
| `internal/parse/guard_climb.go`, `guard_lang.go` | New | Guard engine (`guardLang.climb`, `derive`, `assignedBetween`, `commonGuardSites`) and its JavaScript/TypeScript and Python adapters (terminator detection, helper call-site discovery) |
| `internal/parse/path_guards.go`, `python_path_guards.go`, `path_guard_classify.go` | Modified | Delegate climb/terminate/derive/assigned-between to the engine; classification stays in Path |
| `internal/parse/command_guards.go`, `command_claims.go`, `claim_assembly.go` | New / Modified | Shared Command guard scan (own controls plus common helper-caller controls), allow-list definition evidence, optional per-family gap resolution hook |
| `internal/parse/python_command.go` | Modified | Add engine terminating/helper guards and allow-list definitions beside the existing flow-derived branch preconditions |
| `internal/parse/package_manifest.go`, `package_lock.go`, `modules.go` | New / Modified | Nearest-ancestor manifest and workspace-lock resolution (npm, Yarn v1/Berry, pnpm), bounded and sandboxed, cached per scan |
| `internal/parse/xss_templates.go` | Modified | `readBounded` generalizes the sandboxed text reader's size bound; template reads keep 2 MiB |
| `internal/parse/xss_versions.go`, `xss_protection.go`, `path_archive.go`, `path_render.go`, `mongoose_query_context.go` | Modified | Resolve versions per source file; dependency evidence anchors to the manifest as before |
| `internal/parse/*_test.go`, `internal/parse/testdata/…` | New/Modified | Contract tests below |
| `docs/analysis/command-injection.md`, `.zazz/project/implementation-plan.md`, `.zazz/specifications/README.md`, `.zazz/docs/zazzles-agent-orientation.md`, [milestone index](analyzer-engine-hardening.md) | Modified | Describe E2 state and polarity/version behavior |

### Explicitly out of scope

- **Validation, SQL/NoSQL claim guards.** The roadmap lists Validation; validation and query claims decide field policy through their own check engine and have no `climb` consumer today. E2 introduces no abstraction without a caller ([code structure §4](../standards/code-structure.md#4-anti-slop-rules)); a later slice reuses `climbGuards` when a consumer exists.
- Guard *adequacy* judgment for Command (remains the model's decision); new Command guard classes; `if/else` alternative-exit enforcement.
- Python `HTTPException` semantics beyond the existing terminator set; other Python or Node version managers; `devDependencies`/`peerDependencies`; Bun/Deno lockfiles.
- Wire format, `compact_wire`, prose catalog and `evidence_version` (E3); Express chain and URL inputs (E4).

## 5. Decisions

### D-1 — One engine, per-language adapter

`guardLang` supplies block/if/function node kinds and the language's terminator predicate; `climbGuards(start, lang, visit)` walks ancestors and reports each site as `guardSite{Kind, Polarity, Cond, Whole, End}`:

- sibling `if` before the call in an enclosing block whose consequence always exits → `terminating_guard`, rejects-when-true;
- enclosing `if` consequence → `enclosing_guard`, enforces-when-true;
- enclosing `if` alternative → `enclosing_guard`, rejects-when-true;
- the climb returns the enclosing function so callers can attribute local helpers.

Path keeps its kinds and attaches its classification to each site. Command maps a rejects-when-true enclosing site to the existing **`branch_false_precondition`** evidence kind (already emitted by the Python flow for "reached when the condition is false"), so the vocabulary is uniform across languages and the `enclosing_guard` meaning stays "enforced when true". No new evidence kind is introduced.

**Rejected:** hand-patching the `else` test inside `commandGuards` — leaves four divergent engines and no derived/reassignment/helper support.

### D-2 — Terminators

JS/TS: `return`, `throw`, and an expression statement `process.exit(...)` when `process` is not shadowed in the module. Python: `return`, `raise`, and a call statement whose verified qualified name is `flask.abort`, `werkzeug.exceptions.abort`, `sys.exit` or `fastapi.HTTPException` (the existing set; bare construction without `raise` is retained for compatibility and not extended). `if/else` always exits only when both branches exit; a block exits when any statement exits.

### D-3 — Python Command: add lexical guards, keep flow guards

The Python flow cannot treat `abort()` as terminating without changing every Python analyzer. Command therefore keeps its flow-derived `branch_precondition` / `branch_false_precondition` guards unchanged and **adds** the engine's `terminating_guard` sites (own function and 1-hop helper call sites) that mention an operand name, are not presence-only, and are not invalidated by an assignment between guard and call. Enclosing sites are not re-added because the flow already records them. Candidates without a new terminating guard are byte-identical to today.

### D-4 — Version resolution order

For a source file `F` and dependency `N`:

1. `pkgDir` = nearest ancestor directory of `F` (up to the scan root) containing `package.json`; `root` if none.
2. **Locks**, walking from `pkgDir` to root, first directory with a usable lock wins: `package-lock.json` or `npm-shrinkwrap.json` (v1 `dependencies`; v2/v3 `packages` keys tried as `<pkgDir>/node_modules/N`, each ancestor `…/node_modules/N`, then `node_modules/N`), then `pnpm-lock.yaml` (importer for `pkgDir`, then root importer), then `yarn.lock` (entry whose specifier equals the nearest declared range; if undeclared, the single version shared by all entries). Ambiguity yields no version.
3. **Manifest**: nearest ancestor `package.json` (from `pkgDir`) whose `dependencies` declares `N`; the declared string is returned as today (callers accept only exact `x.y.z`).

The establishing file (lock or manifest) is the evidence anchor. Lock/manifest files are read through the sandboxed text reader with a 16 MiB bound; larger or unreadable files yield no version.

### D-5 — Allow-list definitions travel with the guard

A guard such as `if cmd not in ALLOWED: abort(403)` cannot be judged without the contents of `ALLOWED`, which usually lives outside the handler. Command attaches the declaration of every never-mutated constant collection (string-literal array/`Set`/object, Python set/list/tuple/dict) that an accepted guard condition tests, as `allowlist_definition` evidence — the kind Path already uses. Non-constant, mutated or non-string collections add nothing.

*Found by the first live run:* the guarded Python route was answered `vulnerable` (probability 0.54 vs 0.33 protected) because the list was invisible; with the definition it is `protected_for_claim`.

### D-6 — Verified terminating guards resolve their own control-flow gaps (Command only)

The Node handler walk records `unsupported_control_flow`, `branch_exit` and `unknown_control_effect` on every `if` statement it does not traverse. When the guard engine has verified that exact statement as a terminating guard with no alternative branch, the Command claim moves those gaps from `coverage_gaps` to `resolved_gaps`. Gaps at any other statement, and Path (whose classified guard facts already carry this meaning), are unchanged. Entry-level gaps recorded on the shared invocation context are not rewritten.

## 6. Acceptance criteria

- **AC1 — JS Command polarity.** For `if (isSafe(cmd)) { exec(cmd) } else { exec(cmd) }` the consequence call carries `enclosing_guard` and the alternative call carries `branch_false_precondition` over the same condition and never `enclosing_guard`; `else if` chains attribute each condition to the correct branch; a call inside the condition itself has none. Verified by `TestCommandGuardPolarityJS`.
- **AC2 — JS Command derived values and reassignment.** `const clean = cmd.trim(); if (!ALLOWED.has(clean)) return; exec(cmd)` credits the terminating guard; reassigning `cmd` between guard and call, or a guard on a different variable, does not; presence-only tests never count. Verified by `TestCommandGuardDerivedAndReassigned`.
- **AC3 — Python Command terminators.** `if cmd not in ALLOWED: abort(403)` / `sys.exit(1)` before `os.system`/`subprocess.run` yields a `terminating_guard` on the use and `Protection == "guarded"`; an unrelated-variable guard, an unverified local `abort`, a bare non-exiting call, a presence-only test, or an intervening reassignment yields `raw`; existing Python command fixtures keep identical facts. Verified by `TestPythonCommandTerminatingGuards`.
- **AC4 — Helper call sites.** A guard in the single caller of a local JS or Python helper that sinks the operand is credited; with two callers it is credited only when both carry the same guard. Verified by `TestCommandHelperCallerGuards` (JS and Python subtests).
- **AC5 — `process.exit`.** A JS terminating `if (bad) { process.exit(1) }` is a terminating guard for Command and Path; a shadowed `process` is not. Verified by `TestGuardTerminators`.
- **AC6 — Path is preserved.** All existing Path parser tests, `TestOutboundPredecessorRequests`, `TestCommandPredecessorRequests` and the 360 saved exact replays pass unchanged; engine unit tests cover each `guardSite` kind. Verified by `TestGuardClimbSites` and the existing suites.
- **AC7 — Nearest-ancestor manifests.** `packages/api/package.json` pinning `marked` `0.3.5` and the root pinning `0.3.6` resolve `0.3.5` for a file under `packages/api` and `0.3.6` for a file under `packages/web`; a file under a workspace that does not declare the dependency inherits the nearest declaring ancestor; ranges never produce an exact version. Verified by `TestPackageVersionNearestManifest`.
- **AC8 — Workspace lockfiles.** npm v3 workspace lock (`packages/api/node_modules/N` preferred over hoisted `node_modules/N`), npm v1 `dependencies`, Yarn v1 (specifier-matched; ambiguous entries unresolved) and pnpm importers resolve as D-4. Verified by `TestPackageVersionWorkspaceLocks`.
- **AC9 — Resolver safety.** Missing, oversized, malformed or symlink-escaping manifests and locks yield no version; skipped directories are never read; root-only repositories resolve exactly as before. Verified by `TestPackageVersionBoundsAndRootCompatibility`.
- **AC10 — Consumers use the resolved workspace version.** A workspace-pinned vulnerable `marked`/`sanitize-html` marks the sanitizer ineffective only for that workspace; a workspace-pinned `adm-zip` `0.4.7` is `vulnerable_version` and `0.5.0` is `fixed_version`; a workspace-pinned `mongoose` `4.2.4` selects `mongoose-model-query-v2`; the manifest/lock evidence names the establishing file. Verified by `TestWorkspaceVersionConsumers`.
- **AC10a — Allow-list definitions.** A guard testing a never-mutated constant collection yields exactly one `allowlist_definition` carrying the collection's declaration (JavaScript `Set`/array/object, Python set/list/tuple/dict), on both the terminating and flow-derived Python guards; mutated or non-literal collections yield none. Verified by `TestCommandGuardAllowlistDefinitions`.
- **AC10b — Guarded control-flow gaps.** For a Node command candidate whose terminating guard is an `if` without an alternative, its `unsupported_control_flow`/`branch_exit`/`unknown_control_effect` gaps at that statement are in `resolved_gaps` and absent from `coverage_gaps`; an `if` with an `else`, or a condition that is not a verified guard, keeps them as coverage. Verified by `TestCommandGuardResolvesItsControlFlowGaps`.
- **AC11 — Build, vet, format, docs, race.** `go build ./...`, `go vet ./...`, `gofmt -l cmd internal` (empty), `go test -race ./... -count=1`, `git diff --check` and `.zazz/ephemeral/path-tools/check-docs.py` (or the documented doc check) pass; no `AC-`, `D-`, `OQ-`, `SPEC` or `INVARIANT` tokens appear in Go source or tests.
- **AC12 — Live confirmation.** With a small explicit request count on the owner-selected primary model, representative guarded/unguarded Command and Path candidates and a workspace-version XSS/Path fixture receive verdicts consistent with the source facts (guarded → protected or review with the guard cited; unguarded → vulnerable). Outcomes, request counts and model recorded in the run log. No fallback model; no paid call in any automated test.

## 7. Test strategy

- Engine: table-driven `guardSite` tests over JS and Python snippets (consequence, alternative, `else if`, sibling terminator, nested, helper), parsed with the real adapters.
- Command: fixture-per-case source written to temp roots with the existing `writeSource`/`Analyze` helpers; assert evidence kinds, `Protection`, controls and unchanged facts for cases without new guards.
- Manifest: temp-root trees for each lock format and bounds case; consumer tests assert the contract/assessment change end to end.
- Regression: predecessor request byte tests, existing parser suites, and offline replay of the saved path decisions against freshly parsed uses (local sample apps, never committed).

## 8. TDD entry point and sequence

```bash
GOFLAGS=-buildvcs=false go test ./internal/parse -run 'Test(CommandGuardPolarityJS|CommandGuardDerivedAndReassigned|PythonCommandTerminatingGuards|PackageVersionNearestManifest)' -count=1
```

1. **Phase 1 — tests red:** add the AC1–AC5 and AC7–AC10 tests; confirm they fail for the stated reason.
2. **Phase 2 — engine:** extract `guard_climb.go`; move Path onto it with no test edits; confirm the full `internal/parse` suite is unchanged and green.
3. **Phase 3 — Command:** JS then Python Command on the engine; green AC1–AC5.
4. **Phase 4 — manifests:** resolver, locks, consumer wiring; green AC7–AC10.
5. **Phase 5 — verification:** full race suite, predecessor tests, saved replays, docs; independent read-only verifier.
6. **Phase 6 — live confirmation:** AC12 within the request cap; loop on findings.

## 9. Halt conditions

Stop and surface to the owner if (1) a predecessor request test or a saved path replay changes bytes, (2) Path guard selection changes on any existing test, (3) the diff touches a file outside §4, or (4) a live run needs more than the declared request cap.

## 10. Definition of done

- [ ] AC1–AC11 (including AC10a/AC10b) tests green; predecessor tests and saved replays unchanged.
- [ ] Scope verified against §4; no working-doc tokens in Go source or tests.
- [ ] Live confirmation (AC12) recorded; any defect it exposes fixed, re-tested and re-run.
- [ ] Independent read-only review of AC1–AC12 and the diff scope (a fresh-context verifier agent when the owner authorizes one).
- [ ] Milestone index, plan, README index and orientation describe E2 as implemented in this worktree; E3/E4 remain planned for their own worktrees.

## 11. Open questions

None. Owner decisions captured at kickoff (2026-11-14): E2 continues in `analyzer-engine-hardening` alongside E1; E3 and E4 move to new worktrees; unpaid tests first, then a small paid live confirmation, looping until findings are as expected.

## 12. Implementation and review change log

### 2026-11-14 — Implementation findings folded into the contract

**Source.** Differential and live verification during implementation.

**Changed Sections.** §4 scope table, D-5 and D-6 (new), AC10a and AC10b (new), AC12 outcome in the run log.

**Rationale.** (1) A saved-replay run showed that anchoring `dependency_declaration` evidence to the lockfile instead of `package.json` changed candidate identities; evidence now anchors to the manifest exactly as before, and only a lock-only repository anchors to the lockfile. (2) The live run answered a correctly guarded Python route `vulnerable` because the allow-list contents were not in evidence (D-5). (3) The same run showed that Node control-flow gaps recorded on the guard's own `if` statement remained as coverage after the guard was verified (D-6).

**Summary.** One reassignment rule is shared by both languages: an assignment that encloses the call (`x = run(x)`) evaluates the call first and does not invalidate the guard (previously JavaScript Path treated it as invalidating; no existing test or saved replay depends on it). The sandboxed text reader gained a size parameter so lockfiles above 2 MiB resolve.

**Verification Impact.** No request digest changes across 3,795 parsed candidates in the sample applications and parser fixtures, each scanned as its own root; 360/360 saved path replays unchanged; new tests as listed. Scanning the parser fixture directories as single roots does differ from `HEAD`, as expected: nested manifests are now read, so some `dependency_declaration` anchors move to the nested `package.json`, nested workspaces gain hbs candidates, and guard gaps are resolved.

### 2026-11-14 — Independent verifier findings

**Source.** Fresh-context read-only verifier report.

**Changed Sections.** §3 invariants 2, 3, 6 and 7; D-1 (write forms).

**Rationale.** The verifier demonstrated four defects, each now fixed with a regression test: (1) a guard on a derived value stayed credited when the root value was rewritten, and member, destructuring, tuple, walrus and loop-header writes were not seen as writes; (2) a malformed workspace `package.json` fell through to an ancestor manifest; (3) the Yarn parser could replace an entry's version with a dependency line starting `version`; (4) Python allow-list definitions were collected from a guard's whole `if` statement instead of its test. It also restored the pre-E2 regex-capture scope for top-level calls and corrected two invariant statements that were not literally true.

**Summary.** The write-form and derived-source rules live in the shared engine, so Path also sees them; no saved path replay or sample digest changed.

**Verification Impact.** `TestCommandGuardInvalidatedByEveryWriteForm` and two new resolver subtests.
