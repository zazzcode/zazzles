# Shared Node inputs and phase-2 file APIs (E4)

**Status:** Merged into `stage` via https://github.com/zazzcode/zazzles/pull/15 (`eafabcc`, 2026-11-15)
**Feature branch (historical):** `node-inputs-and-file-apis` (base `6e815ec`)
**Feature:** Shared Express middleware-chain / URL / upload acquisition, phase-2 file APIs, and Node core `http`/`https` SSRF
**Milestone:** Analyzer engine hardening — Slice E4
**Deliverable:** Executable E4 contract
**Project Owner / Deliverable Owner:** Human owner
**Delivery topology:** Completed as one feature branch and one PR into `stage`
**Integration branch:** `stage`
**Drafted:** 2026-11-15
**Shared run log:** `.zazz/ephemeral/shared-node-inputs-and-file-apis-run-log.md` (historical, gitignored)
**Companion skills:** `spec-driven`, `doc-check`

---

## 1. Capability

Promote Express non-final middleware-chain handlers and Node URL/upload request members into the
shared HTTP acquisition pipeline so every assessed Node family can consume the same stage and input
facts; retire path-only duplicate acquisition once parity is proved; add verified phase-2 file and
archive contracts (Node `fs.open`/`copyFile`/`rename` and Python `FileResponse`/`UploadFile`/
`shutil`/`tarfile.extractall`); close Node core `http`/`https` SSRF misses; and replace affected
Node.js GitHub sample presentations from a capped `gpt-6-luna` rebuild.

## 2. Required reading

- [E4 handoff](../../../HANDOFF-E4-shared-node-inputs-and-file-apis.md) (container root) — owner
  boundaries, open items, and mandatory sample replacement.
- [Hardening milestone roadmap](analyzer-engine-hardening.md#0-capability--milestone-roadmap) — E4 row.
- [Hardening proposal](../project/analyzer-hardening-and-wire-efficiency-proposal.md) — T2-5, T2-6.
- [Evidence and claims](../architecture/evidence-and-claims.md#transport-neutral-input-and-value-evidence),
  [analysis packs](../architecture/analysis-packs.md#node-input-interpretation-and-generic-sink-contracts),
  [request size](../architecture/request-size-and-evidence-relevance.md).
- Product rules: [node inputs](../../docs/scan/analysis/node-inputs.md),
  [path traversal](../../docs/scan/analysis/path-traversal.md),
  [SSRF](../../docs/scan/analysis/ssrf.md),
  [command injection](../../docs/scan/analysis/command-injection.md),
  [XSS](../../docs/scan/analysis/xss.md),
  [sensitive logging](../../docs/scan/analysis/sensitive-data-logging.md),
  [calibration](../../docs/scan/analysis/calibration.md).
- Prior contracts: [wire v7](wire-bundle-v7.md), [JavaScript conditional flow](javascript-if-flow.md),
  [path traversal](path-traversal.md), [assessment coverage](analyzer-assessment-coverage.md).
- [Vulnerable samples](../project/vulnerable-sample-apps.md),
  [sample reference policy](../../docs/samples/reference-policy.md),
  [contributor checks](../../docs/contributing.md).
- Standards: [code structure](../standards/code-structure.md), [testing](../standards/testing.md),
  [docs hygiene](../standards/docs-hygiene.md), [spec hygiene](../standards/spec-hygiene.md),
  [PR process](../standards/pr-process.md). Verify `.zazz/standards/index.yaml` before edits.

## 3. Invariants

1. **Source-backed discovery never assigns verdicts.** Names such as auth/upload/validate never prove
   semantics. Unknown, reassigned, shadowed or dynamic middleware remains explicitly unresolved.
2. **Stage isolation.** Preserve registration order and the invocation identity of each Express
   stage. Earlier middleware controls do not automatically protect later stages or sibling
   registrations.
3. **Acquisition distinctions.** Distinguish URL path, complete URL, original/mounted path, query,
   body, upload filename, file bytes and server-generated storage names. Uploaded content is not a
   filename/path; a filename is not automatically a destination URL or executable operand.
4. **Dual-path independence.** For copy/rename/shutil/move and similar operations, source and
   destination are independent path operands. A protected source never lends containment to a
   request-controlled destination.
5. **Open descriptors are not paths.** An open file descriptor / file object is not path text.
   `FileResponse` path is distinct from response headers/content.
6. **Archive policy is versioned.** Do not assume a `tarfile` filter default across Python versions.
   Record exact filter/runtime assumptions; never invent symlink/race/TOCTOU safety.
7. **No provider fallback.** Paid runs use only the owner's selected OpenAI `gpt-6-luna` key and
   explicit caps. Never print credentials or pass keys in CLI arguments.
8. **Exact replay.** Fresh completed decisions must replay against freshly parsed evidence with exact
   body, digest, component and protocol matching. Do not copy old answers onto changed evidence.
9. **Sample cleanliness.** Targets stay read-only at documented pins. Public sample roots stay
   portable (no developer home paths or credentials).

## 4. Scope and review shape

### Approved review shape

Completed: feature branch `node-inputs-and-file-apis` merged to `stage` via PR #15.

### Strict scope directories

`internal/parse/`, `internal/analysis/`, `internal/analysispacks/`, `internal/guidelines/`,
`internal/judge/`, `internal/report/` (only if presentation text must name new contracts),
`docs/`, `README.md`, `.zazz/`, and Node.js sample artifacts under `docs/samples/` for the apps
rebuilt in this deliverable.

### In scope

| Area | Outcome |
| --- | --- |
| A. Shared Express middleware-chain entries | Source-resolved nonfinal route handlers enter the common HTTP pipeline for all assessed families |
| B. Shared Node URL/upload facts | `req.path`/`url`/`originalUrl`/`baseUrl` and verified `req.file`/`req.files` projections become generic acquisition facts under `source.node-input-v2` |
| C. Retire path-only duplication | After candidate/source/operand/guard parity, remove path-only second passes, unused flags and redundant handler passes |
| D. Phase-2 file APIs | Node `fs.open`/`copyFile`/`rename` (and promise forms); FastAPI/Starlette `FileResponse` and verified `UploadFile.filename`; Python `shutil` copy/move forms; `tarfile.extractall` with explicit filter/runtime facts |
| E. Node core HTTP SSRF | Verified `http`/`https` (`node:http`/`node:https`) `get`/`request` destination contracts; vuln-demo-app `/fetch` judged |
| Open items | Juice Shop `uploadToMemory.single('file')` remains an unresolved factory witness unless source-proved; `require` destructuring for winston/Sequelize; traverse `switch` cases, labeled non-block statements and brace-less loop bodies |
| Docs / samples | Node.js sample rebuild + GitHub replacement; root README and implementation-plan updates written for the post-merge state |

### Out of scope

Blanket framework/package safety lists; Windows path/shell guarantees; whole-program SSA rewrite;
dynamic import execution; target remediation or dependency installation; runtime exploitation;
DNS/filesystem-state inference; automatic provider fallback; silent evidence truncation; absorbing a
general Python `InputFacts` project or new Python NoSQL solely because shared inputs would help;
unrelated registry cleanup; paid Python sample rebuild (Python public samples stay at their current
judgments unless a Python request byte-changes and the owner expands the cap).

## 5. Decisions

### D1 — Shared stage entries reuse the path-chain sibling pattern

**Decision.** Source-resolved nonfinal Express handlers become distinct invocation contexts (sibling
entry/invocation records keyed by registration stage), not borrowed protection on the final handler.
**Why.** Stage isolation is an invariant; path-chain already proved this identity shape for Zip Slip.
**Rejected alternative.** Annotating only `DispatchBinding.Stage` on one shared entry — rejected
because existing claim assembly scopes chain evidence by entry ID and would mix predecessor sets.

### D2 — Capability ID `source.node-input-v2` without forcing InputFacts schema v2

**Decision.** Select `source.node-input-v2` (and keep path/SSRF twins aligned) while retaining
`InputFacts.Version = 1` unless a field truly cannot be represented. Extend origins with URL/upload
classifications and keep compatibility tests explicit.
**Why.** The handoff forbids assuming a schema bump from a capability rename alone.
**Rejected alternative.** Silent reuse of `source.node-input-v1` bytes while changing origins —
rejected because digest/request accounting must show the intentional acquisition change.

### D3 — URL/upload members are always-on shared sources for Node HTTP flows

**Decision.** Promote URL and verified upload members into the shared request-field model for all
Node families; remove the path-only second pass after offline parity on every standard app/fixture.
**Why.** Reflected URL XSS, middleware SQL/command sinks and upload-filename path flows need one
acquisition path.
**Rejected alternative.** Keep `urlSources`/`pathOnly` forever as family flags — rejected by
deliverable C.

### D4 — Upload adapters stay source-proved; Juice Shop memory upload stays a witness

**Decision.** Verify multer memory/disk constructors from immutable bindings, literal field names and
storage options. Custom callbacks/stores/dynamic options remain gaps. Do not hardcode a Juice Shop
exception or package-name allowlist to erase `uploadToMemory.single('file')` uncertainty.
**Why.** The handoff forbids erasing that uncertainty by name.

### D5 — Paid matrix is Node.js-scoped for GitHub replacement under a 350-request Luna cap

**Decision.** Run offline checks on all eight standard apps. Paid `gpt-6-luna` evaluation (cap 350)
covers E4 calibration plus all analyzers on the four Node.js apps (juice-shop, nodejs-goof,
vulnerable-typescript-app, vuln-demo-app). Replace only those apps' affected GitHub sample artifacts.
Python phase-2 contracts ship with offline fixtures; Python public samples are not rebuilt unless
their requests change and a separate cap is approved.
**Why.** Owner direction for this unattended run; E3 already refreshed JS samples and left Python
byte-identical.
**Rejected alternative.** Silent claim that E4 is complete for all eight published samples — rejected.

### D6 — Archive extractall records effective filter/runtime instead of assuming defaults

**Decision.** Model `tarfile.extractall` with verified binding and explicit `filter=` / extraction_filter
facts. Treat missing filter on pre-3.14 semantics as unresolved policy rather than inventing safety.
**Why.** Official docs: filter added in 3.12; default became `'data'` only in 3.14.
**Rejected alternative.** Assume `filter='data'` for every Python — rejected by version variance.

## 6. Agent implementation rules

- Work only in `node-inputs-and-file-apis`. Verify `pwd`, branch, clean status and base before edits.
- Commit locally in logical green commits when a slice is verified; do not push or open a PR unless
  the owner asks. Never merge to `stage`.
- Use `GOFLAGS=-buildvcs=false`, Go from `go.mod`, and a C compiler. Format only changed Go files.
- Append execution evidence to the shared run log. Promote durable outcomes to owning docs.
- Halt when: an open question blocks coding; the same test fails three times without a clear fix;
  diff escapes §4 scope; a standard not prescribed matches the file list; paid budget would be
  exceeded; target pins are dirty; or exact replay fails after a claimed fresh judgment.
- Independent read-only QA runs after offline gates and before declaring paid readiness complete.

## 7. Acceptance criteria

- **AC1 — Shared middleware stages.** Fixtures covering local/imported/wrapped/reassigned middleware,
  stage termination vs `next()` forwarding, sink-before-next, and multiple alternatives produce
  per-stage candidates for SQL, command, path, XSS, logging, NoSQL and SSRF where sinks exist.
  Unknown/dynamic middleware remains unresolved. Verified by new parse tests under
  `internal/parse/*chain*` / `*middleware*` and family regressions.
- **AC2 — Shared URL/upload facts.** `req.path`/`url`/`originalUrl`/`baseUrl` and verified
  `req.file`/`req.files` projections appear as shared input origins with distinct filename vs content
  semantics. Capability selection uses `source.node-input-v2`. Verified by parse + analysispacks tests.
- **AC3 — Path parity then retirement.** Offline digest audit over the eight standard apps and parser
  fixtures explains every candidate add/remove vs the E3 baseline. After parity, `pathOnly`/
  `urlSources` second-pass bridges and unused flags are gone; path traversal/archive/render contracts
  remain. Verified by digest diff + grep for retired symbols.
- **AC4 — Phase-2 file APIs.** Positive/negative fixtures for Node `open`/`copyFile`/`rename`
  (callback and promise), Starlette/FastAPI `FileResponse`, verified `UploadFile.filename`,
  `shutil.copy`/`copy2`/`copyfile`/`move`, and `tarfile.extractall` with filter present/absent/
  version uncertainty. Dual-path independence holds. Verified by path parse/judge tests.
- **AC5 — Node core HTTP SSRF.** `http`/`https` get/request forms with URL string, `URL` object,
  options object and `(url, options, cb)` are verified; shadowed/dynamic/Agent/options-spread cases
  stay gaps. vuln-demo-app `/fetch` is no longer “Not covered”. Verified by SSRF fixtures + sample table.
- **AC6 — Flow and binding holes.** `switch` case bodies, labeled non-block statements and brace-less
  loop bodies are traversed; `require` destructuring binds winston `createLogger` and Sequelize.
  Paired regressions included. Verified by flow/logging/SQL/NoSQL tests.
- **AC7 — Offline gates.** `go test -race ./... -count=1`, `go vet ./...`, `gofmt -l` on changed
  files, `git diff --check`, and doc checks pass. Independent QA returns PASS or recorded fixes.
- **AC8 — Paid Node rebuild.** Under the 350-request `gpt-6-luna` cap: E4 calibration + all analyzers
  on the four Node apps complete without provider fallback; every fresh completed decision replays
  exactly; failures/limits are recorded honestly.
- **AC9 — GitHub Node samples and roadmap docs.** Affected
  `docs/samples/{juice-shop,nodejs-goof,vulnerable-typescript-app}` (and vuln-demo-app tables),
  root README, `.zazz/project/implementation-plan.md`, evaluation/completed-work docs and stale
  “draft PR #14” wording reflect merged E3 and completed E4 Node scope. HTML/SARIF regenerated from
  canonical JSON. Counts/privacy/attribution checks pass.

## 8. Test strategy

- Acquisition/stage tables first (middleware order, termination, wrappers, reassignment).
- URL/upload origin tables (path vs originalUrl vs filename vs buffer).
- Binding tables (ESM/CJS/`node:`/destructure/shadow/fake module).
- Dual-path and archive-filter matrices.
- SSRF destination-slot matrices (raw URL, fixed host + request path, allow-list, prefix-only).
- Flow hole fixtures beside existing conditional-flow suites.
- Offline digest inventory comparing E3 baseline
  `.zazz/ephemeral/e3-baseline-digests.json` to post-E4 digests with explained deltas.
- Paid calibration keeps the S4 guarded/unguarded sibling `exec` pair.
- No low-signal “mock was called” tests.

## 9. TDD entry point and execution sequence

### TDD entry point

```bash
GOFLAGS=-buildvcs=false go test ./internal/parse -run 'Test(SharedExpressChain|SharedNodeURLUpload|RequireDestructuring|SwitchAndLoopBodies)' -count=1
```

### Phases

1. Author this contract, initialize the run log, fix stale E3 “draft PR #14” wording, capture E3 baseline digests.
2. Flow holes + `require` destructuring bindings with paired tests.
3. Shared middleware-chain analysis (all families) + shared URL/upload facts + `source.node-input-v2`.
4. Prove path parity; retire path-only passes/flags.
5. Phase-2 file API contracts and Node `http`/`https` SSRF.
6. Offline race/vet/format/doc checks, digest delta report, independent QA.
7. Paid calibration + four Node apps (all analyzers) within 350 requests; exact replay.
8. Replace Node GitHub samples; update README/implementation-plan/evaluation docs; commit locally.

## 10. Definition of done

- [x] All §2 reading and standards-index verification recorded.
- [x] AC1–AC9 evidenced in the run log with commands/outcomes.
- [x] Baseline delta list explained; no unexplained frozen-digest updates.
- [x] Paid ledger under `_test-findings/e4/` with revisions, caps and token accounting.
- [x] Node samples/README/plan docs updated for post-merge state.
- [x] Independent QA aborted on model-limit (owner continued under Auto); offline race/vet/gofmt green.
- [x] Merged to `stage` via PR #15 (`eafabcc`).

## 11. Open questions

None blocking implementation for this unattended run. Owner already selected:

- full Deliverable D in code with Node-only paid sample updates;
- `gpt-6-luna` cap 350, all analyzers on four Node apps;
- commit locally only (no push/PR yet).

## 12. Run log protocol

Append-only `.zazz/ephemeral/shared-node-inputs-and-file-apis-run-log.md` with standards verification,
phase completions, digest deltas, QA findings, paid ledger pointers and deviations.

## 13. Agent implementation prompt

```text
Continue E4 in worktree node-inputs-and-file-apis on branch node-inputs-and-file-apis (base 6e815ec).
Implement `.zazz/specifications/shared-node-inputs-and-file-apis.md` using run log
`.zazz/ephemeral/shared-node-inputs-and-file-apis-run-log.md`. Skills: spec-driven, doc-check.
Never print .env. Paid authorization: gpt-6-luna, global cap 350, Node apps only for sample replacement.
Commit locally when slices are green; do not push/PR/merge unless asked.
```

## 14. Implementation and review change log

### 2026-11-15 — Initial E4 contract

**Source.** Owner unattended implementation request after E3 merge, with Node-scoped paid sample
updates, full Deliverable D offline scope, 350-request Luna cap and local commits only.

**Changed Sections.** Entire document authored.

**Rationale.** Handoff required a tracked bounded contract before production changes.

**Summary.** Encodes deliverables A–E, open items 1–3, Node-scoped evaluation/sample replacement,
and post-merge README/plan updates.

**Verification Impact.** Baseline digests captured before coding; AC1–AC9 tests and paid ledger required.
