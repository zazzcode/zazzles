# Bounded dynamic HTTP registration and dispatch — deliverable contract

Worktree / branch: `common-entry-and-dispatch`. Feature: common entry/dispatch.
Milestone deliverable: 5 of 8. Project and Deliverable Owner: Michael.
Drafted: 2026-11-03. Execution tracking: deliverable-specific ignored local run log only.
Coordination: one Contributor Agent working in the assigned worktree; no delegation required.
Proposed review shape: one milestone draft PR into `stage`, human review/merge.
The user invoked §12 on 2026-11-04, authorizing D5 implementation, verification, commit and
feature-branch push. During implementation the user also authorized full real VulnPy and Juice Shop
Decision-mode evaluations with gpt-6-luna, scanner fixes discovered by those runs, and prompt
deduplication/comment filtering. No new worktree, PR, merge, integration push or D6 is authorized.

## 0. Capability

Resolve finite Express registrations/factories and the bounded generated Flask/FastAPI routes in the pinned VulnPy Python sample through shared dispatch/context records. Retain generation provenance, closure/callback bindings and unresolved alternatives; produce inspectable source-to-sink traces and existing-family findings from a real source-only scan.

## 1. Required reading

- [AGENTS](../../../AGENTS.md#authorization-and-delivery) and
  [orientation](../../docs/zazzles-agent-orientation.md#documentation-map).
- [Milestone index](common-entry-dispatch.md#delivery-order) and [Design §§2–5](../../architecture/common-entry-dispatch.md#2-semantic-records-and-cardinality) and [§8](../../architecture/common-entry-dispatch.md#8-implemented-bounded-framework-subsets).
- Dependency: 03-reporting-selectors; execute after 04-browser-events to keep one ordered lane. [Previous deliverable](common-entry-dispatch-04-browser-events.md)
- [VulnPy sample](../../../docs/samples/vulnpy/README.md), [source reference](../../../docs/samples/vulnpy/reference.md),
  [pinned hashes](../../../docs/samples/vulnpy/source-hashes.json), [case inventory](../../../docs/samples/vulnpy/cases.json)
  and [detection guide](../../evaluation/vulnpy-detection-guide.md). Read the actual generation,
  trigger selection, SQL callback and response code identified in §7 before editing.
- [Database injection](../../../docs/scan/analysis/database-injection.md) and
  [XSS semantics](../../../docs/scan/analysis/xss.md); registration/trace recovery does not change claim policy.
- [Execution discipline](../../docs/agent-execution-discipline.md#verification-discipline)
  and repository `.agents/skills/spec-driven/SKILL.md` for implementation.
- [Code structure §§1–6](../../standards/code-structure.md#1-package-layout),
  [testing §§2–9](../../standards/testing.md#2-test-kinds),
  [docs hygiene](../../standards/docs-hygiene.md#cross-document-linking),
  [spec hygiene](../../standards/spec-hygiene.md#acceptance-criteria-are-testable-from-the-criterion-alone),
  [PR process](../../standards/pr-process.md) at publication.
  Recheck [standards index](../../standards/index.yaml) against actual changed paths.
- Read the source files in §3 and adjacent existing tests before editing.
  Preserve current [analysis semantics](../../../docs/scan/analysis/README.md).

## 2. Invariants

- Existing supported HTTP and browser analyses MUST retain evidence, claim status and coverage semantics.
- Entry kind, dispatch mechanism, transport and implementation language MUST remain independent.
- Controls and input bindings MUST NOT cross invocation contexts; calls alone MUST NOT establish value flow.
- Unknown bindings and reached limits MUST remain explicit; a missing candidate MUST NOT imply protection.
- Source snapshots and historical raw answers MUST remain intact; changed requests MUST NOT reuse old answers.
- Only final scoped protection receives green styling. No entry-wide safety or runtime exploit claim is implied.

## 3. Scope and review shape

All edits MUST remain inside the assigned feature worktree. Allowed implementation paths
for this slice are listed below; focused adjacent consumers in the same named packages
may be updated where necessary for the same contract, with exact paths recorded in the
run log. New packages, framework subsets or public behavior beyond this contract require
an in-place contract revision. Unrelated cleanup is outside scope.

| Path | New / modified | Purpose |
| --- | --- | --- |
| `internal/parse/dynamic_registrations.go, dynamic_registrations_test.go` | new | Finite registration expansion |
| `internal/parse/analysis.go, route_analysis.go, router_mounts.go, helper_resolution.go` | modified | Verified registration/target/closure integration |
| `internal/parse/testdata/typescript/dynamic-dispatch/; internal/parse/testdata/javascript/dynamic-dispatch/` | new | Finite generation and guard controls |
| `internal/parse/python_dynamic_registrations.go, python_dynamic_registrations_test.go` | new | Bounded source-derived Python registry, factory registration and trace acceptance |
| `internal/parse/python_routes.go, python_modules.go, python_flow.go, python_calls.go, python_values.go, python_sql.go, python_dbapi.go, entry_context.go` | modified where necessary | Flask/FastAPI generation, finite trigger selection, captured values and actual callback/cursor flow |
| `internal/parse/testdata/python/dynamic-vulnpy/` | new | Licensed source-only pinned excerpts and independent raw/bound/unknown controls |
| `internal/judge/*_test.go; internal/report/*_test.go` | modified/new as needed | Python trace/policy/report pipeline with local stubs only |
| `docs/analysis/xss.md, database-injection.md; docs/python-support.md, decision-models.md; .zazz/evaluation/common-entry-dispatch-results.md` | modified where necessary | Implemented Python subset, actual sample trace evidence and remaining gaps |
| `internal/analysis/analysis.go, entries.go, entry_validation.go; internal/parse/model_source.go, model_source_test.go` | modified/new where necessary | Source-backed constant closures and original-preserving model source projection |
| `internal/judge/entry_context.go, bundle.go, client.go, source_excerpts.go, compact_bundle.go; adjacent focused tests` | modified/new | Versioned closure evidence and lossless prompt deduplication with replay verification |
| `internal/report/entries.go; cmd/scan/analysis_test.go` | modified | Generation provenance and real pipeline checks |
| `docs/samples/vulnpy/README.md, reference.md; .zazz/evaluation/vulnpy-detection-guide.md` | modified | User-requested source-inspected confirmation table; historical baseline retained |
| `internal/parse/testdata/string-flow/analysis.json, checked-analysis.json; internal/report/scoped_guidance.go` | modified | Reviewed capability wording and correct raw-response guidance |
| `.zazz/specifications/scan/common-entry-dispatch-05-dynamic-http.md` | modified if needed | Contract decisions and evidence links |
| `.zazz/ephemeral/common-entry-dispatch-05-dynamic-http-run-log.md` | ignored local | Append-only execution evidence |

One milestone PR preserves a single canonical migration and removes transitional state
before human integration. Each deliverable remains a distinct review/evidence unit in
that PR. Do not create additional worktrees or branches merely to represent checkpoints.
This proposed review shape remains reviewable by the user before implementation.

Exclusions: new vulnerability families, authorization engine, queues/jobs/CLI entry adapters,
new target languages, full IR, graph database, automatic cache, independent LLM reviewer,
unassigned paid calibration, application execution, sample remediation and unrelated formatting.

The Python addition is limited to existing Flask/Blueprint and FastAPI/APIRouter support,
finite source-backed registry construction/selection and the closure/callback transfers needed
by §7. It adds no target language or vulnerability family. Other VulnPy framework adapters,
arbitrary Python execution/reflection and unrelated Jinja-environment hardening remain outside D5.
The original sample checkout, saved reports, source hashes, case labels and raw model answers
MUST remain unchanged. New results belong in fresh ignored report folders.

## 4. Decisions

**Decision 1.** Expand literal finite tables and direct local factories because this yields source-reviewed bindings without executing target code.

**Decision 2.** Record generated registration origin separately from target resolution and security status because a generated route can be resolved, protected, unsafe or unknown.

**Decision 3.** Report unexpanded remainder at deterministic limits because truncation must not become an all-path protection claim.

**Decision 4.** Use the real pinned VulnPy checkout as an acceptance target, because literal-table
fixtures alone cannot prove recovery of its generated registration, imported trigger lookup and
nested SQLite callback. Statically derive finite members from selected local source; never import
or execute the target, hardcode its endpoint/function map in detector code, or consume evaluation
case labels as analysis input. Unsupported registry mutation, shadowing or external members retain gaps.

## 5. Agent implementation rules

Use the current assigned worktree as command cwd; verify path/branch/status before edits.
Explicit later implementation instructions authorize the requested slice under AGENTS;
do not request a separate ownership ceremony. Follow the milestone usage-window policy.
Record exact modified paths and compare the slice diff against its recorded start revision.

Keep coherent green recovery points. Commit/push only when authorized by the active user
request; verify the `zazzcode` identity/authentication before publication. Never merge,
push to `stage`/`main`, or create a release. Draft PRs target `stage` when publication is requested.
Live keys are permitted only for the user-authorized full VulnPy/Juice Shop evaluations below. Do not execute/install dependencies in target applications.

Halt dependent work for missing required reference data, a conflicting user edit, unresolved
scope/public-contract choice, destructive recovery, or an invariant violation. Investigate
routine failures autonomously; after three repeated failures without progress record the
blocker and surface it. Do not weaken tests or drop mandatory coverage to fit a window.

## 6. Acceptance criteria

- **AC1 — TestDynamicHTTPRegistrations.** A literal table/for-of and direct local literal-argument factory expose the expected entries, original spans, row/call/closure provenance and finite target alternatives. Verified by `TestDynamicHTTPRegistrations` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC2 — TestDynamicHTTPContextIsolation.** Shared function/factory body exposed with different arguments or controls retains separate contexts and correct unsafe/protected/unknown results through real candidate and report paths. Verified by `TestDynamicHTTPContextIsolation` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC3 — TestDynamicHTTPBounds.** Runtime registration data, mutation, recursive factories, unknown wrappers, unbound/fake receivers and over-limit expansions preserve gaps; known alternatives remain visible, zero-use unknown registrations remain reportable, repeated scans are deterministic. Include Python registry/member mutation, shadowed lookup, unresolved callbacks and reached-limit controls; none may acquire a fabricated binding or protected claim. Verified by `TestDynamicHTTPBounds` in the packages named in §7; new test names are planned contracts, not existing results.
- **AC4 — TestDynamicPythonVulnPyTraces.** A fresh source-only scan of **VulnPy at `~/Dev/vulnpy`**, pinned to `b81885e58283a3449b578d20c20557aff637e5ea`, MUST expose the generated Flask GET/POST and FastAPI GET SQL/XSS routes in the §7 matrix, retain their own entry/context identities, and build the actual request → generated handler/closure → selected trigger → callback/cursor → SQL sink or raw HTML response trace. JSON/HTML/SARIF MUST show SQL-construction and raw-XSS poor-practice findings under those dynamic routes using existing classification, preserve supported pre-existing static routes/uses, and retain explicit unsupported/zero-use gaps. A registered path or call graph without value/slot witnesses does not pass. Verified by `TestDynamicPythonVulnPyTraces`, the actual-checkout scan/export commands and source-integrity/parity comparison in §7. No paid judgment or runtime execution is required or claimed.
- **Scope/checks.** Scoped tests pass and the slice diff contains only relevant approved paths;
  verify with `git diff --check`, `git status --short` and slice-diff inspection.

## 7. Test strategy

- `TestDynamicHTTPRegistrations`: A literal table/for-of and direct local literal-argument factory expose the expected entries, original spans, row/call/closure provenance and finite target alternatives.
- `TestDynamicHTTPContextIsolation`: Shared function/factory body exposed with different arguments or controls retains separate contexts and correct unsafe/protected/unknown results through real candidate and report paths.
- `TestDynamicHTTPBounds`: Runtime registration data, mutation, recursive factories, unknown wrappers, unbound/fake receivers and over-limit expansions preserve gaps; known alternatives remain visible, zero-use unknown registrations remain reportable, repeated scans are deterministic. Include Python registry/member mutation, shadowed lookup, unresolved callbacks and reached-limit controls.
- `TestDynamicPythonVulnPyTraces`: Uses source-only pinned fixtures plus the actual VulnPy acceptance scan below. Asserts generated paths/methods, source hashes/spans, closure values, finite callable selection, request dependencies, callback argument/cursor binding, SQL operand separation, claim completeness and matching JSON/HTML/SARIF statuses. Pairs raw traces with bound/escaped and unresolved variants outside the original target. The test MUST NOT pass merely because a finding appears somewhere at the sink line: it must be associated with each required route/context and supported dependency path.

### Existing Node.js application reference

Use the pinned [Juice Shop sample](../../../docs/samples/juice-shop/README.md) at
`~/Dev/juice-shop`, revision `f189f521266f42c6bd05884468292000cee852ed`, as a real
Node.js regression reference: `server.ts:511–536` defines the 14-row `autoModels` table
and `for...of`/`finale.resource` endpoint generation; `server.ts:624,630` registers returned
handlers from `routes/login.ts:18` and `routes/search.ts:19`. Preserve existing specialized
Finale persistence and zero-argument factory support; do not describe those as newly discovered
capabilities. Compare inventory, registration/model provenance and existing candidate/claim
outputs before/after D5. These real paths complement the mandatory focused fixtures for
plain Express finite tables and literal-argument factories with differing closure/guard contexts.
A literal URL parameter such as `:id` alone is not generated registration.

The reviewed `~/Dev/sast-testbench/js-samples` files use fixed Express registrations
(`/login`, `/search`, `/exec`, `/readfile`, `/checkuser`); `weak_crypto.js` has no HTTP route.
They can supply direct-route controls, but do not replace dynamic-registration acceptance.
Do not modify or execute any of these sample applications.

### VulnPy acceptance target and required traces

The user-requested acceptance checkout is explicitly **`~/Dev/vulnpy`** (default local path;
`D5_VULNPY_ROOT` may override it for another machine). Upstream is
`Contrast-Security-OSS/vulnpy`, MIT, pinned at
`b81885e58283a3449b578d20c20557aff637e5ea`. Verify clean `git status --porcelain --ignored`,
HEAD and [reference hashes](../../../docs/samples/vulnpy/source-hashes.json) before/after scanning.
On 2026-11-04 review the local checkout was clean, HEAD matched, and all eight relevant
registration/registry/trigger/application source files matched their reference hashes.

| Required route stem | Flask exposure | FastAPI exposure | Required source-to-use evidence |
| --- | --- | --- | --- |
| `/vulnpy/sqli/sqlite3-execute` | GET and POST, declared trailing slash with `strict_slashes=False` | GET, no declared trailing slash | `_get_user_input` or query parameter → selected `do_sqlite3_execute` → captured input → `_execute` callback/cursor → formatted SQL argument at `trigger/sqli.py:37` |
| `/vulnpy/sqli/sqlite3-executemany` | GET and POST, same slash behavior | GET | Same dispatch/callback path to `trigger/sqli.py:48`; formatted SQL text remains separate from the other operand's bound value |
| `/vulnpy/sqli/sqlite3-executescript` | GET and POST, same slash behavior | GET | Same dispatch/callback path to formatted script at `trigger/sqli.py:59` |
| `/vulnpy/xss/raw` | GET and POST, same slash behavior | GET | Request input and resolved `name="xss"`, `trigger="raw"` branch → concatenated HTML returned at `flask/blueprint.py:57` or `HTMLResponse` at `fastapi/vulnerable.py:44`; `trigger/xss.py:do_raw` is not the rendering sink |

Framework/trigger paths in this matrix are under `src/vulnpy/`. Read `flask/blueprint.py`,
`fastapi/vulnerable.py` and `trigger/{__init__,util,sqli,xss}.py`, plus the checkout-root
`apps/{flask_app,fastapi_app}.py`. Generation includes finite source-module/member discovery
behind `TRIGGER_MAP`, name normalization and `get_trigger` lookup; a literal registry replacement
in a fixture alone is insufficient. Derive names from actual source declarations/import bindings
and observed factory inputs. Keep selected-root restrictions, hashes, spans and expansion bounds.
Do not execute `glob`, `import_module`, `getattr`, registration factories or trigger functions.
Those source constructs need bounded analysis, not target execution or corpus-specific shortcuts.

The Flask trace MUST retain header precedence and GET-query/POST-form alternatives from
`_get_user_input`; the FastAPI trace MUST bind the handler's `user_input` query parameter.
Keep `_execute`'s callback parameter, `_db_reset`'s sqlite3 connection and derived cursor
provenance, rather than treating a call as value transfer. Constant schema setup/`SELECT_ALL`
MUST NOT become request-derived SQL findings. Missing unrelated template-content facts must
remain separate from established request-to-raw-output witnesses; relevant unknowns still block claims.
Reuse the design's deterministic registration/alternative/context/scan budgets and existing
flow limits; do not silently raise/remove limits or replace an unreached required trace with a warning.

A single full-checkout scan MUST produce inspectable findings for the required generated routes
and preserve all previously supported static entries/uses after normalizing identity changes.
Scoped scans of each registration file provide additional trace evidence. Build the scanner in
this worktree (never in the target), then run without `--judge` or live credentials:

```sh
D5_VULNPY_ROOT="${D5_VULNPY_ROOT:-$HOME/Dev/vulnpy}"
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go build -o .zazz/ephemeral/d5-scan ./cmd/scan
.zazz/ephemeral/d5-scan --analyze --json --output-dir .zazz/ephemeral/d5-vulnpy/all "$D5_VULNPY_ROOT"
.zazz/ephemeral/d5-scan --analyze --json --entry src/vulnpy/flask/blueprint.py --output-dir .zazz/ephemeral/d5-vulnpy/flask "$D5_VULNPY_ROOT"
.zazz/ephemeral/d5-scan --analyze --json --entry src/vulnpy/fastapi/vulnerable.py --output-dir .zazz/ephemeral/d5-vulnpy/fastapi "$D5_VULNPY_ROOT"
```

Run the full-checkout command before implementation as a baseline and again after implementation;
each invocation writes a fresh bundle. Export saved fresh JSON offline as HTML/SARIF, inspect route
labels/locations and trace disclosures, and compare use statuses across all three formats. Record
exact commands, route/context-to-sink assertions, missing evidence, file/input hashes and artifact
paths in the D5 log and concise durable results. Automated Go tests use vendored source-only
fixtures with the MIT notice/provenance and no dependency on a developer's local checkout; actual
sample acceptance is a separate mandatory check, not a skipped test counted as success.

Preserve the historical six-positive-miss/four-warning baseline and original case inventory.
Fresh evidence MUST recover `VP-SQL-EXECUTE`, `VP-SQL-EXECUTEMANY`, `VP-SQL-EXECUTESCRIPT`,
`VP-XSS-FLASK` and `VP-XSS-FASTAPI` with the stronger route/context assertions above.
`VP-XSS-JINJA` is separate deferred template-binding work; its existing observation MUST remain
inspectable. Historical warning expectations may cease to apply to resolved fresh registrations:
explain that delta rather than retaining fake gaps, rewriting labels or claiming the original
10-case evaluator now proves all acceptance. Other vulnerability families/frameworks remain
outside the supported finding claim; preserve their inventory/gaps without claiming complete coverage.

Use compact table-driven controls and actual parsed fixtures where adapters are involved.
Hand-built records prove model/presenter boundaries only; they cannot substitute for actual
adapter-to-candidate-to-claim/report acceptance. Reuse adjacent existing tests for unchanged
behavior and inspect golden diffs rather than adding tests that mirror helper calls.

Scoped command (declared Go toolchain, no live network/model credentials):

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/parse ./internal/report ./cmd/scan
git diff --check
```

At the deliverable's completed boundary run race tests for affected packages. Full
race/vet/build and sample/report validation are mandatory for the final milestone; the
index defines the commands and each later code change invalidates affected prior evidence.
Local loopback stubs test policy/transport, not model accuracy. A sandbox bind denial is
an environment limitation to resolve, not a passing test or a reason to use a paid endpoint.

### User-added real-model and prompt acceptance

After offline acceptance, run full source-only Decision-mode assessments of the existing pinned
VulnPy and Juice Shop checkouts with OpenAI Decisions `gpt-6-luna`. The user explicitly chose
both apps and no request/spend cap; a funding/rate response stops further requests without retries
or fallback. Record actual attempts/completions/failures and exact request/response artifacts.
Compare resulting claims with source-reviewed expectations; model confidence is not accuracy.
Fix scanner defects exposed by these real apps and repeat affected checks and exact-request
assessments. Changed requests cannot reuse historical answers. Unsupported families and unresolved
necessary facts stay explicit; a full scan is not a promise of complete framework coverage.

Deduplicate model-bound source/metadata losslessly before transmission, without raising the 64 KiB
request bound or removing controls, witnesses or gaps. Preserve roles, record order, source spans,
hashes and code reconstruction. Exclude parsed code comments and Python docstrings from model-facing
source while keeping original local audit text and runtime code/strings. Record every issue,
hardening change, attempted remedy and verification outcome in the append-only execution log.
Original paid-call prohibitions in the initial prompt below are superseded only by this explicit
user steering for these two evaluations. Other models/providers, target execution/edits and D6 remain
outside scope.

## 8. TDD entry point and execution sequence

First failing test: `TestDynamicHTTPRegistrations` with the observable contract in §6.

1. Start with the failing TestDynamicHTTPRegistrations specified above; then TestDynamicHTTPContextIsolation on two factory registrations using different closure values/controls. Capture the real VulnPy pre-change baseline before Python edits.
2. Implement finite expansion in deterministic order, sharing existing module binding and HTTP metadata models. Retain existing direct routes and finale persistence semantics.
3. Carry actual arguments/closure projections into invocation seeds; unsupported capture/mutation cannot acquire a safe status.
4. Add failing TestDynamicPythonVulnPyTraces using the actual generation/lookup/callback source shape. Implement bounded Python registration/selection, then closure/input/callback-cursor propagation through the existing analysis engine.
5. Exercise per-site, per-entry and scan budgets; run the §7 real VulnPy scans, report review and existing HTTP/browser/sample regressions. Required dynamic routes must have full trace evidence and findings, not only discovered paths.

Illustrative implementation skeleton; names/bodies may adapt to verified existing code:

```go
// internal/parse/dynamic_registrations.go
// expandFiniteRegistration(site, bindings, budget) -> registrations, dispatches, gaps.
// Each derived record cites site + literal row/factory call + supported closure binding.
```

Recovery checkpoints: Express literal expansion; factory/closure context and limits; Python source-derived registration/selection; then real VulnPy end-to-end traces, findings and report acceptance.
A checkpoint MUST leave a coherent runnable state before being called green; otherwise
record exact partial changes and failing checks, without claiming this deliverable complete.

## 9. Definition of done

- [x] Required source/standards read and current scope verified.
- [x] All acceptance criteria have passing, cited evidence; affected regressions explained.
- [x] Scoped tests/race checks and diff checks pass; only changed Go files formatted.
- [x] Required offline reports/manual review performed where this slice changes output.
- [x] Remaining gaps, exact artifact locations and next checkpoint recorded.
- [x] No out-of-scope change, fabricated protection or stale-response replay.
- [x] User receives the completed slice and any remaining unchecked acceptance items.

## 10. Open questions

The user explicitly added VulnPy dynamic-route trace and visible-finding acceptance on
2026-11-04. This authorizes the specification expansion to bounded Flask/FastAPI generation
and necessary registry/closure/callback flow; implementation still requires a separate assignment.
No unresolved target-selection question remains. Python beyond this stated source subset,
new vulnerability families or wider runtime reflection requires a material scope decision.

## 11. Run log protocol

Use `.zazz/ephemeral/common-entry-dispatch-05-dynamic-http-run-log.md`, append-only.
Record standards verification, user decisions, start revision, phase
completions, commands/results, deviations, report paths/hashes, review/rework and recovery.
At session start read AGENTS, this contract, relevant design sections and the log; verify
Git state and choose the next incomplete checkpoint. If the ignored log is absent,
reconstruct from Git and tracked acceptance evidence; never infer success from missing notes.

## 12. Agent implementation prompt

```text
Implement deliverable 5 only, unattended, in the existing common-entry-and-dispatch
worktree and branch. Execute this specification as the implementation instruction:
.zazz/specifications/scan/common-entry-dispatch-05-dynamic-http.md

This instruction authorizes implementation, required verification, then committing
and pushing the completed D5 checkpoint to origin/common-entry-and-dispatch. Do not
create another worktree or PR, merge, push to integration, or begin deliverable 6.
D4 is completed and pushed at fe11151bcb0a11102592a805e7d160fa57c303a9.

Read AGENTS.md and orientation, this complete contract and its required design,
analysis, source/reference and dependency sections. Read the latest D4 run-log entries:
.zazz/ephemeral/common-entry-dispatch-04-browser-events-run-log.md
Maintain a separate append-only ignored D5 log:
.zazz/ephemeral/common-entry-dispatch-05-dynamic-http-run-log.md
Create it if absent; reconstruct unavailable predecessor evidence from Git/contracts,
never infer passing verification from missing notes. Load spec-driven and matched
engineering, testing, database-injection, XSS and documentation standards. Work as one
agent; do not delegate.

Verify actual cwd, branch, HEAD, D4 ancestry and existing changes before editing.
Preserve user edits and prompt/specification preparation. Record the actual start
revision, bounded D5 scope and the next incomplete checkpoint. Maintain an evidence
matrix mapping every AC1-AC4 obligation and Definition of Done item to its test,
actual-sample assertion or manual check, result and artifact location.

Work unattended toward the capability in §0 and every acceptance criterion in §6.
Follow §8's TDD sequence, starting with failing TestDynamicHTTPRegistrations and then
TestDynamicHTTPContextIsolation. For each requirement, implement the smallest supported
change, run its checks, inspect the actual evidence, diagnose failures or missing traces,
correct the implementation and repeat until that requirement passes. Review the complete
AC matrix after each recovery checkpoint and continue to the next unmet obligation.
A passing focused test, partial route inventory, green recovery checkpoint or completed
Express slice is not D5 completion and is not a reason to end the session.

Capture source-only predecessor baselines before the corresponding implementation
changes. Implement finite Express tables/for-of and direct local literal-argument
factories with registration, row/call, argument, closure and control provenance.
Preserve existing direct routes, zero-argument factories and specialized Finale
persistence behavior. Use §7's pinned Juice Shop reference for before/after inventory,
provenance and candidate/claim comparison; existing support is not a new capability.

D5 includes mandatory real VulnPy acceptance at ~/Dev/vulnpy (D5_VULNPY_ROOT may
override the location), pinned to b81885e58283a3449b578d20c20557aff637e5ea.
Read and statically analyze the actual source shapes specified in §7. Derive finite
registry/member selection and Flask/FastAPI generation from source declarations and
bindings. Never import/execute target code, hardcode its endpoint/function map, or
consume evaluation labels as detector input. Verify target cleanliness, HEAD and
reference hashes before and after every acceptance scan.

Recover every required §7 route/context: Flask GET/POST and FastAPI GET for all three
SQLite trigger variants and raw XSS. Prove request -> generated handler/closure ->
selected trigger -> callback/cursor -> executable SQL operand or raw HTML response.
Retain Flask header/query/form alternatives, FastAPI query binding, SQLite connection/
cursor provenance and SQL text versus bound-value separation. Constant setup SQL must
not become request-derived findings. Hand-built records, simplified literal-registry
fixtures, discovered paths or findings elsewhere at the same sink line do not satisfy
this acceptance. The full-checkout scan must recover the required per-route traces and
visible SQL/raw-XSS findings while preserving supported static entries/uses and explicit
unsupported/zero-use gaps. Keep VP-XSS-JINJA deferred and its existing observation visible.

Continue autonomously through ordinary implementation choices, test failures, missing
trace investigation, report defects and rework. Do not ask for routine approval or end
with an offer to continue. Never weaken tests, remove mandatory coverage, replace a
required trace with a warning, relabel expectations to match output, or call partial
work complete. Stop dependent work only for §5's genuine halt conditions, such as missing
required reference data, conflicting user edits, an unresolved material scope/public-
contract decision, destructive recovery or an invariant violation. Investigate routine
failures first; apply the repeated-failure rule without treating one failure or a
recoverable sandbox restriction as a blocker. Explain any genuine blocker precisely,
record attempted remedies and a resumable checkpoint, and report every unmet obligation.

Use the milestone usage-window policy without inventing quota. Keep context, modified
paths, partial state, commands/results, AC coverage, limitations and the exact next action
current in the ignored log. Recovery checkpoints support resumption; they do not reduce
the goal or authorize early completion. If an enforced interruption prevents completion,
leave an honest resumable state and distinguish completed evidence from outstanding work.

Complete all scoped tests, affected-package race checks and applicable local provider/
exact-request replay regressions using the declared Go toolchain. Keep D4 browser-event,
existing browser/framework/inline-script and HTTP regressions green. Run the required
full-checkout and scoped VulnPy baseline/current scans and Node.js reference comparisons.
Generate fresh offline JSON/HTML/SARIF, verify status/provenance parity, and visually
inspect route labels, source/sink locations, traces, gaps, sorting, disclosure, keyboard
focus and narrow layout. Fix defects and repeat all affected checks after changes.
Record exact commands, results, artifact paths/hashes and remaining supported-subset
limits. Update the owning tracked contract, public documentation and durable results.

Before declaring D5 complete, audit every AC1-AC4 subcondition and Definition of Done
item against actual passing evidence. Mandatory sample checks cannot be skipped and
counted as success. Format only changed Go files; run git diff --check, inspect status
and review the entire D5 slice against the recorded start revision. Commit/push a completed
checkpoint only when all required acceptance and verification obligations are satisfied.

Verify the assigned path/branch and zazzcode Git/GitHub authentication before publication.
Commit and push only the verified D5 checkpoint to origin/common-entry-and-dispatch.
Verify a clean worktree and exact remote synchronization. Report the commit, acceptance
matrix results, remaining limitations and next checkpoint, then stop. D6 requires a
separate user assignment.

No paid calls, live-key use, target execution/dependency installation, sample-app changes,
historical raw-answer edits or stale-answer replay. No new worktrees, PR creation, merges,
integration pushes or later-deliverable implementation. Local loopback stubs are allowed;
resolve sandbox socket restrictions through permitted access, never a paid endpoint.
```

## 13. Implementation and review change log

2026-11-03 — Initial contract from the user's design/spec request, Node.js GraphQL
priority, explicit browser-event/reporting requirement, retained HTTP sample compatibility,
and later application evaluation. Product implementation has not started.

2026-11-03 — User requested one ignored run log per deliverable; updated log paths
and resume prompts. This changes execution tracking only, with no product/test change.

2026-11-04 — Deliverable Owner requested explicit VulnPy dynamic-route trace acceptance
and confirmed that a real scan must show findings for generated and existing supported routes.
Updated §§0–4, 6–8, 10 and 12 with the named `~/Dev/vulnpy` checkout/pinned revision,
Flask/FastAPI source subset, three SQL trigger variants and raw-XSS response trace matrix,
actual-checkout commands, Python implementation/test paths and source-integrity controls.
Retained deferred Jinja/framework/family limits and historical labels/answers. Fixed §8's
first-failing-test inconsistency. This is specification work only; D5 is not implemented.

2026-11-04 — Reviewed existing Node.js targets and the user-supplied
`~/Dev/sast-testbench/js-samples` directory. Added §7's Juice Shop generated-Finale and
returned-handler references, preserving their existing bounded support, and distinguished
them from the fixed-route JS snippets. Focused table/closure/guard fixtures remain required.

2026-11-04 — Deliverable Owner requested an explicitly unattended, goal- and acceptance-
driven D5 implementation prompt. Replaced §12 with the D4 predecessor checkpoint,
per-criterion evidence matrix, implement/test/inspect/rework loop, mandatory real-sample
acceptance, interruption recovery and completed-checkpoint commit/push instructions.
Recovery checkpoints are resumable steps, not completion or routine approval gates.
Scope, acceptance criteria and required checks are unchanged. This edit prepares the
new-session instruction only; it does not start D5 implementation.

2026-11-04 — D5 implementation: explicitly named adjacent shared-model/judge consumers for source-backed constant closure values and the corresponding evidence-envelope version increment. These implement the already required actual argument/closure provenance; no new adapter, family or protection rule. Exact-request replay remains mandatory.

2026-11-04 — User expanded D5 acceptance during implementation: full VulnPy/Juice Shop OpenAI Decisions gpt-6-luna runs, no user request/spend cap, stop on funding response, source-reviewed claim checks and scanner fixes found through those apps. User also requested prompt deduplication, exclusion of training comments/instructions and an explicit issue/hardening execution log. Added the corresponding current acceptance section and focused model/projection paths. No target execution, sample edits, model fallback, new family or later deliverable is authorized.

### D5 completion evidence — 2026-11-04

All D5 acceptance criteria pass; see [implementation results](../../evaluation/common-entry-dispatch-results.md)
for the criterion matrix, actual-sample findings, verification and retained limits. User steering added
full live VulnPy/Juice Shop Decision-mode evaluations, lossless request deduplication, code-only model
projections and the VulnPy scan-plus-source confirmation table. These changes remain within D5.
Final source passes all-package race tests, vet/build, fresh offline sample/export/parity checks and
exact offline replay of all 1,015 completed live requests. No D6 work is included. The append-only
local execution log records fixes, artifact paths, final scope and publication verification.
