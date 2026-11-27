# Analysis components 02 — all XSS types and browser coverage

## 0. Capability and implementation order

Second follow-on session, after [NoSQL plus validation](components-01-nosql-validation.md): migrate
existing XSS interpretation to selected components across reflected/server output, templates, stored,
DOM/framework and supported API-to-browser paths. Preserve rendering-specific evidence and all-path
protection. Include one explicit browser correctness fix: fetch-method provenance must not silently
turn a POST/dynamic-method request into GET when matching a server JSON producer.

This specification was requested on 2026-11-05. The user subsequently assigned this implementation in the existing
`analysis-pack-mvp` feature worktree on 2026-11-05. [Outbound](components-03-outbound.md) follows.
Logging remains separate. This is not a general browser-vulnerability detector: CSRF, CORS, browser
storage/token leaks, clickjacking and new code-injection families need their own evidence contracts.
Existing browser string-code sinks retain their current XSS semantics.

## 1. Required reading

- [AGENTS](../../AGENTS.md#start-here), [orientation](../docs/zazzles-agent-orientation.md#task-reading-paths),
  [plan](../project/implementation-plan.md#analysis-pack-mvp-initiative).
- [Component architecture](../architecture/analysis-packs.md#descriptor-and-selection-contract),
  [first migration](components-01-nosql-validation.md#4-decisions-and-extension-risks-to-resolve),
  [original XSS contract](xss-response.md) and [scope](../project/xss-detection-scope.md).
- [XSS analysis](../../docs/scan/analysis/xss.md#stored-and-browser-analysis),
  [trace](../architecture/trace-judgment.md#implemented-evidence-contract),
  [reporting](../architecture/reporting-and-sarif.md#canonical-report).
- [spec-driven](../../.agents/skills/spec-driven/SKILL.md), [execution discipline](../docs/agent-execution-discipline.md),
  [standards index](../standards/index.yaml), [structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [spec hygiene](../standards/spec-hygiene.md),
  [docs hygiene](../standards/docs-hygiene.md), [doc-check](../../.agents/skills/doc-check/SKILL.md).
- Current owners: `internal/judge/{xss,bundle,entry_context}.go`, `internal/analysis/xss.go`,
  `internal/parse/xss_*.go`, `browser_events.go`, `python_templates.go`, `python_rendering.go`;
  component family registrations from session 01. Verify actual paths after its implementation.

## 2. Invariants

- Preserve the SQL/NoSQL/validation component contracts, source trust, mandatory Go gates,
  historical-answer integrity, explicit unsupported scope and per-invocation isolation.
- Every XSS judgment names its output context. HTML escaping cannot certify JavaScript, CSS,
  active/unquoted attributes, template source or URL-scheme safety. Validation is not output encoding.
- Verified sanitization depends on binding, applicable version/configuration, ordering and every
  relevant path. A library/framework/helper name alone is insufficient.
- Stored/cross-tier claims require actual origin, storage/field or API method/path/response-field
  relationships. JSON alone is not an HTML sink. URL equality alone cannot prove response provenance.
- A browser-only source/rendering path needs no invented server route or HTTP request source.
  Browser network activity is not automatically server-side SSRF. A postMessage origin condition
  is distinct from encoding, authorization, and whole-application protection.
- Preserve independent raw/escaped/unknown write paths, zero-use event registrations, source spans,
  framework/inline-script facts and all existing discovery/flow limits. Unknown siblings prevent
  all-path protection; they do not erase a supported unsafe witness.

## 3. Scope and review shape

One XSS deliverable/specification, staged inside one assigned feature worktree/branch and one intended
draft PR to `stage`. The stages are recovery points within the same family; they are not separate
engines, runtime switches or extra worktrees. If the actual review diff requires a split, obtain user
direction and update this contract before changing the review shape.

Start from the accepted session-01 implementation. Record its actual commit or complete source/diff
manifest and passing baseline. Preserve uncommitted predecessor work; `HEAD` alone may not contain it.
No requirement to merge into integration is inferred by this spec; the user assigns the actual checkout.

| Repository-relative path | Change | Purpose |
| --- | --- | --- |
| `internal/analysispacks/` | Add XSS material/registration/tests | Rendering, sanitizer, context and question components |
| `internal/guidelines/` | Narrow modify | Selected validated XSS/shared guidance with one owner |
| `internal/judge/{xss,client,components,trace,validation}.go` and tests | Modify | Selected XSS protocol/questions, provenance, existing Go consistency gates |
| `internal/parse/xss_*.go`, `browser_events.go`, Python rendering/template owners and tests | Narrow modify | Attach selections and preserve extraction; bounded fetch-method correction below |
| `internal/analysis/{components,xss,analysis,json}.go` and tests | Narrow modify if necessary | Existing fact/provenance representation and saved compatibility |
| `internal/report/`, `cmd/scan/` | Narrow tests/wiring | Cross-format counts, server/browser grouping and coverage preservation |
| `internal/parse/testdata/` | Narrow add | Actual browser/server/template paired controls missing from coverage |
| This spec, specification index, component architecture/plan, `README.md`, XSS/technical/model guides | Narrow modify | Implemented scope, compatibility, exception and acceptance evidence |

The diff MUST stay within these paths. No new framework/language, broad helper/heap/async support,
Python API-to-browser completion, stored-origin expansion, generic code-injection engine, DOM
clobbering, prototype-pollution analysis, security-header assessment, browser runtime execution,
application repairs, paid calls, plugins or report redesign. Unrelated cleanup stays separate.

## 4. Decisions and explicit parity exception

**Rendering-specific composition.** Register `xss_candidate` with its existing XSS facts, five named
questions and choices. Keep data-only XSS observations unassessed; do not manufacture rendering
claims or API contracts. Primary rendering contracts and applicable encoder/sanitizer/framework
components may coexist only through declared roles. Do not relax conflict checks to allow arbitrary
competing primary contracts. Browser event, template, storage and server/API capabilities compose
only when actual source facts establish their applicability.

**One family, complete supported coverage.** Inventory and migrate current Express response,
EJS/Handlebars/Pug, Python/Jinja/HTML, Mongoose/Sequelize storage, DOM/jQuery, React, Vue and Angular
subsets. Include literal inline browser scripts in Python templates. This inventory does not broaden
what each adapter supports. Keep existing browser globals and imported DOMPurify semantics distinct
from server execution/configuration. No family-wide safe flag may replace path-specific facts.

**Browser fetch-method defect boundary.** At authoring, `internal/parse/xss_client_calls.go` passes
literal `GET` to `clientHTTPValue` for every browser `fetch`. The cross-tier linker uses that method
to select server producers. This is a code-level risk of wrong/missing producer attribution; this
review has not claimed a reproduced exploit or measured corpus-wide impact.

Add regression fixtures with GET and POST producers at the same path. For an unshadowed browser
fetch with absent/default options, retain GET. For a direct immutable object literal `method` option,
use the established literal method (case-normalized); explicit literal POST must never borrow GET.
For dynamic/unresolved options/methods, Request objects, spreads/overwrites or unsupported aliases,
retain an explicit method/provenance gap and do not link a guessed producer. Options outside the
supported literal subset do not establish protection. Preserve the independent response/rendering
record. Do not add runtime requests or evaluate arbitrary JavaScript objects.

This is the only authorized detection/evidence correction in this migration. Record its before/after
fixture results separately from organizational parity, including affected origin/protection changes.
All other source/outcome differences require a separate scope decision. New evidence and changed
origin linkage MUST reject stale replay.

**Compatibility.** Use `xss-components-v1` for selected XSS requests, with unchanged question names,
choices and meaning. Keep mandatory XSS protocol/context/coverage consistency checks active against
the selected protocol. Retain schemas 1–4 read/export and use schema 4 unless serialized shape changes.
SQL/NoSQL/validation protocols and effective requests remain stable unless an explicitly recorded
shared-content change requires a version bump. Saved historical XSS answers are never relabeled.

**Bounds.** Use existing 32-component/16 KiB material/64 KiB provider-body bounds, lossless
compaction and deterministic ordering. Oversized/unsupported selected claims retain explicit failures;
never truncate storage paths, rendering contexts, required material or blockers to make a request fit.

## 5. Implementation rules and halt conditions

One Contributor Agent performs the staged session, no extra agents or external tracker required.
Use ignored `.zazz/ephemeral/components-xss-run-log.md` under its storage policy; record standards,
accepted baseline, owner inventory, fetch exception, protocols, sizes and per-stage evidence.
No commit/push/PR is requested by this spec-writing turn; later assignments govern those actions.
Agents do not merge into integration. Work from the assigned root with the declared local toolchain.

Halt for missing predecessor code, lost source/origin/path data, unexplained outcome/count drift,
a needed gate weakening, framework expansion or changes outside the explicit fetch exception.
Do not silently expand the exception to fix unrelated known XSS coverage misses. Inspect accepted-base,
working and untracked diffs; preserve unrelated changes and baseline sample applications.

## 6. Acceptance criteria

| ID | Observable acceptance | Verification |
| --- | --- | --- |
| X1 | Source-backed XSS selection handles server, template, stored, DOM/framework and cross-tier material; no invented API required for browser-only flows or rendering verdict on JSON-only observations | `TestXSSComponentSelection`, `TestXSSDataOnlyNotAssessed` |
| X2 | Raw/escaped/context-sensitive server/template cases and native encoder/fake helper/version/options controls retain baseline facts and results | `TestXSSServerComponentParity`; existing response/template/sanitizer tests |
| X3 | Stored paths retain separate writing contexts, storage/field identity, raw/escaped/unknown siblings and unresolved-origin blockers | `TestXSSStoredComponentParity`; existing storage/path tests |
| X4 | Actual parsed DOM/jQuery, React/Vue/Angular, event inputs, duplicate callback registrations and Python inline scripts preserve source/context, protection and gaps | `TestXSSBrowserComponentParity`; existing browser/event/inline-script tests |
| X5 | GET/POST at one URL cannot exchange producers; explicit literal fetch method selects only its actual producer; unresolved methods keep gaps and no guessed linkage; existing supported method/path/field matching remains | `TestBrowserFetchMethodIsolation`, extended `TestCrossTierResponseFieldLinks` |
| X6 | Local OpenAI/Jev stubs receive correct selected five-question material and no unrelated policy/labels; optimistic inconsistent answers cannot bypass origin/context/path gates | `TestXSSComponentPayloadsAndPolicy`; existing XSS policy/decoder controls |
| X7 | Provenance, exact replay and changed material/evidence/context/method/model/protocol rejection work; schema1–4 exports retain original answers/versions; bounded failures make zero HTTP calls | `TestXSSComponentReplay`, `TestXSSComponentFailures`, extended compatibility tests |
| X8 | JSON/HTML/SARIF preserve source, counts, statuses, server/browser grouping and zero-use coverage; SQL/NoSQL/validation/logging/outbound regressions and full checks pass | `TestXSSComponentReportParity`, baseline projection comparisons; contributor checks |

## 7. Test strategy

Freeze source-backed XSS baselines and fixed stub answers before moving content. Compare all supported
claim types with independent expected results, not simply a nonempty report. Reuse
`TestXSSResponseContexts`, `TestXSSRawAndEscapedTemplates`, `TestCompiledTemplateFlows`,
`TestSanitizerBindingGates`, `TestStoredWritePathsStaySeparate`, `TestStoredTemplatePathsAndControls`,
`TestBrowserSourceSinkControls`, `TestReactAndVueRenderingControls`, `TestAngularTrustAndTemplateBindings`,
`TestBrowserEventProvenance`, `TestBrowserEventUnknownAndLimits`, `TestPythonTemplateBrowserBridge`,
`TestXSSPolicyEvidenceAndConsistency` and `TestCrossTierResponseFieldLinks`.

Use raw/protected/unknown/not-applicable stub outcomes plus wrong optimistic answers. Expected labels
stay outside requests. The fetch exception gets a distinct before/after table and minimal synthetic
source fixtures; no sample app changes or browser execution. Verify method mismatch, ambiguous route,
wrong response field, data-only JSON and missing origin without turning absence into protection.
Measure selected sizes/allocations; no timing thresholds. Any automatic golden refresh requires
review of the exact allowed metadata/protocol or fetch-exception difference.

## 8. TDD entry point and execution sequence

1. Verify session-01 baseline and inventory every current XSS material owner and supported claim type.
2. First failing tests: browser-only XSS selection without a server API; POST-fetch cannot link a
   same-path GET producer. Preserve the latter as a separate bounded correction checkpoint.
3. Register/migrate XSS questions/guidance/operation contracts and keep mandatory Go gates active.
4. Verify server/template stage, then stored stage, then DOM/framework/event/inline-script stage,
   running all existing XSS regressions at each checkpoint.
5. Implement the literal fetch-method correction; record each intentional linkage/outcome difference.
6. Verify cross-tier composition, both provider stubs, replay, history, bounds and all report formats.
7. Remove replaced material owners, update docs/ledger and run full contributor/doc checks.

```text
analysispacks/xss.go: rendering-specific material/roles/protocol; no generic injection abstraction
parse/XSS owners: current source facts -> selection, preserving per-path and storage contexts
parse/xss_client_calls.go: supported literal fetch method -> clientHTTPValue; unknown -> explicit gap
judge/xss.go: selected answers -> unchanged context/origin/all-path mandatory policy
```

## 9. Definition of done

- [x] X1–X8 have evidence for every currently supported XSS claim type.
- [x] The fetch correction is isolated and explained; all other behavior is equivalent.
- [x] No browser/server or caller/path protection is borrowed; data-only observations stay observations.
- [x] Provenance/replay/history/bounds, both providers and cross-format parity pass.
- [x] Full race tests, vet, build, changed-file formatting, docs and ledger updates pass.

## 10. Open questions

No drafting question blocks the defined scope. Actual baseline must include session 01. Broader browser
security and Python cross-tier completeness remain unassigned. If the fetch issue has already been
fixed by then, retain its regression coverage and omit duplicate implementation; record that evidence.

## 11. Run log protocol

Keep the named local log append-only for baseline/standards, staged outcomes, fetch-exception evidence,
compatibility decisions, deviations and recovery. Artifacts follow repository output policy. Durable
summaries go in component architecture; a fresh agent resumes from spec, log if present and Git state.

## 12. Implementation prompt

> Implement `.zazz/specifications/components-02-xss.md` in the assigned feature worktree after
> session 01. Read AGENTS and its orientation, this contract, family component architecture,
> XSS analysis guide, spec-driven and matched standards first. Preserve predecessor code and record
> the actual accepted baseline. Migrate all existing XSS material through registered components in
> staged server/template, stored, browser/framework/event/inline-script and cross-tier checkpoints.
> Keep per-context encoding, verified sanitizers, independent write paths, mandatory origin/coverage
> gates and data-only observations. Fix only the explicitly bounded browser fetch-method attribution
> issue: actual literal methods, default GET, unresolved methods retain gaps and no guessed producer.
> Record that exception separately; do not broaden frameworks, flows or vulnerability families.
> Use local stubs for both transports and real source fixtures to prove expected outcomes, source and
> JSON/HTML/SARIF parity, zero-use coverage, limits, saved history and changed-request replay rejection.
> Run full contributor/doc checks, update README/plan/ledger and report every unmet criterion. No
> paid models, target execution, sample edits, extra agents/worktrees or integration merges are implied.
> Follow the user's assignment for any commits, feature pushes or draft PR creation.

## 13. Implementation and review change log

### 2026-11-05 — Assigned implementation and compatibility record

**Source.** User assigned §12 after session 01, in the existing feature worktree.

**Changed sections.** §0 records the implementation assignment; the capability and invariants are
unchanged. Accepted baseline is clean `7610193`, including session-01 `9c83a07` and cleanup.

**Summary.** XSS uses `xss-components-v1`, five unchanged questions/choices, primary rendering and
supplementary context/protection/storage/browser/response roles. Existing core gates remain active;
selected obligations are additive. Schema stays4; SQL/NoSQL/validation effective material/protocols
are unchanged. Historical `xss-use-v1` answers retain their original version during export.
The fetch literal/default/unknown correction is the sole evidence exception; its before/after
origin/protection table and acceptance mapping are in the
[migration ledger](../architecture/analysis-packs.md#xss-migration-verification-2026-11-05).

**Verification impact.** Both local transports, real parsed controls, source/outcome/export parity,
zero-use coverage, replay, history and bounds are verified by the tests named in the ledger.
Final checks pass on native Go1.27.3 with offline modules: `go test -race ./... -count=1`
(all nine packages), `go vet ./...`, `go build ./...`, and `gofmt -l .` (empty).
Scoped manual doc-check covers eight changed Markdown files and 188 local links, final newlines,
private paths, conflict markers and `git diff --check`. No repository doc-lint tool is declared.
X1–X8 have evidence; no unmet acceptance criterion is recorded. These offline checks do not claim
live-model accuracy, runtime exploitation or broader unsupported coverage. No commit, push or PR
was requested or performed.


### 2026-11-05 — User-authorized migration cleanup

**Source.** User requested removal of the two reviewed cleanup remnants and other obsolete
migration code, followed by a feature commit and push.

**Changed sections.** §3 permits narrow cleanup in the existing protocol selector in
`internal/judge/validation.go`; no detection or evidence boundary changes.

**Summary.** Remove the unreachable XSS protocol fallback now handled by registered families;
remove the production historical-validation constant used only by a test (the test retains its
literal historical protocol); make the shared replay provenance error family-neutral. Active XSS
question/choice adapters and historical report compatibility remain in use and are retained.
Commit/push authorization applies to this feature branch; no PR or merge is assigned.

**Verification impact.** Existing protocol/policy/replay/history controls and all nine packages pass
`go test -race ./... -count=1`; `go vet ./...`, `go build ./...`, `gofmt -l .`,
`git diff --check` and scoped documentation checks (21 local links) pass. No request bytes, question
protocols, source facts or successful assessment outcomes change; no new Juice Shop scan or paid
call is required.
