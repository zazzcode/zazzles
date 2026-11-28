# Common entry and dispatch implementation results


## Cross-entry acceptance, 2026-11-05

**Original offline/stub acceptance passes; milestone acceptance remains incomplete.** The browser tool rejected
the local HTML URL and explicitly prohibited workaround or alternate browser surfaces. No rendered
visual, interaction, keyboard-focus or narrow-layout pass is claimed. Mandatory AC4 remains open; the user subsequently added AC5: fresh full real-judge E2E of all seven
example apps, Juice Shop first, now passing supported source-reviewed checks;
The user explicitly approved publishing verified work as a draft with AC4 retained as a pre-merge
blocker. This is not a rendered-review pass or merge authorization. Human review
and merge remain separate. No next initiative was started.

Executed as one agent in `common-entry-and-dispatch`, starting from
`fb8a4012d5426e462d712d2fbac733a22b45a6fd`. Only acceptance tests and owning documentation changed;
production scanner code, fixture sources, expected labels, goldens and historical raw answers were
preserved. The original offline checkpoint used no paid calls; the subsequently authorized fresh
paid E2E results are below. No target execution/dependency installation, new worktree or merge occurred.

| Acceptance | Evidence and result |
| --- | --- |
| AC1: mixed adapter pipeline | `cmd/scan/entry_pipeline_test.go`, `TestMixedEntryPipeline`: actual parsed JS DOM events/Apollo/gRPC, TS finite HTTP and Python generated Flask/FastAPI in one selected root; 68 entries, 53 uses, canonical contexts and immutable HTML/SARIF exports. PASS |
| AC2: scoped protection/coverage | `internal/judge/entry_protection_test.go`, `TestEntryProtectionCoverage`: six actual parsed fixture sets, including mixed, through local HTTP stubs and exact/cross-context replay. Guarded/open shared SQL bodies retain separate outcomes; unknown transforms/guards reject protected answers. PASS |
| AC2: catalog/report boundary | `internal/report/entry_coverage_test.go`, `TestEntryProtectionCoverage`: actual parsed resolver/handler uses plus explicitly synthetic multiple-target/unresolved-remainder and transport metadata additions. Counts do not multiply; unknown alternatives remain visible. These additions prove the catalog/presenter boundary, not automatic transport discovery. PASS |
| AC3: regressions/compatibility | Full race/vet/build; both provider local stubs/failures; changed-request replay; ten exact fixture comparisons; seven real sample source scans; original Python 29/29; immutable schema1/2/3 exports. PASS |
| AC5: real full-judge E2E | User-added requirement:1146 eligible fresh requests across all seven apps, with Juice Shop paid run and full report first, then other apps. PASS1146/1146 eligible completions; no historical replay or stub substitutes for it |
| AC4: report review | 24 generated offline/stub bundles pass source, canonical identity, HTML badge and SARIF status/location parity audits. Required rendered HTTP/event/GraphQL/gRPC/mixed inspection is BLOCKED, not satisfied by markup checks |

### Source-reviewed expected and observed behavior

Expectations derive from fixture source and its existing independent controls, before inspecting
current report output. Fixtures are never executed. Python `src` and literal gRPC descriptor paths
remain at the selected root, preserving the documented import/cwd boundary. An initial fixture
layout failed those boundaries; corrected source-copy layout required no production change. gRPC's
seven uses include six SQL candidates and one independent validation observation.

| Source fixture | Entries / uses | Source expectation and observed contextual outcomes |
| --- | --- | --- |
| JS browser events | 6 / 4 | Shared raw input/change callback has two separate confirmed stub claims; textContent is Protected; unknown message transform remains evidence-limited; click/missing callback remain zero-use entries |
| TS finite HTTP | 4 / 4 | Raw factory output confirms under stub; encoded sibling stays Protected; unresolved runtime factory and no-output route remain zero-use entries; validation observations remain Review |
| JS Apollo | 9 / 7 | Raw/open/object lookup: three confirmed SQL stub claims; bound/guarded injection facets protected; unknown transform evidence-limited. Guarded concatenation still poor practice; only bound SQL is a final green record. Wrapped/absent/constant fields retain coverage |
| JS unary gRPC | 11 / 7 | Raw/open: two confirmed SQL stub claims; bound/guarded injection facets protected; unknown transform/applicable unknown guard evidence-limited. Guarded construction remains orange; streaming/missing/unused methods retain zero-use inventory |
| Python generated fixture | 38 / 31 | Actual generated SQL/raw-HTML paths, closure/input binding and independent raw/encoded/unknown controls retained; no sibling protection transfer |
| Mixed | 68 / 53 | Sum of adapter inventories preserved, with 28 zero-use entries. Stub assesses 36 claim candidates: 22 confirmed, 8 scoped protection, 6 evidence-limited; 17 separate observations remain unassessed |

Final mixed **presentation** records differ intentionally from assessment facets: offline has
27 poor-practice, 23 Review and 3 Protected records; synthetic assessed has 22 confirmed,
5 poor-practice, 17 needs-review, 3 needs-evidence and 6 Protected. SQL construction can remain
orange beside a protected/evidence-limited injection facet. Only final scoped protection gets green;
no entry-wide safety or runtime exploitability is implied. Stubs prove policy/transport, not model accuracy.

### Before/after compatibility

A source archive of the exact start revision was verified against every Git blob and built offline;
it is not a worktree. Current versus start JSON is identical for ten fixture sets: string-flow,
JS/TS events, JS/TS dynamic HTTP, JS/TS GraphQL, JS/TS gRPC and Python generated VulnPy.
No normalized difference is hidden by ID rewriting. All seven actual applications retain exact
complete JSON parity with the preserved final D6 current reports, including source/context/status
facts. There are no unexplained HTTP/browser changes in these bounded comparisons.

| Fresh read-only source scan | Entries / uses | Finding / Review / Protected |
| --- | --- | --- |
| ThreatByte | 24 / 56 | 5 / 40 / 11 |
| Python insecure app | 1 / 2 | 1 / 1 / 0 |
| Vulnerable Flask App | 19 / 24 | 4 / 20 / 0 |
| VulnPy | 564 / 827 | 28 / 799 / 0 |
| Node.js Goof | 19 / 33 | 2 / 29 / 2 |
| Vulnerable TypeScript app | 19 / 20 | 1 / 19 / 0 |
| Juice Shop | 167 / 208 | 8 / 200 / 0 |

Every application matched its pinned revision and clean status, including ignored files, before
and after source scanning. No application was executed or changed. The audit checks 55,553 source
witnesses across the 24 bundles: 53,452 exact raw excerpts, 2,081 explicitly labeled field projections
and 20 excerpt-free scope markers. All retain original hashes/spans/line locations. Generated and
saved-export HTML/SARIF match byte for byte; JSON inputs remain unchanged.

Original saved schema1 Python case commands pass 18 ThreatByte + 3 python-insecure-app +
8 vulnerable-flask-app = 29/29. VulnPy is separate: its original saved baseline still passes 4/10,
with the six documented positive misses unchanged. No expected label or old answer was rewritten.
All seven curated schema1 inputs export unchanged. A synthetic schema2 compatibility input and
fresh schema3 adapter bundles also export unchanged; synthetic empty schema2 coverage is supplemented
by the existing compatibility test suite, not presented as historical application accuracy.

### Commands, artifact integrity and remaining review

All Go commands use installed Go1.27.3 darwin/arm64 (module minimum1.27.2), `GOTOOLCHAIN=local`,
`GOPROXY=off`, and `GOCACHE="$PWD/.zazz/ephemeral/go-cache"` from the assigned worktree.

- `go test -race ./... -count=1` — PASS all eight packages, `d8-final-race.log`; includes final acceptance tests and provider loopback stubs.
- `go vet ./...` and `go build ./...` — PASS, `d8-final-vet.log`, `d8-final-build.log`.
- Focused `TestProviders`, invalid/cancel/duplicate answers, exact/changed-request replay and entry/GraphQL/gRPC policy tests — PASS, exact invocation and verbose output in `d8-provider-replay.log` and the run log.
- `python3 docs/samples/evaluate-python.py <app> docs/samples/<app>/findings.json` — original three apps PASS; separate VulnPy returns expected exit1 for its documented six misses. Exact four commands/output are in `d8-report-manifest.json` / `d8-cli-reports-9med1f6b/case-checks/`.
- `python3 .zazz/ephemeral/d8-verify-reports.py` — PASS, `d8-report-verification-second.log`; exact scanner CLI/export commands, baseline/source checks, input/output SHA256 hashes and cross-format matrix in `d8-report-manifest.json`.
- `gofmt -l cmd internal` — empty; `git diff --check` and focused documentation/link/scope review recorded in the run log.

All paths above are relative to ignored `.zazz/ephemeral/`. The review entry point is
`d8-final-report-index.md`: links to all24 HTML/JSON/SARIF bundles, offline versus stub labels,
seven fresh sample sets and per-bundle counts. Its manifest anchors the exact output bytes.
Manifest SHA256: `511a18c60bf5247262fbc7ed9fcfa61d385ddb02a3748db8b0c11423ea5237af`.
Representative mixed stub HTML SHA256:
`d1465e25c4a79c05e54c0df91fadddd3e641338e18243465a39eb53266550544`;
mixed offline HTML:
`1a44e77a0a11678fd36d62b00f37b84afeda8c9561b0bb2d74946edfdc46f6d1`.

Remaining mandatory review: render HTTP-only, event-only, GraphQL-only, gRPC-only and mixed HTML;
check typed labels/metadata, source locations/excerpts, counts/statuses, zero-use gaps, sorting,
native disclosures, keyboard focus and narrow layout. Record actual observations/screenshots and
hashes; resolve defects and rerun affected checks before completion or conditional publication.
Broader application-level GraphQL/gRPC evaluation remains deferred. Existing Jinja/framework/flow
limits and unassessed fresh model judgments remain explicit; these checks do not establish general
accuracy, universal framework support or independent Findings Review.


## Fresh paid full-judge E2E, 2026-11-05

The user expanded final acceptance to all seven real example apps, with the paid Juice Shop full
report completed and audited first. All1,146 eligible source-backed assessments now complete with
OpenAI Decisions `gpt-6-luna`. There were1,149 paid attempts: the original calls plus one explicit
Juice Shop HTTP504 recovery and two VulnPy HTTP503/token-rate429 recoveries. Every original failure
and raw answer remains preserved. No completed answer was repurchased; every retained answer was
checked against independently freshly parsed exact request hashes. Twenty-four API-data observations
remain unassessable without rendering linkage, rather than receiving fabricated judgments.

| Real application | Completed / eligible | Confirmed | Poor practice | Review | Protected |
| --- | --- | --- | --- | --- | --- |
| juice-shop | 188 / 188 | 7 | 3 | 198 | 0 |
| nodejs-goof | 33 / 33 | 2 | 0 | 29 | 2 |
| vulnerable-typescript-app | 16 / 16 | 2 | 0 | 18 | 0 |
| ThreatByte | 56 / 56 | 4 | 2 | 16 | 34 |
| python-insecure-app | 2 / 2 | 1 | 0 | 1 | 0 |
| vulnerable-flask-app | 24 / 24 | 4 | 0 | 20 | 0 |
| vulnpy | 827 / 827 | 28 | 0 | 799 | 0 |

Fresh full-judge Python case checks pass29/29 (ThreatByte18, FastAPI3, Erlik8). Source-reference
checks retain Goof reflected/stored XSS and escaped controls, TypeScript raw search/sensitive logging
with no invented executed SQL, Juice Shop product-search SQL plus three order/review NoSQL injection
claims and linked FE/BE raw HTML, and all12 required main-app VulnPy SQL/raw-HTML contexts. VulnPy
retains28 contextual confirmed positives across its application mounts. The source-reviewed checks
are in `d8-e2e-source-review.json`; they do not assert exhaustive vulnerability recall.

Juice Shop has7 confirmed findings: one SQL injection, three NoSQL injections, two sensitive request-line
logging contexts and one cross-tier raw-HTML XSS. Its final contextual outcomes exactly match the
preserved previously judged D6 report. The prior offline report had no model assessments; that was
not a model-assessed vulnerability result. Original saved Python29/29 and historical VulnPy4/10
remain separate immutable baselines; the fresh VulnPy required-context matrix demonstrates the
supported generated paths without rewriting historical labels. Running the unchanged original
VulnPy10-case evaluator on the fresh report yields5/10: the three SQL and two framework raw-XSS
positives are recovered; Jinja is still a genuine positive miss. Its four old warning controls
(`dynamic_path` at24/32 and `python_registration_unresolved` at33/61) fail because those generated
registrations are now resolved. They are explained intentional behavior differences, not four new
missed vulnerabilities. No case file was rewritten; exact output is retained in
`d8-e2e-fresh-vulnpy-original-cases.json`.

All final paid bundles pass unchanged-source, canonical identity, JSON/HTML/SARIF status/sink-location
parity and immutable saved-export audits. All targets retain pins, clean status including ignored
files and reference hashes before/after. Fresh successful answers, exact request/response traces,
selected final traces, original failures and provider usage are linked from the final report index.
VulnPy hit the documented2,000,000 TPM provider window; continuation waited for it to clear, then
used one dispatch/second, max4 in flight, without another rate/funding error. No provider fallback,
target execution/modification, dependency installation, new worktree or additional initiative occurred.

Provider-reported usage for successful final assessments: `{"input_tokens": 9965521, "output_tokens": 0}`.
No currency charge or failed-attempt billing is inferred from token counts. Paid manifest:
`.zazz/ephemeral/d8-paid-e2e-manifest.json`, SHA256 `35239d98f85d28fd02a1723777129658c02cc8bec31710ee22ed0900405bc5b6`.
Per-app full reports and all HTML/JSON/SARIF views are in the ignored
`.zazz/ephemeral/d8-final-report-index.md`.

Remaining limits are real: login email SQL is discovered but combined password crypto transfers
block its injection claim; Goof Mongoose/middleware and stored-origin limits remain; Juice Shop token/
model-setter/collection/dialog transfers and VulnPy Jinja remain bounded coverage gaps. Source-positive
cases are not relabeled negative merely because evidence is incomplete. Saved JSON can normalize empty
invocation gap arrays (`[]` versus `null`); direct rehydration may conservatively reject an otherwise
unchanged exact replay. Live/recovery requests used fresh parsing and exact hashes; no replay matching
was weakened and no stale response was accepted. This wire-normalization limitation remains visible
for review rather than changing the protocol after paid evidence was captured.

AC5 real-provider E2E and the supported source-reviewed outcome checks pass. AC4 rendered visual/
interaction/keyboard/narrow review remains outstanding under browser policy. Paid model completion
does not establish universal accuracy, runtime exploitability or independent Findings Review.

## D6 — bounded Apollo GraphQL resolvers, 2026-11-04

Implemented against D5 `7fa55e4d8e4055532993eac4073f9d2c25d59b80` in the existing feature
worktree. The [D6 contract](../specifications/scan/common-entry-dispatch-06-graphql.md) owns acceptance;
D7 has not started. No paid calls, target application execution/modification, new worktree or PR.
The future GraphQL application remains deferred evaluation.

| Acceptance | Passing source-backed evidence |
| --- | --- |
| AC1: Apollo/schema/resolver binding | `internal/parse` TestGraphQLResolverBindings and variants: literal SDL, imported/local/inline/method resolvers, independent schema instances, object fields, unresolved/default/composed maps |
| AC2: independent inputs and SQL transfers | TestGraphQLInputRoles and transfer controls: args to verified Sequelize SQL; parent/context/info unknown; scalar names establish no business policy or protection; calls alone do not establish flow |
| AC3: real completeness and policy | parse/judge TestGraphQLProtectionContexts: raw/bound/unknown SQL, guarded/open shared sink, unknown applicable guard, contextual controls, local Decisions HTTP stub, exact replay and changed-coordinate rejection |
| AC4: actual exports, selectors and bounds | parse/report/CLI TestGraphQLPipelineAndBounds variants: real JS and typed TS fixtures, schema3 JSON, resolver-specific HTML/SARIF, zero-use gaps, exact source hashes/spans, typed selectors, root/symlink escapes, shadowed constructors and deterministic budgets |
| Regression/quality | Scoped suites, full `go test -race ./... -count=1`, `go vet ./...`, `go build ./...`, changed-file formatting and diff review |

Each pinned source-only JS/TS fixture yields nine entries, six SQL candidates and one separate
argument-validation observation. Offline reports contain five construction-practice findings and
two Review observations, with every assessment `not_run`. Under the local stub, three SQL contexts
are confirmed, bound and guarded SQL injection facets are Protected, and the unknown transform
remains evidence-limited despite a protected stub answer. Construction practice keeps the guarded
string-built query orange; only the bound record becomes a final green protection record. A separate
unknown-guard fixture also rejects the stub's protected answer. These tests establish policy and
transport behavior, not model accuracy or runtime exploitability.

A scanner built from an archive of the exact D5 commit produced identical JSON evidence to D6 for
six regression sets: JS/TS dynamic dispatch (four entries/four uses each), Python dynamic VulnPy
(38/31), existing string flow (one/one), and JS/TS browser events (six/four each). No historical report,
raw answer, golden or target source changed. Saved GraphQL exports preserve input hashes and retain
JSON/SARIF statuses, invocation identities, actual sink locations and related schema locations.

The [public subset and limits](../../docs/scan/running-scans.md#bounded-apollo-graphql-analysis) describe
literal named Apollo wiring, supported SDL syntax, independent unknown parent/context/info roles,
and explicit unsupported composition/default/custom-scalar/wrapper/parent-result behavior. The
adapter assumes Apollo Server 4 compatibility; installed versions and transport exposure are not
verified. Reached source/SDL/registration/record/helper limits remain visible gaps, never protection.

Local ignored evidence is under `.zazz/ephemeral/`: the append-only
`common-entry-dispatch-06-graphql-run-log.md`, `d6-{scoped,race,vet,build}.log`,
`d6-report-manifest.json`, `d6-regressions/`, and `d6-reports/`. Report verification covers generated
HTML source, disclosures/sort/filter markup and cross-format evidence/status parity. Browser policy
blocked the local-file visual preview; no visual browser QA is claimed here. Broader milestone visual
acceptance remains separate from these D6 adapter/export tests.

## D6 real-sample follow-up — 2026-11-04

At the user's request, fresh full source scans ran against all seven pinned application checkouts,
followed by a source-evidence audit, saved exports and exact historical decision replay. Every target
matched its recorded revision, reference hashes and clean Git state, including ignored files, before
and after scanning. No target was executed, modified or installed into; no new paid request was made.

| Fresh full scan | Entries | Uses | Offline finding / Review / Protected records |
| --- | ---: | ---: | --- |
| Juice Shop | 167 | 208 | 8 / 200 / 0 |
| Node.js Goof | 19 | 33 | 2 / 29 / 2 |
| Vulnerable TypeScript app | 19 | 20 | 1 / 19 / 0 |
| ThreatByte | 24 | 56 | 5 / 40 / 11 |
| Python insecure app | 1 | 2 | 1 / 1 / 0 |
| Vulnerable Flask App | 19 | 24 | 4 / 20 / 0 |
| VulnPy | 564 | 827 | 28 / 799 / 0 |

These fresh runs contain no model assessments. Their finding counts describe established
construction-practice observations; scoped protection can follow supported structural encoding facts.
They are not fresh vulnerability confirmations or proof of complete coverage.

The initial scan output matched the exact D5 source build for all seven apps. A stricter byte-span
audit then found an inherited logger-evidence defect in Goof and the TypeScript app: verified global
console bindings recorded descriptive text `global console.log` at a span containing `console.log`.
The fix uses the standard source-evidence constructor, preserving original text/hash/span and masked
model text. A failing-then-passing parsed-source regression covers five console methods/forms,
including an inline comment. Final reports retain identical entries, contexts, operations and
classifications; five apps remain completely identical to D5, while the other two differ only in
these two corrected witnesses and their two evidence-derived candidate/finding IDs. Old judgments
were not copied onto the changed evidence.

The final audit verifies 47,937 source-location/hash/line witnesses, including 46,035 byte-exact raw
excerpts. The remainder comprises 1,882 labeled field-projection annotations and 20 excerpt-free
browser scope markers; their original source hashes/spans are verified without relabeling them as
raw source text. JSON/HTML/SARIF entry/context/status/sink-location parity, zero-use entry visibility,
and identical generated/saved-export output pass. All seven curated saved JSON inputs remain
unchanged after offline export.

Current-source exact-request replay accepts all 827 VulnPy and 188 Juice Shop saved D5 decisions,
with zero new calls and complete assessed-report parity. VulnPy retains 28 contextual confirmed
findings and 799 evidence-limited results; the twelve main-app generated route/method contexts all
retain their source-backed SQL/raw-HTML findings. Juice Shop retains seven confirmed findings,
three construction-practice findings, 178 evidence-limited results and twenty unassessable API-data
observations. These are historical decisions applied only to identical current requests.

Original Python saved-report acceptance remains 29/29. Fresh source evidence passes all 22 structural
case checks; seven ThreatByte validation cases remain unassessed under the no-paid-call restriction,
with their policy candidates retained. The old VulnPy baseline intentionally still evaluates 4/10,
including its six documented positive misses; neither labels nor historical results were rewritten.
The separate Jinja coverage gap and other documented framework/flow limits remain. Node source
controls preserve Goof's raw/stored create+update and escaped/unknown outputs, TypeScript's raw
search output with no fabricated SQL sink, and Juice Shop's browser/cross-tier origins. Application
level GraphQL evaluation still awaits the future sample app.

Verification after the repair: focused logging tests, full `go test -race ./... -count=1`, vet/build,
formatting and diff review pass. Local ignored evidence:
`d6-real-sample-manifest.json`, `d6-real-sample-audit.json`, `d6-saved-python-evaluation.json`,
`d6-real-samples/`, `d6-real-logger-{red,green}.log`, and `d6-sample-fix-{race,vet,build}.log`.
The append-only D6 run log records commands, expected deltas, source hashes and publication checks.
No additional scanner regressions were found in this bounded sample verification; known unsupported
paths remain limits rather than protection claims. D7 has not started.

## D5 — bounded dynamic HTTP registration, 2026-11-04

Implemented in `common-entry-and-dispatch` against predecessor `fe11151bcb0a11102592a805e7d160fa57c303a9`.
The [D5 contract](../specifications/scan/common-entry-dispatch-05-dynamic-http.md) owns scope and acceptance.
At the D5 checkpoint, D6 and additional framework/vulnerability families had not started.

Finite Express literal tables/for-of loops and direct local literal-argument factories now produce
source-backed registrations and separate closure/control contexts. Bounded Flask/FastAPI generation
resolves source module/member inventories, supported name transformations, local registry selection,
factory captures and independent application mounts without importing or executing target code.
The value trace retains request input, captured callbacks, actual callback arguments, helper-returned
SQLite connections and cursor/SQL operand provenance. Unsupported alternatives remain explicit gaps.

| Acceptance | Passing evidence |
| --- | --- |
| AC1: finite registration/provenance | `internal/parse` TestDynamicHTTPRegistrations and mounted variant; JavaScript/TypeScript parsed fixtures |
| AC2: context isolation | TestDynamicHTTPContextIsolation variants, Python repeated-path regression, raw/encoded/unknown controls, report assertions |
| AC3: bounded/conservative behavior | TestDynamicHTTPBounds variants: mutation, shadowing, unresolved/decorated callbacks, wrappers, recursion, limits and deterministic repeat scans |
| AC4: actual Python route-to-use traces | TestDynamicPythonVulnPyTraces in parse/judge, witness assertions, full/scoped pinned checkout scans and source/format audit |
| Real Decision-mode acceptance | 827 VulnPy and 188 Juice Shop actual completed requests; final exact-request replay of all 1,015 responses, no additional calls |
| Regression/quality | `go test -race ./... -count=1`, `go vet ./...`, `go build ./...`, scoped parse/report/CLI suite and `git diff --check` |

## Actual source-only sample results

Targets remained clean, including ignored files, at their pinned revisions before and after scans:
VulnPy `b81885e58283a3449b578d20c20557aff637e5ea`; Juice Shop
`f189f521266f42c6bd05884468292000cee852ed`. All VulnPy reference hashes were checked.
No target application was executed, installed into, modified or remediated.

| Offline scan | Entries | Candidate uses | Classification |
| --- | ---: | ---: | --- |
| Predecessor VulnPy Flask registration file | 0 | 0 | Explicit unsupported registration warnings |
| Predecessor VulnPy FastAPI registration file | 0 | 0 | Explicit unsupported registration warnings |
| D5 full VulnPy | 564 | 827 | 28 poor practice; 799 Review |
| D5 scoped Flask registration file | 474 | 756 | 24 poor practice; 732 Review |
| D5 scoped FastAPI registration file | 79 | 65 | 4 poor practice; 61 Review |
| D5 full Juice Shop | 167 | 208 | 8 poor practice; 200 Review; predecessor inventory/evidence/status parity preserved |

The original full VulnPy baseline's 11 static entries and six uses remain present. Its historical
six-positive-miss/four-warning evaluation, saved reports, answer keys and hashes are unchanged.
Resolved fresh registrations no longer carry obsolete blanket unsupported-registration warnings.
JSON/HTML/SARIF status, entry/context and primary sink-location parity was checked across all fresh
baseline/current/control/assessed bundles. The 12 required main-app positive contexts have 704
verified original source/hash/span evidence witnesses.

## Live Decision-mode findings and limits

User-authorized evaluations used OpenAI Decisions `gpt-6-luna`, with no retry or provider/model
fallback. All 1,015 actual requests completed. These are static model assessments checked against
source, not runtime exploit validation, a complete vulnerability inventory or an accuracy percentage.

**VulnPy:** 827 completed assessments produced 28 contextual confirmed vulnerabilities (21 SQL and
seven raw XSS), plus 799 evidence-limited results. All 12 required main Flask/FastAPI method/route
contexts were confirmed. Independent Flask application mounts explain the additional exposures:
there are five source cases, not 28 distinct defects. See the
[scan-plus-code-inspection table](../../docs/samples/vulnpy/reference.md#findings-confirmed-by-scan-and-code-inspection--d5).
The expectations derive from operations and tests; upstream's reviewed setup documentation does not
provide a formal per-route expected-findings manifest. The separate Jinja Environment/template
binding remains a known source-positive coverage gap. Observations lacking business-validation
policy remain evidence-limited rather than becoming invented policy violations.

**Juice Shop:** 188 model-eligible assessments completed across 208 uses. Twenty API JSON XSS-data
candidates correctly remained unassessed because no rendering claim was linked. Final findings:
seven confirmed vulnerabilities, three poor practice, 178 evidence-limited and 20 Review.
Source-inspected positives include product-search SQL (`routes/search.ts:23`), order/review NoSQL
(`trackOrder.ts:18`, `showProductReviews.ts:36`, `updateProductReviews.ts:17`), two sensitive request-line
logging contexts (`server.ts:366`) and cross-tier raw HTML (`track-result.component.html:9`, reviewed
JS-XSS-02). Other documented expected paths remain coverage/judgment limits. Login's SQL construction
remains poor practice because unmodeled password-hash transfers block a complete injection claim;
a vulnerable model answer does not override that blocker. The browser-search trust bypass retains
poor-practice status with exposure unknown.

Juice Shop's 14-row `autoModels`/Finale loop is an existing specialized persistence reference.
Four check-driven User-persistence contexts retain identical row/loop mapping, model constraints
and required evidence roles. D5 does not claim newly enumerated CRUD endpoints for every table row;
existing zero-argument login/search factories are regression references. Focused parsed fixtures
establish the new generic finite-table/literal-argument capability.

## Issues resolved and hardening

Overlapping enclosing source and repeated metadata, rather than uncontrolled route recursion,
caused oversized model requests. Lossless excerpt sharing plus an explicit compact evidence/gap
column schema retain roles, ordering, source spans/hashes, controls and references within the existing
64 KiB bound for both apps (preflight maxima: 47,517 bytes VulnPy; 65,245 Juice Shop). No record is
silently truncated; a remaining oversized request stays unassessed. Evidence envelope version is 6.

AST-derived model projections mask comments and genuine Python docstrings while local audit text
and hashes remain original. Executable f-strings, bytes literals, runtime strings and template code
are preserved. Regression tests cover reconstruction, comment filtering, executable expressions,
request size, replay matching and changed-closure rejection. Final replay matches every saved live
request exactly, including after the executable-string correction.

Additional fixes preserve identity for repeated-path factories with different captures, reject
unknown decorated callbacks, enforce mount-projection budgets, remove stale resolved-registration
warnings and give raw Python HTML responses encoding guidance. Existing golden changes affect
only the capability-limitation sentence. Unknown/mutated bindings cannot acquire fabricated protection.
Browser QA covered the generated route/sink/provenance, disclosures, keyboard sorting/focus, protected
filtering, visible zero-use gaps and a 390-pixel layout without horizontal overflow.

## Reproducible verification and local evidence

Use the declared Go toolchain; offline tests require no provider credentials:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test ./internal/parse ./internal/report ./cmd/scan
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test -race ./... -count=1
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go vet ./...
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go build ./...
git diff --check
```

The append-only execution log and large/raw artifacts are local ignored evidence, not published
sample baselines. Paths below are relative to the assigned worktree's `.zazz/ephemeral/`:

- `common-entry-dispatch-05-dynamic-http-run-log.md`: commands, RED/fix evidence, issues and final audit.
- `d5-publish-{race,vet,build}.log`, `d5-final-projection-scoped.log`: final code checks.
- `d5-live/{vulnpy-01,juice-shop-01}/`: immutable original reports, exact request/raw-response traces,
  usage, run summaries and before/after target-integrity checks.
- `d5-publish-replayed/{vulnpy,juice-shop}/replay-summary.json`: final-source bundles with 827/188
  exact offline replays and zero new requests; 20 unassessable API records preserved.
- `d5-final-sample-manifest.json`: fresh full/scoped/baseline/control bundles, commands and output hashes;
  `d5-publish-offline.log`: counts and export checks, including saved JSON immutability.
- `d5-completion-audit.json`: inventory/evidence/format parity, 12-context matrix and source witnesses;
  `d5-node-persistence-parity.json`: actual Finale persistence parity.
- `d5-publish-scope-manifest.json`: exact implementation/documentation scope and SHA256 hashes.
- `d5-visual/`: generated-route and unresolved-control desktop/narrow screenshot evidence.


## SQL/NoSQL-only accuracy refresh and rendered review

User-authorized follow-up, 2026-11-05. Broader hardening is deferred until after analysis-pack-mvp;
no analysis-pack implementation starts here. Earlier checkpoint counts and browser blockers above
remain historical evidence. The current report index is ignored `d8-final-report-index.md`.

The Goof login selector now carries exact immutable adapter/predicate witnesses, reachable actual
Mongoose schema registration and pinned4.2.4 casting semantics. Its String password selector can
retain operators; a username email predicate cannot constrain that sibling field. The login is now
confirmed NoSQL injection. Two `findById` candidates remain Review rather than inheriting this claim.
Juice Shop's native password hash now has a bounded hex-output transfer through its helper return;
that output does not constrain the raw email sibling in SQL. Login email injection is now confirmed.

| Current full-source app | Completed / eligible | Fresh changed requests | Confirmed contextual records |
| --- | --- | --- | --- |
| Juice Shop |188/188|21|8|
| Goof |33/33|3|3|
| vulnerable TypeScript app |16/16|0|2|
| ThreatByte |56/56|29|4|
| python-insecure-app |2/2|0|1|
| vulnerable Flask app |24/24|1|4|
| VulnPy |827/827|21|28|

All75 refreshed requests completed without errors;1071 previous requests matched exactly and were
retained. Twenty-four API-data observations remain unassessable. Source-backed checks18/18 and
fresh original Python29/29 pass; required VulnPy12 contexts/28 positives remain. Final contextual
status changes against the previous paid checkpoint are exactly the two recovered login cases.
Changed evidence may change use IDs; unmatched IDs were compared only under unique entry,
invocation, candidate kind and exact sink-byte witnesses, never reused for decision replay.

The19 scoped probes exposed real calibration defects: the judge sometimes called hex-only SQL and
scalar-guarded NoSQL vulnerable despite source constraints. New source witnesses and versioned
injection questions keep conversion/selector semantics distinct from construction practice. An
independent conservative gate retains contradictory vulnerable answers as explicit Review, never
fabricating Protected. Final real controls: hex-only SQL Protected; raw-email sibling confirmed;
scalar NoSQL Review; unknown helper Review. Earlier wrong answers remain saved. Scalar protection
recognition is still incomplete; whole-program plugin/type/guard analysis is not claimed. The
[database rules](../../docs/scan/analysis/database-injection.md) describe actual bounds and false-negative risks.

Actual localhost inspection passed for five report types, including typed labels, declaration versus
sink location, resolver/request metadata, source transfers, sorting/filtering, zero-use gap disclosure,
keyboard Enter/Space focus and390px layout without page overflow. AC4's initial `file://` rejection
is no longer a current blocker after the user-opened authorized HTTP tab. The EJS Markdown advice
now preserves intended Markdown and recommends sanitizing generated HTML; JS output no longer
receives Jinja-specific repair text. This is bounded manual QA, not exhaustive accessibility testing.

Exact evidence under ignored `.zazz/ephemeral/`: `d8-db-refresh-plan.json`, `d8-db-refresh-01/`,
`d8-db-final-manifest.json`, `d8-db-source-review.json`, `d8-html-review.json`,
`d8-report-narrow-review.jpg`, `d8-db-paid-ledger.json` and final accuracy race/vet/build logs.
Total session paid attempts1243 =1149 initial +75 refreshed +19 probes;1240 completed and3 original
failed transient attempts retained. Successful provider-reported input tokens10,948,192/output0;
currency cost and failed-attempt billing are not inferred. No provider/model fallback, sample changes,
dependency installs or target execution occurred. Historical curated JSON and raw evidence remain intact.

Final commands: `go test -race ./... -count=1`, `go vet ./...`, `go build -buildvcs=false ./...`
with local Go1.27.3, `GOTOOLCHAIN=local GOPROXY=off` and ignored local cache; source/report audits,
original saved-case checks, doc-check and diff/format checks. Local HTTP stub tests require loopback
permission; the first sandbox listener failure is preserved separately. Human code/design review and
merge remain pending on the draft milestone PR.


Publication verification logs are `d8-publication-race.log`, `d8-publication-vet.log`,
`d8-publication-build.log` and `d8-publication-doc-check.log`. A final-code offline fresh parse of all
seven apps exactly matches the assessed source snapshots and all1146 request hashes; no additional
paid calls were needed. The ignored `d8-current-publication-scope.json` records every staged path/hash.
