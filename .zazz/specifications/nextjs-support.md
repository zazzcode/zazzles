# Next.js support (N0–N5, partial N6)

**Status:** Implemented on `nextjs-support-mvp`; draft PR https://github.com/zazzcode/zazzles/pull/18 into `stage`
**Feature:** Next.js acquisition adapter, library contracts, client/server rendering, practice tier
**Deliverable Owner:** Human owner
**Delivery topology:** One feature branch and one draft PR (owner decision, 2026-11-15)
**Source proposal:** `.zazz/ephemeral/NEXTJS-SUPPORT-PROPOSAL.md` (gitignored, in the `nextjs-support-mvp` checkout)
**Drafted:** 2026-11-16
**User docs:** [Next.js support](../../docs/nextjs-support.md), [Next.js analysis rules](../../docs/analysis/nextjs.md)

## 1. Capability

Make zazzles produce the same quality of evidence for a Next.js application as for Express, Fastify
and Hapi, through an acquisition adapter on the shared Node engine (no new analyzer families), plus
framework-neutral library contracts the sample needs and a separate, model-free practice tier.

## 2. Owner decisions (2026-11-15)

| Question (proposal §15) | Decision |
| --- | --- |
| Scope | N0–N5 complete; N6 only the no-model checks (NX-BP-01..08, 16, 17), which grew to include 10, 12, 19, 20 and the client-request observations |
| Paid cap and model | OpenAI `gpt-6-luna`, at most 300 requests |
| Prisma filter-object injection | NoSQL family, engine `prisma`, contract `prisma-filter-object-v1` |
| Delivery | Commit, push, draft PR into `stage`; pin OopsSec Store `2d530ef` in the sample catalog |

## 3. Scope delivered

| Slice | Delivered | Owner files |
| --- | --- | --- |
| N0 | Byte-preserving parse recovery (JSX `&`, typed tagged templates, `await f<T>()` misparse); tsconfig/jsconfig `paths`/`baseUrl`/`extends`; Next project detection and tsconfig `exclude` scope with `next_scope_excluded` gaps; client calls are not `--routes` registrations | `parse_recovery.go`, `tsconfig_paths.go`, `next_project.go`, `parse.go` |
| N1 | App Router route handlers (all export shapes in §4.3 except `export *`), Pages Router API routes, forwarding auth wrappers as authorization context, `web-request-v1` origins, modeled awaits, zod validation-helper summaries, `--routes` inventory | `next_routes.go`, `next_handlers.go`, `web_request.go`, `zod_validation.go`, `node_input_facts.go` |
| N2 | `prisma-raw-v1`, `better-sqlite3-v1`, `prisma-filter-object-v1`, pino logger binding, zod schema evidence, `readdir`/`stat`/`lstat` in `node-fs-file-v1` | `sql_libraries.go`, `log_sinks.go`, `path_node.go`, `analysispacks/contracts.go`, `nosql.go`, `path.go` |
| N3a | Server Component page and `generateMetadata` entries, navigation exits, server JSX raw-HTML/URL sinks with fixed-prefix exclusion, `request_path_in_internal_url` | `next_pages.go`, `flow.go`, `control_context.go` |
| N3b | `"use client"` modules, React state/effects/refs/callbacks, Next navigation sources and router sinks, verified `api.*` helper summary, `NextResponse.json` producers, Prisma storage reads/writes for stored XSS, fetched-content origin | `react_flow.go`, `xss_client.go`, `xss_storage.go`, `xss_claims.go` |
| N4 | Middleware matcher stages (literal path-to-regexp subset) as entry controls; Server Actions | `next_config.go`, `next_actions.go` |
| N5 | Judged Next.js sample runs with exact replay; published HTML/JSON/SARIF, provenance, licenses and detection guides (§5–§6, §8) | `docs/samples/oss-oopssec-store/`, `docs/samples/vuln-nextjs/`, `.zazz/evaluation/*-detection-guide.md` |
| N6 (partial) | `practice_observations` report section (JSON, HTML, text, SARIF property) | `next_practice.go`, `analysis.go`, `report/*` |

New fact codes: `scope_nextjs`, `zod_schema_supplied`, `sql_multi_statement`, `sql_single_statement`,
`browser_navigation_sink`, `xss_via_fetched_content`, `script_reexecution`.

## 4. Deviations from the proposal

- `input_facts.acquisition` stays `http`: judge selection requires it to equal the entry kind. Initial
  types use the existing vocabulary (`string | null` → `string`, arrays → `array`).
- `generateMetadata` is a separate `page_metadata` entry, not a stage of the page entry. Layouts,
  templates and parallel/intercepting routes produce no entries.
- The sample has 76 exported method handlers in 63 route files, not 75.
- In Next.js code only, the guard engines classify truthiness, extension and sibling-field tests and a
  type-only zod `success` test as non-containing, record Prisma record-lookup early exits as
  unclassified path guards, and treat a `replace(/[^…]/g, "_")` without separators as a component
  sanitizer. These are needed for consistent path/SSRF judgments (§5).
- Not implemented: NX-BP-09, 11, 13, 14, 15, 18, 21, 22; RSC prop exposure; raw-SQL to Prisma stored
  links. (Pages Router `getServerSideProps` pages were added in iteration 2, §6.) Pages Router API routes are covered by
  `TestNextPagesRouterAPI`; the input-helper check now treats verified Prisma raw and better-sqlite3
  calls as sinks (previously only reachable through Express-shaped reads).

## 5. Acceptance evidence

Offline (2026-11-16): `go vet ./...` and `go test ./...` pass. `TestNextJSOopsStoreAnswerKey`
(`ZAZZLES_NEXTJS_SAMPLE`) passes: 76 route handlers, 38 pages, 0 parse errors, no excluded-directory
entries, every record passes judge component selection, required candidates have 0 blockers,
negatives N01–N04 have no XSS record, MW-01 holds, practice rows present. Existing samples:
vuln-demo-app and nodejs-goof byte-identical; vulnerable-typescript-app differs only in the
`node-fs-file-v1` contract text; Juice Shop adds one genuine `fs.stat` path record
(`routes/vulnCodeSnippet.ts`).

Paid: 89 `gpt-6-luna` requests across six passes. Final run
`_test-findings/oss-oopssec-store/oss-oopssec-store/run-1058605849` (21 judged records) replays
21/21 exactly offline (`TestReplaySavedRun`). Sample verified clean at `2d530ef` before and after.

| Answer-key row | Final result |
| --- | --- |
| OOPS-SQL-01..04 | Confirmed (better-sqlite3 `exec` and `prepare` both) |
| OOPS-PATH-01, 02 | Confirmed (`readFile` ×2, `readdir`) |
| OOPS-SSRF-01 | Confirmed |
| OOPS-LOG-01 | Confirmed |
| OOPS-LOG-02 | Confirmed (`POST /api/gift-cards` logs `recipientEmail`; owner added the row 2026-11-16, not in the sample's own key) |
| OOPS-XSS-01, 02, 04, 05 | Confirmed |
| OOPS-SSRF-02, XSS-03, PATH-R01, PATH-R02, PATH-N01 | Review (none red) |
| OOPS-XSS-N01..N04 | No record |
| OOPS-SSR-01, 02 | `request_path_in_internal_url` observations |

## 6. Iteration 2: vuln-nextjs lab (2026-11-16)

**Request:** add the owner-maintained `zazzcode/vuln-nextjs` lab (Next.js 13 Pages Router, PGlite,
zod, DOMPurify) to the catalog with report output and tests, then iterate until every lab row in a
supported family is found. The lab grows over time, so its acceptance is driven by its own
`tests/expected-scanner-findings.json`.

| Slice | Delivered | Owner files |
| --- | --- | --- |
| Handler factories | Multi-argument forwarding factories (`endpoint(methods, run, opts)`); CommonJS `module.exports = {...}` members through a default import, its destructuring and `require` destructuring | `next_handlers.go`, `commonjs.go`, `modules.go` |
| PGlite | `pglite-v1` (`query` single statement with bound `$n`, `exec` multi-statement); client provenance through helpers, `.catch` and a `globalThis` cache; setup helpers are not request flow | `pglite.go`, `sql_libraries.go`, `analysispacks/contracts.go` |
| Validation | Direct `Schema.safeParse/parse` on a module zod schema; it is not an unresolved input helper | `zod_validation.go`, `helper_resolution.go` |
| Pages Router pages | `getServerSideProps` `GET` entries (`context.query/params/req`), props bound to the page component's server render, server `useState` | `next_gssp.go`, `flow.go` |
| Stored XSS | PGlite literal `SELECT`/`INSERT` storage links, `JSON.parse(JSON.stringify(x))` copy, Pages `ALL` producers for cross-tier links | `pglite_storage.go`, `xss_storage.go`, `xss_cross_tier.go` |
| XSS protection | `JSON.stringify` is not script-context protection; `.replace(/</g, '\\u003c')` after it is; `\u2028/\u2029` replacement is neutral | `xss_protection.go` |
| Path | `process.cwd()` is a trusted base | `path_modeled.go` |
| SSRF judge | Fact `url_scheme_only_test`: when every raw-text URL test only fixes the scheme, a `prefix_only` answer counts as no restriction | `ssrf_scheme_tests.go`, `judge/ssrf.go`, `guidelines/facts.md` |

Unsupported lab rows (no analyzer family): JS-001/JS-002 (CWE-95 eval), REDIR-001 (CWE-601), SCA-001.

**Acceptance evidence (2026-11-16).** Offline: `go vet` and `go test ./...` pass;
`TestNextPagesServerSidePropsAndPGlite` covers every slice above; `TestNextJSVulnLab`
(`ZAZZLES_VULN_NEXTJS`, lab at `022a863`) checks 24 supported rows: each required positive has a
complete record of its family, safe controls have no blocked records, React-text controls record
nothing. Existing samples: vuln-demo-app, nodejs-goof and vulnerable-typescript-app unchanged; Juice
Shop unchanged from iteration 1; on OopsSec only `PATH-R01`/`PATH-R02` evidence changed
(`process.cwd()` resolved; still blocked, still Review).

Paid (`gpt-6-luna`): 67 requests this iteration (lab 23 + 23, OopsSec 21), 156 of the 300-request
cap in total. Lab run `_test-findings/vuln-nextjs/vuln-nextjs/run-1392915960` replays 23/23 exactly;
10 of 10 supported required positives Confirmed, 6 safe controls Protected, 6 Review, 2 no record,
none red. The first lab pass judged SSRF-001 `poor_practice` (a scheme-only regex read as a host
prefix check); the `url_scheme_only_test` fact fixed it. OopsSec rerun
`_test-findings/oss-oopssec-store/oss-oopssec-store/run-822779136` replays 21/21 with the same
outcomes as §5. Samples verified clean before and after.

## 7. Follow-ups

Open items are grouped into sessions A–D in the [phase 2 proposal](../../nextjs-support-phase-2-proposal.md)
(A: sample publication completed in this branch; B–D remain separate future deliverables).

Remaining NX-BP checks; a non-vulnerable Next.js app for false-red measurement (proposal §13);
code-injection (CWE-95) and
open-redirect (CWE-601) analyzer families, which the vuln-nextjs lab already has rows for
([proposal](../../code-injection-and-open-redirect-proposal.md), next up in the
[implementation plan](../project/implementation-plan.md#next-up)).

## 8. Sample publication closeout

Owner assigned Session A to this worktree on 2026-11-16, then requested fresh full paid scans of
both samples (including standalone input validation), with OpenAI `gpt-6-luna`, no fallback, and
an explicit 180-request total cap. Published artifacts and source-backed detection guides complete
N5. All reports must retain inconclusive and unsupported records, normalize the public root, preserve
upstream licenses and disclose source pins, coverage and actual assessment counts. The samples
index, refresh script and root README Saved results must link both apps.

Acceptance: fresh scans and exact offline replay; HTML counts agree with canonical JSON; published
files contain no private absolute paths; sample source remains unchanged; `go test ./...` and required
contributor checks pass. Results and verification are recorded below.

**Fresh full results (2026-11-16).** 149 of the approved 180 paid requests, 644,304 reported input
tokens, no retries/fallback, zero failed assessments, zero request-cap omissions. All implemented
analyzers included, including standalone input validation. Every supported required positive remains
Confirmed; no scoped safe control is red.

| Sample / pin | Run | Paid / completed | Confirmed | Review | Protected | Exact replay |
|---|---|---|---|---|---|---|
| OopsSec `2d530ef` | `run-2413679240` | 107 / 107 | 15 | 101 canonical; 99 displayed | 0 | 107/107 |
| vuln-nextjs `ea10efb` | `run-2372184294` | 42 / 42 | 10 | 33 | 7 | 42/42 |

OopsSec retains 9 unassessed outbound observations (two grouped in HTML); the lab retains 8 API
data-transfer observations with no rendering claim. These are intentionally not judged. Practice
observations are separate (29 / 5). OopsSec remains clean at its pin; the lab has no tracked changes
and its pre-existing ignored outputs remain unchanged. Only lab documentation changed since `022a863`.
Raw runs and traces are retained outside worktrees under `_test-findings/nextjs-pr18-closeout/`.
Public metadata records source hashes, target/scanner pins and full assessment coverage.

**Verification.** `go test ./...`, `go test -race ./... -count=1`, `go vet ./...`, `go build ./...`,
`gofmt -l cmd internal` all pass (Go 1.27.3; isolated writable Go cache; local HTTP stub access enabled
for test suites). Both real-sample parser answer-key tests pass. Fresh exact replay is 149/149 with
zero mismatches or missing traces. Offline refresh succeeds for both samples; public path, local-link,
JSON/SARIF parsing, canonical-evidence preservation and HTML count/grouping checks pass. A browser
preview could not open local file URLs under the browser policy; HTML was checked structurally.
Human acceptance and merge remain the owner step; the worktree is retained.

**Worktree closeout.** The assigned checkout is `<container>/nextjs-support-mvp`, branch
`nextjs-support-mvp`, in the existing `.bare/` sibling structure. All completed work and ignored
handoff/verification records are present there. The redundant nested checkout and stale temporary
registration were removed. `AGENTS.md` now prohibits worktrees outside this structure, and the
orientation links to that rule. Fresh offline scans, both sample gates, exact replay (149/149),
`go vet` and the full test suite were rerun successfully from the corrected checkout. No additional
paid calls were made. The PR's existing remote head is retained until human merge.

## Implementation And Review Change Log

### 2026-11-16 — Complete N5 sample publication

**Source.** Owner request to close PR #18, publish both Next.js sample reports, and perform full paid scans.
**Changed sections.** N5 scope row and sample publication closeout (§8).
**Rationale.** Saved-run publication alone did not satisfy the owner's request for current full results.
**Summary.** Added bounded fresh all-family paid scans, public reports, guides and provenance to N5 acceptance.
**Verification impact.** Exact replay, source-pin/state checks, export consistency and full offline contributor checks.

### 2026-11-16 — Enforce the assigned bare-worktree structure

**Source.** Owner correction of the local worktree and explicit restriction against worktrees outside the existing `.bare/` structure.
**Changed sections.** Status and worktree closeout; `AGENTS.md` worktree location; agent orientation and active branch references.
**Rationale.** An older handoff named a nested checkout instead of the assigned sibling worktree.
**Summary.** Moved the completed state into the assigned checkout, preserved execution records, removed redundant/stale worktree registrations, and made the location rule explicit.
**Verification impact.** Rebuilt and reran offline scans, sample gates, all paid-decision replays and the full test suite from the correct sibling checkout; no scanner-code change or new paid calls.
