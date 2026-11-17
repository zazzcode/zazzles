# Analyzer protection and flow coverage results

**Worktree/branch:** `nextjs-analyzer-protection-flow`, based on `8d4013d` (PR #19).
**Contract:** [analyzer protection and flow coverage](../specifications/analyzer-protection-and-flow-coverage.md).
**Inventory:** [P0 inventory and selection](analyzer-protection-and-flow-inventory.md).
**Date:** 2026-11-16. Offline measurement plus a capped paid run of 10 requests (see *Paid evaluation*).

## Method

The baseline scanner was built from unmodified `8d4013d`; the after scanner from this worktree.
Both scanned all eight pinned targets offline into `<container>/_test-findings/analyzer-protection/`
(`baseline/`, `after/`). Records are matched by kind, sink file and byte, entry and invocation
context. The new report fields (`assessment_state`, `blocking_evidence`, `linked_use_ids`) are
projected away before byte comparison; every other difference is listed below. The comparison
script and full verbose output are retained beside the scans.

Offline scans never produce Confirmed, and code/redirect Protected requires a judged answer. The
offline matrix therefore measures what the scanner establishes: candidate presence, per-path
protection (`raw`/`guarded`/`unknown`), blockers and facts. Paid confirmation of changed evidence is
not yet authorized (see *Paid evaluation*).

## Delivered selections

| Sel | Item | Change | Paired tests |
|---|---|---|---|
| S1 | P1 | Flag-only or after-call URL tests are non-enforcing: not a transfer or restriction | `TestP1NonEnforcingURLCheck`, `TestP1NonEnforcingClassifier` |
| S2 | P1 | `safeParse(req.body)` field reads keep request-source evidence | `TestP1ZodSafeParseFieldSource` |
| S3 | P1 | Catch-all `join` modeled so a `..` reject guard attaches; Juice `/`-reject part skipped (below) | `TestP1CatchAllJoinGuard` |
| S4 | P1 | Module/imported `const` literal chains fold to a constant destination | `TestP1ModuleConstDestinationOrigin` |
| S5 | P2 | Fixed-by-construction redirect destinations are excluded | `TestP2RedirectFixedOrigin` |
| S6 | P2 | Per-path redirect bypass/exclusion facts; judge refuses Protected while a bypass form is recorded | `TestP2RedirectPredicateFacts`, `TestP2RedirectPredicatePolicy` |
| S7 | P3 | Inert or after-sink loops no longer add `control_flow_unresolved` | `TestP3LoopsAroundSsrfSink` |
| S8 | P3 | Python decoders/query parsers keep provenance; raw stays raw | `TestP3PythonDecodeCalls`, `TestP3PythonAsyncMultiReturnHelper`, `TestP3DecodeKeepsRawXSS` |
| S9 | P3 | Keyed reads of a server-owned store yield stored state of unresolved origin, not the key's taint | `TestP3KeyedStoreRead`, `TestP3KeyedStoreSsrf`, `TestP3KeyedStoreSecondOrder` |
| S10 | P4 | Per-operand SQLite/PostgreSQL quote-doubling facts in Prisma raw SQL | `TestP4SQLLiteralEscapeFacts`, `TestP4SQLLiteralEscapeKeepsRawRecord` |
| S11 | P4 | Sequelize write→read link for a code-family operand | `TestP4StoredCodeOperandLink` |
| S12 | P5 | `assessment_state`, `blocking_evidence`, `linked_use_ids`; no duplicate XSS at a browser `eval` | `TestP5*` (report and parse) |

Each paired test holds a genuine safe control and vulnerable siblings (guard bypass, reassignment,
mixed raw operand, exceptional flow or unprotected branch). No sibling becomes guarded or Protected.

## Per-case before/after (inventory rows)

| Row | Sample / location | Before (offline) | After (offline) | Sel |
|---|---|---|---|---|
| O-SSRF-02 | OopsSec `ai-assistant/route.ts:69` SSRF | raw, 5 blockers (3 loop) | raw, **0 blockers** | S7 |
| O-PATH-R01 | OopsSec `uploads/[...path]/route.ts:42` | path `unknown` (join), 1 blocker | path **guarded** (`..` test), 0 blockers | S3 |
| O-REDIR-vcs | OopsSec `vcs/[[...path]]/route.ts:95` | redirect candidate, Review | **no candidate** (fixed `/.git/` path in `new URL`) | S5 |
| O-REDIR-checkout-a/b | OopsSec `CheckoutClient.tsx:147` | 2 redirect candidates | **no candidate** (fixed ternary) | S5 |
| L-REDIR-001-safe | Lab `secure/redirect.js` | Review | Review + `redirect_predicate_bypass: slash_backslash` | S6 |
| O-SQL-03 | OopsSec `tracking/route.ts:54` | poor practice, no operand facts | poor practice; `userAgent`/`visitPath`/`visitorSessionId` quote-doubled (sqlite), `ip` raw | S10 |
| O-SSRF-const-a | OopsSec `lib/github.ts:19` | destination `unestablished` | destination **constant** | S4 |
| O-SSRF-mistral | OopsSec `ai-assistant/route.ts:149` | Review | Review, explained as constant destination | S12 |
| L-SQL-003-zod | Lab `zod/notes.js:19` | no `input_source` | `input_source` via field projection | S2 |
| L-JS-001 | Lab `eval-injection.js:8` | code record + duplicate dom-xss | code record only | S12 |
| O-XSS-05 | OopsSec `LoginForm.tsx:37` | redirect + XSS, unlinked | both kept, each lists the other | S12 |
| B-JS-13 | Juice `profileImageUrlUpload.ts:24` SSRF | flag-only `match` listed as transfer | no transfer, raw, no guard | S1 |
| B-JS-16 | Juice `orderHistory.ts:17`, `dataExport.ts:33,40` NoSQL | 3 candidates (key taint) | **no candidate** (stored-only operand, as for ORM reads) | S9 |
| B-JS-26 | Juice `dataErasureForm.hbs:38` unquoted `{{userEmail}}` | Review (key taint) | **Review, stored**, `storage_origin_unresolved` | S9 |
| B-JS-04 | Juice `userProfile.ts:65` eval | storage read, no writer | writer `req.body.username` → stored → read linked; Review | S11 |
| B-VP-02/06 | VulnPy Django ASGI/WSGI path and SQL | 28 path + 15 SQL contexts with unresolved decode gaps | gaps removed; statuses unchanged | S8 |
| B-VP-01 | VulnPy code ×90 | unjudged, indistinguishable | `assessment_state: not_run` | S12 |

Lab, OopsSec and Juice zod/products, `stored.js` and two Juice path records change identity because
their dependency transfers changed (field projection, keyed store or loop gaps); their statuses are
unchanged. Path records `profileImageFileUpload.ts:42` and `profileImageUrlUpload.ts:29` lose two
blockers each through the same gap removal and remain Review.

## Sample totals

| Sample | Records before → after | Identical | Changed | Removed / added | Status change |
|---|---:|---:|---:|---|---|
| vuln-demo-app | 19 → 19 | 18 | 1 (summary sentence) | 0 / 0 | none |
| vulnerable-typescript-app | 26 → 26 | 26 | 0 | 0 / 0 | none |
| nodejs-goof | 32 → 32 | 32 | 0 | 0 / 0 | none |
| Juice Shop | 251 → 251 | 236 | 9 | 6 / 6 (3 re-keyed both ways) | none; 3 NoSQL removed, 3 records added (S9) |
| vuln-nextjs lab | 55 → 54 | 50 | 4 | 1 / 0 | 1 duplicate poor-practice XSS removed |
| OopsSec | 128 → 125 | 119 | 6 | 3 / 0 | 3 redirect Review removed |
| Commerce | 23 → 23 | 23 | 0 | 0 / 0 | none; zero red |
| VulnPy | 3350 → 3350 | 3270 | 80 | 0 / 0 | none |

## Express regression comparison

Against the baseline JSON (also kept as `express-regression/*-before.json` and `*-after.json`):

- **vulnerable-typescript-app, nodejs-goof:** byte-identical after projection.
- **vuln-demo-app:** one outbound summary gains the constant-destination sentence (S12).
- **Juice Shop:** intended changes only.
  - **S9 removes 3 NoSQL Review records:** `orderHistory.ts:17`, `dataExport.ts:33` and `:40`. Their
    email operand is now stored state, and the NoSQL adapter forms no candidate from a stored-only
    operand (the same existing rule as for ORM reads).
  - **S9 keeps the stored renders as Review:** `dataErasureForm.hbs:38` (B-JS-26) and the
    `currentUser.ts` JSON data record now carry a `keyed_store:` storage read with no writer, so they
    are stored claims with `storage_origin_unresolved`. The `dataExport` data record loses its
    session-token dependencies, and an `orderHistory.ts` JSON data record is added on the same basis.
  - **Two field observations added:** `req.headers.authorization` at `orderHistory.ts:13` and
    `dataExport.ts:18` now appear as request-field validation Review records. The header is only a
    store lookup key now, so it is no longer folded into the NoSQL candidates.
  - **`dataExport` is re-keyed:** its invocation context changed, so its outbound, data and validation
    records are matched as removed plus added.
  - **S11** links the eval writer. **S1** removes the flag-only transfer. **S7** removes path-record gaps.

**B-JS-26 and second-order store values:** a first S9 version removed this must-stay-Review record,
because the session-token key had been its only source. The owner asked for a general fix, not a
Juice-specific one, so it was changed:
- **Keyed store reads:** these are now a stored value whose writer is not modeled.
- **One rule for every family and language** (`blockUnlinkedStoredOrigins`): any non-rendering claim
  fed only by unlinked storage reads gets `storage_origin_unresolved`. Rendering claims already had
  this rule.
- **Result:** such claims stay visible as Review and cannot be Confirmed from the stored value. A
  real second-order SQL use through a session store stays a candidate (`TestP3KeyedStoreSecondOrder`).
- **Effect on the eight samples:** no existing record changes, because none is fed only by unlinked
  storage reads.

Linking the actual writers across requests is handed to proposal 2:
- registration → ORM row → login store → render;
- direct writes from another route;
- exported stores and `Map` stores.

## Zero false Protected and false Confirmed

No record moved to Protected or Confirmed offline (deterministic `protected_for_claim` counts are
unchanged: lab 3, Goof 2). Judge policy now refuses redirect Protected while a bypass form is
recorded. Every paired sibling stays raw/unknown/unguarded. Removed candidates are fixed-origin
destinations, a duplicate claim or stored-only NoSQL operands, never request-controlled operands.

## Integration fixes during review

- `xss_claims.go`: P5's duplicate suppression initially covered string timers and `Function`,
  contradicting `TestBrowserSourceSinkControls`. It now applies to browser `eval` only, as
  documented in the code-injection guide.
- `p3_python_decode.go`: the decoder turned an existing `raw` protection into `unknown`, which
  regressed the VulnPy WSGI reflected XSS (`wsgi/app.py:26`, raw → unknown). Raw and unknown now pass
  through; `TestP3DecodeKeepsRawXSS` fails against the previous rule.
- Lead-owned hooks: `controlContextAnchored` in `claim_assembly.go`, `keyedStoreValue`/`noteStoreWrite`
  in `flow.go`, `blockUnlinkedStoredOrigins` (new `storage_origin.go`) in `analysis.go`, `sqlLiteralEscapeFacts` in `query_evidence.go`, and the shared finding fields in
  `internal/analysis/findings.go`.
- `TestOutboundComponentEvidenceParity` hashes updated after a HEAD-overlay dump showed the only
  differences are the new finding fields and the constant-destination sentence.

## Not delivered and handed to proposal 2

- S3 second part: Juice `fileServer.ts` goes through `cutOffPoisonNullByte` and a nested helper;
  the other three Juice servers were already guarded (`separator_text`).
- S4 for OopsSec `app/page.tsx` (`baseUrl` from a function) and `INTERNAL_MCP_URL`
  (`process.env || literal`): correctly not folded.
- S9 limits: cross-request writer tracking through in-memory stores (added to the proposal 2 draft),
  writes through an exported object from another module, `Map.get`/`set` stores.
- Language scope: S1–S7, S9–S11 are JS/TS adapter rules; S8 is Python. Python equivalents (module
  dict stores, redirect predicate facts, non-enforcing checks, constant folding) are not implemented.
  The stored-origin rule and S12 reporting are language-neutral.
- S10 facts are not yet read by judge or report; S6 facts are JS/TS only.
- B-JS-04: the `/#{(.*)}/` match that enables the eval is classified as a guard; B-JS-13: unrelated
  factory/heap-write blockers; O-PATH-R01: model answer contradicts the guard facts.
- Deferred inventory items: MarsDB equality selectors (suspected older false Confirmed B-JS-15),
  argument-inert executables (owner policy), config-field fixed origins, finite-allowlist ternaries,
  base64/hbs encoders, VulnPy SSRF candidates, WSGI `getattr` dispatch (64 path contexts).

## Verification

| Gate | Result |
|---|---|
| `gofmt -l` on changed/new Go files | clean |
| `go vet ./...`, `go build ./...` | pass |
| `go test -race ./... -count=1` with `ZAZZLES_VULN_NEXTJS`/`ZAZZLES_NEXTJS_SAMPLE` | pass (all 9 packages, exit 0) |
| `TestNextJSVulnLab`, `TestNextJSOopsStoreAnswerKey` | both pass (run with real samples) |
| Four Express comparisons | as listed above |
| Sample integrity | all seven Git samples at their pins with no tracked changes; Commerce archive unmodified |

Log: `.zazz/ephemeral/race-closeout3.log` (ignored; final tree).

## Paid evaluation

The owner authorized a paid run "as required". Following the live-call rules, the lead fixed an
explicit cap of 9 requests (one per changed case), plus 1 rejudge after a fix, for **10 requests
sent** to OpenAI `gpt-6-luna`.
- **Selection and keys:** each run used `--judge-limit 1`, `--only-family` and `--entry-id`, and each
  selection was checked offline to contain exactly one judgeable use. Only `OPENAI_API_KEY` was
  passed, through the process environment, not command arguments.
- **No retries or fallback.** Ledger, runs and traces are under
  `<container>/_test-findings/analyzer-protection/paid/`.

| Case | Row | Outcome | Expected |
|---|---|---|---|
| OopsSec AI-assistant SSRF | O-SSRF-02 | **Confirmed** (full URL, no restriction) | Confirmed: previously the only blocked required positive |
| OopsSec tracking SQL | O-SQL-03 | **Confirmed** | Confirmed (raw `ip` beside escaped operands) |
| VulnPy Django path (`pt.py:32`) | B-VP-02 | **Confirmed** | Confirmed |
| VulnPy SQL (`sqli.py:37`) | B-VP-06 | **Confirmed** | Confirmed |
| Lab zod SQL (`zod/notes.js:19`) | L-SQL-003-zod | **Protected** | Protected (genuine safe control) |
| Lab safe-labelled redirect | L-REDIR-001-safe | Review (`same_site_relative` answer refused) | Review: permits `/\host` |
| OopsSec uploads catch-all | O-PATH-R01 | Review (`path_answers_inconsistent`) | Protected was possible; the model claimed traversal against the guard facts and policy refused it |
| Juice profile-image SSRF | B-JS-13 | Review (`unresolved_factory`, `unsupported_write`) | Confirmed not reached: unrelated factory/heap blockers remain |
| Juice stored-username eval | B-JS-04 | Review (answers incomplete) | Confirmed not reached: pre-existing `/#{(.*)}/` match is still classified as a guard |

**No false Confirmed and no false Protected.** All 9 final judgments pass exact replay against fresh
source (`TestReplaySavedRun`: 9 replayed, 0 mismatched, 0 trace-absent).

Two process defects were found and fixed during the run:
- **Fact codes without notes (no request sent).** `redirect_predicate_bypass` and
  `sql_literal_quote_doubling` had no note in `internal/guidelines/facts.md`, so request building
  refused them before sending.
  - Four notes were added. Notes are sent only for codes in use, so existing requests are
    byte-identical and the version stays 1.
  - `TestProducedFactCodesHaveNotes` now scans producers for coded facts offline. It fails if a note
    is removed.
- **Stored-code operand paths.** The first B-JS-04 judgment returned `code_facts_invalid`: the P4 link
  replaced one stored read with writer origins without remapping operand paths.
  - `remapCodePaths` gives each origin the replaced read's path, and P4's test now validates the facts.
  - The superseded run is kept beside the final one.

The prior 155/180 spend is unrelated; this run's ledger stands alone.
