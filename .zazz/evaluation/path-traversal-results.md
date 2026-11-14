# Path traversal evaluation — implementation checkpoint

## Continuation checkpoint — final verification paused

The owner requested stopping tests and committing/pushing the current improvements before the session
limit. The earlier evidence below remains a historical verified checkpoint; `observed.json` describes
that earlier run. The current matrix adds expected Juice Shop positives whose **fresh live judgments
are still pending**, not claimed as detected live.

The continuation implemented shared rate/spend flags and environment configuration, general path-only
chain/export/mount/immediate-invocation acquisition, and `unzipper` entry-write / `hbs` layout contracts.
Scoped limiter/CLI race tests and expanded parser/policy/report tests passed. An intermediate full race
run exposed a missing substring-guard enum case; it was stopped, the case was corrected, and targeted
policy/parser tests passed. **The final full suite was not rerun**, per the owner's request. An earlier
continuation compatibility run preserved every existing non-path use/entry and added two path-only
Juice Shop entries; that comparison predates the last edits and needs a final rerun.

All previously unjudged VulnPy contexts have now been assessed: all 140 archive-open contexts were
confirmed across replay/new calls, and all 64 WSGI template contexts remain Review. The original 56
`open`/`io.open` contexts were already confirmed. No statuses are derived from representative contexts.
Final replay onto the latest code remains pending. The two new batches used 146 fresh requests with
zero failures; two additional old template traces matched exactly, reducing the expected fresh count.

Current ledger: **408 known attempts, 405 successes, 3 earlier free-tier failures; 5,702,950 recorded
input tokens, zero output tokens; at most one separately reserved interrupted request**. Pricing all
recorded input as paid at $0.10/million would be about **$0.5703**, not an invoice. The owner authorizes
up to $10; the evaluation harness stayed below its tighter local $1 guard.

[Continuation accounting and pending work](path-traversal/continuation.json) preserves the distinction
between the completed live work and unverified implementation. New VulnPy bundles:

| Context group | JSON | HTML | SARIF |
|---|---|---|---|
| archive | [JSON](../../../_test-findings/vulnpy/run-2346745897/findings.json) | [HTML](../../../_test-findings/vulnpy/run-2346745897/findings.html) | [SARIF](../../../_test-findings/vulnpy/run-2346745897/findings.sarif) |
| template | [JSON](../../../_test-findings/vulnpy/run-3677647146/findings.json) | [HTML](../../../_test-findings/vulnpy/run-3677647146/findings.html) | [SARIF](../../../_test-findings/vulnpy/run-3677647146/findings.sarif) |

## Scope and outcome

Evaluation on 2026-11-14 uses `gemini-decision-1` only, protocol `path-components-v1`, on the eight pinned
sample repositories and portable TypeScript/Python fixtures. This is a verified implementation checkpoint,
not final acceptance: two Juice Shop operations remain uncovered, 148 repeated VulnPy contexts remain
unjudged, and one protected fixture remains Review after a conservative model disagreement.

The independent [source matrix](path-traversal/matrix.json) owns expectations, revisions, source hashes,
POSIX assumptions and corrections; [observations](path-traversal/observed.json) records every scored row,
fixture outcome, component version/digest, ledger batch and report bundle. Labels never enter model input.
The original matrix predates tuning. Supplementary profile-image writer JS-PATH-N05 is explicitly marked
as source-reviewed after the scan located that operation; it was not relabeled from the model answer.

There are 201 positive sample invocation contexts over 12 distinct sink sites: 116 are confirmed and 85
are structurally detected but unjudged. All four sample protected contexts are protected. Eleven sample
contexts are Review (including the WSGI template and two profile-image writers); another 63 WSGI contexts
are unjudged. No unjudged record is counted as safe, protected or a successful live detection.

## Observed versus expected

Counts are invocation contexts, not unique defects. “Not run” means structural evidence exists but no
live judgment was selected for that context. The tar/bz2 batch judged one context per adapter registration
for each sink; it did not derive judgments for the other contexts.

| Matrix row | Target | Observed |
|---|---|---|
| TS-PATH-01 | vulnerable-typescript-app | 1 confirmed_vulnerability |
| FLASK-PATH-01 | vulnerable-flask-app | 1 confirmed_vulnerability |
| FLASK-PATH-02 | vulnerable-flask-app | 1 confirmed_vulnerability |
| VP-PATH-IO-OPEN | vulnpy | 28 confirmed_vulnerability |
| VP-PATH-OPEN | vulnpy | 28 confirmed_vulnerability |
| TB-PATH-UPLOAD | ThreatByte | 1 confirmed_vulnerability |
| GOOF-PATH-ZIPSLIP | nodejs-goof | 1 confirmed_vulnerability |
| VP-PATH-TAR-BZ2 | vulnpy | 55 confirmed_vulnerability, 85 not_run |
| FLASK-PATH-N-UPLOAD | vulnerable-flask-app | 1 protected_for_claim |
| TB-PATH-P-SEND | ThreatByte | 3 protected_for_claim |
| VP-PATH-U01 | vulnpy | 1 needs_evidence, 63 not_run |
| JS-PATH-FIXKEY | juice-shop | 1 needs_evidence |
| JS-PATH-SNIPPETKEY | juice-shop | 1 needs_evidence |
| JS-PATH-INFRA | juice-shop | 1 needs_evidence |
| TB-PATH-REMOVE | ThreatByte | 1 needs_evidence |
| JS-PATH-SENDFILE | juice-shop | 4 needs_evidence |
| GOOF-PATH-N01 | nodejs-goof | no candidate |
| DEMO-PATH-N01 | vuln-demo-app | no candidate |
| INSECURE-PATH-N01 | python-insecure-app | no candidate |
| JS-PATH-N01 | juice-shop | no candidate |
| JS-PATH-N02 | juice-shop | no candidate |
| JS-PATH-N03 | juice-shop | no candidate |
| JS-PATH-N04 | juice-shop | 1 needs_evidence |
| VP-PATH-N01 | vulnpy | no candidate |
| TB-PATH-N01 | ThreatByte | no candidate |
| JS-PATH-N05 | juice-shop | 1 needs_evidence |
| JS-ZIPSLIP-JUICE | juice-shop | not covered |
| JS-LFR-RENDER-JUICE | juice-shop | not covered |

Every scored sample row matches its permitted status for the judged contexts; the positive matrix's
full-context live expectation is still incomplete for the 85 unjudged archive-open contexts. The 63
unjudged WSGI templates likewise do not satisfy a full-context live check.

**WSGI correction.** VulnPy's WSGI adapter selects a registry key by equality against a component of
`PATH_INFO`, unlike the ten other adapters. Its template read is Review, not confirmed or protected;
non-WSGI template contexts produce no request-path candidate. The old label and its source-based
correction remain in the matrix.

Historical deferred rows retain their initial-scope explanations and point to their current scored rows:
Express send-file → JS-PATH-SENDFILE; goof extraction → GOOF-PATH-ZIPSLIP; Python archive opens →
VP-PATH-TAR-BZ2; Flask uploads/sends/removal → the corresponding positive/protected/unknown rows above.
The Juice Shop extraction and render rows remain explicitly uncovered.

## Portable controls

All 68 fixture candidates were judged: 40/40 vulnerable controls confirmed; 14/15 protected controls
protected; 12 unresolved controls stayed Review and one bare-prefix control became poor practice.
`python /p/prefix-boundary` is the one disagreement: scanner facts establish the boundary guard, but the
model answered traversal=unknown, containment=lexical_boundary, coverage=complete. Evidence validation
kept it at `needs_evidence`. The expectation remains protected; it was not edited to match the model.
There are no false confirmed vulnerabilities or false protections in these labeled fixtures.

The [per-route observations](path-traversal/observed.json) include all fixture answers. They cover allow-list,
separator boundary, relative/commonpath, realpath, secure_filename, framework roots, send_from_directory,
local helper guards, unknown helpers, basename reduction, registry selection and fake sanitizers.
No-candidate controls (constant paths, content-only writes, shadowed bindings and stored values) are
verified by parser regression tables rather than counted as model requests.

## Requests, rate limits and spending
Recorded attempts: **262** (259 successful and 3 failed); **3,098,476 input tokens**, **0 output tokens**. There is also **at most one possible in-flight request** from the interrupted batch; its usage is unknown.

The three failures were earlier free-tier HTTP 429 responses identifying the 50,000-input-token/minute
window. Failed attempts count against the cap. There were no automatic retries or provider/model fallback.
The owner then upgraded to paid billing and explicitly authorized the remaining source transfer to Google.
The three resumed batches made 109 successful requests with zero failures, paced at 600,000 input
TPM and separated by 65-second cooldowns. This verifies that pacing for these batches, not a measured
maximum project quota. Google's published Tier 1 limits are 1,000,000 input TPM and 1,500 RPM; active
project limits may differ ([Google limits](https://aistudio.google.com/docs/rate-limits#gemini-decision)).

The slow VulnPy process was stopped at the owner's request. Fourteen completed responses (221,021 input
tokens) were recovered from traces into an explicit recovery ledger row. One possibly in-flight request
is reserved by reducing subsequent request allowance from 500 to 499; it is not invented as a known
success or failure. The interrupted batch's replay progress was unflushed and is not reconstructed.

The owner authorized up to $10. The ignored evaluation harness retained a tighter local $1 ceiling:
10 million input tokens at the published $0.10/million, reserving the model's maximum 262,144-token
context before a request and for failed/possibly in-flight requests. This is local evaluation tooling,
not yet a product feature. Product controls are requested under the
[shared limits contract](../specifications/decision-model-limits.md).
At [Google's published input price](https://aistudio.google.com/docs/pricing#gemini-decision), all recorded tokens priced as paid would be approximately **$0.3098**, plus at most $0.0263 for the interrupted request at maximum context. Earlier free-tier usage was free; this calculation is not an invoice or the provider's actual billed total.

Ledger batches (replay counts below exclude the separate final replay ledger):

| Batch | Live attempts | Replayed | Failed | Input tokens |
|---|---:|---:|---:|---:|
| pt-01-ts | 1 | 0 | 0 | 10,539 |
| pt-02-vulnerable-flask-app | 2 | 0 | 0 | 14,354 |
| pt-02-juice-shop | 3 | 0 | 0 | 44,675 |
| pt-03-vulnpy-pt | 1 | 0 | 1 | 0 |
| pt-04-vulnpy-pt-paced | 56 | 0 | 0 | 886,359 |
| pt-05-vulnpy-templating-sample | 3 | 0 | 0 | 64,544 |
| pt-06-typescript-fixture | 4 | 0 | 1 | 24,848 |
| pt-06-python-fixture | 1 | 0 | 1 | 0 |
| pt-07-typescript-fixture | 16 | 3 | 0 | 143,723 |
| pt-07-python-fixture | 22 | 0 | 0 | 165,103 |
| pt-08-typescript | 7 | 12 | 0 | 67,820 |
| pt-08-python | 7 | 15 | 0 | 55,134 |
| pt-08-juice | 2 | 1 | 0 | 31,651 |
| pt-f1-vulnerable-typescript-app | 0 | 1 | 0 | 0 |
| pt-f1-vulnerable-flask-app | 1 | 2 | 0 | 9,235 |
| pt-f1-nodejs-goof | 1 | 0 | 0 | 16,167 |
| pt-f1-ThreatByte | 5 | 0 | 0 | 46,407 |
| pt-f1-juice-shop | 7 | 2 | 0 | 109,790 |
| pt-f2-vulnpy-interrupted-recovered | 14 | 0 | 0 | 221,021 |
| pt-paid-vulnpy | 41 | 71 | 0 | 634,256 |
| pt-paid-typescript | 32 | 0 | 0 | 280,662 |
| pt-paid-python | 36 | 0 | 0 | 272,188 |

## Verification and provenance

- Native Go 1.27.3 (compatible patch for `go.mod` 1.27.2), `GOFLAGS=-buildvcs=false`.
- `go build ./...`, `go vet ./...`, and `gofmt -l cmd internal`: passed; format check emitted nothing.
- `go test -race ./... -count=1`: passed, all nine packages; parse 491.091 seconds. The first sandbox
  attempt could not bind local HTTP listeners; the successful rerun exited 0 outside that restriction.
  Raw logs and the successful nine-package extract are retained in ignored execution artifacts.
- Existing-family comparison against `4d7e0612a47b652ce238cbe6fe70272aecc0a4f9`: ADDITIVE across all eight
  samples; 0 changed/missing/extra non-path uses, with every entry equal. Frozen outgoing-component tests
  also preserve existing payload evidence; only the shared finding-type glossary changes.
- Final exact replay: **199 matching responses, 0 live requests**, across eight apps and both fixture roots.
  A zero-live cap and a noncredential placeholder prevent any paid call if replay fails.
- JSON/HTML/SARIF parity: checked every path record in the final bundles for canonical finding, title,
  location/use identity, remediation and CWE-22 on confirmed findings; SARIF includes the Zip Slip variant.
- All eight sample HEAD pins, recorded source hashes and clean status including ignored files verified.
  No app was executed, changed or installed. Final documentation/link checks accompany the checkpoint.

Verified contract IDs: `node-fs-file-v1`, `python-open-file-v1`, `python-pathlib-file-v1`,
`python-archive-open-v1`, `werkzeug-file-save-v1`, `express-send-file-v1`, `adm-zip-extract-v1`,
`python-os-file-v1`, `flask-send-file-v1`. Component versions and SHA-256 digests are recorded in
[observations](path-traversal/observed.json); exact request digests, selected components and source
snapshot hashes remain in canonical findings and exact traces. Matrix source hashes pin the witnesses.

## Local reports and artifacts

Links require the local container layout: the worktree and `_test-findings` are siblings. These artifacts
are not committed. Non-path families are structurally inventoried but were not live-judged by this harness.

| Target | JSON | HTML | SARIF |
|---|---|---|---|
| vuln-demo-app | [JSON](../../../_test-findings/vuln-demo-app/run-846127818/findings.json) | [HTML](../../../_test-findings/vuln-demo-app/run-846127818/findings.html) | [SARIF](../../../_test-findings/vuln-demo-app/run-846127818/findings.sarif) |
| vulnerable-typescript-app | [JSON](../../../_test-findings/vulnerable-typescript-app/run-1444166800/findings.json) | [HTML](../../../_test-findings/vulnerable-typescript-app/run-1444166800/findings.html) | [SARIF](../../../_test-findings/vulnerable-typescript-app/run-1444166800/findings.sarif) |
| nodejs-goof | [JSON](../../../_test-findings/nodejs-goof/run-18027386/findings.json) | [HTML](../../../_test-findings/nodejs-goof/run-18027386/findings.html) | [SARIF](../../../_test-findings/nodejs-goof/run-18027386/findings.sarif) |
| juice-shop | [JSON](../../../_test-findings/juice-shop/run-2335905082/findings.json) | [HTML](../../../_test-findings/juice-shop/run-2335905082/findings.html) | [SARIF](../../../_test-findings/juice-shop/run-2335905082/findings.sarif) |
| vulnpy | [JSON](../../../_test-findings/vulnpy/run-2256299594/findings.json) | [HTML](../../../_test-findings/vulnpy/run-2256299594/findings.html) | [SARIF](../../../_test-findings/vulnpy/run-2256299594/findings.sarif) |
| ThreatByte | [JSON](../../../_test-findings/ThreatByte/run-280363360/findings.json) | [HTML](../../../_test-findings/ThreatByte/run-280363360/findings.html) | [SARIF](../../../_test-findings/ThreatByte/run-280363360/findings.sarif) |
| python-insecure-app | [JSON](../../../_test-findings/python-insecure-app/run-4224359430/findings.json) | [HTML](../../../_test-findings/python-insecure-app/run-4224359430/findings.html) | [SARIF](../../../_test-findings/python-insecure-app/run-4224359430/findings.sarif) |
| vulnerable-flask-app | [JSON](../../../_test-findings/vulnerable-flask-app/run-2075833830/findings.json) | [HTML](../../../_test-findings/vulnerable-flask-app/run-2075833830/findings.html) | [SARIF](../../../_test-findings/vulnerable-flask-app/run-2075833830/findings.sarif) |
| typescript-fixture | [JSON](../../../_test-findings/path-fixtures/path-traversal/run-655178052/findings.json) | [HTML](../../../_test-findings/path-fixtures/path-traversal/run-655178052/findings.html) | [SARIF](../../../_test-findings/path-fixtures/path-traversal/run-655178052/findings.sarif) |
| python-fixture | [JSON](../../../_test-findings/path-fixtures/path-traversal/run-687334135/findings.json) | [HTML](../../../_test-findings/path-fixtures/path-traversal/run-687334135/findings.html) | [SARIF](../../../_test-findings/path-fixtures/path-traversal/run-687334135/findings.sarif) |

Live traces: `_test-findings/<app>/path-traces/<batch>/`, `_test-findings/path-fixtures/traces-*`, and
`_test-findings/<language>-fixture/path-traces/pt-paid-<language>/`. Accounting:
`_test-findings/path-traversal-ledger.jsonl` and `path-traversal-replay-ledger.jsonl`.
Ignored local tools, individual command logs, bundle manifest and review handoff live in
`.zazz/ephemeral/`; durable results and expectations live here.

## Remaining work and limits

The owner requested these improvements after verification and authorized a checkpoint before implementation:

- Juice Shop `routes/fileUpload.ts:34`: the request-supplied ZIP's entry name reaches a write stream,
  but its handler is a middle route-chain element. Needs general source-backed middleware handler entries,
  unzipper entry-name flow and containment evidence; no target-specific rules.
- Juice Shop `routes/dataErasure.ts:104-110`: request `layout` reaches `res.render`; needs verified `hbs`
  engine registration and an engine-specific layout-read contract, including options spread/override order.
- Judge all 148 remaining VulnPy contexts rather than imply outcomes from representative contexts.
- Investigate the conservative Python boundary fixture disagreement without weakening evidence gates.
- Implement shared user-facing rate/spend configuration and document it in README/setup and the plan.

There is no claim that all path traversal in arbitrary code is solved, no provider-equivalence claim,
and no runtime exploitation claim. Windows semantics, symbolic-link/race state, second-order storage
flows, unmodeled libraries and unverified dynamic middleware/helpers remain explicit limits. Human
review is still required. Future changed requests require fresh judgments; unchanged requests replay exactly.
