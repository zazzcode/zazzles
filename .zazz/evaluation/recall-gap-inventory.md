# Recall gap inventory (architecture phase 5)

[Contract](../specifications/architecture-phase-5-accuracy-gaps.md) ·
[Frozen cases](recall-gap-inventory/cases.json) · [Checker](recall-gap-inventory/check.py) ·
[Sample catalog](../project/vulnerable-sample-apps.md#applications)

This inventory measures whether each source-reviewed expectation in the pinned corpus produces its
candidate, witness or registration outcome offline. It does not measure model assessment. Expected
labels stay outside scanner and model input. Measured 2026-11-19 on scanner `2c65588` (inventory
base, `origin/stage` `927ed7b` plus the spec revision).

## Corpus and pins

All eleven samples were measured. Every checkout was at its pin with an empty
`git status --porcelain --ignored` before and after each scan, except vuln-nextjs. Its owner checkout
is at the pin but holds ignored build output, so it was left untouched and a clean local clone at the
pin was scanned instead. The lab key was read from that clone.

| App | Full pin | Oracle rows |
|---|---|---|
| vuln-demo-app | `d27b35bdd2d599f1f79dace71d5272215df04423` | [Detection guide](vuln-demo-app-detection-guide.md), [catalog](../project/vulnerable-sample-apps.md#vuln-demo-app) |
| vulnerable-typescript-app | `7f8b240a2f02beba099da3632d1ba679ff8bc32f` | [Detection guide](vulnerable-typescript-app-detection-guide.md), [XSS key](../../docs/samples/vulnerable-typescript-app/xss-answer-key.md) |
| nodejs-goof | `add14ba59e98240d9e00a235dd7d42cd61ae9912` | [XSS and reference key](../../docs/samples/nodejs-goof/xss-answer-key.md), [catalog](../project/vulnerable-sample-apps.md#nodejs-goof) |
| juice-shop | `f189f521266f42c6bd05884468292000cee852ed` | [XSS key](../../docs/samples/juice-shop/xss-answer-key.md), [catalog](../project/vulnerable-sample-apps.md#owasp-juice-shop) |
| oss-oopssec-store | `2d530ef3c0e668022c93fd2c03b52eef4691a6c3` | [Detection guide](oss-oopssec-store-detection-guide.md) |
| vuln-nextjs | `ea10efb960d5bf4dbabbfee01dc6e5f881b22898` | Lab `tests/expected-scanner-findings.json` at the pin |
| VulnPy | `b81885e58283a3449b578d20c20557aff637e5ea` | [`cases.json`](../../docs/samples/vulnpy/cases.json) |
| ThreatByte | `ede28f27e7e5061866a67b19b6088df4dd11c569` | [`cases.json`](../../docs/samples/ThreatByte/cases.json) |
| python-insecure-app | `b188493768ca2c1ef003e08148fb2e4577219c36` | [`cases.json`](../../docs/samples/python-insecure-app/cases.json) |
| Vulnerable Flask App | `a67cbe590698dc4a0422f28e2495a40af559e257` | [`cases.json`](../../docs/samples/vulnerable-flask-app/cases.json) |
| DVWA | `a1978a2fed195acd093010af6395f86a281537ca` | [Detection guide](dvwa-detection-guide.md) |

## Reproduce

```bash
go build -o <scratch>/scan ./cmd/scan
```

```bash
env -u OPENAI_API_KEY -u GEMINI_API_KEY -u TYPESAFE_API_KEY <scratch>/scan --analyze --output-dir <container>/_test-findings/<app>/run-phase5-<tag> <sample-root>
```

The bundle lands at `<output-dir>/<target-name>/run-*/findings.json`. Map each app name to its
report in a JSON file, then run:

```bash
python3 .zazz/evaluation/recall-gap-inventory/check.py <reports.json> --lab <vuln-nextjs-at-pin> --json <out.json> --markdown <rows.md>
```

```bash
python3 docs/samples/evaluate-python.py <app> <findings.json>
```

Supporting structural tests, each run against the pinned checkout:

```bash
ZAZZLES_NEXTJS_SAMPLE=<DEV_ROOT>/oss-oopssec-store go test ./internal/langjs -run TestNextJSOopsStoreAnswerKey -count=1
```

```bash
ZAZZLES_VULN_NEXTJS=<vuln-nextjs-at-pin> go test ./internal/langjs -run TestNextJSVulnLab -count=1
```

```bash
ZAZZLES_DVWA=<DEV_ROOT>/zazzcode/DVWA go test ./internal/pipeline -run TestDVWASourceKey -count=1
```

All three pass on the base scanner. The lab test checks 29 supported rows.

## How rows are judged

`cases.json` restates the rows of keys that have no machine-readable form. Python rows come from
each app's `cases.json`, and vuln-nextjs rows from the lab key, both read in place. A candidate
matches on kind and sink file, plus line, entry file or dependency file when the key gives one.
A witness is a dependency whose source is a request, storage, browser, API-response, file or fetched
origin, and it must include the key's source anchor when the key names one. `candidate_with_witness`
also requires no completeness blockers. `review` and `present` rows need only candidate presence,
because their expected outcome depends on assessment. Evaluator limits follow the contract's D-2 table.
Fan-out counts source-matching uses and their distinct entries.

## Results

| Measure | Count | Denominator |
|---|---:|---:|
| Required positives with a candidate | 91 | 91 |
| Required positives with a complete witness | 91 | 91 |
| Review-expected candidates present | 7 | 8 |
| Assessment-dependent rows with a candidate (`present`) | 17 | 17 |
| Registration outcomes resolved (VulnPy) | 4 | 4 |
| Structural controls passing (`bound`, `encoded`, `no_record`, `not_raw`, `not_decisive`, `only_*`) | 30 | 30 |
| Lab controls left to assessment (non-XSS safe controls) | 11 | — |
| Excluded rows, each with a reason | 13 | — |
| All rows | 174 | — |

By tag, `independent` rows have 87 of 88 positive or review candidates present, and `post_delivery`
rows have 11 of 11. Python evaluator: ThreatByte exits 1 with 11/18, and every failure is an
assessment-dependent row (six `validation_enforced`, one `validation_defect`). The other three apps
exit 0 (3/3, 8/8, 10/10).

### Misses

| Case | Outcome | First failing stage | Cause | Evidence |
|---|---|---|---|---|
| `OOPS-XSS-R01` | `missing_candidate` | Sink. The entry `GET /api/vcs/:path*?` and the awaited `params` source resolve | `sink_model` | `app/api/vcs/[[...path]]/route.ts:101` returns `new NextResponse(renderListing(directory, …), { headers: { "Content-Type": "text/html" } })`. A one-line fixture (query → template → `new NextResponse(html, text/html)`) also yields no XSS candidate. The JS adapter models only Express `res.send/write/end` as HTML responses |

No required positive is missing or blocked. No evidence-gap row needs the evidence follow-on.

### Ranked eligible groups

| Rank | Group | Cases recovered | Registrations | Scope | Files (est.) |
|---|---|---:|---:|---|---:|
| 1 | Web-standard `Response`/`NextResponse` constructor with an HTML `Content-Type` as an HTML response sink | 1 (`OOPS-XSS-R01`) | 0 | `internal/langjs` plus the XSS rendering-contract seam in `internal/analysispacks/xss.go` | 4 |

There are no other eligible groups, because no other row misses. The at-risk set is every JS/TS
`xss_candidate` and `xss_data_candidate` row, plus the OopsSec `NextResponse` bodies with JSON, CSV,
PDF and plain-text content types: `mcp-config`, `user/export`, `files`, `hub` and `uploads`. Those
must stay silent.

## Reconciliation of historical claims

| Claim | Historical record | Current measurement | Status |
|---|---|---|---|
| `VP-XSS-JINJA` | [VulnPy guide](vulnpy-detection-guide.md) lists the Environment binding as open | Raw candidate at `apps/templates/jinja/xss.html:30` for `GET /template-xss/jinja`, source `request.args` at `apps/flask_app.py:20`, no blockers. [XSS final evaluation](xss-hardening/final-evaluation.json) records it as confirmed | Delivered; guide corrected |
| TS path traversal, code injection, open redirect | [Catalog](../project/vulnerable-sample-apps.md#vulnerable-typescript-app) says not covered | Witnessed candidates at `src/server.ts:104`, `:137`, `:239`. Not judged in this offline run | Delivered structurally; catalog row corrected |
| vuln-nextjs `JS-001`, `JS-002`, `REDIR-001` | [Lab guide](vuln-nextjs-detection-guide.md) says no analyzer family | `TestNextJSVulnLab` maps CWE-95 and CWE-601 and checks 29 rows, and the checker finds witnessed candidates | Delivered structurally; guide corrected |
| D5, XSS hardening, Next.js, DVWA and Python acceptance rows | Their results records | Every row reproduces offline | No regression observed |

## Observations for follow-on contracts

These rows pass, but they point to precision or Review-burden work outside this delivery. Each one
maps to a row of the contract's §11 follow-on table.

- **Shared PHP render sink fan-out.** DVWA has about 90 raw `xss_candidate` records at
  `dvwa/includes/dvwaPage.inc.php:388`, one per page entry. Pages with no module input reach it only
  through the `theme` and `security` cookies read at `:192` and `:202`. Cookie reflection is a real
  source, but root-sink grouping would make this one defect.
- **Spurious request origin through an API response.** `OOPS-PATH-N01` keeps a path candidate at
  `app/vulnerabilities/[slug]/page.tsx:49` with a request origin. The `unknown_transfer` blocker
  holds it at Review.
- **Seed-only storage reaching raw output.** `DEMO-XSS-N02` (`server.js:280`) is a raw candidate
  from a storage read with no request write. It stays non-decisive, but it adds to Review volume.
- **Unkeyed file-content output.** `src/server.ts:108` sends TS-PATH-01 file content as HTML and is
  blocked Review. It is not in the key.
- **Context fan-out.** VulnPy SQL sinks have 26 uses each, one per entry, which separates
  multi-entry reporting from duplicates.

## Per-row results (base scanner)

| Case | App | Kind | Anchor | Expectation | Tag | Result | Uses / entries | Notes |
|---|---|---|---|---|---|---|---|---|
| DEMO-XSS-01 | vuln-demo-app | xss | `server.js:180` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-XSS-02 | vuln-demo-app | xss | `server.js:190` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-XSS-03 | vuln-demo-app | xss | `server.js:166` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-XSS-04 | vuln-demo-app | xss | `server.js:166` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-XSS-05 | vuln-demo-app | xss | `server.js:236` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-XSS-Q01 | vuln-demo-app |  | | excluded | independent | excluded |  | Qualified: Review or no record is acceptable (engine error text) |
| DEMO-XSS-Q02 | vuln-demo-app |  | | excluded | independent | excluded |  | Qualified: Review or no record is acceptable (network error text) |
| DEMO-XSS-Q03 | vuln-demo-app | xss | `server.js:131` | not_decisive | independent | control_pass | 1 / 1 |  |
| DEMO-XSS-N01 | vuln-demo-app | xss | `server.js:236` | only_sources | independent | control_pass | 1 / 1 |  |
| DEMO-XSS-N02 | vuln-demo-app | xss | `server.js:280` | not_decisive | independent | control_pass | 1 / 1 |  |
| DEMO-XSS-N03 | vuln-demo-app | xss | `server.js` | no_record | independent | control_pass | 0 / 0 |  |
| DEMO-XSS-N04 | vuln-demo-app | xss | `server.js` | only_lines | independent | control_pass | 7 / 6 | lines 131,166,180,190,236,280 |
| DEMO-SQL-01 | vuln-demo-app | sql_query | `server.js:46` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-SQL-02 | vuln-demo-app | sql_query | `server.js:46` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-SQL-03 | vuln-demo-app | sql_query | `server.js:46` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-SQL-04 | vuln-demo-app | sql_query | `server.js:46` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-SQL-05 | vuln-demo-app | sql_query | `server.js:291` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-SQL-N01 | vuln-demo-app | sql_query | `server.js:208` | bound | independent | control_pass | 0 / 0 |  |
| DEMO-SQL-N02 | vuln-demo-app | sql_query | `server.js` | only_lines | independent | control_pass | 5 / 5 | lines 46,291 |
| DEMO-SSRF-01 | vuln-demo-app | ssrf | `server.js:232` | positive | independent | candidate_with_witness | 1 / 1 |  |
| DEMO-IDOR | vuln-demo-app |  | | excluded | independent | excluded |  | out_of_family: IDOR and missing admin authorization |
| TS-XSS-01 | vulnerable-typescript-app | xss | `src/server.ts:117` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-CMDI-01 | vulnerable-typescript-app | command_execution | `src/server.ts:90` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-LOG-01 | vulnerable-typescript-app | log_sink | `src/server.ts:74` | present | independent | candidate_present | 1 / 1 |  |
| TS-PATH-01 | vulnerable-typescript-app | path_traversal | `src/server.ts:104` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-SSRF-01 | vulnerable-typescript-app | ssrf | `src/server.ts:125` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-CODE-01 | vulnerable-typescript-app | code_execution | `src/server.ts:137` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-REDIRECT-01 | vulnerable-typescript-app | open_redirect | `src/server.ts:239` | positive | independent | candidate_with_witness | 1 / 1 |  |
| TS-SQL-N01 | vulnerable-typescript-app | sql_query | `src/server.ts` | only_lines | independent | control_pass | 0 / 0 | lines  |
| TS-XSS-N01 | vulnerable-typescript-app | xss | `src/server.ts` | only_lines | independent | control_pass | 2 / 2 | lines 108,117 |
| TS-OTHER | vulnerable-typescript-app |  | | excluded | independent | excluded |  | out_of_family: AUTH, AUTHZ, IDOR, MASS, SECRET, DISCLOSE, SESSION, ERROR and the nine qualified Review leads (XXE, YAML, PROTOTYPE, REDOS, RANDOM, CORS, ENV, UPLOAD, CLIENT) |
| GOOF-XSS-01 | nodejs-goof | xss | `views/admin.ejs:17` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-XSS-02 | nodejs-goof | xss | `views/index.ejs:20` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-XSS-03 | nodejs-goof | xss | `views/index.ejs:20` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-XSS-N01 | nodejs-goof | xss | `views/edit.ejs:23` | not_raw | post_delivery | control_pass | 1 / 1 |  |
| GOOF-XSS-N02 | nodejs-goof | xss | `views/edit.ejs:20` | not_raw | post_delivery | control_pass | 1 / 1 |  |
| GOOF-XSS-N03 | nodejs-goof | xss | `views/account.hbs` | review | post_delivery | candidate_present | 6 / 1 | render_protection_unresolved |
| GOOF-XSS-N04 | nodejs-goof | xss | `public/js/ga.js` | no_record | post_delivery | control_pass | 0 / 0 |  |
| GOOF-CMD-01 | nodejs-goof | command_execution | `routes/index.js:174` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-NOSQL-01 | nodejs-goof | nosql_query | `routes/index.js:52` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-NOSQL-N01 | nodejs-goof | nosql_query | `routes/index.js` | present | post_delivery | candidate_present | 2 / 2 |  |
| GOOF-PATH-01 | nodejs-goof | path_traversal | `routes/index.js:270` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| GOOF-LOG-N01 | nodejs-goof | log_sink | `routes/index.js:312` | present | post_delivery | candidate_present | 1 / 1 |  |
| GOOF-OTHER | nodejs-goof |  | | excluded | post_delivery | excluded |  | Dust template code-execution demonstration and TypeORM field validation: out_of_family or no source positive |
| JS-XSS-01 | juice-shop | xss | `frontend/src/app/search-result/search-result.component.html:11` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-02 | juice-shop | xss | `frontend/src/app/track-result/track-result.component.html:9` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-03 | juice-shop | xss | `frontend/src/app/last-login-ip/last-login-ip.component.html:10` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-04a | juice-shop | xss | `frontend/src/app/administration/administration.component.html:26` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-04b | juice-shop | xss | `frontend/src/app/administration/administration.component.html:113` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-05a | juice-shop | xss | `frontend/src/app/administration/administration.component.html:60` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-05b | juice-shop | xss | `frontend/src/app/about/about.component.html:51` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-06 | juice-shop | xss | `frontend/src/app/product-details/product-details.component.html:18` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-07 | juice-shop | xss | `routes/userProfile.ts:101` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-XSS-08 | juice-shop | xss | `routes/videoHandler.ts:72` | review | independent | candidate_present | 1 / 1 | storage_origin_unresolved |
| JS-XSS-N01 | juice-shop | xss | `frontend/src/app/product-details/product-details.component.html` | no_record | independent | control_pass | 0 / 0 |  |
| JS-XSS-N02 | juice-shop |  | | excluded | independent | excluded |  | General Angular contract with no single anchor; covered by the per-sink rows |
| JS-XSS-N03 | juice-shop | xss | `frontend/src/app/track-result/track-result.component.html:80` | no_record | independent | control_pass | 0 / 0 |  |
| JS-XSS-N04 | juice-shop | xss | `frontend/src/app/data-export/data-export.component.html:29` | not_decisive | independent | control_pass | 1 / 1 |  |
| JS-SQL-01 | juice-shop | sql_query | `routes/login.ts:34` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-SQL-02 | juice-shop | sql_query | `routes/search.ts:23` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-NOSQL-01 | juice-shop | nosql_query | `routes/showProductReviews.ts:36` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-NOSQL-02 | juice-shop | nosql_query | `routes/trackOrder.ts:18` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-NOSQL-03 | juice-shop | nosql_query | `routes/updateProductReviews.ts:17` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-LOG-01 | juice-shop | log_sink | `server.ts:366` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SQL-01 | oss-oopssec-store | sql_query | `app/api/products/search/route.ts:55` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SQL-02 | oss-oopssec-store | sql_query | `app/api/orders/search/route.ts:58` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SQL-03 | oss-oopssec-store | sql_query | `app/api/tracking/route.ts:54` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SQL-04 | oss-oopssec-store | sql_query | `app/api/admin/reviews/route.ts:79` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SQL-Q01 | oss-oopssec-store |  | | excluded | independent | excluded |  | Unsafe construction practice with a random UUID; no injection candidate is expected |
| OOPS-PATH-01 | oss-oopssec-store | path_traversal | `app/api/files/route.ts` | positive | independent | candidate_with_witness | 3 / 1 |  |
| OOPS-PATH-02 | oss-oopssec-store | path_traversal | `app/api/files/route.ts` | positive | independent | candidate_with_witness | 3 / 1 |  |
| OOPS-PATH-R01 | oss-oopssec-store | path_traversal | `app/api/uploads/[...path]/route.ts` | review | independent | candidate_present | 1 / 1 |  |
| OOPS-PATH-R02 | oss-oopssec-store | path_traversal | `app/api/admin/products/[id]/image/route.ts` | review | independent | candidate_present | 1 / 1 |  |
| OOPS-PATH-N01 | oss-oopssec-store | path_traversal | `app/vulnerabilities/[slug]/page.tsx` | not_decisive | independent | control_pass | 1 / 1 |  |
| OOPS-SSRF-01 | oss-oopssec-store | ssrf | `app/api/support/route.ts:16` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-SSRF-02 | oss-oopssec-store | ssrf | `app/api/ai-assistant/route.ts:69` | review | independent | candidate_present | 1 / 1 |  |
| OOPS-LOG-01 | oss-oopssec-store | log_sink | `app/api/auth/login/route.ts:16` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-LOG-02 | oss-oopssec-store | log_sink | `app/api/gift-cards/route.ts:74` | positive | post_delivery | candidate_with_witness | 1 / 1 |  |
| OOPS-XSS-01 | oss-oopssec-store | xss | `app/products/[id]/ProductDetailClient.tsx:55` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-XSS-02 | oss-oopssec-store | xss | `app/profile/ProfileClient.tsx:411` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-XSS-03 | oss-oopssec-store | xss | `app/admin/analytics/AnalyticsClient.tsx:334` | review | independent | candidate_present | 1 / 1 |  |
| OOPS-XSS-04 | oss-oopssec-store | xss | `app/support/SupportForm.tsx:103` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OOPS-XSS-05 | oss-oopssec-store | xss | `app/login/LoginForm.tsx:37` | positive | independent | candidate_with_witness | 4 / 2 |  |
| OOPS-XSS-R01 | oss-oopssec-store | xss | `app/api/vcs/[[...path]]/route.ts` | review | independent | missing_candidate | 0 / 0 |  |
| OOPS-XSS-N01 | oss-oopssec-store | xss | `app/admin/documents/page.tsx` | no_record | independent | control_pass | 0 / 0 |  |
| OOPS-XSS-N02 | oss-oopssec-store | xss | `app/products/search/ProductSearchClient.tsx` | not_raw | independent | control_pass | 0 / 0 |  |
| OOPS-XSS-N03 | oss-oopssec-store | xss | `app/vulnerabilities/[slug]/page.tsx:191` | no_record | independent | control_pass | 0 / 0 |  |
| OOPS-XSS-N04 | oss-oopssec-store | xss | `app/live/page.tsx` | no_record | independent | control_pass | 0 / 0 |  |
| OOPS-MW-01 | oss-oopssec-store |  | | excluded | independent | excluded |  | Registration-stage row verified by TestNextJSOopsStoreAnswerKey, not by a candidate |
| OOPS-PRACTICE | oss-oopssec-store |  | | excluded | independent | excluded |  | SSR-01..05, CL-01..04, VAL-*: model-free observations owned by practice accuracy, not candidate recall |
| SQLI-001 | dvwa | sql_query | `vulnerabilities/sqli/source/low.php` | positive | independent | candidate_with_witness | 3 / 2 |  |
| SQLI-002 | dvwa | sql_query | `vulnerabilities/sqli_blind/source/low.php` | positive | independent | candidate_with_witness | 3 / 2 |  |
| AUTH-001 | dvwa | sql_query | `vulnerabilities/brute/source/low.php` | positive | independent | candidate_with_witness | 2 / 2 |  |
| AUTH-002 | dvwa | sql_query | `vulnerabilities/captcha/source/low.php:61` | review | post_delivery | candidate_present | 2 / 2 | storage_origin_unresolved |
| CSRF-001 | dvwa | sql_query | `vulnerabilities/csrf/source/low.php` | present | independent | candidate_present | 2 / 2 | storage_origin_unresolved |
| CMD-001 | dvwa | command_execution | `vulnerabilities/exec/source/low.php` | positive | independent | candidate_with_witness | 4 / 2 |  |
| XSSR-001 | dvwa | xss | `dvwa/includes/dvwaPage.inc.php:388` | positive | independent | candidate_with_witness | 4 / 1 |  |
| XSSS-001 | dvwa | xss | `dvwa/includes/dvwaPage.inc.php` | positive | post_delivery | candidate_with_witness | 4 / 1 |  |
| UPLD-001 | dvwa | path_traversal | `vulnerabilities/upload/source/low.php:9` | positive | independent | candidate_with_witness | 2 / 2 |  |
| FI-001 | dvwa | path_traversal | `vulnerabilities/fi/index.php:36` | positive | independent | candidate_with_witness | 4 / 1 |  |
| REDIR-001 | dvwa | open_redirect | `vulnerabilities/open_redirect/source/low.php:4` | positive | independent | candidate_with_witness | 1 / 1 |  |
| CODE-001 | dvwa | code_execution | `vulnerabilities/view_help.php` | positive | independent | candidate_with_witness | 2 / 1 |  |
| DVWA-IMPOSSIBLE | dvwa |  | | excluded | independent | excluded |  | Impossible-level controls share each module's candidate and are decided by assessment; not offline-measurable |
| TB-SQL-01 | ThreatByte | sql_query | `server/routes.py:138` | positive (construction) | independent | candidate_with_witness | 1 / 1 |  |
| TB-XSS-01 | ThreatByte | xss | `client/templates/dashboard.html:64` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| TB-XSS-02 | ThreatByte | xss | `client/templates/profile.html:41` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| TB-XSS-04 | ThreatByte | xss | `client/templates/dashboard.html:123` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| TB-SQL-BOUND | ThreatByte | sql_query | `server/routes.py:99` | bound (bound) | independent | control_pass | 1 / 1 |  |
| TB-SQL-KEYS | ThreatByte | sql_query | `server/api/v1/api_v1.py:207` | present (not_confirmed) | independent | candidate_present | 1 / 1 | input_helper_unresolved, python_call_unresolved, python_comprehension_unresolved, python_value_unresolved; assessment unmeasured offline |
| TB-LOG-SESSION | ThreatByte | log_sink | `server/api/v1/api_v1.py:182` | present (not_confirmed) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VAL-EMAIL | ThreatByte | sql_query | `server/routes.py:99` | present (form_policy) | independent | candidate_present | 1 / 1 |  |
| TB-XSS-ESCAPED | ThreatByte | xss | `client/templates/profile.html:39` | encoded (encoded) | independent | control_pass | 1 / 1 |  |
| TB-XSS-UNKNOWN-ORIGIN | ThreatByte | xss | `client/templates/profile.html:42` | present (not_confirmed) | independent | candidate_present | 1 / 1 | storage_origin_unresolved; assessment unmeasured offline |
| TB-OUT-01 | ThreatByte | ssrf | `server/api/v1/api_v1.py:254` | positive (candidate) | independent | candidate_with_witness | 1 / 1 |  |
| TB-VALIDATION-LOGIN-USER | ThreatByte | input_validation | `server/routes.py:37` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-LOGIN-PASSWORD | ThreatByte | input_validation | `server/routes.py:38` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-SIGNUP-USER | ThreatByte | input_validation | `server/routes.py:81` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-SIGNUP-EMAIL | ThreatByte | input_validation | `server/routes.py:82` | present (validation_defect) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-SIGNUP-COUNTRY | ThreatByte | input_validation | `server/routes.py:83` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-SIGNUP-PASSWORD | ThreatByte | input_validation | `server/routes.py:84` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| TB-VALIDATION-SIGNUP-CONFIRM | ThreatByte | input_validation | `server/routes.py:85` | present (validation_enforced) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| PI-XSS-01 | python-insecure-app | xss | `app/main.py:41` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| PI-OUT-FIXED | python-insecure-app | outbound_http | `app/main.py:31` | no_record (absent) | independent | control_pass | 0 / 0 |  |
| PI-VAL-NAME | python-insecure-app | input_validation | `app/main.py:19` | positive (candidate) | independent | candidate_with_witness | 1 / 1 |  |
| VF-SQL-01 | vulnerable-flask-app | sql_query | `vulnerable-flask-app.py:20` | positive (construction) | independent | candidate_with_witness | 1 / 1 |  |
| VF-XSS-02 | vulnerable-flask-app | xss | `vulnerable-flask-app.py:37` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| VF-XSS-03 | vulnerable-flask-app | xss | `vulnerable-flask-app.py:51` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| VF-XSS-04 | vulnerable-flask-app | xss | `vulnerable-flask-app.py:62` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| VF-XSS-JSON | vulnerable-flask-app | xss | `vulnerable-flask-app.py:32` | no_record (absent) | independent | control_pass | 0 / 0 |  |
| VF-LOG-ROW | vulnerable-flask-app | log_sink | `vulnerable-flask-app.py:25` | present (not_confirmed) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| VF-LOG-LITERAL | vulnerable-flask-app | log_sink | `vulnerable-flask-app.py:109` | present (not_confirmed) | independent | candidate_present | 1 / 1 | assessment unmeasured offline |
| VF-LOG-ARBITRARY | vulnerable-flask-app | log_sink | `vulnerable-flask-app.py:188` | no_record (absent) | independent | control_pass | 0 / 0 |  |
| VP-SQL-EXECUTE | vulnpy | sql_query | `src/vulnpy/trigger/sqli.py:37` | positive (construction) | independent | candidate_with_witness | 26 / 26 |  |
| VP-SQL-EXECUTEMANY | vulnpy | sql_query | `src/vulnpy/trigger/sqli.py:48` | positive (construction) | independent | candidate_with_witness | 26 / 26 |  |
| VP-SQL-EXECUTESCRIPT | vulnpy | sql_query | `src/vulnpy/trigger/sqli.py:59` | positive (construction) | independent | candidate_with_witness | 26 / 26 |  |
| VP-XSS-FLASK | vulnpy | xss | `src/vulnpy/flask/blueprint.py:57` | positive (raw_xss) | independent | candidate_with_witness | 6 / 6 |  |
| VP-XSS-FASTAPI | vulnpy | xss | `src/vulnpy/fastapi/vulnerable.py:44` | positive (raw_xss) | independent | candidate_with_witness | 1 / 1 |  |
| VP-XSS-JINJA | vulnpy | xss | `apps/templates/jinja/xss.html:30` | positive (raw_xss) | post_delivery | candidate_with_witness | 1 / 1 |  |
| VP-COVERAGE-24 | vulnpy | dynamic_path | `src/vulnpy/fastapi/vulnerable.py:24` | registration (registration_or_gap) | post_delivery | resolved |  |  |
| VP-COVERAGE-32 | vulnpy | dynamic_path | `src/vulnpy/fastapi/vulnerable.py:32` | registration (registration_or_gap) | post_delivery | resolved |  |  |
| VP-COVERAGE-33 | vulnpy | python_registration_unresolved | `src/vulnpy/flask/blueprint.py:33` | registration (registration_or_gap) | post_delivery | resolved |  |  |
| VP-COVERAGE-61 | vulnpy | python_registration_unresolved | `src/vulnpy/flask/blueprint.py:61` | registration (registration_or_gap) | post_delivery | resolved |  |  |
| DEMO-001 | vuln-nextjs |  | | excluded | independent | excluded |  | no_security_finding_expected |
| DEMO-002 | vuln-nextjs |  | | excluded | independent | excluded |  | no_security_finding_expected |
| FS-001 | vuln-nextjs | path_traversal | `pages/api/vulnerable-file-read.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| FS-001-safeControl | vuln-nextjs | path_traversal | `pages/api/secure/file-read.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| JS-001 | vuln-nextjs | code_execution | `pages/vulnerable/eval-injection.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-002 | vuln-nextjs | code_execution | `pages/api/vulnerable-submit.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| JS-002-safeControl | vuln-nextjs | code_execution | `pages/api/protected-example.js` | control_assessment | independent | assessment_dependent | 0 / 0 |  |
| OS-001 | vuln-nextjs | command_execution | `pages/api/vulnerable-exec.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| OS-001-safeControl | vuln-nextjs | command_execution | `pages/api/secure/command.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| REDIR-001 | vuln-nextjs | open_redirect | `pages/vulnerable/redirect.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| REDIR-001-safeControl | vuln-nextjs | open_redirect | `pages/secure/redirect.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SCA-001 | vuln-nextjs |  | | excluded | independent | excluded |  | out_of_family (CWE-502, SCA) |
| SQL-001 | vuln-nextjs | sql_query | `pages/api/sql/unsafe/login.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| SQL-001-safeControl | vuln-nextjs | sql_query | `pages/api/sql/safe/login.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SQL-001-safeControl | vuln-nextjs | sql_query | `pages/api/sql/zod/login.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SQL-002 | vuln-nextjs | sql_query | `pages/api/sql/unsafe/products.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| SQL-002-safeControl | vuln-nextjs | sql_query | `pages/api/sql/safe/products.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SQL-002-safeControl | vuln-nextjs | sql_query | `pages/api/sql/zod/products.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SQL-003 | vuln-nextjs | sql_query | `pages/api/sql/unsafe/notes.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| SQL-003-safeControl | vuln-nextjs | sql_query | `pages/api/sql/safe/notes.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SQL-003-safeControl | vuln-nextjs | sql_query | `pages/api/sql/zod/notes.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| SSRF-001 | vuln-nextjs | ssrf | `pages/vulnerable/ssrf.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| SSRF-001-safeControl | vuln-nextjs | ssrf | `pages/secure/ssrf.js` | control_assessment | independent | assessment_dependent | 1 / 1 |  |
| XSS-001 | vuln-nextjs | xss | `pages/xss/unsafe/reflected.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| XSS-001-safeControl | vuln-nextjs | xss | `pages/xss/safe/reflected.js` | not_raw | independent | control_pass | 0 / 0 |  |
| XSS-001-safeControl | vuln-nextjs | xss | `pages/xss/sanitized/reflected.js` | not_raw | independent | control_pass | 1 / 1 |  |
| XSS-002 | vuln-nextjs | xss | `pages/xss/unsafe/stored.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| XSS-002-safeControl | vuln-nextjs | xss | `pages/xss/safe/stored.js` | not_raw | independent | control_pass | 0 / 0 |  |
| XSS-003 | vuln-nextjs | xss | `pages/xss/unsafe/script-context.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| XSS-003-safeControl | vuln-nextjs | xss | `pages/xss/safe/script-context.js` | not_raw | independent | control_pass | 1 / 1 |  |
| XSS-004 | vuln-nextjs | xss | `pages/xss/unsafe/comments.js` | positive | independent | candidate_with_witness | 1 / 1 |  |
| XSS-004-safeControl | vuln-nextjs | xss | `pages/xss/sanitized/comments.js` | not_raw | independent | control_pass | 1 / 1 |  |
