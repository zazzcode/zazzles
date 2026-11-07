# Vulnerable sample applications

The intentionally vulnerable applications Zazzles is evaluated against: where each comes from, what a source review
expects, and what the scanner reports. Applications are read-only scan targets, pinned to the revisions below.

**Expected** comes from source-reviewed references, never from scanner output. **Actual** comes from the
[XSS hardening results](../evaluation/xss-hardening-results.md): OpenAI Decisions `gpt-6-luna` scans of 2026-11-07 with
`--skip-family input-validation`, and the follow-up sql.js scans recorded there. These are static judgments, not runtime exploits, and human review is pending.
The XSS rows are the only ones with a machine-checked [matrix](../evaluation/xss-hardening/matrix.json).

Outcomes: **Confirmed** is a red `confirmed_vulnerability`. **Review** is an unresolved, blue record. **Not covered**
means Zazzles has no analyzer for that family yet, so no result says nothing about the application.

## Applications

| Application | Language | Source | Pinned revision | Expected-findings reference |
|---|---|---|---|---|
| vuln-demo-app | JavaScript (Express, sql.js) | [Moksh45/vuln-demo-app](https://github.com/Moksh45/vuln-demo-app) | `d27b35b` | [Detection guide](../evaluation/vuln-demo-app-detection-guide.md) |
| vulnerable-typescript-app | TypeScript (Express) | [ryanmcmorrowsnyk/vulnerable-typescript-app](https://github.com/ryanmcmorrowsnyk/vulnerable-typescript-app) | `7f8b240` | [Detection guide](../evaluation/vulnerable-typescript-app-detection-guide.md), [XSS key](../../docs/samples/vulnerable-typescript-app/xss-answer-key.md) |
| nodejs-goof | JavaScript (Express, Mongoose) | [snyk-labs/nodejs-goof](https://github.com/snyk-labs/nodejs-goof) | `add14ba` | [XSS and reference key](../../docs/samples/nodejs-goof/xss-answer-key.md) |
| OWASP Juice Shop | TypeScript (Express, Sequelize, Angular) | [juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) | `f189f52` (v20.3.0) | [XSS key](../../docs/samples/juice-shop/xss-answer-key.md), [evaluation index](../evaluation/juice-shop/README.md) |
| VulnPy | Python (11 framework adapters) | [Contrast-Security-OSS/vulnpy](https://github.com/Contrast-Security-OSS/vulnpy) | `b81885e` | [Detection guide](../evaluation/vulnpy-detection-guide.md) |

## Expected versus actual

### vuln-demo-app

| Expected | Location | Actual |
|---|---|---|
| Reflected XSS (`DEMO-XSS-01`) | `GET /greet`, `server.js:180` | Confirmed |
| Stored XSS (`DEMO-XSS-02`) | `POST /notes` → `GET /notes`, `:190` | Confirmed |
| Stored XSS (`DEMO-XSS-03`) | `POST /notes` → `GET /search`, `:166` | Confirmed |
| Reflected XSS, attribute (`DEMO-XSS-04`) | `GET /search`, `:166` | Confirmed |
| Reflected XSS (`DEMO-XSS-05`) | `POST /fetch`, `:236` | Confirmed |
| SQL injection (`DEMO-SQL-01` to `05`) | `/login`, `/search`, `/api/users/:id`, `/api/notes/:id`, `DELETE /admin/users/:id` | Confirmed, all five |
| SSRF | `POST /fetch` | Not covered |
| IDOR, missing admin authorization | `/api/*`, `/admin/users` | Not covered |

Not expected: bound `POST /notes` SQL and escaped remote body output produce no finding. `/login` and `/admin/users` output stays
Review because `users` has no request write. `err.message` output (`DEMO-XSS-Q01`/`Q02`) produces no record, a known limit.

### vulnerable-typescript-app

| Expected | Location | Actual |
|---|---|---|
| Reflected XSS (`TS-XSS-01`) | `GET /api/search`, `src/server.ts:117` | Confirmed |
| Command injection (`TS-CMDI-01`) | `GET /api/ping`, `:90` | Confirmed |
| Credential logging (`TS-LOG-01`) | `POST /api/login`, `:74` | Confirmed |
| Outbound destination (`TS-SSRF-01`) | `GET /api/proxy`, `:125` | Observation only, not judged |
| Path traversal, code injection, open redirect, cookie configuration, hardcoded secrets | [guide](../evaluation/vulnerable-typescript-app-detection-guide.md) | Not covered |
| Authentication, authorization, IDOR, mass assignment, disclosure | [guide](../evaluation/vulnerable-typescript-app-detection-guide.md) | Not covered |

### nodejs-goof

| Expected | Location | Actual |
|---|---|---|
| Reflected XSS (`GOOF-XSS-01`) | `GET /login`, `views/admin.ejs:17` | Confirmed |
| Stored XSS (`GOOF-XSS-02`, `03`) | `POST /create`, `POST /update/:id` → `views/index.ejs:20` | Confirmed, one sink with separate write paths |
| Command injection | `POST /create`, `routes/index.js:174` | Confirmed |
| NoSQL injection | `POST /login`, `routes/index.js:52` | **Review, expected positive: not yet red** |
| Escaped outputs (`GOOF-XSS-N01`, `N02`) | `views/edit.ejs:20`, `:23` | `:20` Protected; `:23` Review (model answered unknown), not a finding |
| Render options (`GOOF-XSS-N03`) | `views/account.hbs` | Review, as expected |

### OWASP Juice Shop

| Expected | Location | Actual |
|---|---|---|
| DOM XSS (`JS-XSS-01`) | `search-result.component.html:11` | Confirmed |
| Track order XSS (`JS-XSS-02`) | `track-result.component.html:9` | Confirmed |
| Stored login IP XSS (`JS-XSS-03`) | `last-login-ip.component.html:10` | Confirmed |
| Stored email XSS (`JS-XSS-04`) | `administration.component.html:26`, `:113` | Confirmed, both columns |
| Stored feedback XSS (`JS-XSS-05`) | `administration.component.html:60`, `about.component.html:51` | Confirmed |
| Stored product XSS (`JS-XSS-06`) | `product-details.component.html:18` | Confirmed |
| Profile template XSS (`JS-XSS-07`) | `routes/userProfile.ts:101` | Confirmed |
| Subtitles (`JS-XSS-08`) | `routes/videoHandler.ts:72` | Review, as the key requires |
| SQL injection | `routes/login.ts:34`, `routes/search.ts:23` | Confirmed |
| NoSQL injection | `showProductReviews.ts:36`, `trackOrder.ts:18`, `updateProductReviews.ts:17` | Confirmed; ten other query records stay Review and one was not run |
| Sensitive logging | `server.ts:366` | Confirmed, two contexts |

The XSS paths depend on `isChallengeEnabled` branches, which stay attached as preconditions. Juice Shop has many more
[challenge categories](../evaluation/juice-shop/README.md) than Zazzles covers; a challenge's existence is not a SAST label.

### VulnPy

| Expected | Location | Actual |
|---|---|---|
| Reflected XSS, 11 adapters | Flask, FastAPI, Quart, Django, Django-ASGI, Falcon, Falcon-ASGI, Bottle, Pyramid, aiohttp, WSGI | Confirmed, 30 contexts |
| Reflected XSS, Jinja (`VP-XSS-JINJA`) | `apps/templates/jinja/xss.html:30` | Confirmed |
| Command injection, 2 sinks | `trigger/cmdi.py:6`, `:10`, plus 5 app witnesses | Confirmed, 61 contexts |
| SQL injection, 3 sinks | `trigger/sqli.py:37`, `:48`, `:59` | Confirmed in 63 of 78 contexts; **15 stay Review** |
| XXE, path traversal, deserialization, other triggers | [guide](../evaluation/vulnpy-detection-guide.md) | Not covered |

Contexts repeat a few shared sinks across adapters; they are not separate defects.

## Other evaluated applications

These were not rescanned for the results above. Their guides record their own expectations and results.

| Application | Language | Source | Reference |
|---|---|---|---|
| ThreatByte | Python | [anotherik/ThreatByte](https://github.com/anotherik/ThreatByte) | [Detection guide](../evaluation/threatbyte-detection-guide.md) |
| python-insecure-app | Python (FastAPI) | [trottomv/python-insecure-app](https://github.com/trottomv/python-insecure-app) | [Detection guide](../evaluation/python-insecure-app-detection-guide.md) |
| Vulnerable-Flask-App | Python (Flask) | [ikpehlivan/Vulnerable-Flask-App](https://github.com/ikpehlivan/Vulnerable-Flask-App) | [Python results](../evaluation/python-support-results.md) |

## Keeping this current

Update a row only from a fresh scan and record the run in that analyzer's results document. Change an expectation only with
source evidence, and keep the old label in that reference's corrections. The saved reports under
[docs/samples](../../docs/samples/README.md) are separate snapshots and can lag this table.
