# XSS hardening: acceptance results

[Contract](../specifications/xss-hardening.md) · [Matrix](xss-hardening/matrix.json) · [Evaluator](xss-hardening/evaluate.py) ·
[Expected versus actual](xss-hardening/final-evaluation.json) · [vuln-demo-app reference](vuln-demo-app-detection-guide.md) ·
[Public guide](../../docs/analysis/xss.md)

Recorded 2026-11-07 on `xss-hardening` from base `3315cf0` with uncommitted changes. Final scans used binary SHA-256
`24132434bbf38cbe4d47ab711e08a3e95078e098b9564638d312510058d0c83e`, OpenAI Decisions `gpt-6-luna`,
`--skip-family input-validation` and no fallback. Only documentation and this record changed after those scans.
These are static judgments. No target was executed, and independent human review is pending.

## Result

All 28 required cases are completed `confirmed_vulnerability` records and all 7 controls hold. `evaluate.py` exits 0.

| App | Required cases | Red at baseline | Red at final | XSS records: red / Review / Protected |
|---|---:|---:|---:|---|
| vuln-demo-app | 5 | 0 | 5 | 5 / 2 / 0 |
| vulnerable-typescript-app | 1 | 1 | 1 | 1 / 1 / 0 |
| nodejs-goof | 2 | 2 | 2 | 2 / 9 / 1 |
| Juice Shop | 8 | 2 | 8 | 9 / 14 / 0 |
| VulnPy | 12 (31 contexts) | 2 (7 contexts) | 12 (31 contexts) | 31 / 0 / 0 |

The VulnPy adapters each repeat one shared raw concatenation, so 30 contexts are exposures of one defect pattern,
not 30 distinct defects. Falcon and Falcon-ASGI each report two contexts against an expected minimum of one.

## False-positive review

Every confirmed record maps to a required case except `administration.component.html:113`. Source review confirms
it is a true positive: the same trusted `user.email` rendered in a second table column.

Two false Review classes were found in the source and fixed:

| Record | Why it was false | Fix |
|---|---|---|
| Goof `todo._id` in six `href`/`action` outputs | Generated ObjectId, no request write, and EJS-escaped | A Mongoose `_id` with no request write is not a claim |
| Juice Shop `routes/dataExport.ts:108` | `res.send(object)` is JSON | Object arguments are API data |

The remaining Review records were read and left as Review on purpose:

| Records | Why Review is correct |
|---|---|
| Juice Shop `videoHandler.ts:72` (`JS-XSS-08`) | Raw construction is real; its key leaves attacker control of the configured file unresolved |
| Juice Shop `data-export.component.html:29` (`JS-XSS-N04`) | Trust bypass of a generated CAPTCHA, no attacker source |
| Juice Shop about, navbar, recycle and welcome-banner bindings | Values come from server configuration with no request origin |
| Goof `account.hbs` (`GOOF-XSS-N03`) | Escaped fields, but request-controlled render options |
| Goof `routes/index.js:197` | Body of a 302 response, which browsers do not render |
| Goof `routes/index.js:313` | Dust render whose output context is unresolved |
| TypeScript `src/server.ts:108` | File contents reach `res.send`; depends on path traversal and file content |
| vuln-demo-app `server.js:131`, `:280` | `users` columns have no request write; reachable only by chaining SQL injection |

Goof `views/edit.ejs:23` is correctly escaped but judged Review, not Protected: the model answered `xss_exposure: unknown`
with every other answer protective. It is not a false positive, and the policy did not override the answer.

## Known limits

- `DEMO-XSS-Q01`/`Q02` (`err.message` in `<pre>`) produce no record. Exception text is not modeled as a source.
- SQL-backed storage covers sql.js and Sequelize raw queries only. Other clients stay unlinked.
- Juice Shop's unsafe paths are branch-gated by `isChallengeEnabled`; the condition stays attached as a precondition.
- Each case rests on one model sample per scan. See the correction under the follow-up section.
- Exit status 1 for three apps is the existing rule for observation-only records, not a failed XSS case.
- Saved sample reports under `docs/samples/` were not refreshed.

## Regression checks

Non-XSS outcomes match the baseline scans for every family by kind and status. The command matrix still passes on the
final reports with `--require-judged`. Two pinned digests changed (`TestSQLDiscoveryBaseline` and
`TestCommandPredecessorRequests`, `python/dynamic-vulnpy` only). A record-level diff of that fixture showed only its
Jinja XSS record changed; no SQL, command or logging record did.

## Follow-up: sql.js SQL injection and rejudged records

After the scans above, the SQL analyzer gained a `sqljs-statement-v1` contract and `try` control context. A paid
Juice Shop and vuln-demo-app scan then exposed two scanner faults, both fixed:

- `POST /login` SQL was blocked although the model answered vulnerable: automatic field matching ignored
  destructured sources such as `const { email } = req.body`. Destructuring projections now name the fields.
- `DEMO-XSS-04` fell to Review: the model named `html_text` for the attribute claim, and the consistency gate
  correctly refused it. When one response splits into several claims, both showed the same whole sink. Each now
  carries its own substitution line as `render_markup_context` evidence and a `claim_output` fact.

Final follow-up binary SHA-256 `e1dc998cbb43d8559d658ea1a73b3c61019d1141d161aa93a01f9138ca24f302`. Offline output for
Juice Shop, Goof, the TypeScript app and VulnPy is byte-identical to the scanned sql.js binary, so the Juice Shop
scan stands. vuln-demo-app was scanned twice on the final binary:

| Check | Juice Shop | vuln-demo-app, run A | vuln-demo-app, run B |
|---|---|---|---|
| XSS matrix cases and controls | 8 cases, 3 controls pass | 5 cases, 1 control pass | 5 cases, 1 control pass |
| `DEMO-SQL-01` to `05` | — | 5 of 5 confirmed | 5 of 5 confirmed |
| SQL/NoSQL statuses | Unchanged: 2 SQL and 3 NoSQL confirmed, 10 Review, 1 not run | — | — |
| `POST /notes` bound insert | — | No candidate | No candidate |

The 10 Juice Shop records whose evidence `try` modeling changed were rejudged and kept their statuses. Runs A and B
sent identical request bytes, so their agreement shows the answers repeat, not that varied evidence converges.

**Correction:** the earlier note that pass 1 and the final scan agreed on every case held only for identical
requests. Changed evidence changed an answer here, so single-sample results remain a stated limit.

## Usage

| Run | Provider requests | Input tokens |
|---|---:|---:|
| Baseline | 314 | 2,478,865 |
| Pass 1 | 345 | 2,733,353 |
| `/profile` rejudge | 3 | 15,798 |
| Final | 339 | 2,690,784 |
| sql.js follow-up: Juice Shop and vuln-demo-app | 147 | 519,380 |
| vuln-demo-app runs A and B | 30 | 205,736 |
| **Total** | **1,178** | **8,643,916** |

Pass 1 confirmed 27 of 28; `JS-XSS-07` exceeded the 64 KiB request limit, which led to stored-path compaction.
Raw reports and traces are under `_test-findings/xss-hardening/`. Target checkouts stayed clean at their pins.
