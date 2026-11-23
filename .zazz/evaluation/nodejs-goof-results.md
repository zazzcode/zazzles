# Node.js Goof: initial Bearer and zazzles baseline

**2026-11-01; before XSS implementation.** Run `20261101-goof-baseline-02` uses target
`add14ba59e98240d9e00a235dd7d42cd61ae9912`. The
[scanner-independent answer key](../../docs/samples/nodejs-goof/xss-answer-key.md) owns expected
XSS outcomes. Comparator results do not supply those labels.

## Reproduction and validity

The [runbook](../../docs/samples/nodejs-goof/bearer-runbook.md) was executed with the same Bearer
binary as the earlier pinned experiment: source `e3753de6347988bed15bdba80b9ff731bf028c80`,
rules `82c335f781a61a6d8b052394f84fd1d93edec467`, binary SHA256
`ca0964352fd4b2e2cb1288e9718b205b69bd7de9032abc5faa59d8acd1c4a1b0`; CLI reports `dev/devSHA`.
The current zazzles source is `602387063816838b7a56bac96dc911e4502d7023`, with no changes to
`cmd`, `internal`, `go.mod` or `go.sum` at build time. Built locally with Go 1.27.3 darwin/arm64,
readonly modules and `GOPROXY=off`. Binary hash and exact commands are in saved metadata.

Both tools received the same 22-file snapshot, including EJS/Handlebars/Dust templates, tests and
package manifests; 38 tracked files were excluded. Bearer logs show template files completed
processing, which does not prove route-to-template taint linkage. Default rules, version checks,
domain resolution and caches were disabled; external pinned rules supplied detection. Child
environments contained only PATH/TMPDIR. No target server, database, exploit script, dependency audit
or model assessment ran. Zero new model calls/tokens.

Attempt 01 failed on sandbox-blocked loopback worker sockets despite exit 0. Its invalid output was
not published and has been removed from scratch. Attempt 02 ran with authorized worker socket
access, exited 1 (findings), and passed execution validation with no worker/file errors. Elapsed Bearer time: 1.579 seconds.
These are single local timings with different analysis coverage, not a speed benchmark.

## Saved artifacts

- [Bearer findings and run summary](../../docs/samples/nodejs-goof/bearer/20261101-goof-baseline-02/SUMMARY.md).
- [Zazzles JSON](../../docs/samples/nodejs-goof/zazzles/20261101-goof-baseline-02/findings.json),
  [HTML](https://zazzcode.github.io/zazzles/nodejs-goof/zazzles/20261101-goof-baseline-02/findings.html),
  [SARIF](../../docs/samples/nodejs-goof/zazzles/20261101-goof-baseline-02/findings.sarif).
- [Syntactic route inventory](../../docs/samples/nodejs-goof/zazzles/20261101-goof-baseline-02/scan-routes-nodejs-goof.json).

Public artifacts normalize local prefixes to documented tokens and the zazzles report root to
`nodejs-goof`. Relative locations, source hashes, fingerprints and diagnostic messages are retained.
Original uncurated outputs were temporary scratch and are not retained.

## Results and claim comparison

Bearer emitted **43 findings / 12 rule IDs**: 15 critical, 2 high, 3 medium, 23 low.
Five hardcoded-secret records are in tests; the other 38 records are in application/support files.
These are tool findings, not confirmed vulnerabilities. Except for the one XSS false positive
reviewed below, findings remain unadjudicated; source overlap alone does not confirm exploitability.

Zazzles `--strings --entry app.js` completed in 0.021 seconds with **0 entries / 0 uses**, one
attached source file and four explicit limitations. Omitting `--entry` also produced 0 entries/uses
(10 attached JS files, 0.020 seconds). Its evidence analyzer requires ESM Express bindings and does
not resolve Goof's CommonJS `require(...)` handlers. This is absent analysis coverage, not a clean
security assessment. Its separate syntactic `--routes` inventory found 19 registrations and two
gaps in 0.010 seconds; that mode does not establish data flow or protection.

| Expected case / claim | Bearer observation | Initial zazzles observation | Disposition / next work |
|---|---|---|---|
| `GOOF-XSS-01`, reflected raw EJS attribute | No XSS finding at route/template | No analyzed route/use | Missing target detection in both; CommonJS and template-render linkage required |
| `GOOF-XSS-02/03`, stored Markdown bypass | No XSS finding at write/read/template path | No analyzed route/use | Missing target detection in both; persistence, versioned sanitizer and rendering context required |
| `GOOF-XSS-N01/N02`, escaped EJS output | No corresponding XSS finding | Unassessed | Bearer absence is consistent with the controls, not an explicit protection judgment |
| `GOOF-XSS-N03`, escaped Handlebars fields | No corresponding XSS finding | Unassessed | Keep field escaping separate from render-options injection |
| `GOOF-XSS-N04`, fixed analytics script creation | `javascript_lang_dangerous_insert_html`, `public/js/ga.js:3` | Client analysis absent | Source-inspected false XSS finding: literal script tag/fixed destination, no attacker-controlled HTML or code established |
| Login NoSQL selector | `javascript_express_nosql_injection`, `routes/index.js:52` | No analyzed use | Source-aligned candidate, not adjudicated; three additional NoSQL records at :185/:204/:232 need independent review |
| Command execution at `routes/index.js:174` | No command-injection finding | No analyzed use | Missing detection in this run; not a safe claim |
| Open redirect at `routes/index.js:74` | No redirect finding | No analyzed use | Separate from reflected XSS |
| Session literal/configuration | Secret at `app.js:42` and :43; cookie at :45; header/server configuration at :28/:86 | No analyzed use | Overlapping rules count separately in raw totals, not as independently established vulnerabilities |
| Token-shaped startup log `app.js:83-84` | Not the source of any logger finding; 21 logger records elsewhere | No analyzed use | Non-request/global logging is outside the implemented zazzles logging contract |

## Juice Shop frontend question

The historical pinned [Bearer review ledger](juice-shop/bearer-review.jsonl) contains two
`javascript_lang_dangerous_insert_html` records at `frontend/src/hacking-instructor/index.ts:77,126`.
Those remain pending source review. It has no XSS-family record for the Angular challenge components'
`bypassSecurityTrustHtml` paths listed in the [XSS scope](../project/xss-detection-scope.md).
The historical snapshot included JS/TS/JSON and omitted Angular HTML templates, so it does not
measure full frontend-template coverage. These observations do not establish that Bearer generally
supports or cannot support Angular XSS. Goof's only XSS-labeled comparator result is the false
positive described above; its expected positives are server-rendered cases.

Subsequent XSS implementation increments MUST preserve this pre-change baseline and save fresh
zazzles reports separately, matching results to answer-key IDs and explaining unresolved cases.
