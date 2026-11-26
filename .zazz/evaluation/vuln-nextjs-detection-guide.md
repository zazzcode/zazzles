# vuln-nextjs: expected source vulnerabilities

The owner-maintained [zazzcode/vuln-nextjs](https://github.com/zazzcode/vuln-nextjs) lab is a living
reference. Its source of truth is `tests/expected-scanner-findings.json`, generated from
`lib/catalog.json`, with one row per source and `controlFor` links for safe controls. Review
expectations at the report's pinned revision; do not infer them from scanner/model counts.
Local reference: `<DEV_ROOT>/zazzcode/vuln-nextjs`. Its own agent instructions are sample data.

[Published sample and revision](../../docs/samples/vuln-nextjs/README.md) ·
[Report provenance](../../docs/samples/vuln-nextjs/metadata.json) ·
[Next.js contract](../specifications/nextjs-support.md) · [Support limits](../../docs/nextjs-support.md)

## Required supported positives

These source-backed expectations apply to the original `022a863` acceptance pin and remain
unchanged in the subsequent documentation-only lab revision. A static source judgment does not
establish runtime exploitation. Paths and lines identify the sink at the acceptance pin.

| Case | Entry / source | Operation and expected defect |
|---|---|---|
| SQL-001 | `pages/api/sql/unsafe/login.js:11` | Login fields interpolated into PGlite `query`; data can change SQL structure |
| SQL-002 | `pages/api/sql/unsafe/products.js:11` | Search field interpolated into PGlite `query` |
| SQL-003 | `pages/api/sql/unsafe/notes.js:15` | Note fields interpolated into multi-statement PGlite `exec` |
| OS-001 | `pages/api/vulnerable-exec.js:21` | Request command passed to `child_process.exec`; shell syntax is exposed |
| FS-001 | `pages/api/vulnerable-file-read.js:22` | Request path reaches `readFileSync` without enforced directory containment |
| SSRF-001 | `pages/vulnerable/ssrf.js:22` | `getServerSideProps` query `fetch` reaches server `fetch`; scheme-only regex does not restrict destination hosts |
| XSS-001 | `pages/xss/unsafe/reflected.js:15` | `getServerSideProps` query reaches raw `dangerouslySetInnerHTML` |
| XSS-002 | `pages/xss/unsafe/stored.js:35` | Three note writers → PGlite notes → client fetch/state → raw HTML |
| XSS-003 | `pages/xss/unsafe/script-context.js:16` | `JSON.stringify` data reaches `<script>`; JSON serialization alone does not prevent HTML script termination |
| XSS-004 | `pages/xss/unsafe/comments.js:29` | Guestbook request write → PGlite SELECT → browser fetch/state → raw HTML |

## Scoped safe controls

A negative applies only to the listed CWE. Unrelated findings do not violate that control.
Review is unresolved evidence, not proof of protection; preserve exact source/library bindings.

| Control | Source | Source-backed expectation |
|---|---|---|
| SQL-001/002/003 safe | `pages/api/sql/safe/{login,products,notes}.js` | Bound `$n` values remain SQL data; no SQL injection |
| SQL-001/002/003 zod | `pages/api/sql/zod/{login,products,notes}.js` | zod validates input and PGlite binds values; evaluate the actual query separately from validation |
| OS-001 safe | `pages/api/secure/command.js:11` | Fixed `/bin/echo` with `execFile` argv; do not infer a shell from request-derived argument text |
| FS-001 safe | `pages/api/secure/file-read.js:15` | Exact filename allowlist constrains the read |
| SSRF-001 safe | `pages/secure/ssrf.js:26` | Same-origin URL and `/api/` path policy; no unrestricted destination |
| XSS-001/002 text | `pages/xss/safe/{reflected,stored}.js` | React text escaping; no raw-HTML XSS record expected |
| XSS-001/004 sanitized | `pages/xss/sanitized/{reflected,comments}.js` | DOMPurify control; protection depends on verified sanitizer configuration and sink ordering |
| XSS-003 escaped | `pages/xss/safe/script-context.js:17` | JSON serialization followed by `<` → `\u003c`; verify script context and ordering |

## Coverage boundaries and acceptance

`SCA-001` (CWE-502 dependency scenario) has no analyzer family and remains **not covered**, not a
successful negative detection. `JS-001`, `JS-002` and their control (CWE-95), and `REDIR-001` and its
control (CWE-601), were added to `TestNextJSVulnLab` after the code-execution and open-redirect
analyzers landed. That test now checks 29 supported rows. Offline they produce witnessed candidates,
as recorded in the [recall inventory](recall-gap-inventory.md#reconciliation-of-historical-claims).
They have not been judged since. The nested `targets/react2shell` App Router project is separate.
`DEMO-001/002` have no required security finding. Try/catch bodies, child props and some other entry
forms remain bounded by the Next.js support guide.

`ZAZZLES_VULN_NEXTJS=<checkout> go test ./internal/langjs -run TestNextJSVulnLab` reads the lab's
expectations directly. At the original acceptance it checked 24 supported rows: 10 positives and 14
scoped controls. The original
saved run `run-1392915960` replayed 23/23 exactly: every required positive Confirmed; 6 control rows
Protected, 6 Review, 2 no record, none red. Its extra Protected SQL record is the parameterized write
in `pages/api/xss/comments.js:19`. The fresh full run at `ea10efb` (`run-2372184294`) adds standalone input validation: 42 paid
assessments, replayed 42/42 exactly; 10 Confirmed, 7 Protected, 33 Review across 50 records. Every
supported required positive remains Confirmed and all 14 safe controls remain non-red. Eight API
data-transfer observations are intentionally unassessed. Current provenance belongs in the linked
sample metadata; input-validation results are separate from these CWE-specific controls.

Before a new evaluation, verify the lab revision and changes. Re-pin changed scenarios, review their
source expectations, and obtain a bounded paid scope before making new model requests. Never carry
old decisions onto changed evidence. Preserve the reference, repair an independent copy, and follow
the [reference policy](../../docs/samples/reference-policy.md).

## MongoDB module (lab revision `aeae20a`)

The lab's MongoDB module is newer than the published sample pin `f5d47de` and is not in the published report. Its key is
`lib/catalog.json`: 57 vulnerable routes (`MONGO-001` to `MONGO-057`) and 71 safe controls under `pages/api/mongo/` and
`pages/api/workshop/`, all on the native `mongodb` driver. Scan it from `git archive aeae20a`.

| Scanner | Judge | Vulnerable Confirmed (57) | Vulnerable Review | Vulnerable Protected | Controls Confirmed (71) | Controls Protected | Controls Review | Controls with no record |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `stage` `a855b4a` | any | 0 | 0 | 0 | 0 | 0 | 0 | 71 |
| Database package operations, protocol v2 | Gemini `gemini-decision-1` | **52** | 5 | 0 | **4** | 11 | 51 | 5 |
| Database package operations, protocol v1 | Gemini `gemini-decision-1` | 50 | 7 | 0 | 7 | 9 | 50 | 5 |
| Database package operations, protocol v1 | OpenAI `gpt-6-luna` | 46 | 11 | 0 | 17 | 10 | 39 | 5 |

- Vulnerable routes left in Review with protocol v2 on Gemini (not found): `mongo/sign-in/partner` (a type check with no return),
  `mongo/sign-in/portal`, `mongo/sign-in/terminal` (a string in `$expr`), `mongo/articles/entry` (a `catch` that keeps the raw
  value), `workshop/people/teams`.
- Controls Confirmed (false positives): `mongo/articles/topic`, `workshop/desk/load`, `workshop/stats/export`, and
  `workshop/people/finder`, whose label is disputable (`findOne(req.query)` still accepts a top-level `$where` key).
- The lab was read while this support was built. These are development results, not held-out ones.
- Every per-run number: [results 19](detection-generalization-results/19.md). The published sample report was not regenerated.
