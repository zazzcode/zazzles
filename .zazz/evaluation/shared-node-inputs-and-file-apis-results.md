# E4 results — shared Node inputs and file APIs

**Merged:** [PR #15](https://github.com/zazzcode/zazzles/pull/15) into `stage` (`eafabcc`, 2026-11-15)  
**Feature branch (historical):** `node-inputs-and-file-apis` (base `6e815ec`)  
**Paid ledger:** `_test-findings/e4/request-ledger.json`  
**Model / cap:** OpenAI `gpt-6-luna`, 350; **charged 250**; exact replay **250/250**.

## Deliverables

| ID | Outcome |
| --- | --- |
| A | Shared Express middleware-chain sibling entries for all assessed families |
| B | `source.node-input-v2` URL/upload acquisition facts (InputFacts v1) |
| C | Retired `withRequestURLPaths` / `urlSources`; pathImmediate/archive/render on shared pass |
| D | Phase-2 file APIs: Node `open`/`copyFile`/`rename`; Python FileResponse/UploadFile/shutil/extractall |
| E | Node `http`/`https` SSRF (`node-http-url-v1`); vuln-demo-app `POST /fetch` confirmed |
| AC6 | Switch/labeled/brace-less loop bodies; require destructuring (winston, Sequelize) |

## Digests

E3 baseline 4042 → post-C 4082 (+40). Explained in the E4 run log (shared chain/URL facts, `/fetch` SSRF, fixture validation/XSS).

## Samples

Juice Shop, Node.js Goof, and Vulnerable TypeScript app GitHub samples republished from this ledger.
Python samples unchanged. See each sample README **Current report** section.

## Efficacy vs source-reviewed keys

Metric: confirm **required positives** for shipped analyzers; leave key-approved Review/Protected
cases unresolved. Not “every vulnerability in the app.”

On this rebuild, cataloged required positives for XSS / SQL / NoSQL / command / path / logging /
SSRF on the four Node apps were confirmed. Families without an analyzer stay Not covered.

### Known acceptable non-reds (not misses)

These stay **Review** (or no red finding) because the answer keys say a definitive vulnerability
claim is not established from the inspected source—not because discovery failed.

| App | Case | Why Review is correct |
| --- | --- | --- |
| Goof | `GOOF-XSS-N03` `views/account.hbs` | Field interpolations are escaped (`{{…}}`), but the request also controls render locals/options (layout injection). Escaped fields alone must not be labeled Protected or Confirmed until options are resolved. |
| Juice Shop | `JS-XSS-08` subtitles `videoHandler.ts:72` | Unsafe file→HTML construction is established; whether an attacker can write that configured subtitle file is **unresolved on this route**, so stored-XSS exploitability stays Review. |
| vuln-demo | `DEMO-XSS-Q03` login page `:131` | User fields have no request write; a `UNION` via the confirmed SQL injection could supply them. That is a **chain from SQLi**, not a standalone stored XSS positive. |
| vuln-demo | `DEMO-XSS-N02` `GET /admin/users` `:280` | Raw table render of seed-only `users` columns—no request write. Poor practice possible; not a required XSS red. (Stacked SQL on `DELETE` is a separate SQL claim.) |

Protected-by-key cases that improved this run (for context): Goof escaped `edit.ejs` (`GOOF-XSS-N01`/`N02`)
are now `protected_for_claim` rather than Review.
