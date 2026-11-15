# E4 results — shared Node inputs and file APIs

**Branch:** `node-inputs-and-file-apis` (base `6e815ec`)  
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
