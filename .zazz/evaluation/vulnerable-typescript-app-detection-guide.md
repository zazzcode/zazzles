# Vulnerable TypeScript app: expected source vulnerabilities

Reviewed 2026-11-07 at revision `7f8b240a2f02beba099da3632d1ba679ff8bc32f` of
[ryanmcmorrowsnyk/vulnerable-typescript-app](https://github.com/ryanmcmorrowsnyk/vulnerable-typescript-app).
Local reference: `<DEV_ROOT>/vulnerable-typescript-app`. All application code below is in
`src/server.ts`; line numbers identify the operation, not its preceding vulnerability comment.
The checkout remains unchanged; no target execution, installs or live scanner calls were made.

[Published sample](../../docs/samples/vulnerable-typescript-app/README.md) ·
[Existing XSS/reference controls](../../docs/samples/vulnerable-typescript-app/xss-answer-key.md) ·
[Command analyzer contract](../specifications/command-injection.md)

## Source-backed expected defects and exposure paths

These expectations are independent of scanner/model output. A source-backed defect is not a runtime
exploit confirmation. Some families remain outside the Command Injection Analyzer implementation;
full-scan reports must state those coverage limits rather than imply every row is detected.

| Case / concern | Entry or configuration | File:line | Source-reviewed expected behavior |
| --- | --- | --- | --- |
| TS-CMDI-01 — Command injection | GET /api/ping | `src/server.ts:90` (source88, import9) | Query host is interpolated into imported child_process.exec's shell command. Mandatory positive in the command implementation's final full judged scan |
| TS-XSS-01 — Reflected XSS | GET /api/search | `src/server.ts:117` (source115) | Query text interpolated into HTML string passed to res.send without output encoding; retain existing XSS positive |
| TS-AUTH-01 — Password check missing | POST /api/login | `src/server.ts:76–80` | User selected by username alone; supplied password is not compared before signing/returning a token. This is an authentication defect, not executed SQL injection |
| TS-LOG-01 — Credential-content logging | POST /api/login | `src/server.ts:73–74` | SQL-shaped string includes the supplied login password and reaches console.log; assess credential sensitivity independently of simulated SQL execution |
| TS-PATH-01 — Path traversal | GET /api/files | `src/server.ts:103–104` (source101) | Request filename reaches path.join and fs.readFile without enforced uploads-directory containment; normalization alone is not containment |
| TS-SSRF-01 — Unrestricted outbound destination | GET /api/proxy | `src/server.ts:125` (source122) | Request URL forwarded to axios.default.get without local destination restrictions. Source-positive SSRF review target; verified import/client semantics and deployment reachability remain separate obligations |
| TS-CODE-01 — Code injection | POST /api/calculate | `src/server.ts:137` (source134) | eval directly receives request expression; separate code-execution family, not a child_process shell operand |
| TS-AUTHZ-01 — Unauthenticated admin deletion | DELETE /api/admin/users/:id | `src/server.ts:145–150` | No authentication/authorization check before deleting the selected in-memory user |
| TS-IDOR-01 — Unrestricted user-object disclosure | GET /api/users/:id | `src/server.ts:158–163` | Caller chooses user ID and receives the full user object, including password field, without a local identity/authorization gate |
| TS-MASS-01 — Mass assignment | POST /api/register | `src/server.ts:197–202` | Unrestricted request-body spread can set role and override the initially assigned id before storage; no server-side role allowlist |
| TS-SECRET-01 — Hardcoded credentials/signing secrets | Module/session configuration | `src/server.ts:22–24`, `:36` (JWT use79) | Literal signing/session secrets and credential-like configuration. Do not reproduce secret values in the evaluation guide; dependency audit is separate |
| TS-DISCLOSE-01 — Debug endpoint | GET /api/debug | `src/server.ts:208–215` | Response includes process.env, signing secret, credential configuration and user store |
| TS-SESSION-01 — Cookie configuration | Global session middleware | `src/server.ts:35–44` (secure40, httpOnly41) | Explicitly disables Secure and HttpOnly; deployment HTTPS requirements and lifetime policy are separate from the source configuration |
| TS-REDIRECT-01 — Open redirect | GET /redirect | `src/server.ts:239` (source237) | Request URL passed directly to res.redirect without destination policy |
| TS-ERROR-01 — Error information/credentials | GET /api/error-test | `src/server.ts:253–256` | Throws a credential-bearing connection-string message and returns message plus stack |
| TS-ERROR-02 — Global error disclosure | Error middleware | `src/server.ts:301–304` | Response exposes err.message, err.stack and the error object; diagnostic logging at299 is a separate sink |

## Documented claims that need qualification

The upstream README names older `main.ts` / `app.controller.ts` locations absent from this pinned
`src/` tree. Source comments and the README's category labels are leads, not an answer key. These
cases MUST NOT be forced into confirmed findings merely to match the author's vulnerability list.

| Case / claimed concern | Actual file:line | Correct expected classification |
| --- | --- | --- |
| TS-SQL-N01 — Simulated SQL injection | `src/server.ts:73–76` | SQL-shaped text is constructed/logged but never passed to a database. users.find is an array lookup. Negative for executed SQL injection; preserve the separate authentication/logging defects |
| TS-XXE-REVIEW — XML parsing | `src/server.ts:173` | xml2js.parseString with strict:false alone does not establish external-entity resolution. Requires verified parser/version behavior before a positive XXE expectation |
| TS-YAML-REVIEW — YAML deserialization | `src/server.ts:187` | Actual API is js-yaml.safeLoad, not unrestricted load. Do not infer arbitrary code execution from the comment; verify pinned version/schema/advisory semantics separately |
| TS-PROTOTYPE-REVIEW — Prototype pollution | `src/server.ts:246` | Request target/source reach lodash.merge; package.json declares lodash4.17.4. Strong source/dependency review lead; confirm the affected operation/version and dangerous-key semantics before promoting a positive |
| TS-REDOS-REVIEW — Regex DoS | `src/server.ts:223–224` | Request text reaches a regex with nested/overlapping repetition and no local input bound. Review algorithmic complexity; no timing/runtime exploit was executed |
| TS-RANDOM-REVIEW — Insecure randomness | `src/server.ts:231` | Math.random creates a value returned as a token. Non-cryptographic construction is established; actual security-token use/policy must be established for a security claim |
| TS-CORS-REVIEW — Wildcard plus credentials | `src/server.ts:48–50` | Wildcard origin and credentials:true are emitted, but this does not by itself prove credentialed browser access; that combination is not a valid credentialed allow-origin response |
| TS-ENV-REVIEW — Development setting | `src/server.ts:27` | Development environment explicitly set. Do not claim production deployment or a separate exploit solely from this line |
| TS-UPLOAD-N01 — Claimed unrestricted upload | No corresponding handler in `src/server.ts` | The upstream README lists an upload example, but none is established in this source file. Do not invent a route or pass an unsupported source claim as a detected vulnerability |

## Final command acceptance and sample refresh

The independent command-positive set is TS-CMDI-01, at the single shell sink on line90. Its source
trace MUST retain GET /api/ping → req.query.host → TypeScript cast/local host → template command →
verified exec. A cast is not runtime validation. Callback output/error handling does not protect
command syntax. Keep constant process-call and fixed-executable/allowlisted-argv controls in scanner
fixtures rather than altering this vulnerable baseline.

The final full judged run includes all source-supported analyzer families and preserves existing XSS
and other supported findings. Unsupported additional families above remain explicitly documented;
this contract does not implement every vulnerability category as hidden command-detector work.
Refresh the sample's canonical HTML/JSON/SARIF, metadata and README using actual final scan results.
Expected labels remain outside scanner/model inputs. Preserve old runs and keep public paths and
upstream attribution correct. No fresh findings are claimed by this documentation-only source review.

## Source hashes

| File | SHA-256 |
| --- | --- |
| `src/server.ts` | `14c7e1e0189e4688edaa48ad1d777943d667d9d8040c74baafd7b7c2b81ac9bb` |
| `package.json` | `654c071947aa9212caef62134222cce0de48a4fdf66423c58fd4b08b67e3d791` |
| `README.md` | `5363098f3cdd18371ec87aac06da56c0671f70a7c3583d12d59c98f296512366` |


## Command-injection result

The final judged scan confirmed TS-CMDI-01 at `src/server.ts:90` as a completed, gated `confirmed_vulnerability` (see the [acceptance results](command-injection-results.md)). This guide remains the independent expectation, unchanged.
