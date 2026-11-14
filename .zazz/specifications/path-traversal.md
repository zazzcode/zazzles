# Path Traversal Analyzer

## 1. Capability and prerequisite

Implement bounded request-to-filesystem path traversal analysis for JavaScript, TypeScript and
Python on the existing shared analysis engine, component catalog and report pipeline. The analyzer
covers request-controlled file paths **and** request-supplied archive entry names (the Zip Slip
variant of CWE-22) for the operations in the [supported operation matrix](#supported-operation-matrix),
reports confirmed, poor-practice, protected and Review records, and is verified across the eight
cataloged sample apps plus portable positive/protected/unknown fixtures.

Shared Gemini support is an existing provider integration, delivered and verified separately under
the [Gemini contract](gemini-decisions.md#capability-and-boundary). This specification does not
implement a provider. The selected `JUDGE_DECISION_MODEL` applies to every analyzer. No per-family
provider or fallback.

**Detection must be general.** Samples are test targets, never inputs to the analyzer. No target name,
file name, line number, challenge name or answer key may appear in analyzer code, catalog material or
model-bound evidence. A case the analyzer cannot detect through a verified, source-backed model is
reported as not covered, never special-cased or faked.

## 2. Required reading

- [Agent rules](../../AGENTS.md#authorization-and-delivery),
  [code map](../docs/zazzles-agent-orientation.md#code-structure),
  [claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes).
- [Component ownership](../architecture/analysis-packs.md#boundary-and-ownership),
  [selection contract](../architecture/analysis-packs.md#descriptor-and-selection-contract),
  [bounds](../architecture/analysis-packs.md#bounds-and-compatibility).
- [Calibration pairs](../../docs/analysis/calibration.md#regression-pairs),
  [sample policy](../../docs/samples/reference-policy.md),
  [TypeScript source guide](../evaluation/vulnerable-typescript-app-detection-guide.md).
- Standards: [code structure](../standards/code-structure.md), [testing](../standards/testing.md),
  [docs hygiene](../standards/docs-hygiene.md), [spec hygiene](../standards/spec-hygiene.md).

## 3. Invariants and decisions

- Static adapters establish bindings, effective path operands, source snapshots, invocation identity
  and value/control transfers. Selected guidance cannot invent facts or close missing evidence.
- Path normalization, path construction, containment enforcement and file operation are distinct.
  A join/resolve call by itself does not establish containment within a trusted directory.
- Preserve branch, operand and invocation identity. A sibling's guard does not protect this path.
  A verified unsafe path may establish a scoped finding; unresolved siblings remain visible.
- Only final protected_for_claim is green; model confidence does not close blockers. Do not claim
  runtime exploitation or independent Findings Review.
- Reuse the catalog and mandatory evidence validation checks rather than adding a separate detector
  engine/prompt.
  Preserve existing-family request bytes and historical reports; changed evidence needs new answers.
- Targets remain read-only. No dependency installs, app execution or remediation in pinned checkouts.
- Only request-origin (`input_source`) dependencies are path sources. Stored, file, API-response and
  browser values are never invented as request fields; write content and options are never path sources.
- A verified binding, an enforcing control and a dependency version are facts established from source
  (imports, syntax, manifest/lockfile), never from names, comments or model confidence.
- Adding the analyzer must not change any existing analyzer's evidence: every non-path use and every
  entry of every sample must stay byte-identical to the base commit (verified by comparison), and a
  path-only pass (for example the request-URL second pass) must discard all non-path uses.
- A candidate hook must run before any shared model that consumes the same call whole (template-file
  read, framework response model) and must be additive.

## 4. Scope and review shape

One analyzer deliverable stays in the assigned `path-traversal` worktree/branch, with one eventual
draft PR into `stage`. User review owns launch of the later unattended implementation session;
this spec preparation does not launch it. No extra worktree or branch stack is needed.

| Allowed file groups | Responsibility |
| --- | --- |
| `internal/analysis/path*.go` and shared records | Optional filesystem/path facts, operands and compatibility |
| `internal/parse/path*.go`, `python_path*.go`, minimal binding/flow hooks | Verified operations, transfers, guards and explicit gaps |
| `internal/analysispacks/path*.go`, catalog hooks; `internal/guidelines/path*` | Versioned operation contracts, material, questions and obligations |
| `internal/judge/path*.go`, minimal dispatch/bundle/coverage hooks | Selected questions, wire facts, completeness and claim policy |
| `internal/report/path*.go`, classification/SARIF/guidance hooks | Scoped CWE-22 findings and JSON/HTML/SARIF parity |
| `internal/parse/testdata/{javascript,typescript,python}/path-traversal/` | Independent positive/protected/unknown fixtures |
| `docs/analysis/path-traversal.md`, analysis index; `.zazz/evaluation/path-traversal*` | Product rules, reviewed source matrix and acceptance evidence |
| `internal/parse/claim_assembly.go` | Hook-driven claim assembly shared with the command analyzer |
| README, orientation, implementation plan and architecture status | Delivered coverage/limits after verification |

Strict scope: only these file groups and necessary integration hooks in the named roots.
Archive extraction (Zip Slip) is in scope only for the libraries that have a source-reviewed contract
(currently `adm-zip` `extractAllTo`, with the release decided from the dependency declaration). No new
languages, general graph rewrite, unbounded filesystem modeling, other vulnerability classes or provider implementation. Identify exact shared hooks in the run log
before editing; add a generalizable fixture for each required structural prerequisite.

## 5. Acceptance criteria

### Supported operation matrix

The first source-reviewed witness is `src/server.ts:104` of the pinned vulnerable TypeScript sample:
`req.query.filename` flows through `path.join(__dirname, '../uploads', filename)` into
`fs.readFile(filePath, 'utf8', callback)` with no enforcing containment; type assertions are not runtime
constraints and neither the error branch nor `try/catch` protects the path. Each row below has its own
catalog contract with cited official semantics; an operation not listed is not covered.

| Binding / API | Contract | Effective operand and bounded behavior |
| --- | --- | --- |
| Node `fs` `readFile(Sync)`, `writeFile(Sync)`, `appendFile(Sync)`, `createReadStream`, `createWriteStream`, `unlink(Sync)`, `rm(Sync)`; `fs/promises` and `fs.promises` forms | `node-fs-file-v1` | first argument; write data, options and callbacks are separate; verified core import/require/destructuring only |
| Express `res.sendFile`, `res.download` | `express-send-file-v1` | first argument; a constant `root` option is a library-enforced boundary; request-derived root is not |
| `adm-zip` `extractAllTo(Async)` on an `AdmZip(...)` instance | `adm-zip-extract-v1` | the request-supplied archive (entry names); release from lockfile/manifest decides: below 0.4.11 witness, fixed release control, range/missing unknown |
| Python builtin `open`, `io.open` | `python-open-file-v1` | first/file operand; mode decides read/write; shadowing blocks the contract |
| Python `pathlib.Path.open/read_text/read_bytes/write_text/write_bytes` | `python-pathlib-file-v1` | verified Path receiver (constructor, module-level Path, `/`) |
| Python `tarfile.open/TarFile/TarFile.open`, `bz2.open/BZ2File`, `gzip.open/GzipFile`, `lzma.open/LZMAFile` | `python-archive-open-v1` | name/filename argument or keyword |
| Python `os.remove`, `os.unlink` | `python-os-file-v1` | first argument (delete role) |
| Flask `send_file`, `send_from_directory` | `flask-send-file-v1` | `send_file` first argument; `send_from_directory` path argument, library `safe_join` boundary when the directory is not request-derived |
| werkzeug `FileStorage.save` on a `request.files` value | `werkzeug-file-save-v1` | destination argument; client `filename` is unsanitized; verified `secure_filename` is a lexical component control |
| Node `path.join/resolve/normalize/basename/dirname/extname/relative/isAbsolute`; Python `os.path.join/abspath/normpath/realpath/basename/dirname/relpath/commonpath`, Path `/` | (transformations) | never automatic containment; `join` appends an absolute segment, `resolve`/`os.path.join`/`/` replace the base |
| Controls: allow-list membership, separator-bounded prefix, `relative`, `commonpath`, `is_relative_to`, `secure_filename`, Express root, `send_from_directory`, fixed extractor release | (guard kinds) | enforcing only on the same value with a rejecting, terminating branch; bare prefix, `..` text, separator-only and unclassified controls never establish containment |

Request sources: Express `body`, `query`, `params`, `headers`, `cookies`; for path claims only `req.path`,
`req.url`, `req.originalUrl`, `req.baseUrl`, `req.file(s)` (a path-only second pass of the handler);
Flask `request` containers and `request.files`; GraphQL and gRPC request fields through the shared entry
model. Deferred, reported as not covered: `copyFile`, `rename`, `readdir`, `stat`, `existsSync`,
`express.static`, multer disk storage, `shutil`, Python archive extraction, archive libraries other than
`adm-zip`, template-layout reads (`res.render` layout), handlers that are not the last element of an Express
route chain, second-order flows and symbolic-link/race behavior.

### Required outcomes

1. Bind the supported operations above from source,
   not names alone. Verify their version-specific semantics before coding. Fake objects,
   shadowed imports/requires, reassignment and unmodeled wrappers cannot acquire trusted contracts.
2. Record source field, effective file-path operand, trusted root if established, transformations,
   guard outcomes and witness. Read/write/send roles stay separate; other string arguments are not
   fabricated paths. Unknown platform, overloads, dynamic options and helpers retain relevant gaps.
3. Test traversal via `..`, absolute paths, sibling-prefix collisions, decode-after-check, reassignment,
   missing helpers, bypassing/sibling branches and platform ambiguity. Normalization alone must not
   yield Protected. Trusted allow-listed file identities and actual enforcing containment checks
   have paired controls.
4. Distinguish lexical containment from symlink/runtime containment. A realpath-based claim requires
   source-backed resolution, guard and use identity, with race/filesystem assumptions explicit.
   Missing relevant facts stay Review; do not infer safe filesystem state from the scanner host.
5. Add all required path components/guidance, protocol version and provenance. Ask atomic traversal,
   containment and coverage questions over the candidate evidence; mandatory gates remain in Go.
6. JSON/HTML/SARIF agree on finding status (`confirmed_vulnerability`, `poor_practice`, `protected_for_claim`,
   `needs_evidence`), filesystem operation, CWE-22 and scoped remediation; the archive variant has its own
   title and SARIF rule id under the same finding type.
   Historical schemas/replay remain readable; existing analyzers retain their results.
7. The independently reviewed `/api/files` positive and JS/TS/Python positive/protected/unknown
   controls pass. Source expectations precede tuning and never enter model input. Sample acceptance
   declares pins, denominator, routes and request cap before live calls and scores every row of the
   reviewed matrix (positive, protected, unknown, no-candidate), reporting remaining blocked rows.
8. A new `poor_practice` outcome applies only when every request flow is guarded solely by a recognized
   weak control and the assessment finds no enforced containment; unclassified controls stay Review.
9. Guards are found across a local helper boundary by following the helper to its call sites; several call
   sites with one uncontrolled site leave the flow unresolved.

## 6. Test strategy

Use small fixtures and HTTP stubs first: recognition/operand mapping, independent guard/branch pairs,
component selection and provenance, policy contradictions/blockers, replay and three-format parity.
Goldens come from the repository's existing update mechanism and receive diff review. Preserve
unknown controls rather than adding exact-pattern tests that merely mirror implementation.

Official semantics to verify at the target-relevant runtime/platform before coding:
[Node fs](https://nodejs.org/api/fs.html), [Node path](https://nodejs.org/api/path.html),
[Python pathlib](https://docs.python.org/3/library/pathlib.html),
[Python os.path](https://docs.python.org/3/library/os.path.html), and each selected framework's
file-response contract. The deployed platform is not inferred from the development computer.
Independently review pinned sample source before locking the positive denominator; test false
findings and false protection alongside recall. Required test kinds: per-language fixture tables
(`TestPathJSOperands`, `TestPathCommonJSBindings`, `TestPathPythonOperands`, GraphQL/gRPC entries, archive
extraction by dependency version); catalog selection and contract tests; model-answer policy matrices over the
same fixtures with honest, over-claimed and unknown answers; request payload, provenance, exact replay and
mutation rejection; JSON/HTML/SARIF parity; an independent structural source-case test that scores the
matrix against the pinned targets (`TestPathSourceCases`); and a comparison proving every non-path use and
entry of every sample equals the base commit. A live fixture run with the selected model verifies protected
and unknown controls end to end.

## 7. Prescriptive execution sequence

1. Verify shared judge prerequisite and user launch instruction. Read source witness, fix exact
   API/operand/platform scope and independent expectation matrix; record it before production edits.
2. Add a failing vulnerable/protected/unknown extraction pair for each supported language.
3. Add `PathFacts` in shared analysis, verified bindings and operand/guard assembly in parse.
   Skeleton: `source -> effective path -> guard/control witness -> filesystem operation`.
4. Add embedded path contracts/guidance and selection; project facts through shared judge bundles.
   Skeleton: `attachPathComponents(use) -> Assess(use) -> applyPathPolicy(use, assessment)`.
5. Add scoped report/CWE presentation and compatibility/replay tests; run the existing-family suite.
6. Perform agreed bounded live evaluation only after offline checks; record failures and controls.
   Update actual supported APIs/limits and acceptance docs, then prepare human review when requested.

## 8. Agent implementation rules, halt conditions and run log

The Lead Agent executes sequentially; no contributor-agent delegation is required. Future requested
independent QA reads this contract and evidence without modifying implementation. Load matched
standards, use the declared Go toolchain/compatible native patch, format changed Go files only.
Append attempts, exact scope decisions and check evidence to ignored
`.zazz/ephemeral/path-traversal-run-log.md`; read it on resume. No Board is used.
Halt the affected slice for unresolved API/platform semantics, scope expansion, invalid sample pin,
credential/quota errors or destructive recovery. Preserve user changes and local `.env` files.
No fallback, live Jev calls, integration push, merge or release is authorized.

## 9. Definition of done

- [x] Shared Gemini prerequisite verified before analyzer launch.
- [x] Exact API/platform matrix and independent references locked (versioned `matrix.json` with corrections).
- [ ] JS/TS/Python positive, protected and unknown controls pass offline and live (offline passes; live 40/40 vulnerable, 14/15 protected and 13/13 unknown/weak match; Python prefix-boundary remains Review).
- [x] Selected components, mandatory gates and exact replay verified.
- [x] JSON/HTML/SARIF parity and existing-family checks pass (byte-identical non-path evidence).
- [x] Authorized sample evidence and public coverage limits recorded ([results](../evaluation/path-traversal-results.md)).
- [ ] Close both remaining Juice Shop rows through general verified models: middleware-chain upload handler/unzipper entry-name flow and `hbs` render-layout read.
- [ ] Judge all remaining 148 VulnPy contexts; current representative sampling does not satisfy this expanded acceptance.
- [ ] Human review completed.

## 10. Open questions

Resolved: the API matrix is the supported operation matrix above; the platform is POSIX by declaration; the
unattended scope covers all eight cataloged sample apps, Gemini only, with bounded requests.

Owner-authorized next: general middle-handler entries and unzipper entry-name flow; verified `hbs`
render-layout semantics with source-backed engine registration; all remaining VulnPy live contexts.
These are implementation requirements, not unresolved permission questions. Existing records must remain
unchanged while the newly admitted middleware-handler records are enumerated separately.

Still open beyond that scope: additional archive operations (`tar`, Python `zipfile`/`tarfile` extraction)
and unmodeled hand-written entry loops; second-order flows through storage; Windows path semantics.

## 11. Copy/paste prompt: unattended implementation, testing and correction loop

Copy the following prompt into a new implementation session **when the user chooses to launch it**:

```text
Implement the Path Traversal Analyzer in the existing path-traversal worktree/branch.
Read AGENTS.md, .zazz/specifications/path-traversal.md, its focused references and the ignored
.zazz/ephemeral/path-traversal-run-log.md. Verify the shared Gemini prerequisite using
.zazz/evaluation/gemini-decisions-results.md. Do not reimplement Gemini or edit .env files.
Use the configured GEMINI_API_KEY with JUDGE_DECISION_MODEL=gemini-decision-1, and no fallback.

Work sequentially and autonomously through the implementation, testing and correction loop below.
Do not stop at a first detector, a successful build, one positive example or a draft plan.
No contributor agents, new worktrees, application execution, sample fixes or integration merge.

1. Verify the actual worktree/branch and preserve existing changes. Follow this contract's scope,
   static evidence gates, initial API matrix and matched engineering standards. Record exact
   changes, decisions, failed attempts and acceptance evidence in the ignored run log.
2. Review all eight available sample apps from the agent orientation and pinned catalog:
   vuln-demo-app, vulnerable-typescript-app, nodejs-goof, juice-shop, vulnpy, ThreatByte,
   python-insecure-app and Vulnerable-Flask-App. Verify each target's pinned HEAD and clean Git
   status including ignored files before/after. Missing targets/pins must be explicit blockers.
3. Before tuning, build a source-reviewed path-traversal expectation matrix for every app:
   actual input field -> path construction/guard -> effective filesystem operation, file/line,
   expected positive/protected/unknown outcome, platform/API assumptions and reference source.
   Distinguish a real no-applicable-case result from unsupported/missed extraction. Review all
   source-documented traversal cases, including VulnPy's shared trigger/framework contexts;
   repeated contexts are not separate root defects. Do not use application comments, challenge
   names or scanner output alone as truth. Keep answer keys out of model-bound evidence.
4. Add vulnerable/protected/unknown JS/TS/Python regression pairs first. Implement extraction,
   operands, verified API models, flow/guard facts, versioned path components and guidance,
   atomic judge questions, mandatory evidence validation checks, and JSON/HTML/SARIF output. Extend
   shared flow only with a generalizable path-relevant fixture; no target-name or answer-key exceptions.
5. Run scoped offline tests after each change. Then scan the pinned apps structurally and evaluate
   their source-backed path candidates with Gemini. Use a Go evaluation harness when needed to
   select path candidates from the canonical scan without paying to rejudge every other analyzer.
   Do not hide other analyzers, overwrite their historical outcomes, or treat unjudged paths as safe.
   Retain exact requests/responses, source hashes, component/protocol versions and canonical reports.
6. Inspect every expected positive, protected control and unknown case against the source matrix.
   Check both detection and final reporting: correct operation/operand, branch/invocation/source,
   CWE-22, scoped explanation/remediation, evidence spans, raw assessment and final status in
   JSON, HTML and SARIF. A candidate without a supported final finding is not a detected positive.
7. For each missed positive, false finding, false protection or reporting mismatch: identify the
   scanner defect, add a failing general regression, fix the source/evidence/model/policy/report
   implementation, then rerun affected cases and regressions. Reassess changed requests freshly;
   replay only exact matching requests. Preserve failed iterations rather than replacing history.
   Repeat steps 4-7 until every in-scope expected positive is correctly detected/reported, every
   protected control remains protected, and intentionally unknown cases remain unresolved.
8. Keep live requests bounded: Gemini only, no retries, at most 100 HTTP requests in any evaluation
   batch and 500 total for the session, counting discovery and failed requests. Record cumulative
   use; never loop through authentication/quota/transport failures. If the cap, missing evidence
   or an out-of-scope API blocks completion, save a precise checkpoint and report the remaining
   failing matrix rows. Do not mark the deliverable complete or switch models to force a pass.
   Resolve a material scope/API expansion with the user; keep unaffected cases moving.
9. On matrix convergence, run go build ./..., go vet ./..., go test -race ./..., changed-file
   formatting and documentation checks. Verify report parity, exact replay and existing-family
   regressions. Publish the independently reviewed matrix and source/protocol/model provenance in
   .zazz/evaluation/path-traversal-results.md, update actual supported coverage/limits in public
   analysis docs, README and project checklist, and provide local three-format report links.
10. Return a reviewable checkpoint with exact check outcomes, all expectation rows accounted for,
    request totals, artifact paths and any remaining blockers. Do not claim all path traversal in
    arbitrary code is solved. Follow current user commit/push instructions; never merge or release.

Completion means the agreed source-reviewed positive/control matrix passes, not merely that the
model answered or the scanner exited zero. No broader provider-equivalence claim is implied.
```

## 12. Implementation And Review Change Log

2026-11-14 — User separated the shared provider prerequisite and requested the copy/paste
unattended implementation/testing prompt, including a correction loop across all cataloged sample
apps. This specification prepares that session; it does not start it.

2026-11-14 (implementation session) — User approved widening scope so every source-documented traversal in
the eight samples is detected with accuracy: Express `res.sendFile`/`download`, `req.path`/`req.url`/
`req.originalUrl`/`req.file(s)` as path-claim sources (through a path-only second pass of the handler, so no
other analyzer's evidence changes), Node `createReadStream`/`createWriteStream`/`appendFile`/`unlink`/`rm`,
Python `tarfile`/`bz2`/`gzip`/`lzma` opens, `os.remove`/`os.unlink`, Flask `send_file`/`send_from_directory`,
werkzeug `FileStorage.save` with verified `secure_filename`, and `adm-zip` extraction (Zip Slip, archive
variant of CWE-22, reported under the same finding type with its own title and SARIF rule). A `poor_practice`
outcome was added for recognized weak controls. Remaining and reported, not faked: Juice Shop's zip upload
(middle handler of a route chain is not an entry) and its `res.render` layout read (no verified per-engine
contract).

### 2026-11-14 — Owner authorizes remaining coverage and shared controls

**Source.** Owner requested fixing both uncovered Juice Shop cases and the unjudged VulnPy contexts in this session, updating specifications/capability docs, then committing/pushing a checkpoint before implementing improvements.

**Changed sections.** Definition of done and open-question status; the results record now reports exact live fixture variance and partial context judgment. Shared runtime limits have their own [contract](decision-model-limits.md).

**Rationale and scope.** Model Express route-chain handlers and unzipper entry names generally, and verify `hbs` engine registration/layout semantics for `res.render`; no target-specific rules or expectation changes to match model answers. Judge the 85 remaining archive-open and 63 WSGI-template contexts. Existing records/evidence must remain byte-identical; explicitly added middleware-handler entries/records are allowed coverage expansion, not permission to rewrite old evidence.

**Verification impact.** Failing portable regressions before each new model; source-reviewed official API contracts; all matrix rows/live contexts scored; exact replay for unchanged bytes; fresh judgments only for changed/new requests. Compare all existing non-path uses/entries byte-for-byte while enumerating any newly admitted middleware entries. Re-run build/vet/race, report parity and documentation checks. Pricing/rate configuration must not alter evidence payloads.
