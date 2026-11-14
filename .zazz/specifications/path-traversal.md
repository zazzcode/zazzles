# Path Traversal Analyzer

## 1. Capability and prerequisite

Implement bounded request-to-filesystem path traversal analysis for JavaScript, TypeScript and
Python on the existing shared analysis engine, component catalog and report pipeline. Begin with
`GET /api/files` in the pinned vulnerable TypeScript sample, then verify positive, protected and
unresolved controls across all supported languages.

Shared Gemini support is an existing provider integration, delivered and verified separately under
the [Gemini contract](gemini-decisions.md#capability-and-boundary). This specification does not
implement a provider. Before unattended analyzer execution, verify the project plan's
[Gemini prerequisite](../project/implementation-plan.md#active-delivery-shared-gemini-then-path-traversal)
and its live sample result; an unchecked prerequisite blocks that session.
The selected `JUDGE_DECISION_MODEL` applies to every analyzer. No per-family provider or fallback.

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
| README, orientation, implementation plan and architecture status | Delivered coverage/limits after verification |

Strict scope: only these file groups and necessary integration hooks in the named roots.
No archive extraction/Zip Slip, new languages, general graph rewrite, unbounded filesystem modeling,
other vulnerability classes or provider implementation. Identify exact shared hooks in the run log
before editing; add a generalizable fixture for each required structural prerequisite.

## 5. Acceptance criteria

### Initial operation contract

The source-reviewed first witness is `src/server.ts:104`: `req.query.filename` flows through
`path.join(__dirname, '../uploads', filename)` into `fs.readFile(filePath, 'utf8', callback)`.
The path join has no enforcing containment check. Type assertions are not runtime constraints.
Preserve the callback/error branches; neither an error response nor `try/catch` protects the path.

| Binding / API | Effective path slot and bounded behavior |
| --- | --- |
| Node `fs.readFile`, `readFileSync`; `fs/promises.readFile` | First path argument, not encoding/options or callback output; support verified core import/require aliases |
| Node `fs.writeFile`, `writeFileSync`; `fs/promises.writeFile` | First path argument; file content is a separate operand, not a path source |
| Python builtin `open`, `io.open` | First/file positional or keyword operand; mode distinguishes read/write; shadowing blocks the builtin contract |
| Python `pathlib.Path.open`, `read_text`, `read_bytes`, `write_text`, `write_bytes` | Verified Path receiver carries the effective path; content/encoding are distinct |
| Node `path.join`, `resolve`, `normalize`; Python `os.path.join`, `abspath`, `normpath`, Path `/` | Transformations, never automatic containment proof |
| Node `path.relative`, `realpath`; Python `commonpath`, `realpath`, `Path.resolve` | Evidence for a guard only with same value/root and enforcing control; lexical prefix alone is insufficient |

Framework send-file wrappers, uploads, delete/rename and multi-path operations are deferred unless
explicitly added with source-reviewed operand contracts before their implementation. This keeps the
initial read/write boundary reviewable rather than guessing framework or filesystem semantics.

### Required outcomes

1. Bind the initial Node filesystem and Python open/pathlib APIs above from source,
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
6. JSON/HTML/SARIF agree on finding status, filesystem operation, CWE-22 and scoped remediation.
   Historical schemas/replay remain readable; existing analyzers retain their results.
7. The independently reviewed `/api/files` positive and JS/TS/Python positive/protected/unknown
   controls pass. Source expectations precede tuning and never enter model input. Any broader
   sample acceptance declares pins, denominator, routes and request cap before live calls.

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
findings and false protection alongside recall.

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

- [ ] Shared Gemini prerequisite verified before analyzer launch.
- [ ] Exact API/platform matrix and independent references locked.
- [ ] JS/TS/Python positive, protected and unknown controls pass.
- [ ] Selected components, mandatory gates and exact replay verified.
- [ ] JSON/HTML/SARIF parity and existing-family checks pass.
- [ ] Authorized sample evidence and public coverage limits recorded.
- [ ] Human review completed.

## 10. Open questions

The initial API matrix is fixed above; target-relevant platform assumptions must be recorded in
§7 step 1 before coding.
The unattended scope below selects all eight cataloged sample apps, Gemini only, with bounded
requests and explicit incomplete-state reporting. It does not launch the session.

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
