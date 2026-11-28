# XSS detection and reporting

## Outcome, authorization and scope

The user requested implementation and testing of each XSS type in `xss-response` on 2026-11-01,
with a saved zazzles findings report after each type before proceeding. The
[scope](../../project/xss-detection-scope.md) supplies named sources, sinks, controls and delivery order.
The user also requested a separate client-side results section and a language-neutral design for
a Python vulnerable application after XSS. The human user owns scope and review decisions.

One feature worktree contains the related implementation, docs, tests and evaluation samples.
Integration remains `stage` through human-reviewed draft PRs; the user subsequently authorized committing and pushing the feature branch. No PR or merge is
requested. Execution is local by the primary agent; progress/evidence go to
ignored `.zazz/ephemeral/xss-response-run-log.md`.

Read [AGENTS.md](../../../AGENTS.md), the scope, [answer key](../../../docs/samples/nodejs-goof/xss-answer-key.md),
[baseline](../../evaluation/nodejs-goof-results.md), and relevant existing parse/graph/report/judge code.
Applicable standards: [code structure](../../standards/code-structure.md),
[testing](../../standards/testing.md), [spec hygiene](../../standards/spec-hygiene.md), and
[documentation hygiene](../../standards/docs-hygiene.md).

Changes may touch `internal/parse` (JS/TS extraction and templates), `internal/analysis` (shared claim
facts), `internal/report` (classification and export), `internal/judge` / `internal/guidelines` (XSS
protocol/policy), `cmd/scan` (integration only), matching tests/fixtures, `docs/analysis` and user
guides, curated `docs/samples`, and the owning `.zazz` architecture/project/spec/evaluation docs.
Target repositories remain unchanged. Python parsing, SCA, live exploit execution, paid model
calls and general whole-program soundness are outside this incremented implementation.

## Invariants and design decisions

- Source, sink binding, dependency transfers, rendering context and protection evidence MUST be
  source-backed. Target/challenge names, expected labels and exploit payloads MUST NOT drive detection.
- XSS facts MUST use language-neutral source/context/protection/persistence/entry fields. JS/TS and
  template extraction belong in parser adapters; Python later supplies the same claim representation.
  No Python adapter is scaffolded before its application and language contracts are selected.
- Static raw-output construction is an orange finding when established; protection is green only
  for the stated context on every modeled path. Unknown sanitizer/context/origin remains Review.
  A failed parse or unknown call MUST NOT become protection. Red requires complete consistent
  versioned judgment evidence. No live judgment is authorized here.
- JSON owns canonical evidence. HTML and SARIF consume the same classifications. Browser claims
  have their own client entry identity and report section, rather than invented HTTP method/path.
  Cross-tier links share related identities and MUST NOT imply independently confirmed duplicates.
- Existing non-XSS analysis and saved historical judgments remain intact. Changed evidence never
  inherits old model answers. The pre-change Goof baseline remains immutable.

## Increments and acceptance

Proceed sequentially. For each increment implement paired positive/protected/unknown fixtures,
run affected package tests, regenerate a fresh target JSON/HTML/SARIF sample, inspect its finding
records against the independent answer key, and record remaining gaps before starting the next.

| Increment | Behavior / acceptance | Evidence |
|---|---|---|
| 1. Reflected server output | Resolve verified CommonJS Express imports and named exported handlers, with shadow/reassignment negatives. Find request data in Express string HTML responses (`send`, `write`, `end`) and raw EJS/Handlebars/Pug output. Preserve content-type negatives, safe interpolation and unknown transforms; context-specific encoder/sanitizer contracts. Goof login and TypeScript search produce XSS findings. | Parse/report/CLI fixtures and separate target bundles; Goof cases 01/N01/N02/N03 |
| 2. Template construction | Link file/template text, replacement and compile/render bindings. Request/stored values inserted before Pug compilation retain context. Juice Shop username and subtitle cases have source-backed findings or named Review blockers, never template-name guesses. | Pug/EJS/Handlebars paired raw/escaped and template-construction controls; target bundles |
| 3. Stored and cross-tier flows | Link request write fields to model/file storage and read/render fields. Goof create/update → Todo.content → Markdown output is stored XSS with version-aware unresolved/ineffective sanitizer evidence. API-only echo/storage is Review until a rendering sink is established. | Cross-route field/model identity and sanitizer before/after/conditional controls; target bundles and case matches |
| 4. Judgment | Versioned `xss-use` context/encoding/sanitizer/exposure questions and rules; fixtures for complete, contradictory, failed and blocked answers. No broad injection protocol reused to decide XSS. | Offline typed response tests; no paid requests |
| 5. Browser output | Browser sources; DOM, Angular/React/Vue and URL/code sinks in scope; Angular template extraction and field links. Default framework interpolation/sanitization is protected; verified trust bypass plus rendering is a sink. Client entries/results appear in a separate section, with file/component/source/sink/context instead of HTTP route labels. | Browser positive/negative/unknown pairs, source-to-component/template witnesses, API links, JSON/HTML/SARIF agreement; Juice Shop fresh bundle |

Parser limits, missing bindings, unresolved storage identity and unsupported template expressions MUST
remain explicit in evidence and results. The acceptance target is bounded semantic modeling for
the scope's named XSS types, not a claim to detect every XSS vulnerability in arbitrary code.

## Verification and delivery

Use the declared Go toolchain (native Go 1.27.3 is available). Run scoped package tests while
iterating, then build, vet and race tests before final delivery. Verify only changed Go files with
gofmt. Tests use synthetic repositories and typed local judgment fixtures; no external keys.
Run `doc-check` for touched documentation, inspect curated report content and retain upstream
licenses. Save implementation bundles under distinct per-increment run IDs alongside their target
revision, scanner source identity, source hashes, assessment mode and answer-key case dispositions.

If a requirement cannot be resolved from source, keep it as Review with its precise blocker and
continue independent scope. Never use a target-specific exception to manufacture a finding.

## Implementation and review change log

### 2026-11-01 — Initial authorized contract

Source: user implementation request plus client-section, independent-answer-key and Python-next
steering. Increment gates preserve the original backend-first/browser-last order and require a
saved report per completed type. Pre-XSS baseline shows the CommonJS prerequisite. Language-neutral
claim facts avoid binding future Python support to Express or Angular entry labels.

### 2026-11-01 — User review and hardening handoff

The user requested all implemented analyzer results (including static imported router mounts and
Mongoose NoSQL), a hide-Protected remediation control, stronger protection evidence, per-app source
references, unchanged baselines/remediation copies, and a local, gitignored handoff in `.zazz/ephemeral/` for a different agent.
Whole-query logging is not a sensitive-data leak without class/content evidence. Whole-object
request rendering stays Review despite escaped field syntax. Five specifically approved Luna
requests completed; confidence/probability metadata and request/response bodies are now retained,
with exact-request offline replay. Deeper analysis/judgment hardening remains next-session work in
the same branch; no additional paid requests are authorized by that completed batch.

### 2026-11-01 — Hardening 08: stored write-path separation

Source: handoff's first bounded task. Unsupported-statement traversal now explores every fall-through
branch exit, so `else`/`catch`/`finally` bodies are no longer skipped. Exact duplicate dependencies are
merged, branch-only paths carry their condition, and per-path protection with writing entries is
exported when paths differ. Paired fixtures cover a supported unsafe path beside an unknown sibling, an
unknown sibling beside encoded paths, an all-path-protected control, and returning and single-statement
branches. Goof create/update remain one orange Markdown sink with three separate paths. The changed
stored request no longer replays its saved answer. Results and blockers:
[evaluation](../../evaluation/xss-implementation-results.md#hardening-08-stored-write-path-separation).

### 2026-11-01 — Hardening 09: helpers, string building, gates, Angular paths, same-sink merge

Source: user steering to harden XSS detection fully, and to write scan results to `_test-findings/<app>`.
Precise content-neutral branching helpers, `+=` propagation (server and DOM), server-side DOMPurify and
Handlebars SafeString gates, per-path Angular bypass classification, and merged same-sink browser records,
each with paired fixtures. Goof matches all answer-key cases. The user also clarified that sample apps are
read-only scan targets, recorded in the agent orientation. Results:
[evaluation](../../evaluation/xss-implementation-results.md#hardening-09-helpers-string-building-gates-and-same-sink-merging).

### 2026-11-01 — Hardening 10: cross-tier response-field links

Source: user approval to take on cross-tier linking next. Server promise continuations, local field writes,
JSON producer fields, browser response-field paths and a single-producer linker. Regex replace is classified
as allow-list, neutral or unknown. Paired fixtures cover linked raw, neutral, allow-list and partial-escape
paths, a different field, a constant response and ambiguous routes. Juice Shop `JS-XSS-02` is now a
supported finding. Also added Semgrep CE as a second local comparator
([cheat sheet](../../../docs/scan/semgrep-ce-cheat-sheet.md)) and refreshed the README capability summary.
Results: [evaluation](../../evaluation/xss-implementation-results.md#hardening-10-cross-tier-response-field-links).

