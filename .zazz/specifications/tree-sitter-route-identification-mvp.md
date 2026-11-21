# Tree-sitter route identification — Deliverable Specification

Historical contract/evidence below retains its original names. Current package, CLI and report
names are documented in the [implemented architecture](../architecture/README.md#naming-and-compatibility).

**Worktree / branch:** `tree-sitter-route-identification-mvp`
**Feature:** JS/TS API route and syntactic code-path inventory
**Milestone:** N/A — first scanner slice, ahead of the later phase list
**Deliverable:** Tree-sitter route identification MVP
**Project Owner:** zazzcode
**Deliverable Owner:** zazzcode
**Delivery topology:** single-deliverable branch
**Review artifact:** one PR for this specification and its implementation
**Approved review shape:** one PR
**Decomposition rationale:** One parser, one JSON contract, and one CLI mode. A stack or a second PR would split the fixture from the command that proves it. Rejected: sibling PRs, a stacked lane, and implementing before this draft is greenlit.
**Integration branch:** `stage`
**Merge policy:** PR review required — agents commit and push this feature branch only
**Drafted:** 2026-10-24
**Status:** Greenlit 2026-10-24. Implemented in this worktree. The program scans a local directory and emits a JSON route index. A Juice Shop checkout at tag `v20.3.0` is the manual check. The index is not a resolved execution trace and does not judge validation or sanitization.
**Shared run log:** `.zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md` (single-specification section). Create it at implementation start. It is gitignored.
**Execution tracking:** local run log only
**Implementation coordination:** Lead Agent working alone
**Companion skills for implementation:** `spec-driven`

---

## 0. Capability

`scan --routes` reads a local JS/TS tree and writes a versioned JSON route index. Each route records its method, path, and the ordered handler chain written at the registration (middleware and the final handler, including calls such as `login()`). The index does not follow imports, Express internals, or string flow. A later spec can use it as the starting point for validation and sanitization analysis. This slice does not judge validation and does not call a model.

---

## 1. Required Reading For The Implementor

Read these before opening an editor. Required reading is section-pinned context, not a license to load the whole repo.

### 1.a This Specification

Read this specification end to end first.

### 1.b Feature / Milestone Context

- [`.zazz/architecture/README.md` §3 Parsing and language adapters](../architecture/README.md#3-parsing-and-language-adapters) — a query match is syntax, not proof of a sink.
- [`.zazz/architecture/README.md` §4 Normalized representation and graph views](../architecture/README.md#4-normalized-representation-and-graph-views) — spans and provenance; this slice does not implement the full IR.
- [`.zazz/architecture/README.md` §11 Proposed package boundaries](../architecture/README.md#11-implemented-package-boundaries) — add `internal/parse` and `internal/graph` only as this spec uses them.
- [`.zazz/project/implementation-plan.md` First build](../project/implementation-plan.md#first-build) — this spec is the first slice. Later phases stay proposed.

### 1.c Prior Specifications In This Delivery Effort

- [`.zazz/specifications/phase0-skeleton/README.md`](phase0-skeleton/README.md) — historical CLI and walker contract. Preserve `scan --list`. Do not treat that spec as approval to extend it.

### 1.d Standards

Per [`.zazz/standards/index.yaml`](../standards/index.yaml):

| Standard | What it governs here |
| --- | --- |
| [`.zazz/standards/code-structure.md`](../standards/code-structure.md) | `cmd/scan` stays thin; `internal/parse` does not learn rules or models; no speculative packages |
| [`.zazz/standards/testing.md`](../standards/testing.md) | table-driven cases, one golden graph, deterministic output, `go test -race` |
| [`.zazz/standards/spec-hygiene.md`](../standards/spec-hygiene.md) | this document: repo-relative paths, no inlined standards |
| [`.zazz/standards/pr-process.md`](../standards/pr-process.md) | one PR into `stage`, draft until human review |

**Verification step before writing code:** run the standards lookup yourself against the file list in §3. If an applicable standard is missing from this table, stop and surface it to the Deliverable Owner before proceeding.

### 1.e Existing Code References

- [`cmd/scan/main.go`](../../cmd/scan/main.go) — flag parsing, exit codes `0/1/2`, indented JSON (CLI implementation now in `scan/cli/`).
- [`cmd/scan/main_test.go`](../../scan/cli/main_test.go) — CLI tests call `run` and do not spawn a binary.
- [`internal/walk/walk.go`](../../scan/internal/walk/walk.go) — file selection and `node_modules` skipping. Reuse it. Do not reimplement the walk.

### 1.f Project Orientation

- [`AGENTS.md`](../../AGENTS.md) — `stage` is the integration branch; agents do not merge.
- [`.zazz/docs/zazzles-agent-orientation.md` Portable workspace](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root) — Juice Shop lookup. Do not hardcode a machine path.

---

## 2. Invariants

These are load-bearing and must hold verbatim. Restate them in the PR body when useful.

### INVARIANT 1 — JSON is the graph file

The execution graph that leaves the process is indented JSON, `schema_version` 1. There is no binary graph file. In-memory values are Go structs. Field names in §4 are the contract.

### INVARIANT 2 — Every fact cites source

Every route and every path step carries a file path relative to the scan root and a 1-based line span plus a byte span. An agent must be able to open that span in the target tree and see the registration, handler, or call.

### INVARIANT 3 — A gap is not a route

A dynamic path, an unresolved handler, or a file that fails to parse is a `gaps` entry. It is not omitted and it is not stored as a guessed route.

### INVARIANT 4 — The chain is syntactic

`steps` are the registration and the handler arguments in source order, plus direct calls inside a same-file handler body. They are the execution graph the next phase reads. They are not a value trace and not a claim that a handler runs at runtime.

### INVARIANT 5 — `scan --list` stays

Existing list text, list JSON, and exit codes stay as covered by the current `cmd/scan` tests. `--routes` is an additional mode.

---

## 3. Scope

### Approved Review Shape

This specification is approved for one PR into `stage`.
Implementation must follow this review shape. If implementation surfaces a need to split, stack, combine, or treat the work as a large exception differently than described here, stop for Deliverable Owner sign-off, update the affected specification sections in place, and record the change in §13 before continuing.

**Rationale.** The review unit is the command plus the JSON it emits on a small fixture. Reviewers can read one golden file. A second PR for libraries, or a stack for the CLI, hides the contract.

**Review units owned by this specification.**

- One PR — route JSON, Express-style extraction for JS/TS, and `scan --routes`.

### Strict Scope Constraint

Every file modification lives under `cmd/scan/`, `internal/parse/`, `internal/graph/`, `go.mod`, `go.sum`, `README.md`, and the two durable-doc pointers named below. If implementation surfaces a need to modify outside this scope, stop and surface it to the Deliverable Owner.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `.zazz/specifications/tree-sitter-route-identification-mvp.md` | New | this contract |
| `go.mod`, `go.sum` | Modified | pin the parser and grammars from §4 |
| `internal/graph/graph.go` | New | route-graph types and JSON |
| `internal/parse/parse.go` | New | Tree-sitter lifecycle and route extraction |
| `internal/parse/parse_test.go` | New | fixture and gap tests |
| `internal/parse/testdata/express-login/` | New | JS, TS, and TSX fixtures plus one golden |
| `cmd/scan/main.go` | Modified | `--routes` mode |
| `cmd/scan/main_test.go` | Modified | routes CLI cases; existing list tests stay |
| `.zazz/project.md` | Modified | point the direction at this first slice |
| `.zazz/project/implementation-plan.md` | Modified | record this spec as the first build |
| `README.md` | Modified | setup, run, and what the route index contains |

### Out Of Scope

- OpenAI Decisions API, Jev, and the LLM Findings Reviewer. No API key and no network call.
- Control-flow, dataflow, taint, rules, findings, or a graph viewer.
- Fastify, Nest, Next, Hono, and other frameworks. A match that is not Express-style is not a route.
- Rewriting the Jev research notes or the later phase list, except the first-build pointer.
- Cloning, installing, or running Juice Shop from tests. A local `v20.3.0` checkout is a manual check only.
- `internal/ir`, `internal/flow`, `internal/trace`, and the other packages in the architecture map.

---

## 4. Decisions

Each decision answers "why this over the obvious alternative?"

### D-1 — JSON route graph, not a binary store

**Decision.** Persist `schema_version` 1 JSON with `root`, `routes`, and `gaps`. Route fields: `id`, `method`, `path_pattern`, `framework` (`express`), `registration`, `handler`, `steps`. Step fields: `kind` (`registration`, `handler`, `call`), `symbol`, and `caller` on calls. Symbol fields: `name`, `kind` (`function`, `method`, `arrow`, `identifier`, `anonymous`), `span`. Span fields: `file`, `start_line`, `end_line`, `start_byte`, `end_byte`. Gap fields: `kind` (`dynamic_path`, `unresolved_handler`, `parse_error`), `detail`, `at`. Route `id` is `route:<file>:<start_byte>:<METHOD>:<path>`.

**Why.** The agent inspects the file. A binary graph or a viewer adds a tool the check does not need. Gonum is rejected for this slice; the records are the graph.

### D-2 — Official Tree-sitter Go binding and the two grammars

**Decision.** After greenlight, add and pin:

- `github.com/tree-sitter/go-tree-sitter` at `v0.24.0`
- `github.com/tree-sitter/tree-sitter-javascript/bindings/go`
- `github.com/tree-sitter/tree-sitter-typescript/bindings/go` (`LanguageTypescript` and `LanguageTSX`)

Both grammar modules currently require `go-tree-sitter` `v0.24.0`. Do not move to `v0.25.0` in this deliverable. Record the exact grammar versions `go get` resolves in `go.mod`. Close every `Parser` and `Tree`. JavaScript and JSX use the JavaScript grammar. TypeScript uses the TypeScript grammar. TSX uses the TSX grammar.

**Why.** The binding does not ship grammars. `v0.24.0` is the version those grammars declare. A newer binding is a separate compatibility change.

### D-3 — Express-style registrations only

**Decision.** A route is a call whose function is a member expression named `get`, `post`, `put`, `patch`, `delete`, `all`, or `use`. The path is a string literal starting with `/`, or an array of such strings (one route per string). The same methods count when chained off `route`: `receiver.route('/path').get(handler).put(handler)` is one route per method, and the path is the string on `route`. `route` itself is not a route. Any receiver name matches; the rule is the call shape, not an application. `use` counts only when a path is present. Map `all` to method `ALL` and `use` to method `USE`. A path argument that is not a string or an array of strings is `dynamic_path` and creates no route.

**Why.** Express registers both `app.post('/path', handler)` and `app.route('/path').get(handler)`, including path arrays. Requiring a leading `/` keeps `map.get('token')` out of the graph. The matcher does not special-case a sample repository. Other frameworks are a later spec.

### D-4 — Same-file handler and direct calls

**Decision.** Arguments after the path are the execution steps, in order. An identifier is a step named by that identifier. A call such as `login()` or `security.isAuthorized()` is a step named by the callee text. If that call has one argument that is an identifier or call, add a further step for it, so `utils.asyncHandler(changePassword())` records both `utils.asyncHandler` and `changePassword`. An inline function is an `anonymous` step, and direct calls in its body are `call` steps. The route's `handler` field is that argument step, not a call found later inside the body. A name with no function body in the same file still keeps the step and adds `unresolved_handler`. Do not follow a callee into another file.

**Why.** Juice Shop's handlers are calls and imports, not local function declarations. The next phase needs those names and spans. Cross-file resolution is a later spec.

### D-5 — Local tree, fixture first, Juice Shop later

**Decision.** The command takes a local directory. Tests use `internal/parse/testdata/express-login/`. The manual check is a separate OWASP Juice Shop checkout at tag `v20.3.0`, found through the orientation's portable workspace rule. Tests must pass with no Juice Shop clone present.

**Why.** Tree-sitter reads files. A moving branch would change the manual check. The old plan SHA is not the pin.

### D-6 — Decisions API is not this slice

**Decision.** The Project Owner will use the OpenAI Decisions API (`gpt-6-luna`, `POST /v1/decisions`) later instead of Jev. This deliverable does not call it.

**Why.** Route structure has to exist before a model can judge a candidate. Installing an OpenAI client now has nothing to call.

---

## 5. Agent Implementation Rules

These rules apply throughout implementation. Specification-specific halt conditions may add to this list but should not duplicate it.

### Team Integration

Commit and push only to `tree-sitter-route-identification-mvp`. Do not merge directly to `stage`. All integration happens through human PR review.

### Command Working Directory

Run from the worktree root:

```bash
go test ./...
go test -race ./...
go vet ./...
gofmt -l .
```

### Commit And Push

Default to one coherent green commit after the DoD and verifier pass. Waypoint commits are allowed only at coherent green recovery points. Do not commit red tests. Push at the handoff, not after every phase. Do not push unless the Deliverable Owner asks.

### Scope Verification

`git diff stage --stat` lists exactly the files in §3 unless a contract change is recorded in §13.

### Autonomy Boundaries

Hard constraints:

- Scope in §3.
- Approved review shape in §3.
- Invariants in §2.
- Public contract: `scan --routes [--json] <path>`, exit codes, and the JSON fields in D-1.
- Standards in §1.d.
- Acceptance criteria in §6.
- Halt conditions below.

Adaptive guidance:

- helper names, query text, and file split inside `internal/parse`
- skeleton bodies
- test helper mechanics

The agent may adapt guidance when verified local evidence supports it, provided hard constraints still hold. Meaningful deviations go in the run log. Contract-changing deviations require Deliverable Owner sign-off, in-place specification updates, and a §13 change-log entry.

### Run Log

Maintain `.zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md`. Append entries after OQ resolutions, phase completions, deviations, manual evidence, QA findings, and load-bearing issues. Do not commit the run log.

### Execution Tracking

Use the local run log only.

- **Authoritative record:** `.zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md`
- **Required updates:** phase completions and the commands that proved them
- **Companion skill:** N/A
- **Fallback:** the run log is the only record. Zazz Board is not used.

### Lead Agent / Contributor Agent Coordination

Implementation uses a Lead Agent working alone in this worktree. No delegated agents.

| Phase / task | Responsible agent | Allowed scope | Required evidence |
| --- | --- | --- | --- |
| All §8 phases | Lead Agent | §3 | tests named in §7 |

### Independent QA / Verification Agents

Use a fresh-context verifier for functionality and code hygiene when the harness supports it. The verifier does not modify code.

### Halt Conditions

Stop and surface to the Deliverable Owner if any of these occur:

1. A later edit withdraws the 2026-10-24 greenlight.
2. The same automated test fails 3 iterations in a row.
3. `gofmt` or `go vet` fails for a reason not addressable by the obvious fix in 2 iterations.
4. Scope verification shows a file outside §3.
5. A grammar module does not build against `go-tree-sitter` `v0.24.0`.
6. A standard not prescribed in §1.d matches the file list.
7. Juice Shop `v20.3.0` is required to make `go test` pass.
8. A needed deviation changes scope, the JSON contract, an AC, the review shape, or an invariant.

---

## 6. Acceptance Criteria

- **AC1** — Express login fixture. `scan --routes --json` on `internal/parse/testdata/express-login` emits a route for `app.post('/rest/user/login', login())` with method `POST`, path `/rest/user/login`, framework `express`, and a handler step named `login`. A same-file `app.get` handler that calls `security.login` includes that call. Spans fall on those source lines. Verified by: `TestExpressLoginGolden`.
- **AC2** — Dynamic path. `router.post(path, handler)` with a non-literal path produces no route and one `dynamic_path` gap at that call. Verified by: `TestRouteGaps`.
- **AC3** — Unresolved handler. `app.get("/health", health)` with no local `health` declaration produces the route and an `unresolved_handler` gap. Verified by: `TestRouteGaps`.
- **AC4** — TS and TSX. A `.ts` file and a `.tsx` file each contribute one `GET` route through their own grammars. Verified by: `TestTypeScriptRoutes`.
- **AC5** — Parse failure. A `.js` file with a syntax error produces a `parse_error` gap and does not fail the scan. Verified by: `TestRouteGaps`.
- **AC6** — Determinism and skip. Two scans of the same tree are byte-identical. A route under `node_modules/` is absent. Verified by: `TestRoutesDeterministic`.
- **AC7** — CLI. `--routes` text lists `POST /rest/user/login` and the file. `--routes --json` is the golden object. `--routes` and `--list` together, or a missing path, exit `2`. A missing directory exits `1`. Existing `--list` tests still pass. Verified by: `TestRoutesCLI` and the existing list tests.
- **AC8** — Toolchain. `gofmt -l .` prints nothing, `go vet ./...` is clean, `go test -race ./...` passes. Verified by those commands.
- **AC9** — Scope. `git diff stage --stat` matches §3. Verified by that command.
- **AC10** — Juice Shop graph. `scan --routes --json` on a local checkout at tag `v20.3.0` exits 0 and the JSON contains a route with method `POST` and path `/rest/user/login`. Verified by running that command and recording the route count in the run log. Unit tests do not open that checkout.

---

## 7. Test Strategy

Test value rule: the golden proves the JSON contract. The gap table proves the three failure kinds. The CLI test proves the mode switch. Do not add a test per HTTP method.

Reference data sources:

- `internal/parse/testdata/express-login/` — synthetic Express sources written for this spec. The golden is generated by the implementation with `-update` and reviewed in the PR. It is not copied from Juice Shop.
- Existing `internal/walk` tests — already prove `node_modules` is skipped. `TestRoutesDeterministic` is the routes-level check that the extractor uses that walk.

Automated tests:

- `TestExpressLoginGolden` — verifies AC1, including `app.post('/rest/user/login', login())`, by comparing JSON against `express-login.graph.json`.
- `TestRouteGaps` — verifies AC2, AC3, and AC5 by asserting gap kind and that dynamic paths create no route.
- `TestTypeScriptRoutes` — verifies AC4 by asserting one route per `.ts` and `.tsx` fixture.
- `TestRoutesDeterministic` — verifies AC6 by scanning twice and by planting a route under `node_modules/`.
- `TestRoutesCLI` — verifies AC7. Existing list tests stay and are not duplicated.

Existing coverage intentionally reused:

- `cmd/scan` list tests — already prove AC7's list half. No new list cases.

Manual verification:

- On a local Juice Shop checkout at tag `v20.3.0`, run `scan --routes --json` against that root. Open one cited Express registration and confirm the method, path, and handler text. Record the file and the command in the run log. This is not a unit test.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

The execution sequence is derived from §6 and §7. Do not change the contract by editing only this section.

### TDD Entry Point

Add the first failing test `TestExpressLoginGolden` in `internal/parse/parse_test.go`. It scans the login fixture and compares the graph JSON to the golden. It fails because the extractor does not exist.

### Prescriptive Execution Sequence

**Phase 1: Libraries, after greenlight**

1.1. From the worktree root, pin the modules in D-2. Do not start this phase on an ungreenlit draft.
1.2. Run `go test ./...`. Expect the existing tests to pass and the new test to fail on a missing symbol, not on a cgo or grammar error. If the grammars do not build, halt.

**Phase 2: Graph types and the login fixture**

2.1. Add `internal/graph` types matching D-1 and the login fixture sources.
2.2. Extract the `GET /rest/user/login` route and its `security.login` call. Write the golden with the test's `-update` flag and review the diff.
2.3. Run `go test ./internal/parse/ -run TestExpressLoginGolden`. Expect pass.

**Phase 3: Gaps, TS, and determinism**

3.1. Add the gap fixtures and `TestRouteGaps`, `TestTypeScriptRoutes`, and `TestRoutesDeterministic`.
3.2. Run `go test ./internal/parse/`. Expect pass.

**Phase 4: CLI**

4.1. Add `--routes` beside `--list` in `cmd/scan`. Text mode prints one `METHOD path file:line` line per route, then gap lines. JSON mode encodes the graph with `json.Encoder` indent `"  "`.
4.2. Run `go test ./cmd/scan/ ./internal/parse/ ./internal/walk/`. Expect pass, including the old list tests.

**Phase 5: Docs and full check**

5.1. Update the two durable docs named in §3 so they point at this spec and at Juice Shop tag `v20.3.0`. Do not rewrite the Jev research notes.
5.2. Run `gofmt -l .`, `go vet ./...`, and `go test -race ./...`. Expect clean.
5.3. Run the manual Juice Shop check from §7 when the checkout is present. If it is absent, record that and do not block the unit tests.

### Skeleton: `internal/graph/graph.go`

```go
type Graph struct {
    SchemaVersion int    `json:"schema_version"`
    Root          string `json:"root"`
    Routes        []Route `json:"routes"`
    Gaps          []Gap   `json:"gaps"`
}

type Route struct {
    ID           string  `json:"id"`
    Method       string  `json:"method"`
    PathPattern  string  `json:"path_pattern"`
    Framework    string  `json:"framework"`
    Registration Span    `json:"registration"`
    Handler      Symbol  `json:"handler"`
    Steps        []Step  `json:"steps"`
}

type Step struct {
    Kind   string `json:"kind"`
    Symbol Symbol `json:"symbol"`
    Caller string `json:"caller,omitempty"`
}

type Symbol struct {
    Name string `json:"name"`
    Kind string `json:"kind"`
    Span Span   `json:"span"`
}

type Span struct {
    File      string `json:"file"`
    StartLine int    `json:"start_line"`
    EndLine   int    `json:"end_line"`
    StartByte int    `json:"start_byte"`
    EndByte   int    `json:"end_byte"`
}

type Gap struct {
    Kind   string `json:"kind"`
    Detail string `json:"detail"`
    At     Span   `json:"at"`
}
```

### Skeleton: `internal/parse/parse.go`

```go
func Routes(root string) (*graph.Graph, error) {
    // Walk root with the existing walker.
    // Parse only JavaScript and TypeScript files.
    // Apply the Express-style query. Resolve handlers in-file.
    // Sort routes by file, then start_byte. Return gaps alongside routes.
}
```

---

## 9. Definition Of Done

- [ ] All §1 required reading consumed; standards-index verification performed.
- [ ] Deliverable Owner greenlight recorded in the run log.
- [ ] Scoped tests green: `go test -race ./...`.
- [ ] Manual Juice Shop check recorded, or explicitly skipped because the checkout was absent.
- [ ] `gofmt -l .` and `go vet ./...` exit 0.
- [ ] Scope verification lists exactly the files in §3.
- [ ] PR shape is one draft PR into `stage`.
- [ ] AC1–AC9 verified, with evidence cited.
- [ ] Run log is up to date.
- [ ] Verifier sub-agent dispatched and returned all-pass.
- [ ] PR draft body links this specification and lists each AC's verification.

---

## 10. Open Questions

None. The decisions in §4 are the contract proposed for greenlight. Implementation still waits for the Deliverable Owner to greenlight this draft. A review comment that changes a decision is a §13 update, not an open question.

---

## 11. Run Log Protocol

Create `.zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md` when implementation starts. It stays untracked. Append only. Zazz Board is not used.

Required sections:

- Standards Verification
- OQ Resolutions
- Phase Completions
- Deviations
- Manual Evidence Locations
- QA Findings & Rework
- Issues & Recoveries
- Verifier Sub-Agent Report

Session start protocol:

1. Read this specification end to end.
2. Read the entire run log.
3. Confirm the draft is greenlit. If it is not, stop.
4. Confirm the next phase from the most recent Phase Completion entry.
5. Begin implementation.

---

## 12. Agent Implementation Prompt

Paste this into a fresh implementation session after greenlight:

```text
You are starting fresh in the worktree for branch tree-sitter-route-identification-mvp.
Your task is to implement the Tree-sitter route identification MVP.

Specification: .zazz/specifications/tree-sitter-route-identification-mvp.md
Shared run log: .zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md
Execution tracking: local run log only
Implementation coordination: Lead Agent working alone
Companion skills to load: spec-driven

Read the specification end to end before doing anything else. Then read the run log.
If the Status line does not say the draft is greenlit, stop.

TRACKING SYSTEM
- Local run log only. Do not use Zazz Board.

LEAD AGENT / CONTRIBUTOR AGENT OPERATING MODEL
- Work in this single worktree.
- The Lead Agent performs every phase. Do not delegate.

FRESH-CONTEXT QA / VERIFICATION
- After the DoD checklist is green, dispatch the verifier described below.
- The verifier does not modify code.

NON-NEGOTIABLE RULES
1. Follow the specification's Agent Implementation Rules.
2. Do not write code before greenlight.
3. Verify standards via .zazz/standards/index.yaml before writing code.
4. Tests and verification are not optional. Every AC must have evidence.

ORDER OF WORK
1. Read the specification, run log, required docs, standards, and code references.
2. Confirm greenlight.
3. Review ACs (§6) and Test Strategy (§7). Start with the TDD entry point in §8.
4. Confirm the work is still one PR.
5. Execute the phases. Install the §4 libraries only in Phase 1.
6. Run verification and complete the DoD (§9).
7. Dispatch a verifier sub-agent.
8. Prepare PR-ready output. Do not merge to stage.

VERIFIER SUB-AGENT
After your own DoD checklist is green, dispatch a fresh sub-agent:

  "You are verifying the Tree-sitter route identification MVP. Read
  .zazz/specifications/tree-sitter-route-identification-mvp.md and the run log
  .zazz/ephemeral/tree-sitter-route-identification-mvp-run-log.md. For each AC,
  independently run the cited test or command. Do not modify code or the run log.
  Return PASS/FAIL per AC with evidence."

Only declare done after the verifier reports all-pass.
```

---

## 13. Implementation And Review Change Log

### 2026-10-24 12:00 ET — Implement in this worktree and scan Juice Shop

**Source.** Deliverable Owner steering.

**Changed Sections.** §0 Capability, §2 Invariant 4, §4 D-3, §4 D-4, §6 AC1, §6 AC10, status line.

**Rationale.** The graph is built in this worktree and must be producible by pointing `scan` at Juice Shop `v20.3.0`. That tree registers routes with call-style handlers and path arrays. A leading `/` keeps ordinary `.get('token')` calls out of the graph. The JSON is the handoff for the later validation and sanitization phase.

**Summary.** Greenlit implementation here. Handler chains include calls and one level of unwrapping. Juice Shop `POST /rest/user/login` is an acceptance check.

**Verification Impact.** Fixture golden covers `login()`. AC10 is the Juice Shop run, separate from `go test`.

### 2026-10-24 12:10 ET — Generic Express shapes, not a sample-specific matcher

**Source.** Deliverable Owner steering. The scanner must stay generic because more sample programs will be scanned later. Juice Shop is the first corpus, not a hardcoded target.

**Changed Sections.** §4 D-3.

**Rationale.** `receiver.route('/path').get(handler)` is ordinary Express. Dropping it would miss routes in the first corpus and in later ones. The rule keys off the call shape and a path literal. No sample path, file, or helper name is special-cased in code.

**Summary.** Chained `route(path).method(...)` emits one route per method. Symbol kinds stay inside the D-1 list (`identifier` or `method`).

**Verification Impact.** `TestChainedRoute` and the regenerated fixture golden. AC10 is unchanged.

### 2026-10-24 12:55 ET — Route index wording and README

**Source.** Deliverable Owner steering during cleanup before the PR.

**Changed Sections.** Status line, §0 Capability, §3 scope.

**Rationale.** The JSON is a route index. Calling it an execution graph overclaims import resolution and string flow. The root README is the setup and run guide the owner asked for.

**Summary.** Status and capability name the artifact a route index. `README.md` is in scope.

**Verification Impact.** None. AC1–AC10 are unchanged.

---

*End of specification. Implementation proceeds from this specification and the run log; no separate execution document is created.*
