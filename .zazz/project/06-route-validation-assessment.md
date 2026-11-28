# Route identification and string-validation assessment

Historical contract/evidence below retains its original names. Current package, CLI and report
names are documented in the [implemented architecture](../architecture/README.md#naming-and-compatibility).

**Reviewed 2026-10-31 on `route-string-validation`, scanner commit `5836908`.** This records initial verification
and planning. The user subsequently authorized implementation in this worktree; see the
[current contract](../specifications/scan/route-string-validation.md). The [implementation plan](implementation-plan.md#route-string-validation-delivery-sequence)
owns the next delivery sequence; the [architecture](../architecture/README.md) owns technical contracts.

## Route verification

Target: clean local OWASP Juice Shop checkout, tag `v20.3.0`, commit
`f189f521266f42c6bd05884468292000cee852ed`. Resolve its local location using the
[workspace conventions](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root).
No application installation, server startup, HTTP attack, or model call was needed.

Run from the feature worktree, with the target root substituted:

```bash
go run ./cmd/scan --routes --json <juice-shop-root>
go test ./...
go test -race ./...
go vet ./...
```

All commands passed on Go `1.27.3`, macOS arm64. Two route scans were byte-identical. Registration
spans for all 1,018 matches were nonempty and their start bytes agreed with their start lines.
The source-registration checks below also matched method, literal path, and handler text.
This verifies the current syntax contract, not application-route precision or vulnerability detection.

| Observation | Result |
|---|---|
| `POST /rest/user/login` | Found at `server.ts:624`, handler `login` |
| `GET /rest/products/search` | Found at `server.ts:630`, wrapper `utils.asyncHandler`, handler `searchProducts` |
| Whole-tree syntactic matches | 1,018: `server.ts` 157; `test/` 566; `data/static/codefixes/` 293; `routes/` 2 |
| Gaps | 680 `unresolved_handler`, 263 `dynamic_path`, 39 `parse_error` |
| `server.ts` gaps | 258 unresolved handlers; no parse-error or dynamic-path gaps |
| Imported login/search bodies | Not connected by the scanner; registration spans identify call sites only |

The full JSON is intentionally local execution evidence under `.zazz/ephemeral/`; regenerate it using
the command above. Its absolute `root` makes the file specific to the invocation. Repeatability means
the same invocation and target snapshot, not cross-machine byte equality.

**Conclusion:** route identification works as the MVP's syntactic registration inventory. It is not
ready to serve as a confirmed attack-surface inventory without the improvements below. The 157
`server.ts` entries include middleware registrations and repeated method/path registrations; they
are not a unique endpoint count. No exhaustive route-recall ground truth was built in this review.

## Architecture and plan assessment

The core design is sound: Tree-sitter syntax, Go resolution and bounded flow, explicit gaps, minimized
model evidence, and independent review. Keep Go ownership of graph facts and reporting. There is no
present reason to add a graph database, a second implementation runtime, or a general agent framework.
The immediate risks are semantic correctness and delivery order.

| Priority | Gap and evidence | Improvement / acceptance evidence |
|---|---|---|
| High | Any receiver with `.get('/...')` or `.post('/...')` matches and is labeled `express`. `test/api/login.test.ts:22` contains `request(app).post('/api/Users')`, which is emitted as a route with an empty handler. | Establish Express app/router receiver provenance and explicit source selection. Include HTTP-client, map/cache, shadowing, and training-snippet negatives. Keep ambiguous receivers visible; do not classify them as confirmed routes. |
| High | Login/search handlers are imported factories returning request handlers. Current same-file call steps cannot reach `req.body.email` or `req.query.q`. | Resolve the selected import/export/factory/wrapper subset with lexical scope. Prove registration → returned handler → actual source/sink spans; unresolved constructs stay uncertain. |
| High | Pathless middleware is omitted, and `USE` is a registration rather than a concrete HTTP method. Mount prefixes and order are not composed. | Model required middleware/mount semantics before claiming effective protection. In the first slice, report unsupported chains as gaps and scope judgments to explicit source/sink cases. Never infer missing protection from an omitted middleware step. |
| High | Proposed next verdicts “covered, unvalidated, unsanitized, uncertain” mix unrelated facets. SQL parameter binding can protect a use without sanitization. | Separate validation, transformation, sink-specific protection, and evidence completeness. Report potential protection gaps; missing validation alone is not a vulnerability. |
| High | The old architecture selects TypeSafe Jev; the 2026-10-24 plan selects OpenAI Decisions. | The provider-neutral judge boundary in the [current architecture](../architecture/README.md#current-provider-decision) resolves this. Do not reuse TypeSafe schemas or assume its performance/accuracy transfers. |
| Medium | The long-term backlog places the first production model adapter after broad interprocedural analysis. It also lists parser evaluation/extraction despite an existing MVP. | Deliver a bounded SQL vertical slice and a separate early provider experiment. Audit/reuse existing parser code; expand IR and cross-function analysis only for demonstrated cases. |
| Medium | Route-v1 IDs embed byte offsets, and output has no snapshot hash or distinction between inferred and observed relationships. | Preserve v1 compatibility unless a spec versions the contract. Give security candidates separate snapshot-bound evidence and explicit provenance; design stable finding identity before baselines. |
| Medium | Some whole-tree parse failures are incomplete training snippets; client calls also generate dynamic-path noise. | Report selected/excluded/failed files and reasons. Pin corpus selection. An exclusion changes the analysis scope, not the safety of excluded code. |

The API adapter should consume evidence already prepared by Go. It should not reopen the repository,
follow arbitrary graph edges, or turn missing relationships into a protected verdict. Branch bypass,
ignored validator return, reassignment, and wrong-context encoding need explicit negative cases.
A reviewer cannot repair absent static evidence by agreeing with a model.

## Suggested first security slice

Proposed scope: Express/TypeScript, SQL string construction, the two named Juice Shop registrations,
and small controlled safe/vulnerable/unknown pairs. The selected target source shows:

- `routes/login.ts:34`: `req.body.email` is interpolated into `models.sequelize.query` SQL text.
  The password's `security.hash` call does not establish SQL protection for the email expression.
- `routes/search.ts:21–23`: `req.query.q` flows through a length limit into interpolated SQL text.
  A length limit does not establish SQL parameter separation.

These are human source-review observations for candidate/fixture design, not findings produced by
zazzles. Confirm sink API/library semantics in the owning spec before asserting exploitability. Do not
label a case from challenge comments alone. A safe comparison should bind a parameter; an unknown
comparison should include an unresolved helper or unsupported flow. Keep request-input validation
separate from protection of the SQL use.

Proposed acceptance: the scoped analyzer reconstructs those supported relationships, distinguishes
paired SQL parameter binding from interpolation, retains bypass/unknown cases, emits evidence and
coverage, and runs offline with semantic assessment marked `not_run`. Live Decisions evaluation uses
the same prepared bundles and independent labels; no universal accuracy percentage is claimed.

## Documentation entry-point assessment

`AGENTS.md` is a sufficient automatic entry point: it already required the orientation and linked its
map. There is no need to duplicate the full map there. Keep binding rules and command routing in
`AGENTS.md`; keep current status and task-based reading paths in the orientation. Detailed procedures
remain in their owning guides. Added routes for verification and API setup make the current task easy
to discover, and the spec index now includes the implemented route MVP.

Remaining full-pipeline decisions belong to a scoped implementation contract: exact JS/TS subset, evidence/report
schema and compatibility, selection policy, sink models, per-case uncertainty rules, payload limits,
source-transmission permission, spend limits, and evaluation thresholds. The current assessment
resolves entry-point/provider direction. The explicit user implementation request now authorizes
the bounded current contract; no additional greenlight ceremony applies.

## Overall approach assessment

The approach is valid for investigating source-code security risks: deterministic structural analysis
provides source-to-use evidence, and a decision model assesses custom validation/protection without
requiring a hard-coded regex rule for every acceptable validator. Source/sink/library models still
identify API roles and preconditions; CFG/value analysis still establishes whether the checked value
reaches the sink. A function name, regex match, or model opinion cannot substitute for that evidence.

The strongest initial experiment compares paired cases with identical dataflow but different custom
checks, then cases with the same check but ignored results or bypass branches. Measure discovery
recall separately from judge recognition and false-safe outcomes. Review only of reported findings
cannot measure missed candidates. Provider estimates need human-labeled calibration; cheaper/faster
per-call models may still require costly context assembly and independent review.

Long-term OWASP Top 10 support is a sensible direction, not a coverage claim. Authorization, business
logic, configuration, dependencies and runtime behavior may require evidence beyond strings. Add
those capabilities through explicit question and evidence contracts. The first implementation is an
advisory dependency/evidence tool; a passing scan cannot certify that no vulnerability exists.

## Implementation verification after user authorization

The current `--strings` artifact records bounded route-linked dependency paths. It is separate from
unchanged `--routes` syntax JSON and from the complete future IR/CFG. Source inspection and hash/span
checks passed for all 186 evidence records in the two manual reports below.

| Target and selected registration file | Entry candidates / resolved handlers | Candidate string uses |
|---|---|---|
| Juice Shop `v20.3.0`, `server.ts` | 152 / 47 | Login SQL, search SQL, profile-image outbound HTTP: 3 uses |
| Vulnerable TypeScript app, `src/server.ts`, commit `7f8b240a2f02beba099da3632d1ba679ff8bc32f` | 19 / 19 | Axios proxy URL: 1 use |

These are supported-subset counts, not unique endpoints or recall measurements. The second app's
login only builds/logs a SQL-like string; it does not call SQL, so no SQL sink is fabricated there.
Command execution, file reads, HTML output and other families in that application are outside the
current candidate-use catalog. Chained routes, mounts and general async/cross-function response
propagation are not implemented in `--strings`; their absence is declared in its limitations.

The custom-validator regression case retains its guard and helper body as source evidence without
matching an approved-validator regex or inventing protection. The reassignment, ignored result,
unknown sanitizer, method transformation, import shadowing, scope selection and dependency-limit
cases pass. OpenAI and Jev HTTP-stub tests pass, including invalid/duplicate/refused/missing answers,
non-success responses, cancellation and payload caps. Full tests, race tests, vet, build, formatting
and documentation checks passed. No live model call or target application execution occurred.

This establishes the first structural/evidence and adapter slice. It does not yet establish that a
live judge reliably recognizes sufficient validation. That requires the key configured locally and
an explicit small, labeled evaluation using the [setup guide](../docs/openai-decisions-setup.md).
