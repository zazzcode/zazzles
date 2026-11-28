# Common entry and dispatch — milestone specification index

Requested 2026-11-03. Worktree and branch: `common-entry-and-dispatch`.
Project and Deliverable Owner: Michael. Integration: `stage`, human PR review/merge.
The user requested design/specification authoring, then authorized deliverable 1
implementation on the same date, then deliverable2 and its success assessment.

The [architecture design](../../architecture/common-entry-dispatch.md) owns record semantics,
flow boundaries and reporting approach. Each linked deliverable below is its own executable
contract, with acceptance criteria, tests, scope, recovery points and implementation prompt.
This index owns ordering and milestone-wide verification, not a separate execution document.

## Delivery order

| Order | Deliverable contract | Observable outcome | Small recovery units |
| --- | --- | --- | --- |
| 1 | [Shared model](common-entry-dispatch-01-model.md) | Implemented foundation: typed records, deterministic identity, contexts and reference validation | Cardinality/identity; validation |
| 2 | [Existing consumers and compatibility](common-entry-dispatch-02-consumers-compatibility.md) | Implemented: real HTTP/browser contexts, schema3 and saved schemas1/2 compatibility | JS/TS HTTP; Python/browser; judge/report/schema cutover |
| 3 | [Reports and selectors](common-entry-dispatch-03-reporting-selectors.md) | Entry-specific HTML/text/SARIF; typed checks and entry filters | Presentation/locations; selectors; visual checks |
| 4 | [Browser events](common-entry-dispatch-04-browser-events.md) | Explicit event/callback entries and event-source flow | Binding; source/control pairs; reports |
| 5 | [Dynamic HTTP](common-entry-dispatch-05-dynamic-http.md) | Bounded Express/Python registration and dispatch; real VulnPy traces/findings | Literal tables; factory/closure contexts; Python registry/callbacks; sample acceptance |
| 6 | [Node.js GraphQL](common-entry-dispatch-06-graphql.md) | Schema field/resolver analysis and resolver-specific reports | SDL/binding; input/SQL pairs; exports |
| 7 | [Node.js gRPC](common-entry-dispatch-07-grpc.md) | Unary service/method handler analysis and gRPC reports | Proto/binding; input/SQL pairs; exports |
| 8 | [Acceptance and behavior reports](common-entry-dispatch-08-acceptance.md) | Existing regressions verified and improvements demonstrated | Mixed fixture; full checks; report inspection |

The proposed review shape is one milestone draft PR with eight bounded evidence units,
all in the assigned worktree. This keeps canonical schema/consumer migration and removal
of transitional aliases in one human-reviewed integration artifact. The user can request
one deliverable or recovery unit per session. No additional worktrees or stack are needed.
Review shape is proposed for discussion; no PR creation, push or merge is part of this request.

## Usage-window policy

The user's five-hour cap is a usage-window constraint, not a promise that five wall-clock
hours of work or a fixed number of tokens are available. Exact remaining quota/reset data
is not assumed visible to the agent. These contracts MUST NOT prescribe an invented token
allowance or promise that the entire milestone fits one window.

- Start one requested deliverable or named recovery unit with its scoped reading and tests.
  Do not reload every design/spec/history document for each small change.
- Reserve roughly the final quarter of the known available allowance for verification,
  recovery notes and a concise handoff. If quota information is unavailable, keep the unit
  to one stated checkpoint and avoid starting the next unit automatically.
- End a completed unit with a focused passing test set, exact diff scope, evidence paths
  and next action. A partial checkpoint MUST record failures and partial edits honestly;
  it is not acceptance or authorization to publish broken work.
- Deliverable 2 is the largest migration risk. Its three recovery units may span several
  usage windows. Intermediate bridges are implementation scaffolding, not completed common
  model support; remove duplicate canonical state at its final schema cutover.
- Do not cut fixtures, browser/HTTP coverage, compatibility, unknown controls or final
  verification to fit a window. Reduce the active unit and resume from the deliverable log.
- No automatic background continuation or paid model calls are implied. A later explicit
  implementation request is sufficient authorization under AGENTS; no repeated ceremony.

Use one ignored `.zazz/ephemeral/common-entry-dispatch-<number>-<slug>-run-log.md`
per deliverable, as named by its contract. A later deliverable reads predecessor completion
evidence when it depends on that contract; it does not combine execution histories.
Tracked contracts and the final evaluation document retain durable decisions and outcomes.

## Existing behavior is a release constraint

Existing JS/TS HTTP, Python HTTP, browser/framework/inline-script analyses, checks, samples,
JSON, HTML and SARIF MUST continue to work. New entry kinds do not replace HTTP or reinterpret
its requirements. Preserve `--routes` inventory schema 1, `--entry` file scope, `--route`
HTTP filtering, old check arrays and saved report schema-1/schema-2 exports.

Node.js GraphQL is the first new server adapter; exact targets are flexible. Apollo
resolver maps and grpc-js unary registrations are chosen concrete initial subsets.
Browser event dispatch is an explicit deliverable, beyond preserving existing script/
component analysis. The user will build a GraphQL application later; its application-level
evaluation is deferred and MUST NOT be implied by source-fixture acceptance.

## Milestone verification

Before consumer changes, record the baseline revision, source hashes, selected entry
inventories, source/sink/claim outcomes and existing report exports. After migration,
compare normalized outcomes; changed IDs and presentation do not justify lost candidates,
borrowed protection, hidden gaps or changed raw historical answers.

Use the toolchain declared in `go.mod` and the applicable local/linked-computer setup;
do not download a replacement toolchain or dependency merely to run offline checks.
From the feature worktree, final mandatory commands are:

```sh
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go test -race ./...
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go vet ./...
GOTOOLCHAIN=local GOPROXY=off GOCACHE="$PWD/.zazz/ephemeral/go-cache" go build ./...
gofmt -l cmd internal
git diff --check
```

Format only changed Go files. Loopback stub failures caused by sandbox access MUST be
resolved through permitted local access; never replace a stub with a paid API call.
Run both provider stub suites and changed-request replay tests. No unit/integration test
may depend on live model availability.

Run `python3 docs/samples/evaluate-python.py <app> <saved-report>` for each original
ThreatByte, python-insecure-app and vulnerable-flask-app curated report. Discover the
actual saved report paths from their tracked sample references, then record exact commands
and combined 29-case result. Run VulnPy separately against its documented baseline: its six
known positive misses MUST NOT be silently absorbed into a new all-pass claim. Do not alter
expected case labels to match current output. Saved evidence checks are not fresh accuracy.

For each supported saved schema, export HTML/SARIF with the built scanner and hash the
input before/after. For actual new-adapter fixtures and selected existing HTTP/browser
samples run `--analyze --output-dir` to generate JSON/HTML/SARIF; verify fresh current JSON
uses one canonical entry association. Export offline without keys or target-source rereads.
The exact baseline/current artifact manifest and commands belong in the run log and results.

## Report acceptance artifacts

Required report sets: existing HTTP-only, browser-event-only, GraphQL-only, gRPC-only,
and mixed-entry fixtures. Each new adapter set includes source-reviewed raw/protected/
unknown controls and zero-use unresolved registrations. Keep offline discovery output
separate from local-stub assessed policy output; label both accurately.

Generated report bundles and visual-review images belong in ignored
`.zazz/ephemeral/`, outside all target apps. Durable source-reviewed expectations and the
concise before/after matrix belong in `.zazz/evaluation/common-entry-dispatch-results.md`.
Record entry identity/kind, registration/target counts, source/sink discovery, contextual
claim status, gap visibility and entry-specific presentation. More findings alone is not
proof of improvement; demonstrate expected recovery and unchanged protected/unknown controls.

Visually inspect generated HTML for labels, source locations, findings/review/protection
counts, sorting, native disclosure, keyboard focus and narrow layout. Confirm JSON/SARIF
status parity and no fabricated HTTP values, execution paths or security results.

## Implementation authorization and completion

The user approved starting deliverable 1 and committing/pushing the design checkpoint
on 2026-11-03. Later deliverables remain separately assignable. No paid evaluation or PR
creation is authorized by this index.

Completion requires all eight deliverables' acceptance evidence, no obsolete canonical
route/client aliases, documented limits, unchanged historical inputs, passing mandatory
checks and reviewed entry-specific reports. User application evaluation and human PR
review/merge remain separate future steps.

## Separate follow-on initiative

The user designated [analysis-pack-mvp](../../project/analysis-pack-mvp.md) on 2026-11-05 as a separate
initiative with its own future worktree/branch, after this milestone completes acceptance and merges
into `stage`. It precedes command injection in the [project roadmap](../../project/implementation-plan.md#analysis-pack-mvp-initiative).
Proposal and README updates may be prepared on the current branch; pack implementation and worktree
creation are not part of this eight-deliverable milestone and require a separate assignment.
