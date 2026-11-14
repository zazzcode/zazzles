# 03 — Tree-sitter, Go dataflow, and Jev proposal

**Latest proposal: 2026-10-19.** This is a concept and research record, not an approved implementation
specification. This record owns the design change, rationale, research concepts, graph/library choices,
and open decisions. See the [overview](../project.md) for status and the
[architecture](../architecture.md) for current technical contracts.

## Proposed change and rationale

Use Jev, TypeSafe's System One decision model, to assess string validation/sanitization, followed by
an **LLM Findings Reviewer** to inspect identified issues against source evidence. This is the chosen
architecture direction; experiments refine quality and evidence requirements. Keep parsing,
resolution, graph traversal, rules, evidence assembly, and policy in Go. Add supported control-flow and
dataflow analysis rather than asking a model to reconstruct value movement from function snippets.

The proposal has merit because it gives software ownership of repeatable facts and restricts model
work to named semantic decisions. Jev is chosen for the objective of fast, lower-cost assessment
across many candidates, followed by deeper LLM review of identified issues. The
[architecture](../architecture.md#1-architecture-premise) defines the all-Go implementation boundary.
Its value is conditional on measured accuracy and on the engineering effort needed to prepare adequate evidence.
The earlier premise that a model is broadly better than static analysis is not a design fact.

| Earlier direction | Latest proposal | Consequence |
|---|---|---|
| Generative LLM as the primary detector | Jev assesses validation/sanitization; LLM Findings Reviewer reviews identified issues | Distinct assessment/review contracts; Go reconciles results |
| Call paths, no taint/dataflow engine | Local CFG/dataflow, then bounded cross-function summaries | More Go analysis work, explicit supported semantics |
| Model-written rationale and citations | Go source spans/templates plus evidence-referenced reviewer interpretation | Findings retain separate detector and reviewer provenance |
| Broad scope review (Track C) | Deferred, explicitly enumerated scope checks | Separate feasibility and approval before adding capability |
| Five languages treated as initial release | Staged adapters; release set unresolved | Prove a thin JS/TS slice first |

Deterministic rules, graph provenance, candidate identity, local execution, versioned artifacts,
baselines, and spec-driven delivery remain useful.

The [feasibility study](05-prior-art-and-feasibility.md) owns the stack assessment, prior-art comparison,
and principal engineering risks. The [Jev research](04-jev-validation-research.md) owns published
sanitizer evidence and the evaluation protocol. The [phase plan](implementation-plan.md) turns those
conclusions into proposed deliverable slices.

## Research sources and what they support

The user-supplied research excerpts and linked material motivated this proposal. This document
and the [capability research note](04-jev-validation-research.md) preserve their substantive concepts
and improvements; no future session needs the temporary attachments. The original excerpts included
useful ideas as well as incomplete package URLs and illustrative code; they are not a build contract.
The primary references below govern API and parser claims; integration articles remain background.

| Reference | Supported design input |
|---|---|
| [TypeSafe API](https://docs.typesafe.ai/api) | System One request/answer contract, including Noul and Choice |
| [Official Go Tree-sitter bindings](https://github.com/tree-sitter/go-tree-sitter) | Binding and grammar integration, explicit native-resource cleanup |
| [Tree-sitter query syntax](https://tree-sitter.github.io/tree-sitter/using-parsers/queries/1-syntax.html) | Structural S-expression queries and captures |
| [Gonum graph API](https://pkg.go.dev/gonum.org/v1/gonum/graph) | General graph interfaces/algorithms; not a ready-made CFG or taint engine |
| [jev-go maintainer repository](https://github.com/Gaurav-Gosain/jev-go) | Candidate Go client with typed accessors and transport configuration |

Background supplied by the Project Owner:
[Jeff semantic checking](https://www.alessandroferrini.com/posts/jeff-semantic-code-checking-jev/),
[HoneyHive integration article](https://www.honeyhive.ai/blog/how-to-use-typesafe-ais-jev-as-an-llm-judge),
[Firecrawl overview](https://www.firecrawl.dev/blog/what-is-jev),
[Tree-sitter video](https://www.youtube.com/watch?v=8WMV4_DfQyo),
[Jev video](https://www.youtube.com/watch?v=qwnJJMNGwgY), and
[taint-tracking discussion](https://www.reddit.com/r/AskNetsec/comments/1r287ju/building_taint_tracking_for_a_sast_tool_on/).
Video/discussion claims have not been independently validated here. The repo docs deliberately avoid
turning performance or security assertions from those summaries into requirements.

### Supplied architecture concepts and their durable homes

The supplied Go-versus-Rust / Go–Tree-sitter–Jev research transcript was checked against these docs.
This mapping preserves its substantive ideas independently of the temporary attachment. The original
three-tier design is extended with our chosen LLM Findings Reviewer; illustrative snippets are not
accepted implementation code, and their incomplete package URLs are replaced by the references above.

| Supplied concept | Durable home | Adopted direction or refinement |
|---|---|---|
| Go versus Rust, cyclic graphs, concurrency, distribution | [Architecture premise](../architecture.md#1-architecture-premise), [parser](../architecture.md#3-parsing-and-language-adapters) | Go implementation; benchmark resource/build behavior. Broad ecosystem, competitor-language, and performance claims are not selection evidence |
| Tree-sitter CST and S-expression source/sink/validator queries | [Parsing](../architecture.md#3-parsing-and-language-adapters) | Syntax captures feed adapters; a match does not establish a flow or effective protection |
| Assignment tracking and cross-function execution graphs | [IR/graphs](../architecture.md#4-normalized-representation-and-graph-views), [flow](../architecture.md#5-go-analysis-engine) | Separate CFG, call, and value dependencies; cycle-aware bounded analysis rather than a DAG or DFS alone |
| Structural filtering before paid inference | [Candidate selection](../architecture.md#6-detection-and-candidate-selection) | Filter using established facts; retain gaps and coverage. Encountering a sanitizer alone never discharges a candidate |
| Send snippets and path context to Jev | [Evidence bundles](../architecture.md#7-evidence-bundle-contract) | Include actual value use, guards, helpers, sink semantics, provenance, and explicit missing context |
| Typed Noul/Choice decisions and richer CWE metadata | [Jev contract](../architecture.md#8-jev-assessment-and-findings-review), [report records](../architecture.md#9-findings-comparison-and-ci) | Atomic questions and validated responses; Go owns mappings/severity. Model confidence questions do not establish calibration |
| Sanitizer subtree fingerprint cache; memory/Redis suggestion | [Persistence](../architecture.md#10-persistence-and-determinism) | Context/dependency-aware local cache first; no globally safe helper hash or Redis dependency adopted |
| Async parsing, graph, and inference pools | [Pipeline](../architecture.md#2-pipeline) | Bounded workers, ownership, cancellation, backpressure, and deterministic merging |
| Multi-language normalization into universal primitives | [IR/graphs](../architecture.md#4-normalized-representation-and-graph-views), [adapters](../architecture.md#3-parsing-and-language-adapters) | Shared Go IR with language-specific lowering/transfer semantics; source/sink/sanitizer labels alone are insufficient |
| Go libraries and executable blueprints | [Candidate libraries](#library-choices) | Verify/pin the chosen parser and stdlib adapters; use zazzles-owned adjacency; no unchecked client code adopted |
| JSON/SARIF, CLI, and CI alerts | [Reports/CI](../architecture.md#9-findings-comparison-and-ci), [capabilities](01-functionality.md) | JSON/Markdown first, SARIF later; configurable policy distinguishes findings from incomplete analysis |
| Parsing → graph → semantic analysis → reporting phases | [Sequenced implementation plan](implementation-plan.md) | Corpus/semantic feasibility early, then bounded engine slices, integration, reporting, and further languages; separate specs/worktrees |
| Fast, cheap decisions and aggressive filtering | [Quality hypotheses](02-project-scope.md#non-functional-hypotheses) | Measure end-to-end latency/spend and missed candidates; no adopted 250 ms, fractional-cent, or 98% filtering guarantee |

## Corrections to carry into future specs

- Structured probabilities are predictions, not proof of safety, determinism, or absence of false
  classifications. “No hallucinations” is not an adopted security guarantee.
- Encountering a validator does not stop flow. Its use, value, branch, result, sink, and bypass paths
  determine whether a modeled mitigation applies.
- Shell invocation differs from passing an argument array. Both require context-specific analysis;
  passing user input to a command API alone does not establish shell injection.
- SQL parameterization protects bound value positions, not arbitrary interpolated identifiers or
  fragments. NoSQL safety also depends on the API, value types, and filter construction.
- “Input fabrication” is ambiguous. The initial concern is untrusted/attacker-controlled input,
  missing or insufficient validation, and dangerous use. Runtime attacker intent or fabricated facts
  cannot be established from source alone.
- Jev cannot invent missing evidence or supply generated explanations. Use named evidence candidates
  and evidence validation; missing context remains explicit.
- The pasted client snippets and numerical thresholds are illustrative. Verify the chosen client's
  current API and calibrate policy before implementation; no blind copy of unchecked type assertions.
- Sub-quarter-second latency, fractional-cent requests, and “98% filtered” are unverified hypotheses
  for zazzles. Measure end-to-end behavior, including network time, retries, and coverage lost to limits.

## Graph representation decision

**Decision for the concept design: use zazzles-owned typed Go adjacency structures for core storage.**
Gonum remains an optional algorithm library when a named need justifies it. This narrows the planned
implementation; it is not a claim that custom storage benchmarks faster or uses less memory.

| Concern | Gonum | Zazzles-owned adjacency |
|---|---|---|
| Graph algorithms | Reusable traversal/topology algorithms and graph interfaces | Implement the small worklist/witness operations needed initially; test their correctness |
| Program semantics | Custom nodes/edges or views can carry domain facts; CFG/dataflow semantics remain our work | Domain records and relation indexes directly express values, guards, bindings, and provenance |
| Multiple relationships and loops | Choose suitable graph/multigraph types or views; the simple directed type rejects self-edges | Explicitly preserve parallel relation kinds and self-edges where required by the IR |
| Integration and maintenance | Library supplies algorithms; zazzles still owns representation adapters and analysis state | Fewer initial integration layers; scan owns index invariants, traversal, and resource behavior |

Sources: [Gonum interfaces and implicit-graph example](https://pkg.go.dev/gonum.org/v1/gonum/graph),
[simple directed graph](https://pkg.go.dev/gonum.org/v1/gonum/graph/simple#DirectedGraph.SetEdge),
[multigraphs](https://pkg.go.dev/gonum.org/v1/gonum/graph/multi), and
[traversal algorithms](https://pkg.go.dev/gonum.org/v1/gonum/graph/traverse), reviewed 2026-10-19.
Gonum can work with custom storage, so this is not a permanent either/or decision.

The [architecture](../architecture.md#graph-storage-decision) owns the storage/read-view contract.
Current domain requirements are sufficient to choose that direction without a separate library
comparison project. `analysis-ir-contract` and `local-cfg` must validate relation preservation, cycles,
stable traversal, and bounded work on representative fixtures; collect build/traversal time and peak
memory. Later performance work measures repository-scale costs. Reconsider only for a named algorithm
with substantial implementation/verification cost, a measured bottleneck, or a contract mismatch.
If adopted, expose the selected relation view through a small Gonum adapter and justify any copying.
Do not prebuild a backend abstraction, duplicate graph stores, or implement a generic graph framework.

## Library choices

These are concept-design defaults for later specs; no dependency is installed by this session.
Keep the standard library wherever it meets the defined need. Reopen a settled choice only for a
concrete requirement, compatibility failure, or measured limitation.
The supplied library excerpt contains incomplete `://github.com` links; those cannot establish exact
module identities. The sources below replace the missing references with explicit choices and research references rather
than treating the pasted examples as an executable library specification.

| Concern | Planned choice | Verification / remaining work |
|---|---|---|
| Parser | [`github.com/tree-sitter/go-tree-sitter`](https://github.com/tree-sitter/go-tree-sitter) with separate grammars | Benchmark correctness/build portability; decide native/cgo constraints and pin compatible versions |
| Graph storage/algorithms | Scan-owned typed adjacency; Gonum only for a justified later algorithm | Follow the [graph decision](#graph-representation-decision); verify index invariants, cycles, and deterministic traversal |
| Jev and reviewer transport | `net/http` + `encoding/json` behind small Go adapters | Validate provider-specific schemas, model pinning, cancellation, retries, and budgets; reviewer provider/model remains open |
| CLI | Existing stdlib `flag`, JSON encoding, and Go exit-code handling | Sufficient for the planned CLI; no Cobra or other CLI framework planned |
| Concurrency | Bounded goroutine/channel pools | Define ownership/backpressure; add a helper dependency only for a concrete need |
| Reports and tests | `encoding/json`, templates, `testing`, `httptest` | Prefer existing tools; SARIF library choice belongs to a later export spec |
| Persistence | Ordered JSON plus a local content-addressed cache | Decide format after dependency invalidation semantics are established |

The binding does not bundle grammars. The planned initial grammars are the
[JavaScript grammar](https://github.com/tree-sitter/tree-sitter-javascript) and
[TypeScript/TSX grammars](https://github.com/tree-sitter/tree-sitter-typescript); dialect coverage and
binding/grammar compatibility belong to `parser-binding-evaluation`. Native parser, tree, query, and
cursor allocations require explicit cleanup under the selected API.

The third-party [jev-go README](https://github.com/Gaurav-Gosain/jev-go#reading-answers), reviewed 2026-10-19,
documents `Answers.Noul`, `Answers.Choice`, and `Answers.Score` accessors with errors for missing/wrong
answer kinds. It uses `OneOf` as a choice-question constructor. The pasted raw `.Value.(float64)` and
other illustrative calls are not an adopted API contract. Keep this client as an API-design reference;
our planned transport uses the standard library and the official provider API. An SDK dependency
would require a concrete benefit over that small adapter.

The [spec backlog](implementation-plan.md#ordered-specification-backlog) assigns parser selection to
`parser-binding-evaluation`, graph representation to `analysis-ir-contract` / `local-cfg`, experimental
adapter validation to `semantic-feasibility-eval`, and production integration to `decision-judge-adapters`.
The experiment records its API/schema versions for production integration. Each owning
spec records exact module/version or revision, license, maintenance/API fit, Go/native toolchain and
platform constraints, alternatives, and scoped verification. Recheck these facts at selection time;
this concept document intentionally does not pin future dependencies.

The module currently declares Go `1.27.2`; retaining or changing it is future foundation/toolchain
work. A Go binary embedding a native parser does not automatically meet a no-cgo/static-build goal.

## Open decision register

| Decision | Evidence needed | Refinement gate |
|---|---|---|
| First useful scope | Named frameworks, rules, OWASP edition, language/release set | Definition review before implementation specs |
| Jev fitness | Human-labeled pairs, held-out evaluation, deterministic-only comparison | Corpus/feasibility phase; revisit before integration |
| Question/policy contract | Atomic questions, unknown states, per-family error budgets | Corpus phase, then Jev integration spec |
| LLM Findings Reviewer implementation | Review contract, provider/model, budgets, agreement/error rates, citation validity and completeness | Semantic feasibility and findings-review specs |
| Artifact contracts | Versioned IR, rule, bundle, and finding schemas with compatibility rules | Owning schema/parser/reporting specs |
| Parsing/runtime | Grammar parity, errors, native lifetimes, platform/build measurements | Parser spec |
| IR/flow contracts | Scan-owned adjacency chosen; finalize operations, joins, calls/returns, unknowns, and bounds | Schema/local-flow/cross-function specs |
| Library models | Versioned framework facts and mitigation preconditions | Classification and flow specs |
| Finding identity/CI | Site collisions, grouping, assessment changes, incomplete scans | Reporting/identity spec |
| Source handling/spend | Allowed evidence, payload minimization, budgets, failure policy | Before live evaluation and integration |
| Scope checks | Enumerated authorization/logic questions and a distinct labeled corpus | Deferred Track C proposal review |

Project Owner and Deliverable Owner assignments remain for the human to declare in future specs. A
phase grouping does not appoint an owner or authorize a live API experiment.

## Current provider decision

The [architecture](../architecture.md#current-provider-decision) owns the 2026-10-31 provider
decision (GPT Decisions or Jev, OpenAI first, future adapters allowed); [setup](../docs/openai-decisions-setup.md)
owns credentials. Earlier Jev-specific rationale, API examples, and questions in this proposal are
historical context; provider schemas, quality, availability, and performance MUST be verified separately.

## Decision lifecycle

Refine this proposal and the durable product/architecture docs first. Record choices and rationale
here when resolved; update the affected canonical document instead of leaving contradictory guidance.
A failed feasibility result can narrow scope or reopen the proposal with the Project Owner.
Diagnostic Jev-only/LLM-only baselines measure the chosen Jev Assessment → Findings Review pipeline; they do
not make the selected model roles optional or imply a return to unrestricted LLM detection.

Methodology refinements follow the [working protocol](../docs/zazzles-agent-orientation.md#working-protocol).
Unrelated cleanup remains a separate change.
