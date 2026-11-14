# Node acquisition and value-fact refactor: verification

[Contract](../specifications/node-http-input-refactor.md) ·
[Public guidance](../../docs/analysis/node-inputs.md)

Implemented in the existing `command-injection` worktree after baseline `63cb126`.
Python implementation remains unchanged. No new paid model calls, target execution, target edits,
dependency installation or integration merge was performed for this refactor.

## Delivered boundary

Bounded Express, Fastify and Hapi acquisition adapters reuse shared invocations/flow and produce
optional `InputFacts` version 1. Acquisition kind and optional framework are distinct from existing
entry network-transport associations. Facts keep origin, initial/sink type, transformations, lifecycle
stage/source order, source-present controls and missing evidence separate. Existing GraphQL and unary
gRPC can carry the same records, with runtime types left unknown where not established. Queue
acquisition remains future work.

The fresh Mongoose default-ObjectId `findById` contract is framework/transport independent. The judge
assesses supplied controls under the existing NoSQL protocol. Policy rejects contradictory scalar
operator-injection answers, missing source/helper evidence and unknown-type protection without an
enforcing control. Route/logging options do not qualify as value controls. Historical contracts and
saved reports remain readable; no old model answer was applied to changed Node evidence.

Opt-in `--discover-routes --discovery-limit N` shares the normal parse pass, inventories bounded
source alternatives and uses a separately versioned choice protocol. Resolved wrapper implementations
are included as evidence. A cached verifier checks canonical references, selected manifest/source
hashes and independently known callable bindings, with explicit source refresh after model calls.
It never promotes an unfamiliar wrapper into trusted flow. Provisional/failed/budget-limited results
remain coverage uncertainty in JSON, HTML and SARIF. Discovery requests use local stubs in this work.

## Verification evidence

- `go test ./...`, `go test -race ./...`, `go vet ./...`, `go build ./...` passed. The full race source
  acceptance suite completed with the pinned target corpus; affected race suites, vet and build were
  rerun after final review corrections and metadata changes.
- `TestNodeHTTPInputs` and `TestNodeInputJudgment`: equivalent Express/Fastify/Hapi lookups use shared
  facts and one generic operation contract; path protection, unsafe body objects, schemas, unknown
  hooks and replay invalidation are distinct.
- `TestNodeCommandSharedPipeline`: the same acquisition layer feeds command analysis; scalar values
  remain unsafe when interpreted as unprotected shell text. Type facts are not global safety flags.
- Registration/missing-body tests cover Hapi/Fastify GET payload negatives, fake/mutated bindings,
  full route objects, conflicting aliases, deferred registrations, late/unknown hooks, missing schema
  and nested helper bodies, registration-versus-declaration order and non-enforcing options.
- Discovery tests cover opt-in behavior, finite request budgets, strict choices, exact replay, source
  hash/span changes, out-of-manifest references, canonical comment masking and no manufactured entries.
- Historical Node request checks project out only the explicitly added input-fact/component extension;
  prior evidence/identities/questions/contracts remain frozen. Current Node evidence goldens include
  the additive facts. Existing Python request baselines remain unchanged.
- Full offline replay of the retained final VulnPy run reproduced **147/147 judgments**, with zero
  mismatches and zero missing traces, against fresh current-source analysis. This includes its 61
  command contexts and preserved input-validation skip.
- Changed-file formatting, `git diff --check` and local links in changed documentation were checked.

The partial independent code/spec review passes surfaced four defects: GET payload provenance,
hook ordering by handler declaration, options counted as constraints, and discovery reparsing.
Each was corrected and covered by regression tests. Final deferred-registration testing also tightened
function/class/conditional acquisition boundaries. No live accuracy or full Fastify/Hapi feature
coverage is claimed. Existing real-app samples retain their historical scan provenance; framework
fixture/stub verification is separate from a new paid corpus evaluation.
