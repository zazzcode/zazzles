# Node.js HTTP input facts and model-assisted discovery

## Authorized delivery

User requested this refactor in the existing command-injection worktree and draft PR on 2026-11-07.
Python implementation remains unchanged; save its migration proposal as `PYTHON-INPUT-REFACTOR-PROPOSAL.md`
in the project root. Follow AGENTS.md, spec-driven, code-structure/testing standards and doc-check.

Implement the pipeline: verified framework registration → shared input origin/initial type → supplied
hooks, validators and transformations → framework-independent operation contract → semantic judge →
mandatory completeness/consistency policy. Adapters MUST NOT assign security verdicts. Missing source
or unknown dispatch cannot be invented by model confidence.

The core fact schema MUST be transport-neutral. Existing GraphQL/gRPC acquisition may populate it;
no queue implementation is implied. Acquisition kind, framework and network transport remain independent metadata, and
no sink contract may depend on HTTP route syntax. This corrects the earlier Express-coupled shortcut.

## Bounded scope

- `internal/analysis`: optional versioned language-neutral input facts and separate discovery proposals;
  schemas 1–4 remain readable. Proposals are not entries or vulnerability findings.
- `internal/parse`: thin Express/Fastify/Hapi adapters, reusing existing shared invocations/flow/query
  assembly. Support direct immutable imported factories, literal route methods/paths, direct/named
  handlers, Fastify shorthand/full route objects, Hapi route objects, supplied same-instance hooks and
  literal schema/options evidence. Hapi payload maps to body origin. Dynamic plugins, mounts,
  extensions, validators, parsers or missing hook bodies retain explicit gaps; no false completeness.
- Replace the Express-coupled fresh Mongoose lookup contract with a generic default-ObjectId
  `findById` contract. Preserve the historical contract for saved reports. Type facts are separate
  from sink semantics; unknown sink type is not sufficient by itself for protection. Supplied
  application guards/schemas can be assessed by the judge without a bespoke validator implementation.
- `internal/analysispacks`, `internal/judge`, `internal/report`: selected versioned input interpretation,
  source/type/transfer evidence on the wire, mandatory gates and three-format status consistency.
- Opt-in model-assisted route discovery: source-backed bounded route/handler/hook alternatives,
  exact source references/hashes, explicit provider/model and cap, no retries/fallback. Model chooses
  proposed bindings from supplied syntax candidates; it cannot invent source spans. The engine
  checks source integrity and whether the binding is already independently established. Unverified
  wrappers/frameworks remain provisional coverage records, never trusted entry/flow evidence. This
  extends useful discovery without adding a second vulnerability-analysis pipeline.
- CLI/public docs/tests and root Python proposal. No target edits/execution, dependency installation,
  Python behavior changes, authorization analyzer, unrelated parser fixes, merge or integration push.

## Acceptance

1. Equivalent Express/Fastify/Hapi direct lookup fixtures feed one shared input-fact schema, generic
   Mongoose operation contract, NoSQL questions and policy. Correct stub answers produce Protected;
   body/query object controls remain unsafe or Review as appropriate.
2. Hooks and schema configuration are source-backed, ordered and supplied to the model. A schema
   declaration alone never establishes protection. Parameter mutation, missing/custom hooks,
   unmodeled plugin scopes and unsupported registrations cannot inherit the raw-string guarantee.
3. Shared facts preserve origin, initial/sink type, exact transfers, invocation and source hashes.
   Known unchanged primitives and native transformations can supply bounded type witnesses; the
   model assesses source-present application logic. No confidence-based gap removal.
4. Discovery protocol is separately versioned and budgeted, opt-in, tested through local HTTP stubs,
   strict choice decoding and exact replay. Malformed/out-of-manifest proposals, stale hashes,
   optimistic model answers, failed transport and budget exhaustion cannot create trusted entries.
   JSON/HTML/SARIF show provisional coverage and do not imply a complete scan.
5. Python source adapters/requests remain unchanged; existing fixture effective-request baselines
   pass for Python. Expected Node request changes are recorded as shared input/type evidence, new
   component provenance and generic lookup semantics; historical answers remain untouched. Retained
   real sample reports stay historical rather than receiving fabricated fresh verdicts.
6. Scoped parser/catalog/judge/CLI/report tests, full test/race/vet/build, changed-file formatting,
   scoped document/link checks and diff checks pass. No paid calls are authorized for this slice;
   model integration uses local stubs. Existing two-call Goof authorization is exhausted.
7. Root Python proposal describes staged adapter migration, shared contracts, compatibility tests,
   input coercion/hooks/dependencies, provisional discovery, risks and acceptance criteria. It MUST
   be marked proposed, with no Python implementation claimed.

## Execution record

Append progress, exact affected files, evidence and accepted changes to
`.zazz/ephemeral/command-injection-run-log.md`. Reuse the current feature branch and draft PR.
Commit/push verified changes under the existing feature delivery authorization; never merge.

## Change log

### 2026-11-07 — Node implementation; Python deferred

The user explicitly requested Node refactoring and a root Python proposal, then confirmed piecewise
implementation. This contract keeps Python runtime behavior unchanged and makes discovery opt-in.

### 2026-11-07 — Transport-neutral boundary correction

User clarified that the separation must also accommodate RPC and queue acquisition. Shared values
and sink contracts are transport-neutral; framework code remains solely at acquisition boundaries.
Queue runtime support is not part of this slice. Existing Python acquisition remains unchanged.

## Implemented verification

The [verification record](../evaluation/node-input-refactor-results.md) maps this slice to its tests,
review corrections, conservative framework limits and complete unchanged VulnPy replay. Node source
facts and generic sink selection are implemented; discovery is opt-in and provisional outside known
dispatch. Python remains unchanged and its root proposal is deferred. No fresh paid corpus scan was
performed or claimed.
