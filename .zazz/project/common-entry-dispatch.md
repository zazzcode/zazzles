# Common entry and dispatch model — follow-up scope

**Updated user priority, 2026-11-02:** this is the next activity after the merged Python/terminology
work. Implement the common model using existing HTTP and browser consumers, with bounded support
for dynamic routes, GraphQL resolvers and gRPC handlers. The exact framework/language subsets and
coverage limits belong in the next tracked implementation contract. Command injection follows as
the next new vulnerability family. The common model, HTTP/browser migration and bounded event/dynamic/GraphQL/gRPC adapters are
implemented. Final cross-entry acceptance has passing automated and bounded localhost rendered
report evidence; human review/merge remains pending; see the [results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05).

gRPC handlers are an entry/dispatch capability independent of source language. The model should
facilitate their registration, callable binding and invocation context without HTTP-route assumptions.
Language adapters supply their own binding and flow evidence; adding gRPC or the common model
does not itself implement support for another source language.

The [architecture proposal](../architecture/common-entry-dispatch.md) and
[eight-deliverable specification set](../specifications/scan/common-entry-dispatch.md) refine this
brief as of 2026-11-03. They retain HTTP/sample compatibility, make browser events explicit,
and prioritize Node.js GraphQL before gRPC. The user-built GraphQL application is a later
evaluation; source-only fixtures support initial adapter acceptance. Deliverables1–7 have implementation evidence in their contracts; deliverable8 remains incomplete until mandatory visual acceptance passes.

## Governing design

Read [AGENTS.md](../../AGENTS.md), the [orientation](../docs/zazzles-agent-orientation.md), then
[architecture: entry/dispatch](../architecture/README.md#multiple-entry-and-dispatch-mechanisms),
[repository graph](../architecture/repository-graph.md), [evidence/claims](../architecture/evidence-and-claims.md)
and [trace judgment](../architecture/trace-judgment.md). These documents own the semantic boundaries;
this brief defines a bounded follow-up rather than a second canonical schema.

## Outcome

Analysis entry points MUST be independent of HTTP routes. Separate logical entry identity,
registration evidence, dispatch bindings, callable identity, invocation context and optional transport.
The same callable can serve multiple entries; an entry can have multiple supported dispatch targets.
Entry kind does not determine input trust. Multiple registrations and target alternatives MUST retain
conditions, provenance and unresolved coverage. Source/control/value semantics remain explicit.

The migration removes `analysis.Entry.Route` and competing route/browser associations,
introducing common entry/context identities and evidence roles. Typed check selectors and framework-specific report details are implemented. A struct-only addition
or an output projection of unchanged route-only internals does not meet the outcome.

## Bounded implementation

- Create a tracked implementation contract before coding, based on this brief and real consumers.
  Use a feature worktree from reviewed integration containing the terminology migration; if starting
  earlier is explicitly requested, name the reviewed parent commit and dependency in the draft PR.
- Establish common entry identity and registration/dispatch/callable records. IDs are snapshot-scoped
  unless an edit-stability policy is independently specified/tested. Model one-to-many/many-to-one
  relationships and partial/unknown resolution without inventing target callables.
- Migrate existing JS/TS HTTP, Python HTTP and browser analysis to that representation. Keep
  method/path and mount details as HTTP metadata. Preserve source/hash evidence and bounded flows.
- Add bounded generated/factory-route registration, GraphQL schema-field/resolver binding and
  gRPC service/method/handler binding through the common model. Select actual frameworks and
  source-reviewed cases in the contract; name unresolved generation, runtime schema composition,
  generated stubs and unsupported streaming behavior explicitly. No universal framework coverage claim.
- Carry entry/dispatch invocation context through candidate identity and claim completeness. A guard,
  value binding or protection fact in one registration context cannot protect another context.
- Make checks/selectors and judgment-required roles work without an HTTP route. Preserve old HTTP
  requirements and source policies; a newly generic name cannot weaken a completeness requirement.
- Group JSON/HTML/SARIF records by actual entries and locations. Retain HTTP/browser presentation
  where useful, and explicitly handle unknown kinds; no fake method/path or lost candidate record.
- Specify report versioning and saved schema-1/schema-2 conversion at the input boundary. Keep
  historical source/answers intact. Version changed model inputs and reject stale decision replay.
  Remove replaced internal aliases and duplicate canonical state in the same PR.

## Acceptance evidence

- Existing HTTP and browser scans use the common model and preserve supported candidates, source
  evidence, defect/protection semantics and coverage gaps in JS, TS and Python.
- One callable exposed twice has one callable identity, separate registration/dispatch contexts and
  separate applicable controls. A guarded entry cannot lend protection to an unguarded entry.
- An entry with two supported callable targets retains both; an unresolved additional target prevents
  an all-path protection conclusion when relevant. Discovery gaps remain visible even with zero uses.
- A non-HTTP entry fixture exercises the real shared candidate, completeness and JSON/HTML/SARIF
  paths without setting HTTP method/path, RouteID or ClientID. Exercise actual bounded GraphQL
  and gRPC adapter output as well as model fixtures. Reachability alone does not fabricate a value dependency.
- Selected dynamic-route, GraphQL and gRPC cases have positive/protected/unknown controls and
  declared per-language/framework coverage. Unknown registration/dispatch remains visible and cannot
  establish protection. Keep generated-route origin separate from resolution and finding status.
- Selection and source provenance remain explicit. Unknown input is not automatically attacker-controlled;
  schema/type validation does not automatically establish application policy or sink protection.
- Saved old reports export without changing files/answers. Current serialized records have one
  canonical entry association; compatibility conversion is tested and does not silently drop metadata.
- Identical input yields deterministic identities/order and bounded work. No whole-repository path
  enumeration or unbounded factory/target expansion is introduced.
- Run paired raw/protected/unknown controls, local HTTP-stub judgment/policy/replay tests, existing
  source-reviewed Python case checks, offline CLI scans/exports, Go race tests, vet, build and format.
  Record evidence and remaining gaps in the owning contract/evaluation documents.

## Exclusions

New vulnerability families, a general authorization engine, queue/CLI/scheduler adapters, a full IR
replacement, graph database, independent reviewer, automatic cache, sample remediation and unbounded paid
calibration are outside this activity. Dynamic-route, GraphQL and gRPC support is bounded by the
selected source/binding/flow contracts and acceptance evidence; unsupported frameworks and runtime
behavior remain explicit gaps.


The user-authorized final SQL/NoSQL-only follow-up recovers Goof login NoSQL and Juice Shop login
SQL, with full-source reports and conservative negative controls. Five-set localhost rendered review
now passes; human code/design review and merge remain pending. See the
[current accuracy closeout](../evaluation/common-entry-dispatch-results.md#sqlnosql-only-accuracy-refresh-and-rendered-review).
Broader hardening waits until after analysis-pack-mvp; no next-deliverable implementation is included.
