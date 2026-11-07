# Node.js input acquisition and shared value facts

[Analysis index](README.md) · [Database analysis](database-injection.md) · [Running scans](../running-scans.md)

Node acquisition adapters identify registrations, handlers and request fields. Shared `input_facts`
version 1 separates origin, initial type, type at the actual sink, transformations, lifecycle stages,
source-present controls and gaps. `acquisition` identifies the entry/input boundary; actual network
transports remain on the existing entry transport associations, independently of framework metadata. The facts are transport-neutral: HTTP, GraphQL and unary gRPC can
feed the same sink contracts and judgment policy. Queue acquisition is not implemented. Python
keeps its existing behavior; its staged migration is [proposed](../../PYTHON-INPUT-REFACTOR-PROPOSAL.md).

## Supported HTTP boundary

- Express retains its existing bounded direct/mounted/finite-registration analysis and middleware context.
- Fastify recognizes immutable direct imported/required factories, direct shorthand registrations and
  literal full `route` objects with a direct or statically resolved handler.
- Hapi recognizes direct imported `server()` factories and literal `route` objects; `request.payload`
  maps to body origin. Plain named `{id}` path captures are distinct from body/query objects.
- Earlier same-instance Fastify request hooks, route/instance schema options and source-present custom validators
  are supplied to the judge. Known stages retain lifecycle ordering and scope; instance and route configuration may override
  one another rather than run as sequential validators. Hapi default/route
  validation source is supplied; GET/HEAD do not invent parsed payload inputs; advanced extensions remain gaps.

Dynamic factories, route objects/spreads, conditional/deferred registrations, plugin encapsulation,
late hook applicability, custom parser/compiler overrides, missing validator/helper bodies, advanced Hapi extensions and
unverified third-party validator semantics stay explicit gaps. Source fixtures verify these subsets;
this is not comprehensive certification of either framework or all their versions.

## Type facts and semantic judgment

A raw named URL parameter can start as a string. Hooks, validation/coercion, JSON decoding, assignments
and helper calls can change it before a sink. Initial type never automatically becomes sink type.
Native Number/String conversions supply a bounded output fact; unknown transformations remain unknown.
The model sees exact source references, supplied controls and schema configuration and assesses their
actual effects. A schema's presence or a validator's name never makes a claim Protected.

The generic pinned Mongoose default-ObjectId `findById` contract describes casting and query behavior,
without referencing a framework or URL syntax. Separate type/control evidence and the ordinary NoSQL
questions determine protection. Body/query objects do not inherit raw path-string protection. Missing
bodies and contradictory model answers remain Review. Authorization and field policy remain separate.

Fresh Node requests include this evidence and new selected component provenance. Old saved responses
cannot be reused for changed requests. Historical sample reports retain their recorded scan provenance;
this refactor was verified offline and does not fabricate new paid sample judgments.

## Opt-in model-assisted discovery

```bash
./bin/scan --analyze --json --judge openai --judge-model gpt-6-luna \
  --judge-limit 10 --discover-routes --discovery-limit 3 --trace-dir /external/traces /path/to/app
```

`--discovery-limit` bounds additional discovery attempts independently of security judgments. Discovery
is off by default, uses the selected provider/model, and has no automatic retries or fallback. Use
`--entry` to restrict registration files; route/kind/ID/check filters are not combined with discovery.

The scanner inventories at most 1,000 syntactic registration/handler alternatives from selected Node
sources. The model chooses a proposed relationship from exact source-backed alternatives; it cannot
return arbitrary file paths or invent snippets. The engine rechecks the selected manifest, source
spans/hashes and comment-masked projection. Already verified dispatch is reused without a model call.
Unknown frameworks/wrappers remain provisional even when the model proposes a route. They are separate
coverage records, never trusted entries, new flow edges or vulnerability findings.

Provisional, failed, rejected-but-unverified or budget-limited alternatives leave the requested run
incomplete. JSON, HTML and SARIF expose the proposals and coverage limitations. This bounded inventory
is not complete application discovery. Saved discovery traces support exact-request offline replay.

## Official semantics

The bounded adapters follow [Fastify routes](https://fastify.dev/docs/latest/Reference/Routes/),
[Fastify hooks](https://fastify.dev/docs/latest/Reference/Hooks/),
[Fastify validation](https://fastify.dev/docs/latest/Reference/Validation-and-Serialization/),
[Hapi routing](https://hapi.dev/tutorials/en_us/routing) and
[Hapi validation](https://hapi.dev/tutorials/en_us/validation). Target versions and supplied overrides
remain relevant; moving documentation is not evidence of an installed target runtime.
