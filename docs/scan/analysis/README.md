# Analysis rules and guidelines

[Documentation index](../../README.md) · [Coverage by weakness](../detection-capabilities.md) · [Result interpretation](../interpreting-results.md)

These product documents explain how zazzles evaluates code and how contributors and coding agents
should improve its analysis. They belong outside `.zazz/`, alongside user documentation.

| Guide | Scope |
|---|---|
| [Node input acquisition](node-inputs.md) | Transport-neutral value facts, bounded Express/Fastify/Hapi adapters and provisional model-assisted discovery |
| [Next.js acquisition and practice](nextjs.md) | Addendum: file-system entries, Web Request API origins, wrappers as authorization context, client/server rendering rules and NX-BP practice checks |
| [Database injection](database-injection.md) | SQL/NoSQL library contracts, source flow, branch constraints, and verdicts |
| [Command injection](command-injection.md) | Verified Node/Python process APIs, shell/executable/argument facets, guards and outcomes |
| [Server-side request forgery](ssrf.md) | Verified `fetch`/`axios`/Python HTTP clients, destination-operand origin, restrictions, grouped outbound observations and outcomes |
| [Unrestricted file upload](file-upload.md) | Verified PHP, Werkzeug and Express `multer` upload writes, stored-name origin, server-side type controls, served destinations and outcomes |
| [Path traversal](path-traversal.md) | Verified Node `fs` and Python `open`/`pathlib` operations, effective path operands, containment controls and outcomes |
| [Prototype pollution](prototype-pollution.md) | Verified JS/TS prototype writes, key-bearing inputs, and per-level controls |
| [Code and template injection](code-injection.md) | Verified interpreter and template-source operands and their restrictions |
| [Unsafe deserialization](deserialization.md) | Verified data operands, loader and schema facts, and byte-level integrity and class restrictions |
| [Information exposure](information-exposure.md) | PHP diagnostic operations, the internal state they reveal, entry reach and dominating guards |
| [Mass assignment](mass-assignment.md) | Request-chosen property names, key origin, key guards and the security-field census |
| [Authorization](authorization.md) | Subject, operation, entry access and the guards that dominate a protected operation |
| [Account security](account-security.md) | Account lookups and their branch responses, recovery secrets delivered by mail, and fast password digests |
| [Insecure configuration](configuration.md) | Allow-listed framework and deployment settings joined to application facts |
| [Open redirect](open-redirect.md) | Verified redirect destinations and effective origin restrictions |
| [Input validation](input-validation.md) | Business requirements, enforcing checks, and separate destination protection |
| [Sensitive-data logging](sensitive-data-logging.md) | Logger bindings, data classes, content versus derived facts, and outcomes |
| [Cross-site scripting](xss.md) | Source-to-rendering evidence, HTML contexts, template escaping, sanitization and XSS outcomes |
| [Analysis changes and calibration](calibration.md) | General rules, positive/negative controls, and acceptance evidence |

The current scanner implements these rules in Go evidence assembly, question construction, and
classification. These Markdown files describe and govern that behavior; editing them alone does
not change a running binary or load a new model prompt. Keep implementation, tests, and these guides
aligned when changing a rule. Analysis decisions preserve the raw source and provider answers.

Sensitive-data logging analysis covers explicit logger calls in analyzed route handlers and morgan
request logging of URL query credentials, with a logging judgment protocol. Scoped live calibration and its limits are recorded in the
[Python evaluation](../../../.zazz/evaluation/python-support-results.md).

`.zazz/` owns internal architecture, specifications, project planning, evaluation history, and SDLC
standards. User instructions, product philosophy, analysis rules, and zazzles operation guides live in
root `docs/`. See [contributing](../../contributing.md) for repository workflow.

## Embedded Analysis Guidelines

The scanner also embeds versioned language **Analysis Guidelines** from
[`scan/internal/guidelines/`](../../../scan/internal/guidelines/). These documents combine secure coding
recommendations with instructions for interpreting source evidence. SQL, NoSQL, standalone validation,
XSS, command execution, path traversal and sensitive-data logging select applicable sections through the embedded component catalog, alongside family-specific
contracts, questions and evidence obligations. Logging selects the Logging and Do not claim sections, with catalog-owned questions and provenance. Reports retain guideline identity/version under
`analysis_guidelines` and selected component provenance under `analysis_components`. Outbound
observations select static components but send no model request. See the
[component organization](../../technical-approach.md#analysis-knowledge-and-components).
They do not implement detection or override missing evidence, application requirements or mandatory
evidence validation checks. Unlike the product guides on this page, their text is included in model requests.

“Poor practice” remains a finding classification for established defects. It is independent of the
former `Practice` name for guideline documents. See the [architecture terminology](../../../.zazz/architecture/README.md#1-architecture-premise).

Fixed interpretation sentences for query and middleware facts are owned by one embedded note
document, [`facts.md`](../../../scan/internal/guidelines/facts.md). A candidate's `model_facts` carry only a
short code plus the exact expression and file, and its request includes only the notes for the codes
it names. A code without a note fails the request instead of reaching the model unexplained.

## JavaScript conditional flow

The shared JavaScript/TypeScript flow models `if`, `else if` and `else` statements precisely. Every
analyzer uses it.

- **Polarity.** The test is evaluated once. A use inside an arm records the test as
  `branch_true_precondition` or `branch_false_precondition`.
- **Exits.** An arm that returns, throws or calls the unshadowed Node `process.exit` leaves the
  continuing path. When every arm leaves, later code is not discovered.
- **Joins.** Arms run in isolated copies of the environment and context. Where both arms continue,
  a dependency specific to one arm carries that arm's test as a transfer. Path controls survive the
  join only when both arms carry them, so a guard on one arm never protects a sibling arm or later code.
- **Ambiguity.** Binding, model, origin and response content-type metadata stay verified only when the
  arms agree; otherwise an `unknown_control_effect` gap records the ambiguity.
- **Heap writes.** An unmodeled heap write inside an arm stays an `unsupported_write` gap for later code.
- **Block scope.** `let`, `const` and `class` bindings are block scoped; `var` keeps function scope.

These statements keep the conservative fallback and its `unsupported_control_flow` gap: loops,
`switch`, `try`/`finally`, request/response identifier rebinding, browser/client flows and model
setters. Case bodies of `switch` are not traversed (a recorded limit).

The fallback never carries a path control recorded inside a body to later code. A helper whose
conditional can exit early, or whose test may guard content, stays a may-dependency for its callers.
For GraphQL and gRPC, a precondition that every use carries and that holds at the end of the resolver
becomes an invocation control: `conditional_test` when true, `conditional_false_test` when false.

## Entry adapters

The [bounded Apollo GraphQL adapter](../running-scans.md#bounded-apollo-graphql-analysis) adds
resolver-specific argument sources to these existing analysis rules. Parent/context/info provenance,
SDL syntax coverage and application policy remain separate from SQL protection and claim status.

The [bounded Node.js gRPC adapter](../running-scans.md#bounded-nodejs-unary-grpc-analysis) joins
source-visible unary registrations to request-field inputs and existing SQL claims. Proto field
types/decoding do not establish validation or protection; metadata/context/callback roles remain
separate. Streaming and unresolved descriptor/handler bindings retain visible coverage gaps.

The [cross-entry acceptance record](../../../.zazz/evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05)
checks these same claim policies across actual parsed entry adapters. Synthetic local-stub answers
cannot override unknown guards/transforms, transfer protection between invocations, or turn coverage
gaps into protection. This verification changes no analysis rule or historical model answer.
