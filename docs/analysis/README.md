# Analysis rules and guidelines

[Documentation index](../README.md) · [Result interpretation](../interpreting-results.md)

These product documents explain how zazzles evaluates code and how contributors and coding agents
should improve its analysis. They belong outside `.zazz/`, alongside user documentation.

| Guide | Scope |
|---|---|
| [Database injection](database-injection.md) | SQL/NoSQL library contracts, source flow, branch constraints, and verdicts |
| [Command injection](command-injection.md) | Verified Node/Python process APIs, shell/executable/argument facets, guards and outcomes |
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
[Python evaluation](../../.zazz/evaluation/python-support-results.md).

`.zazz/` owns internal architecture, specifications, project planning, evaluation history, and SDLC
standards. User instructions, product philosophy, analysis rules, and zazzles operation guides live in
root `docs/`. See [contributing](../contributing.md) for repository workflow.

## Embedded Analysis Guidelines

The scanner also embeds versioned language **Analysis Guidelines** from
[`internal/guidelines/`](../../internal/guidelines/). These documents combine secure coding
recommendations with instructions for interpreting source evidence. SQL, NoSQL, standalone validation
and XSS select applicable sections through the embedded component catalog, alongside family-specific
contracts, questions and evidence obligations. Logging still receives the full applicable language
document pending its component migration. Reports retain guideline identity/version under
`analysis_guidelines` and selected component provenance under `analysis_components`. Outbound
observations select static components but send no model request. See the
[component organization](../technical-approach.md#analysis-knowledge-and-components).
They do not implement detection or override missing evidence, application requirements or Go policy
gates. Unlike the product guides on this page, their text is included in model requests.

“Poor practice” remains a finding classification for established defects. It is independent of the
former `Practice` name for guideline documents. See the [architecture terminology](../../.zazz/architecture.md#1-architecture-premise).

The [bounded Apollo GraphQL adapter](../running-scans.md#bounded-apollo-graphql-analysis) adds
resolver-specific argument sources to these existing analysis rules. Parent/context/info provenance,
SDL syntax coverage and application policy remain separate from SQL protection and claim status.

The [bounded Node.js gRPC adapter](../running-scans.md#bounded-nodejs-unary-grpc-analysis) joins
source-visible unary registrations to request-field inputs and existing SQL claims. Proto field
types/decoding do not establish validation or protection; metadata/context/callback roles remain
separate. Streaming and unresolved descriptor/handler bindings retain visible coverage gaps.

The [cross-entry acceptance record](../../.zazz/evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05)
checks these same claim policies across actual parsed entry adapters. Synthetic local-stub answers
cannot override unknown guards/transforms, transfer protection between invocations, or turn coverage
gaps into protection. This verification changes no analysis rule or historical model answer.
