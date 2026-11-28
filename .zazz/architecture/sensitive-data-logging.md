# Sensitive-data logging design

Product [analysis rules](../../docs/scan/analysis/sensitive-data-logging.md) own interpretation. This
internal document owns data flow and boundaries. The contract is
[sensitive-data logging](../specifications/scan/sensitive-data-logging.md).

## Data flow

Logging sinks reuse the route-handler flow in `scan/internal/parse/flow.go`. `flow.call` asks
`logSink` (in `log_sinks.go`) whether the callee is a verified logger method before considering
query or HTTP kinds. Verification is binding-based, never name-based:

- `console.<method>` requires that `console` is not shadowed by a parameter, local, or module binding.
- A winston logger requires a local or imported binding whose value is `X.createLogger(...)` with `X`
  imported from `winston`, or a default import of a relative module whose `export default` is such a call.

Arguments are evaluated by the existing value engine, so dependencies keep request-source evidence and
transfers. `log_classes.go` classifies each request dependency by field key (the source member or a
`field_projection` binding), header/cookie container, or whole container. Lexicon matching splits
camelCase, snake_case and kebab-case into tokens; it yields a hint, not an established class, except
for protocol credential headers whose meaning comes from HTTP semantics.

`eval` records `non_content_projection` transfers for `.length`, comparisons, `typeof`, `!`, and
`Boolean(...)`. A dependency whose transfers include one has been reduced to non-content. Any
`unknown_transfer` remains an unresolved transformation; helper bodies resolved by the existing
helper expansion keep their transfers.

The use carries `Kind: log_sink_candidate`, the call as sink evidence, logger binding evidence in
`Context` (kind `logger_binding`), and classification gaps: `log_protocol_credential`,
`log_sensitive_field_hint`, `log_request_container`, `log_non_content_only`,
`log_transform_unresolved`. Gaps carry the field key in `Detail` for reporting.

## Request-line logging

`analysis.go` resolves a destructured first handler parameter with `requestParts`; container members
(`query`, `body`, ...) become request sources in `flow.eval` unless a local rebinds the name, and other
members stay explicit as `request_projection_partial`. `flow.eval` records credential destinations on
`inputFacts`: a request value in an object `pair` whose key is credential-named, or compared with
`===`/`!==` against a credential-named member. After the handler flow, `requestLineLogs`
(`log_access.go`) looks for `<receiver>.use(morgan(format))` before the route in the same function
scope with a URL-bearing literal format and a matching path prefix. Query fields with destination
evidence produce `log_request_line_credential`; credential- or personal-data-named query fields produce
`log_request_line_hint`; conditional registration or a `skip` option adds `log_request_line_conditional`.
The claim's sink is the middleware registration; context carries the import, format and destination.

Chained calls keep their receiver's value: `flow.call` combines the evaluated inner call into the
outer call's may-dependency. This is shared engine behavior, so it also changes query evidence.

## Semantic judgment

`judge/logging.go` defines protocol `log-use-v1` (data_class, content_exposure, redaction,
log_exposure) with strict choices. `applyLogPolicy` requires a `logger_binding` context item and a
request source, then accepts vulnerable only with a sensitive class, content yes and redaction no or
not applicable, and never against non-content-only scanner facts. The embedded JavaScript/TypeScript Analysis Guidelines
(`scan/internal/guidelines/javascript.md`, v5) carry the logging guidance supplied with each request.
The generic query protocol is now `candidate-use-v9`; logging questions retain `log-use-v1`.

## Reporting

`findingTypeIDs` maps `log_sink_candidate` to `sensitive-data-logging` (coverage now bounded analysis).
`describe` applies the contract's outcome rules; guidance gives removal/allowlist/redaction actions.
Logger calls are excluded from `noteInputTouch`, so logging no longer makes validation look unresolved.

## Limits

Only analyzed route-handler flows are inspected; module-level startup logs are outside routes and
produce no records by construction. Logger formats other than morgan's URL-bearing ones, transports, levels and
redaction configuration are not modeled, so destination exposure is not established offline.
Shorthand object properties (`{ password }`) are not evaluated as dependencies yet, and checked-mode
claim assembly does not use destructured request parameters.
