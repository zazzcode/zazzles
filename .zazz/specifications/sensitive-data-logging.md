# Sensitive-data logging (logger-leak)

## Outcome and authorization

On 2026-11-01 the user requested logger-leak analysis refinement and reporting of findings in the
`logger-leak` worktree, ahead of the remaining SQL/NoSQL acceptance items. Product rules live in
[sensitive-data logging analysis](../../docs/scan/analysis/sensitive-data-logging.md); internal data flow
lives in the [logging design](../architecture/sensitive-data-logging.md). Known target answers remain
evaluation evidence only.

## Scope

Work proceeds in increments; each one leaves code, tests, product rules and this contract aligned.

1. **Explicit emissions (implemented).** In analyzed route-handler flows, record a `log_sink_candidate`
   use when a verified logger call receives a value that depends on a request source with a
   data-class hint. Verified bindings: unshadowed global `console` methods, and a winston logger
   created by `winston.createLogger` in the same module or the default export of a relative module.
   Data-class hints: protocol credentials (`authorization`/`proxy-authorization`/`cookie` headers),
   credential or personal-data lexicon on the request field key, and whole request containers.
   Non-content projections (length, comparison, `typeof`, negation, `Boolean`) are recorded separately
   from content. A logger call is not a validator and no longer marks a field as validated-unresolved.
2. **Request-line logging (implemented).** Model `morgan` request logging (predefined formats and
   literal formats containing `:url`) registered with `use` on the route's receiver, in the route's
   function scope, before the route, with a matching path prefix. Resolve destructured request
   parameters. Credential evidence for a query field comes from its destination (assigned to a
   credential-named property, or compared for equality with one), not only its name.
3. **Semantic judgment (implemented offline; live calibration pending).** Protocol `log-use-v1` asks
   data class, content exposure, redaction, and log exposure; the policy requires logger binding and
   request source evidence and consistent answers. Rule pack `javascript` v3 adds logging rules.
   Live calibration uses capped `gpt-6-luna` batches only after explicit user authorization.

Excluded until separately scoped: non-request sensitive sources (hardcoded secrets, environment
variables, database records), pino/bunyan/custom transports, logger-level redaction configuration,
error-object contents, log injection, and log-file access control.

## Outcome rules

- Protocol credential with revealing content, verified logger and no unresolved transfer: orange
  poor-practice finding. Red requires a consistent `log-use-v1` vulnerable judgment and no blockers.
- Request-line logging of a query field with credential destination evidence: orange finding;
  Review when registration is conditional or has a `skip` option, or when only a name hints.
- Lexicon or whole-container hints, or an unresolved transformation on the path: blue Review.
- Only non-content projections of hinted values: green Protected for the logging claim.
- No hint, unverified logger binding, or a constant message: no record.

## Acceptance

- Fixture tests cover: logged authorization header (finding); password field via template text
  (Review); whole `req.body` (Review); password `.length` and comparison (Protected); unknown masking
  helper (Review); constant startup message, non-sensitive field, shadowed `console`, same-name fake
  logger object (no record); verified winston default-import logger (record).
- The vulnerable-typescript-app `POST /api/login` SQL-text log is recorded as Review naming `password`
  (`username` carries no hint); its startup messages and error-handler stack log produce no record.
- JSON/HTML/SARIF share one presentation record using the `sensitive-data-logging` type.
- Existing query/validation tests pass; any golden changes from the logger-is-not-validator rule are
  inspected and explained. Samples are refreshed only after the user accepts the outputs.

Juice Shop acceptance: `GET /rest/user/change-password` is an orange finding naming `current` and
`new`, with `server.ts` morgan registration as the sink; `GET /rest/user/security-question` (email in
query) is Review; no explicit `logger.*` call in routes produces a record.

## Execution

Use the [execution discipline](../docs/agent-execution-discipline.md), [testing](../standards/testing.md)
and [code structure](../standards/code-structure.md). The cloud session lacks the declared Go
toolchain; checks run on the linked computer with the shared toolchain described in
[worktree setup](../docs/worktree-setup.md#linked-computer-agent-toolchain). Results are recorded in
ignored `.zazz/ephemeral/sensitive-data-logging-run-log.md`. No PR, merge, or paid calls without request.

## Implementation and review change log

### 2026-11-01 — Contract authored

Scope, increments and offline outcome rules recorded from the session handoff and inspection of both
sample targets. Juice Shop's change-password query credentials with global `morgan('combined')` are
the increment 2 positive case; the TS login SQL-text log is the increment 1 case.

### 2026-11-01 — Increments 2 and 3, engine fixes, Bearer comparison

User confirmed the target: Juice Shop writes cleartext passwords to access logs. Source tracing
showed Bearer's 278 logger findings never cover it (false negative) and its credential-looking lines
log keys, masked emails or constant text. Implemented destructured request parameters, credential
destination/comparison evidence, morgan request-line claims, and the logging judgment protocol.
Chained method calls now keep their receiver's dependencies (`a.b().c()`), which also completes the
login SQL and track-order NoSQL evidence; their earlier judgments are not reused in samples.
