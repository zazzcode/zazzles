# Proposal: shared Python HTTP input facts

**Status: Proposed; Python implementation is deferred.**

This proposal follows the [Node.js input refactor](.zazz/specifications/node-http-input-refactor.md).
It is a migration plan, not a claim that existing Python coverage has changed.

## Objective

Keep small framework adapters for registration and input acquisition, and let shared flow analysis,
reusable sink contracts and the decision model assess application behavior. Flask, FastAPI and the
other existing Python adapters should produce the same language-neutral origin/type/transfer facts
as Node.js. Do not duplicate SQL, command or rendering analysis per framework.

The pipeline is:

1. A verified framework adapter identifies the route, callable, request origin and initial runtime type.
2. Shared flow records assignments, conversions, validation dependencies, hooks and conditional paths.
3. A separately selected sink contract defines DB-API, process or rendering operand behavior.
4. The judge evaluates the supplied application logic and all relevant paths.
5. Mandatory evidence and consistency gates decide the supported claim status.

## Current state to preserve

Python already contains framework-specific route, request and response handling in
[python_routes.go](internal/parse/python_routes.go),
[python_entry_adapters.go](internal/parse/python_entry_adapters.go) and
[python_frameworks.go](internal/parse/python_frameworks.go). Shared invocation records and bounded
flow feed SQL, XSS and command analysis. VulnPy's documented command coverage spans 11 adapters;
that evidence does not establish complete coverage of every framework feature.

Preserve pinned source cases, invocation identities, conditional paths, uploaded-file and thread
witnesses, raw historical answers, skipped-family behavior and report parity. Python NoSQL remains
outside the implemented corpus; this refactor must not imply new database-driver support.

## Incremental migration

### 1. Compatibility foundation

Freeze existing Python effective request bytes, source facts, candidate identities and statuses with
local stubs and retained exact-request replay. Adopt optional shared facts without changing the
historical reader or silently reclassifying saved reports. Keep feature activation bounded until
adapter parity is demonstrated.

### 2. Flask and Quart

Map path captures, query strings, form fields, parsed JSON, files and ambient request objects into
shared input origins. Preserve converter types separately from untyped query/form/JSON values.
Record before-request hooks, blueprint/app scope, custom converters, decorators and parsers with
source references; unsupported ordering or registration remains a gap. A function named validator
or a Flask path annotation does not independently prove protection.

### 3. FastAPI and Starlette

Separate raw transport values from values produced by runtime path/query/body validation. Supply
actual dependency functions, Pydantic model definitions, configuration, custom validators and relevant
framework/library versions. Do not treat a Python annotation alone as a runtime guarantee outside
verified framework binding. Preserve dependencies that mutate, reject, replace or bypass inputs.
The judge should reason over source-present validators; missing dependency bodies remain blockers.

### 4. Remaining adapters

Migrate Django sync/ASGI, Falcon sync/ASGI, Bottle, Pyramid, aiohttp and WSGI independently. Each
adapter maps route/dispatch/input mechanics to the shared schema. Preserve finite-registry dispatch,
URLconf registration identity, app conditions and loop/upload/thread source transfers. Model async
and thread boundaries explicitly; unsupported continuations cannot inherit parent-path protection.

### 5. Model-assisted discovery

Reuse the separately versioned Node discovery boundary: bounded source-backed alternatives, exact
snapshot references, strict output validation, explicit request caps and exact replay. Models may
suggest unfamiliar decorators, router factories and wrappers. Only independently checked bindings
can become trusted entries; other suggestions remain provisional coverage records, separate from
vulnerability findings. Discovery failure must not look like a clean scan.

## Contracts and responsibilities

Framework adapters own input acquisition and runtime boundary semantics. Shared flow owns value
transfers and per-path identity. Versioned analysis packs own interpretation and API behavior.
The model judges supplied application code; deterministic gates enforce evidence requirements.
No component may fabricate a source, edge, type guarantee or missing implementation.

Support initial type, sink type and uncertainty separately. A string may be decoded into an object;
a validated value may later be overwritten; one constrained branch does not protect its sibling.
Record exact transformations instead of adding framework-and-sink-specific protection flags.

## Acceptance and rollout

- Equivalent framework fixtures reach identical sink contracts/questions and preserve independent
  field validation, injection and authorization boundaries.
- Positive/protected/unknown controls cover JSON objects, scalar converters, coercion, custom validators,
  mutation after validation, missing hooks, route shadowing and conditional/thread paths.
- Existing VulnPy command witnesses and Erlik controls retain coverage; full target checkouts stay
  read-only. Compare unique sink coverage and per-context coverage separately.
- JSON/HTML/SARIF agree, provisional discovery stays separate, old schemas still render, and changed
  requests reject historical replay. Document expected deltas before fresh paid assessment.
- Run scoped and full test/race/vet/build checks, then seek a separately bounded authorization for
  fresh source-transmitting evaluation. Keep VulnPy input-validation skipped if the user retains
  that decision; report the skip explicitly.

The main risks are coercion/version differences, framework lifecycle ordering, dynamic dependencies,
false trust in annotations and model-inferred reachability. Address them through source provenance,
small adapter migrations, independent expected cases and conservative explicit gaps. No all-framework
rewrite or Python implementation is required to deliver the Node.js slice first.
