# zazzles — agent orientation

Read [AGENTS.md](../../AGENTS.md) first. This guide maps the code, worktrees and development process.
Follow only the section links relevant to the task; linked documents are not automatic includes.

## Current work

The assigned worktree/branch is `path-traversal`. Shared Gemini support for **all analyzers** is
implemented with a [passing two-request live sample](../evaluation/gemini-decisions-results.md#scope-and-outcome).
Path traversal implementation, [Tier-1 soundness/determinism hardening](../specifications/path-traversal-hardening.md),
and [shared rate/spend configuration](../specifications/decision-model-limits.md) are implemented and verified
under the [analyzer contract](../specifications/path-traversal.md#1-capability-and-prerequisite) and
[results](../evaluation/path-traversal-results.md): all 204 positive sample contexts, 4/4 sample protected
controls, 78/78 portable controls, 11/11 live adversarial controls and 360 exact replays pass, alongside
the full 9-package `-race` suite. Higher-difficulty cross-analyzer improvements are ranked in the
[hardening and wire-efficiency proposal](../project/analyzer-hardening-and-wire-efficiency-proposal.md).
Human review remains open. Read the ignored `.zazz/ephemeral/path-traversal-run-log.md` on resume if present.
Preserve concurrent user edits, especially local credentials. No live Jev evaluation is assigned.

## Code structure

| Path | Owns | Read more only when needed |
| --- | --- | --- |
| `cmd/scan/` | CLI flags, configuration, limits, output wiring and exit codes | [CLI use](../../docs/running-scans.md), [contributor checks](../../docs/contributing.md#contributing) |
| `internal/walk/`, `internal/lang/` | File inventory and supported-language detection | [Parsing](../architecture.md#3-parsing-and-language-adapters) |
| `internal/parse/` | Tree-sitter bindings, imports/entries, bounded flow, source-backed candidate assembly | [Acquisition facts](../architecture/evidence-and-claims.md#transport-neutral-input-and-value-evidence), [graph boundary](../architecture/repository-graph.md) |
| `internal/analysis/` | Shared candidate/report/entry records, facts, provenance and compatibility | [Package boundary](../architecture.md#11-implemented-package-boundaries), [claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) |
| `internal/analysispacks/`, `internal/guidelines/` | Embedded contracts, selected guidance, questions and versions | [Selection](../architecture/analysis-packs.md#descriptor-and-selection-contract), [bounds](../architecture/analysis-packs.md#bounds-and-compatibility) |
| `internal/judge/` | Provider requests, decoding, replay, evidence validation and findings classification | [Judge boundary](../architecture.md#provider-neutral-judge-boundary), [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates) |
| `internal/report/` | Findings, Review/Protected presentation, JSON/HTML/SARIF and bundles | [Reporting design](../architecture/reporting-and-sarif.md), [HTML design](../architecture/html-reporting.md) |
| `internal/parse/testdata/` | Small JS/TS/Python regression repositories | [Test conventions](../standards/testing.md#2-test-kinds) |
| `docs/`, `.zazz/`, `.agents/skills/` | User docs; internal contracts/design/evaluation; development skills | [Document owners](#documentation-map) |

Each [analyzer](../architecture.md#analyzer-terminology) spans the shared engine's activities.
Use the architecture's [evidence validation terminology](../architecture.md#evidence-validation)
and follow the [code structure rules](../standards/code-structure.md#1-package-layout).

## Portable workspace and DEV_ROOT

`<DEV_ROOT>` means the computer's development directory (usually `~/Dev`), not an environment variable.
Resolve it each session; tracked docs/configuration must not hardcode a developer's home directory.
The usual container is `<DEV_ROOT>/zazzcode/zazzles`; sample checkouts are siblings under `<DEV_ROOT>`.

## Branches and worktrees

```text
zazzles/                   container, not a source checkout
├── .bare/                 shared Git directory and worktree metadata
├── stage/                 integration checkout
├── path-traversal/        assigned feature checkout and branch
├── <other-feature>/       independent feature checkout and branch
├── .tools/                optional shared linked-computer toolchain/cache
└── _test-findings/         local scan artifacts, outside targets and worktrees
```

Run commands from the assigned feature checkout. Verify `pwd`, `git branch --show-current` and
`git status --short --branch` before edits; do not edit `.bare` directly. `stage` receives reviewed
PRs; `main` is human-operated release promotion. Related design, spec, implementation and tests stay
in the assigned worktree. See [authorization](../../AGENTS.md#authorization-and-delivery),
[worktree verification](worktree-setup.md#verification-checklist),
[Worktrunk operations](worktree-setup.md#worktrunk-usage) and
[linked-computer toolchain](worktree-setup.md#linked-computer-agent-toolchain) only for linked VM sessions.
Native development uses the Go version in `go.mod` and a C compiler.

Ignored `.env` files are local to each checkout. Worktrunk's configured copy step seeds new worktrees
from `stage`; later edits are not synchronized. Current intent: stage uses `gpt-6-luna`,
path-traversal uses `gemini-decision-1`. Never print tokens or overwrite the user's local file.
[Environment loading](../../docs/getting-started.md#local-environment-file) and
[provider setup](../../docs/decision-models.md#credentials-and-local-environment) own configuration.

## Working protocol

1. Read the assigned contract and local run log; verify worktree, branch and diff. A roadmap row
   alone is not an implementation assignment.
2. Load only matched [standards](../standards/index.yaml), product analysis rules and repository
   skills (`spec-builder`, `spec-driven`, `doc-check`) required for the current task.
3. Define acceptance before coding; run scoped tests and then required contributor checks.
   Format only changed Go files. [Verification discipline](agent-execution-discipline.md#verification-discipline)
   and [test commands](../../docs/contributing.md#contributing) own details.
4. Append attempts/evidence to ignored `.zazz/ephemeral/`; promote durable outcomes to their owning
   docs. [Execution records](agent-execution-discipline.md#execution-records) own resumption rules.
5. Follow [PR process](../standards/pr-process.md) when packaging: verify Git identity/profile,
   draft PR into `stage`, human review/merge. Never merge or push integration directly.

## Implemented features

The [capability matrix](../project/implementation-plan.md#supported-capability-checklist) owns current
language coverage and limits; the [delivery checklist](../project/implementation-plan.md#complete-delivery-list)
owns branch outcomes. Implemented foundations include bounded JS/TS/Python analysis, shared entry/
dispatch and schema4 reports; analyzers cover validation, SQL, MongoDB-style NoSQL (JS/TS), logging,
XSS, command injection and path traversal (verified Node `fs`/Python `open`/`pathlib` operands; see
[results](../evaluation/path-traversal-results.md)). Outbound is observation-only. Inspect/Audit/Fix workflows remain planned.

For exact acceptance read only the matching record:
[command results](../evaluation/command-injection-results.md),
[XSS hardening](../evaluation/xss-hardening-results.md),
[Python limits](../evaluation/python-support-results.md),
[entry acceptance](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05), or
[component status](../architecture/analysis-packs.md#current-implementation-status).
NoSQL is the extensible category; MongoDB-style models are its initial scope. Findings should name
the actual engine/driver; [database rules](../../docs/analysis/database-injection.md#database-specific-nosql-scope)
distinguish MongoDB, MarsDB and future databases such as DynamoDB.

## Available vulnerable sample apps

Local names below are expected checkout names under `<DEV_ROOT>`; verify existence and pinned revision
before a scan. The [primary catalog](../project/vulnerable-sample-apps.md#applications) owns pins;
[other evaluated apps](../project/vulnerable-sample-apps.md#other-evaluated-applications) owns older targets.

| Sample checkout | Stack | Focused source reference |
| --- | --- | --- |
| `vuln-demo-app` | JavaScript, Express, sql.js | [Expected findings](../project/vulnerable-sample-apps.md#vuln-demo-app) |
| `vulnerable-typescript-app` | TypeScript, Express | [Expected findings](../project/vulnerable-sample-apps.md#vulnerable-typescript-app); small `/api/ping` command and `/api/files` path witnesses |
| `nodejs-goof` | JavaScript, Express, Mongoose | [Expected findings](../project/vulnerable-sample-apps.md#nodejs-goof) |
| `juice-shop` | TypeScript, Express, Sequelize, Angular | [Expected findings](../project/vulnerable-sample-apps.md#owasp-juice-shop) |
| `vulnpy` | Python, 11 adapters | [Expected findings](../project/vulnerable-sample-apps.md#vulnpy) |
| `ThreatByte` | Python | [Source expectations](../evaluation/threatbyte-detection-guide.md) |
| `python-insecure-app` | Python, FastAPI | [Source expectations](../evaluation/python-insecure-app-detection-guide.md) |
| `Vulnerable-Flask-App` | Python, Flask | [Results and limits](../evaluation/python-support-results.md) |

Sample apps are read-only: no fixes, formatting, dependency installation, checkout changes or output
inside them. Verify clean `git status --porcelain --ignored` and pinned HEAD before/after evaluation.
Write reports to the container's `_test-findings/<app>/run-<id>/` via `--output-dir`. Repairs belong in
[independent copies](../../docs/samples/reference-policy.md#remediate-a-copy).

## Task reading paths

| Task | Load these sections first | Expand only for |
| --- | --- | --- |
| Configure/run a judge | [Credentials](../../docs/decision-models.md#credentials-and-local-environment), [live scope](../../docs/decision-models.md#scope-a-live-run) | API-specific diagnosis; never load/print secrets |
| Add an analyzer | Assigned contract, [component ownership](../architecture/analysis-packs.md#boundary-and-ownership), matching [analysis guide](../../docs/analysis/README.md) | Exact operand/flow/parser models required by its tests |
| Change evidence or gates | [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [calibration pairs](../../docs/analysis/calibration.md#regression-pairs) | Relevant graph/trace/API sections |
| Change entries/dispatch | [Entry model](../project/common-entry-dispatch.md), [graph design](../architecture/repository-graph.md) | Specific HTTP/browser/GraphQL/gRPC contract |
| Write/refine a spec | [Delivery checklist](../project/implementation-plan.md#complete-delivery-list), [spec index](../specifications/README.md#specification-index), `spec-builder` | Relevant architecture decisions, not all historical contracts |
| Implement/resume | Assigned contract, local run log, [execution verification](agent-execution-discipline.md#verification-discipline), `spec-driven` | Matched standards and focused code |
| Edit docs | [Owners](#documentation-map), [docs hygiene](../standards/docs-hygiene.md), `doc-check` | Relevant implementation/evaluation evidence |

## Documentation map

| Owner | Start at |
| --- | --- |
| Product goals and roadmap | [Capability boundaries](../project/implementation-plan.md#product-goals-and-capability-boundaries), [complete delivery list](../project/implementation-plan.md#complete-delivery-list) |
| Architecture | [Pipeline](../architecture.md#2-pipeline), [package map](../architecture.md#11-implemented-package-boundaries), [judge boundary](../architecture.md#provider-neutral-judge-boundary) |
| Product rules | [Analysis index](../../docs/analysis/README.md), [database rules](../../docs/analysis/database-injection.md), [input rules](../../docs/analysis/input-validation.md), [XSS rules](../../docs/analysis/xss.md) |
| User setup/output | [Setup](../../docs/getting-started.md), [scan options](../../docs/running-scans.md), [interpretation](../../docs/interpreting-results.md) |
| Contracts and process | [Spec index](../specifications/README.md#specification-index), [execution records](agent-execution-discipline.md#execution-records), [standards index](../standards/index.yaml) |
| Sample evidence | [Pinned apps](../project/vulnerable-sample-apps.md#applications), [sample provenance](../../docs/samples/reference-policy.md) |

## Commands and credentials

`JUDGE_DECISION_MODEL` is one scan-wide model selection; `--judge` explicitly enables requests and
must match its provider. Keys may coexist, but only the selected provider's key goes to the client.
The scanner does not auto-load `.env`. Live calls transmit source and need an explicitly scoped
request count; a key alone is not authorization. No fallback or live Jev testing is assigned.
See [user setup](../../docs/decision-models.md#credentials-and-local-environment).
