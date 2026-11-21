# zazzles — agent orientation

This guide maps the code, worktrees, and development process. Agent startup and context loading are
managed by [AGENTS.md](../../AGENTS.md#start-here). Current delivery status, roadmap ordering, and
implemented capability lists live in the [implementation plan](../project/implementation-plan.md)
and [detection capabilities](../../docs/scan/detection-capabilities.md), not here, so this guide
stays stable.

<a id="current-work"></a>

## Contents

| Section | Consult for |
| --- | --- |
| [Code structure](#code-structure) | Module layout (`scan/`, `fix/`, `probe/`), package ownership, and architecture references |
| [Portable workspace and DEV_ROOT](#portable-workspace-and-dev_root) | Resolving local checkout and sample paths |
| [Branches and worktrees](#branches-and-worktrees) | Assigned checkout, `.bare/` layout, and worktree operation references |
| [Working protocol](#working-protocol) | Implementation, verification, execution records, and PR preparation |
| [Available vulnerable sample apps](#available-vulnerable-sample-apps) | Sample handling rules and catalog pointers |
| [Task reading paths](#task-reading-paths) | Focused references for specific engineering tasks |
| [Documentation map](#documentation-map) | Finding the document that owns a topic (including current status and roadmap) |
| [Commands and credentials](#commands-and-credentials) | Scan model selection, local configuration, and live-call limits |

## Code structure

Zazzles is organized into three top-level module directories — **Code Scan** (`scan/`), **Fix**
(`fix/`), and **Endpoint Probe** (`probe/`) — under one root Go module (`go.mod` / `go.sum`). This
keeps dependency management, root builds, CI, and shared documentation unified while giving each
module a clean top-level home and using Go's `internal/` import rule (`scan/internal/`) to enforce
the Code Scan package boundary. The canonical CLI binary builds from `scan/cmd/scan/`, while root
`cmd/scan/` stays as a thin compatibility entry point; both wrap the shared `scan/cli` package
(`cli.Run`). User documentation mirrors the modules under `docs/scan/`, `docs/fix/`, and
`docs/probe/`, with shared project guides and curated sample reports kept in root `docs/`.

| Path | Owns | Read more only when needed |
| --- | --- | --- |
| `scan/cmd/scan/`, `cmd/scan/` | Canonical (`scan/cmd/scan/`) and root compatibility (`cmd/scan/`) CLI entry points calling `scan/cli.Run` | [Setup](../../docs/scan/getting-started.md#compile), [contributor checks](../../docs/contributing.md#contributing) |
| `scan/cli/` | CLI flags, configuration, limits, output wiring, exit codes, and CLI/baseline tests (`TestArchitectureBaseline`) | [CLI use](../../docs/scan/running-scans.md), [contributor checks](../../docs/contributing.md#contributing) |
| `scan/internal/walk/`, `scan/internal/lang/` | File inventory and supported-language detection | [Parsing](../architecture/README.md#3-parsing-and-language-adapters) |
| `scan/internal/pipeline/` | One walk, language-runner selection and concurrency, fixed-order assembly, check/pack attachment, route inventory (`pipeline.Routes`) | [Pipeline](../architecture/README.md#2-pipeline) |
| `scan/internal/parse/` | Language core: inventory and runner selection, `Assemble`, entry finalization, shared claim/completeness/guard engines, spans, model and text sources; core API index (`core_api.go`) | [Parsing and language adapters](../architecture/README.md#3-parsing-and-language-adapters), [package boundary](../architecture/README.md#11-implemented-package-boundaries) |
| `scan/internal/langjs/` | JS/TS adapter (`Run`, `Routes`): Node/Express, Next.js, browser, GraphQL/gRPC, bounded flow, source-backed candidate assembly; the inline-script bridge | [Parsing and language adapters](../architecture/README.md#3-parsing-and-language-adapters) |
| `scan/internal/langpy/` | Python adapter (`Run`, `Routes`) on the `parse` core API | [Python support contract](../specifications/python-support.md) |
| `scan/internal/langphp/` | PHP adapter (`Run`, `Routes`) on the `parse` core API | [Acquisition facts](../architecture/evidence-and-claims.md#transport-neutral-input-and-value-evidence), [graph boundary](../architecture/repository-graph.md) |
| `scan/internal/analysis/` | Shared candidate/report/entry records, facts, provenance and compatibility | [Package boundary](../architecture/README.md#11-implemented-package-boundaries), [claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) |
| `scan/internal/analysispacks/`, `scan/internal/guidelines/` | Embedded contracts, selected guidance, questions and versions | [Selection](../architecture/analysis-packs.md#descriptor-and-selection-contract), [bounds](../architecture/analysis-packs.md#bounds-and-compatibility) |
| `scan/internal/judge/` | Provider requests, decoding, replay, evidence validation and findings classification | [Judge boundary](../architecture/README.md#provider-neutral-judge-boundary), [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates) |
| `scan/internal/report/` | Findings, Review/Protected presentation, JSON/HTML/SARIF and bundles | [Reporting design](../architecture/reporting-and-sarif.md), [HTML design](../architecture/html-reporting.md) |
| `scan/internal/langjs/testdata/`, `scan/internal/langpy/testdata/`, `scan/internal/langphp/testdata/`, `scan/internal/pipeline/testdata/mixed/` | Small JS/TS, Python, PHP and multi-language regression repositories | [Test conventions](../standards/testing.md#2-test-kinds) |
| `fix/`, `probe/` | Top-level landing directories for planned Fix and Endpoint Probe modules | [Module boundaries](../project/implementation-plan.md#product-goals-and-capability-boundaries) |
| `docs/`, `.zazz/`, `.agents/skills/` | Shared user docs + module guides (`docs/scan/`, `docs/fix/`, `docs/probe/`) + `docs/samples/`; internal contracts/design/evaluation; development skills | [Document owners](#documentation-map) |

Each [analyzer](../architecture/README.md#analyzer-terminology) spans the shared engine's activities.
Use the architecture's [evidence validation terminology](../architecture/README.md#evidence-validation)
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

Contributors are encouraged to follow the maintainer's `.bare/` sibling-worktree structure for
consistency. The [setup guide](worktree-setup.md) owns the layout convention and optional Worktrunk
recommendation. Other local layouts can still submit feature-branch PRs, with
contributors responsible for adapting their setup and paths. Agents in the maintained workspace
MUST use the assigned sibling checkout.

Operational references (selection follows the [AGENTS.md loading policy](../../AGENTS.md#start-here)):

| When needed | Reference |
| --- | --- |
| Create, move, remove or repair a worktree; configure the local layout or file copying | [Worktree setup](worktree-setup.md) |
| Use Worktrunk commands or configure its hooks | [Worktrunk cheat sheet](wt-cheat-sheet.md) |
| Run Go checks in a linked VM without a local toolchain | [Linked-computer toolchain](worktree-setup.md#linked-computer-agent-toolchain) |

The [worktree location rules](../../AGENTS.md#worktree-location) always apply: use the assigned
sibling checkout managed by the existing `.bare/`; a stale handoff does not override that assignment.
Related design, documentation, implementation and tests stay there. Native development uses the Go
version in `go.mod` and a C compiler; [contributing](../../docs/contributing.md) owns check commands.

Ignored `.env` files are local to each checkout. Never print credentials or overwrite the user's
local file. For configuration tasks, consult [environment loading](../../docs/scan/getting-started.md#local-environment-file)
and [provider setup](../../docs/scan/decision-models.md#credentials-and-local-environment) as needed.

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
| Configure/run a judge | [Credentials](../../docs/scan/decision-models.md#credentials-and-local-environment), [live scope](../../docs/scan/decision-models.md#scope-a-live-run) | API-specific diagnosis; never load/print secrets |
| Add an analyzer | Assigned contract, [component ownership](../architecture/analysis-packs.md#boundary-and-ownership), matching [analysis guide](../../docs/scan/analysis/README.md) | Exact operand/flow/parser models required by its tests |
| Change evidence or gates | [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [calibration pairs](../../docs/scan/analysis/calibration.md#regression-pairs) | Relevant graph/trace/API sections |
| Change entries/dispatch | [Entry model](../project/common-entry-dispatch.md), [graph design](../architecture/repository-graph.md) | Specific HTTP/browser/GraphQL/gRPC contract |
| Write/refine a spec | [Delivery checklist](../project/implementation-plan.md#complete-delivery-list), [spec index](../specifications/README.md#specification-index), `spec-builder` | Relevant architecture decisions, not all historical contracts |
| Implement/resume | Assigned contract, local run log, [execution verification](agent-execution-discipline.md#verification-discipline), `spec-driven` | Matched standards and focused code |
| Edit docs | [Owners](#documentation-map), [docs hygiene](../standards/docs-hygiene.md), `doc-check` | Relevant implementation/evaluation evidence |

## Documentation map

| Owner | Start at |
| --- | --- |
| Product goals, current status, and roadmap | [Capability boundaries](../project/implementation-plan.md#product-goals-and-capability-boundaries), [complete delivery list](../project/implementation-plan.md#complete-delivery-list), [detection capabilities](../../docs/scan/detection-capabilities.md) |
| Architecture | [Request size and relevance](../architecture/request-size-and-evidence-relevance.md), [Pipeline](../architecture/README.md#2-pipeline), [package map](../architecture/README.md#11-implemented-package-boundaries), [judge boundary](../architecture/README.md#provider-neutral-judge-boundary) |
| Product rules | [Analysis index](../../docs/scan/analysis/README.md), [database rules](../../docs/scan/analysis/database-injection.md), [input rules](../../docs/scan/analysis/input-validation.md), [XSS rules](../../docs/scan/analysis/xss.md) |
| User setup/output | [Code Scan docs](../../docs/scan/README.md), [Setup](../../docs/scan/getting-started.md), [scan options](../../docs/scan/running-scans.md), [interpretation](../../docs/scan/interpreting-results.md), [Fix docs](../../docs/fix/README.md), [Endpoint Probe docs](../../docs/probe/README.md) |
| Contracts and process | [Spec index](../specifications/README.md#specification-index), [execution records](agent-execution-discipline.md#execution-records), [standards index](../standards/index.yaml) |
| Sample evidence | [Pinned apps](../project/vulnerable-sample-apps.md#applications), [sample provenance](../../docs/samples/reference-policy.md) |

## Commands and credentials

`JUDGE_DECISION_MODEL` is one scan-wide model selection; `--judge` explicitly enables requests and
must match its provider. Keys may coexist, but only the selected provider's key goes to the client.
The scanner does not auto-load `.env`. Live calls transmit source and need an explicitly scoped
request count; a key alone is not authorization. No fallback or live Jev testing is assigned.
See [user setup](../../docs/scan/decision-models.md#credentials-and-local-environment).
