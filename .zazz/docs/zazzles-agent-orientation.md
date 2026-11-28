# zazzles — agent orientation

Routing map for code layout, local workspace paths, sample checkouts, and document owners.
Startup policy, worktree rules, branch rules, and credential/live-call rules live in
[AGENTS.md](../../AGENTS.md#start-here) and are not repeated here. Current delivery status and
capabilities live in the [implementation plan](../project/implementation-plan.md) and
[detection capabilities](../../docs/scan/detection-capabilities.md).

<a id="current-work"></a>

## Contents

| Section | Consult for |
| --- | --- |
| [Code structure](#code-structure) | Top-level module layout (`scan/`, `audit/`, `agent/`, `probe/`) and links to package maps |
| [Portable workspace and DEV_ROOT](#portable-workspace-and-dev_root) | Resolving local checkout and sample paths |
| [Branches and worktrees](#branches-and-worktrees) | Worktree operational guides and `_test-findings/` output location |
| [Working protocol](#working-protocol) | Pointers to execution, verification, and PR guides |
| [Available vulnerable sample apps](#available-vulnerable-sample-apps) | Local checkout paths under `<DEV_ROOT>` and read-only handling rules |
| [Task reading paths](#task-reading-paths) | Focused starting sections for scanner engineering tasks |
| [Documentation map](#documentation-map) | Single owning document for each topic |

## Code structure

Zazzles is organized into four top-level module directories — **Code Scan** (`scan/`),
**Dependency Audit** (`audit/`, planned), **Zazzles Agent** (`agent/`, planned), and **Endpoint
Probe** (`probe/`) — under one root Go module (`go.mod` / `go.sum`). This
keeps dependency management, root builds, CI, and shared docs unified while giving each module its
own top-level home and enforcing the Code Scan package boundary with Go's `scan/internal/` rule.
The canonical CLI builds from `scan/cmd/scan/`, root `cmd/scan/` remains a thin compatibility
entry point, and both delegate to `scan/cli.Run`. User docs mirror the modules under `docs/scan/`,
`docs/audit/`, `docs/agent/`, and `docs/probe/`, with shared guides and sample reports in root `docs/`.

Package-level responsibilities and rules live in their owning docs:

- [Implemented package boundaries](../architecture/README.md#11-implemented-package-boundaries) —
  authoritative Go package map, analyzer terminology, and evidence validation model.
- [Contributor repository layout](../../docs/contributing.md#repository-layout) — directory map and
  build/test/format commands.
- [Code structure standard](../standards/code-structure.md#1-package-layout) — package rules and
  splitting thresholds.

## Portable workspace and DEV_ROOT

`<DEV_ROOT>` means the computer's development directory (usually `~/Dev`), not an environment
variable. Resolve it each session; tracked docs and config must never hardcode a developer's home
directory. The usual repository container is `<DEV_ROOT>/zazzcode/zazzles`; sample checkouts live
under `<DEV_ROOT>` or `<DEV_ROOT>/zazzcode/`.

## Branches and worktrees

Worktree location rules and branch policy live in [AGENTS.md](../../AGENTS.md#worktree-location).
Routine scan output goes outside every worktree to `<DEV_ROOT>/zazzcode/zazzles/_test-findings/`.
Load operational guides only when needed:

- [Worktree setup](worktree-setup.md) — `.bare/` sibling-worktree layout, creation, repair, and
  [linked-computer toolchain](worktree-setup.md#linked-computer-agent-toolchain).
- [Using gh-stack](using-gh-stack.md) and the [gh-stack skill](../../.agents/skills/gh-stack/SKILL.md) —
  optional reading when the specification assigns multiple dependent PRs to one worktree. The
  bottom PR targets `stage` and every higher PR targets its immediate parent.
- [Worktrunk cheat sheet](wt-cheat-sheet.md) — only when using `wt` or configuring its hooks.
- [Getting started](../../docs/scan/getting-started.md#local-environment-file) &
  [decision models](../../docs/scan/decision-models.md#credentials-and-local-environment) — local
  `.env`, `direnv`, and provider configuration.

## Working protocol

Follow the owning process guides rather than duplicating steps here:

- [Execution discipline](agent-execution-discipline.md) — scope checks,
  [verification discipline](agent-execution-discipline.md#verification-discipline), and
  [execution records](agent-execution-discipline.md#execution-records) in ignored `.zazz/ephemeral/`.
- [Standards index](../standards/index.yaml) & [contributor checks](../../docs/contributing.md#verification) —
  matched engineering standards and required Go gates.
- [PR process](../standards/pr-process.md) — bracketed scope labels and draft-first PRs into `stage`.

## Available vulnerable sample apps

The [vulnerable sample apps catalog](../project/vulnerable-sample-apps.md#applications) owns pinned
revisions, stacks, and expected findings (with older Python targets under
[other evaluated apps](../project/vulnerable-sample-apps.md#other-evaluated-applications) and PHP
DVWA under [PHP evaluation](../evaluation/php-support-results.md)).

Expected local checkout paths under `<DEV_ROOT>` (verify existence, clean
`git status --porcelain --ignored`, and pinned `HEAD` before and after scanning):

- Under `<DEV_ROOT>/zazzcode/`: `vuln-nextjs` (owner-maintained Next.js lab; full app + prototype
  pollution fixtures), `DVWA` (PHP), `vuln-symfony` (PHP), `vuln-drupal` (PHP)
- Under `<DEV_ROOT>/`: `oss-oopssec-store`, `juice-shop`, `nodejs-goof`, `vuln-demo-app`,
  `vulnerable-typescript-app`, `vulnpy`, `ThreatByte`, `python-insecure-app`, `vulnerable-flask-app`

Sample apps are read-only: never edit, format, install dependencies, or write output inside them.
Write scan output to `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<app>/run-<id>/` via
`--output-dir`. Repairs belong in [independent copies](../../docs/samples/reference-policy.md#remediate-a-copy).

## Task reading paths

For general startup, worktree, spec, and PR tasks, see the
[AGENTS.md task table](../../AGENTS.md#load-context-by-task). For Code Scan engineering tasks:

| Task | Start here | Expand only for |
| --- | --- | --- |
| Configure/run a judge | [Credentials](../../docs/scan/decision-models.md#credentials-and-local-environment), [live scope](../../docs/scan/decision-models.md#scope-a-live-run) | API-specific diagnosis; never print secrets |
| Add an analyzer | Assigned contract, [component ownership](../architecture/analysis-packs.md#boundary-and-ownership), matching [analysis guide](../../docs/scan/analysis/README.md) | Exact operand/flow/parser models required by its tests |
| Change evidence or gates | [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [calibration pairs](../../docs/scan/analysis/calibration.md#regression-pairs) | Relevant graph/trace/API sections |
| Change entries/dispatch | [Entry model](../project/common-entry-dispatch.md), [graph design](../architecture/repository-graph.md) | Specific HTTP/browser/GraphQL/gRPC contract |

## Documentation map

| Topic | Owning document |
| --- | --- |
| Product goals, status, and roadmap | [Implementation plan](../project/implementation-plan.md), [detection capabilities](../../docs/scan/detection-capabilities.md) |
| Architecture & package map | [Architecture README](../architecture/README.md), [request size and relevance](../architecture/request-size-and-evidence-relevance.md) |
| Product analysis rules | [Analysis rules index](../../docs/scan/analysis/README.md) |
| Symfony analysis | [User guide](../../docs/scan/symfony-support.md), [implementation contract](../specifications/scan/php-symfony-support.md), [application-security lane](../specifications/scan/symfony-more-analyzers.md), [configuration design](../architecture/configuration-analysis.md), [evaluation results](../evaluation/symfony-results.md) |
| User docs by module | [User docs index](../../docs/README.md): [Code Scan](../../docs/scan/README.md), [Dependency Audit](../../docs/audit/README.md), [Zazzles Agent](../../docs/agent/README.md), [Endpoint Probe](../../docs/probe/README.md) |
| Contracts, standards, and process | [Spec index](../specifications/README.md#specification-index), [standards index](../standards/index.yaml), [execution discipline](agent-execution-discipline.md) |
| Learnings from research and experiments | [Learnings index](../learnings/README.md), by topic; start with a topic's `README.md` |
| Go language-server tooling for agents | [gopls setup](gopls-setup.md) |
| Sample pins and published reports | [Sample catalog](../project/vulnerable-sample-apps.md#applications), [published samples](../../docs/samples/README.md), [reference policy](../../docs/samples/reference-policy.md) |
