# Contributor setup and notes

[Documentation index](README.md) · [User setup](scan/getting-started.md) · [Project introduction](../README.md)

<a id="contributing"></a>

## Development setup

Use Go 1.27.2 or newer, as declared in [go.mod](../go.mod), and a C compiler on `PATH` for the
Tree-sitter bindings. Check `go version` and `cc --version`. On macOS, install the Xcode command-line
tools if needed. Go downloads module dependencies during the first build or test run.

The preferred contributor setup is the project's `.bare/` repository with sibling worktrees. Use
an existing assigned feature checkout. Worktree setup and optional Worktrunk procedures are
[task references below](#branches-worktrees-and-review); consult them when those operations are needed.
From the feature checkout:

```bash
cd <repo-container>/<feature-worktree>
go build -o bin/scan ./scan/cmd/scan
go test ./...
```

The root compatibility entry point `go build -o bin/scan ./cmd/scan` builds the same `scan` binary.

Contributors may use another local layout and submit a feature-branch PR normally. The layout is a
shared working convention, not a PR acceptance requirement; contributors choosing another setup
are responsible for adapting paths and commands. Agents in the maintained workspace MUST use its
assigned sibling worktree and existing `.bare/` repository.

Run commands from the directory containing `go.mod`. Tests use fixtures and local HTTP stubs;
no API key, target-application server, or paid decision-model calls are required. User scans and
private environment configuration are covered in [getting started](scan/getting-started.md) and the
[decision-model guide](scan/decision-models.md). Local credentials live in each worktree's Git-ignored
`.env`; the tracked `.envrc` plus [direnv](https://direnv.net) auto-loads it on `cd` (one
`direnv allow` per worktree) — otherwise `set -a; . ./.env; set +a` in the invoking shell.

## Repository layout

Root retains one Go module (`go.mod` / `go.sum`), `.env.sample`, CI workflows, and shared project
documentation. Scan, Fix, and Probe each own a top-level directory; Go's `internal` package rule
enforces the Scan package boundary under `scan/internal/`.

| Path | Responsibility |
|---|---|
| `scan/cmd/scan/` | Canonical `scan` CLI executable wrapper calling `scan/cli.Run` |
| `cmd/scan/` | Root compatibility `scan` CLI executable wrapper calling `scan/cli.Run` |
| `scan/cli/` | CLI flag parsing, pipeline wiring, request caps, export modes, and CLI/baseline tests |
| `scan/internal/pipeline/` | One walk, language-runner selection, fixed-order assembly, and route inventory |
| `scan/internal/parse/` | Language core shared by the adapters: inventory, assembly, entry finalization, shared claim and guard engines (core API index in `core_api.go`) |
| `scan/internal/langjs/` | JavaScript/TypeScript adapter (Node, Express, Next.js, browser, GraphQL, gRPC) |
| `scan/internal/langpy/` | Python adapter built on the `scan/internal/parse` core API |
| `scan/internal/langphp/` | PHP adapter built on the `scan/internal/parse` core API |
| `scan/internal/analysis/` | Shared evidence, candidate, entry, and report records |
| `scan/internal/analysispacks/` | Embedded interpretation components and API contracts |
| `scan/internal/guidelines/` | Embedded versioned language Analysis Guidelines |
| `scan/internal/judge/` | Provider requests, scheduling, replay, and evidence-based classification |
| `scan/internal/report/` | Findings, HTML, JSON, SARIF, and output bundles |
| `scan/internal/walk/`, `scan/internal/lang/` | Target file inventory and file-extension language registry |
| `scan/internal/lang*/testdata/`, `scan/internal/pipeline/testdata/` | Small source fixtures and regression repositories (multi-language fixtures in `pipeline`) |
| `audit/`, `agent/`, `probe/` | Landing directories for the planned Dependency Audit, Zazzles Agent and Endpoint Probe modules |
| `docs/` | Shared user guides (`README.md`, `contributing.md`, `technical-approach.md`, `philosophy.md`), module docs (`docs/scan/`, `docs/audit/`, `docs/agent/`, `docs/probe/`), and curated sample reports (`docs/samples/`) |
| `.zazz/` | Internal architecture, plans, implementation contracts, and evaluation evidence |

Read the [technical approach](technical-approach.md) for architecture. Load the relevant
[analysis guide](scan/analysis/README.md) before changing scanner evidence or judgment. Keep source
extraction, model assessment, and deterministic evidence validation distinct.

## Verification

CI checks new and edited Markdown lines before the Go format, vet, build, and test steps.
See the [Markdown lint guide](markdown-linting.md) for the local command and the checks it runs.

While developing, run the smallest relevant package or test:

```bash
go test ./scan/internal/judge ./scan/cli -count=1
```

Before submitting, format only changed Go files, then run:

```bash
gofmt -l cmd scan
go vet ./...
go build ./...
go test -race ./... -count=1
```

The format check should print nothing. Use `gofmt -w path/to/changed.go` to format a changed file.
Keep test evidence proportional to the change: source and policy changes need vulnerable,
protected, and unresolved controls. Provider changes use local stubs; do not introduce live calls
into unit tests. Changes to request content must account for exact-replay compatibility.

Check documentation links, commands, formatting, and setup defaults when changing guides. Use the
repository's [doc-check workflow](../.agents/skills/doc-check/SKILL.md). Record the commands and
outcomes in the review description.

## Samples and findings

Treat pinned vulnerable applications as read-only references. Verify revision, local changes, and
source expectations before comparing findings; make repairs in an independent copy. Write routine
scan output outside the target and checkout, for example under `$HOME/zazzles-findings`.

The [sample guide](samples/README.md) explains saved-report provenance and offline presentation
refreshes. The [baseline policy](samples/reference-policy.md) explains hashes and remediation
copies. Model agreement and finding totals do not define the expected source-level result.

## Branches, worktrees, and review

`stage` integrates reviewed changes. `main` is reserved for human-operated releases. Submit a focused
draft pull request targeting `stage`, with the problem, resulting behavior, and verification evidence.
Follow the [PR process](../.zazz/standards/pr-process.md); humans approve and merge.

The maintained workspace uses `.bare/` with direct sibling worktrees, and contributors are encouraged
to follow it for consistency. Reuse the assigned checkout. Nested tool worktrees and external fallback
checkouts are not permitted for agents working in this workspace.

Contributor references for the operation being performed:

- [Worktree setup](../.zazz/docs/worktree-setup.md) for creating, moving, removing or repairing
  worktrees, local layout, file copying and the optional Worktrunk recommendation.
- [Worktrunk cheat sheet](../.zazz/docs/wt-cheat-sheet.md) only when using `wt` or configuring its hooks.
- [Agent orientation](../.zazz/docs/zazzles-agent-orientation.md) for the agent entry point and topic map.

For coding agents, [AGENTS.md](../AGENTS.md#start-here) owns startup and context-loading rules,
including opening the [orientation contents](../.zazz/docs/zazzles-agent-orientation.md#contents)
and selecting sections for the current task. The assigned implementation contract governs the work.
Keep transient execution notes in ignored `.zazz/ephemeral/`; preserve unrelated local changes and
private credentials. The maintained checkout uses the `zazzcode` Git identity and authentication
profile; verify that profile before publishing from it.

## Documentation ownership

The root README introduces the project, modules, and quick start. `scan/`, `audit/`, `agent/`, and
`probe/` hold module landing READMEs. `docs/` owns shared user guides (`README.md`, `contributing.md`,
`technical-approach.md`, `philosophy.md`), module user guides (`docs/scan/`, `docs/audit/`,
`docs/agent/`, `docs/probe/`), and curated sample reports (`docs/samples/`). `.zazz/` owns internal architecture,
project plans, specifications, evaluation records, and process standards. Keep each topic in its
owning guide and link to it rather than repeating a detailed implementation ledger in the README.
