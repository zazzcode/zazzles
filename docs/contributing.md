# Contributor setup and notes

[Documentation index](README.md) · [User setup](getting-started.md) · [Project introduction](../README.md)

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
go build -o bin/scan ./cmd/scan
go test ./...
```

Contributors may use another local layout and submit a feature-branch PR normally. The layout is a
shared working convention, not a PR acceptance requirement; contributors choosing another setup
are responsible for adapting paths and commands. Agents in the maintained workspace MUST use its
assigned sibling worktree and existing `.bare/` repository.

Run commands from the directory containing `go.mod`. Tests use fixtures and local HTTP stubs;
no API key, target-application server, or paid decision-model calls are required. User scans and
private environment configuration are covered in [getting started](getting-started.md) and the
[decision-model guide](decision-models.md).

## Repository layout

| Path | Responsibility |
|---|---|
| `cmd/scan/` | CLI arguments, configuration, output wiring, and exit codes |
| `internal/parse/` | Supported-language parsing, entry discovery, flow and evidence assembly |
| `internal/analysis/` | Shared evidence, candidate, entry, and report records |
| `internal/analysispacks/` | Embedded interpretation components and API contracts |
| `internal/judge/` | Provider requests, scheduling, replay, and evidence-based classification |
| `internal/report/` | Findings, HTML, JSON, SARIF, and output bundles |
| `internal/parse/testdata/` | Small source fixtures and regression repositories |
| `docs/` | User guides, analysis rules, contributor notes, and curated sample reports |
| `.zazz/` | Internal architecture, plans, implementation contracts, and evaluation evidence |

Read the [technical approach](technical-approach.md) for architecture. Load the relevant
[analysis guide](analysis/README.md) before changing scanner evidence or judgment. Keep source
extraction, model assessment, and deterministic evidence validation distinct.

## Verification

While developing, run the smallest relevant package or test:

```bash
go test ./internal/judge ./cmd/scan -count=1
```

Before submitting, format only changed Go files, then run:

```bash
gofmt -l cmd internal
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

The root README introduces the project and the user workflow. `docs/` owns setup, CLI use,
interpretation, analysis rules, and contributor guidance. `.zazz/` owns internal architecture,
project plans, specifications, evaluation records, and process standards. Keep each topic in its
owning guide and link to it rather than repeating a detailed implementation ledger in the README.
