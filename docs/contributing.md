# Contributor setup and notes

[Documentation index](README.md) · [User setup](getting-started.md) · [Project introduction](../README.md)

<a id="contributing"></a>

## Development setup

Use Go 1.27.2 or newer, as declared in [go.mod](../go.mod), and a C compiler on `PATH` for the
Tree-sitter bindings. Check `go version` and `cc --version`. On macOS, install the Xcode command-line
tools if needed. Go downloads module dependencies during the first build or test run.

For an ordinary contribution, clone the current development branch and create a feature branch:

```bash
git clone --branch stage https://github.com/zazzcode/zazzles.git
cd zazzles
git switch -c your-feature
go build -o bin/scan ./cmd/scan
go test ./...
```

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

The maintained development workspace uses a bare repository with sibling worktrees. Contributors
using that layout should follow the [worktree setup guide](../.zazz/docs/worktree-setup.md), verify
`pwd` and `git status --short --branch`, and work in the assigned feature checkout. An ordinary
clone does not need conversion merely to build or contribute.

Coding agents must read [AGENTS.md](../AGENTS.md), the
[orientation](../.zazz/docs/zazzles-agent-orientation.md), and the assigned implementation contract.
Keep transient execution notes in ignored `.zazz/ephemeral/`; preserve unrelated local changes and
private credentials. The maintained checkout uses the `zazzcode` Git identity and authentication
profile; verify that profile before publishing from it.

## Documentation ownership

The root README introduces the project and the user workflow. `docs/` owns setup, CLI use,
interpretation, analysis rules, and contributor guidance. `.zazz/` owns internal architecture,
project plans, specifications, evaluation records, and process standards. Keep each topic in its
owning guide and link to it rather than repeating a detailed implementation ledger in the README.
