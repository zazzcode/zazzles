# gopls for coding agents

This guide owns why and how coding agents use [gopls](https://go.dev/gopls/), the Go language
server, in this repository: the benefits, the shared install, and the per-harness setup for Claude
Code and Codex. gopls is optional tooling. [AGENTS.md](../../AGENTS.md#verification) and the
[contributor guide](../../docs/contributing.md#verification) own the required checks.

## Benefits

- **Symbol-accurate navigation.** gopls answers definition, reference, and hover questions from the
  type checker instead of text search. A lookup follows imports across the `scan/cli` and
  `scan/internal/` package boundary, separates identically named symbols in different packages, and
  ignores matches in comments and strings.
- **Complete impact lists before an edit.** A reference lookup returns every use of a symbol,
  including test files, so an agent changing a signature sees all call sites first.
- **Diagnostics without a build.** After an edit gopls reports compile errors, missing imports,
  unused parameters and functions, analyzer findings, and `go.mod` tidiness, before `go build` or
  `go test` runs.
- **Smaller context.** One hover returns a full signature; one definition lookup replaces reading
  several files to find a declaration.

gopls is not a gate. Agents MUST still run the assigned contract's scoped build, vet, test, and
format checks. Agents MUST NOT fix diagnostics outside the task's scope; hint- and info-level
diagnostics in untouched files are not part of the active change.

## Install gopls

Both harnesses start the `gopls` binary from `PATH`. Neither bundles it.

```bash
go install golang.org/x/tools/gopls@latest
gopls version
```

- `go install` writes to `$(go env GOPATH)/bin`. That directory MUST be on the `PATH` of the shell
  or app that starts the agent.
- The Codex setup needs gopls v0.20 or newer, the first release with the MCP server.
- Reinstall gopls after raising the `go` line in `go.mod`. A gopls built with an older Go toolchain
  may fail to load the module.

## Claude Code

Claude Code connects to gopls through the Language Server Protocol with the `gopls-lsp` plugin from
Anthropic's official marketplace. Anthropic's
[code intelligence guide](https://code.claude.com/docs/en/plugins/code-intelligence) owns the
install flow and troubleshooting.

1. Install gopls as above.
2. Install the plugin. In a terminal session enter
   `/plugin install gopls-lsp@claude-plugins-official`. In the desktop app or the VS Code
   extension, install `gopls-lsp` from the app's plugin screen.
3. Start a new session in the assigned worktree.

The plugin provides two things:

- An `LSP` tool for read-only lookups: definition, references, hover, document and workspace
  symbols, implementations, and call hierarchy. The tool may be deferred; load it before the first
  call.
- Diagnostics pushed into the conversation after Claude edits or opens a Go file. The `LSP` tool
  has no operation that requests diagnostics for a named file, so the absence of a file from a
  pushed batch is not an explicit clean result.

Cloud sessions do not start plugin language servers. A session there has no `LSP` tool and no
pushed diagnostics; use `go build` and `go vet` instead.

To verify, ask Claude to use the `LSP` tool to go to the definition of
`langjs.NewDiscoveryVerifier` from `scan/cli/discovery.go`. It MUST resolve to
`scan/internal/langjs/discovery_verify.go`. If the tool is missing, run `/plugin` and read the
**Errors** tab; `Executable not found in $PATH: "gopls"` means the `PATH` rule above is not met.

## Codex

Codex has no documented language-server client. It reaches gopls through the experimental
[gopls MCP server](https://go.dev/gopls/features/mcp), started with `gopls mcp`. OpenAI's
[MCP guide](https://developers.openai.com/codex/mcp) owns the Codex configuration format.

Register the server once per user, either with the CLI:

```bash
codex mcp add gopls -- gopls mcp
```

or in `~/.codex/config.toml`, which the Codex CLI, IDE extension, and ChatGPT desktop app share:

```toml
[mcp_servers.gopls]
command = "gopls"
args = ["mcp"]
```

- Keep this in user configuration. A project-scoped `.codex/config.toml` MUST NOT be committed to
  this repository without an owner decision.
- If the desktop app cannot find `gopls`, set `command` to the absolute path that
  `command -v gopls` prints. Machine-specific paths belong in user configuration only.
- `gopls mcp` uses the directory Codex starts it in as the workspace. Start Codex in the assigned
  worktree and do not set a fixed `cwd`.
- The server runs detached: it sees files saved on disk, not unsaved editor buffers.

The `gopls` MCP server in gopls v0.24 exposes these tools. The server is experimental, so confirm
the current names with `/mcp` in a Codex session.

| Tool | Use |
| --- | --- |
| `go_workspace` | Summarize the module and workspace layout |
| `go_search` | Fuzzy symbol search across the workspace |
| `go_file_context` | Summarize a file's dependencies on other files in its package |
| `go_package_api` | Summarize a package's exported API |
| `go_symbol_references` | List references to a package-level symbol before changing it |
| `go_diagnostics` | Report build and analysis errors for named files or the workspace |
| `go_rename_symbol` | Rename a symbol across the workspace |
| `go_vulncheck` | Check dependencies against the Go vulnerability database (network call) |

After each Go edit, call the `go_diagnostics` tool exposed by the `gopls` MCP server with the
edited file paths. If the tool is unavailable, run `go build` and `go vet` on the changed packages.

`gopls mcp -instructions` prints gopls's own workflow text. Agents MUST NOT load it as standing
instructions: it directs a `go_vulncheck` run at every session start, and this repository's rules
in [AGENTS.md](../../AGENTS.md) take precedence. Run `go_vulncheck` only when a task adds or
updates a dependency. To switch it off, add `disabled_tools = ["go_vulncheck"]` to the
`[mcp_servers.gopls]` table.

To verify, run `codex mcp list` and confirm `gopls` is listed, then ask Codex to call
`go_symbol_references` for `VerifyDiscovery` in `scan/internal/langjs/discovery_verify.go`. The
result MUST include the call sites in `scan/internal/langjs/node_discovery_test.go`.

## Choosing one integration

Claude Code can also register the MCP server with `claude mcp add gopls -- gopls mcp`. Use the
`gopls-lsp` plugin instead: it pushes diagnostics without a tool call. Do not enable both in the
same Claude Code session; two gopls processes would index the same worktree.
