# Phase 0 — Skeleton, fixture access, CI

Historical foundation specification. The revised
[implementation plan](../../../project/implementation-plan.md) treats Phase 0 as an audit of existing
bootstrap artifacts before further work. This contract is retained as historical context; it does not
approve implementation of the concept-stage architecture or assert scanner completion.

## Contract

Stand up the Go module, the minimum real package structure, and a quality gate — enough to prove the
toolchain, the fixture layout, and the repository shape before any analysis exists.

## In scope

- `go.mod` for `github.com/zazzcode/zazzles`.
- `internal/lang`: the extension-to-language registry. The only place that knows about file extensions.
- `internal/walk`: deterministic repository traversal selecting supported source files, skipping
  dependency and build directories, and reporting what it skipped.
- `cmd/scan`: `scan --list [--json] <path>` printing a file and language manifest, with stable exit
  codes.
- `.github/workflows/ci.yml`: format gate, `go vet`, `go build`, `go test -race`.

## Out of scope

- Any parsing, Tree-sitter integration, or graph construction.
- Any rule, path tracking, or model call.
- Fixture vendoring. The two TypeScript fixtures are not yet wired in; `--list` takes an arbitrary path,
  and the tests build their own temporary trees so the suite does not depend on them.
- A public API. Everything lives under `internal/`.

## Acceptance criteria

- `scan --list <path>` reports the root, the number of files examined, the number supported and
  unsupported, a per-language count, and the sorted list of supported file paths.
- `scan --list --json <path>` emits the same information as JSON with stable field names.
- Unsupported files are counted, never listed as source files, and never silently dropped.
- Directories that were not descended into are reported.
- Output ordering is deterministic and independent of filesystem enumeration order.
- Exit codes: `0` success, `1` error, `2` usage.
- `gofmt -l .` prints nothing, `go vet ./...` is clean, and `go test -race ./...` passes.

## Test plan

- `internal/lang`: table-driven extension detection, including uppercase extensions and unsupported
  names.
- `internal/walk`: selection and counting, skip-directory reporting, extra skip directories, repeated-run
  determinism, and a missing root.
- `cmd/scan`: text and JSON manifest output, the four usage-error paths, and a missing target path.

## Halt conditions

Stop and ask if: the fixture repositories need to be modified to be scanned; a supported file must be
skipped to make a test pass; or the manifest shape needs to change to accommodate a downstream phase.
