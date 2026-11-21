# Code Structure

Structure rules for authored Go source and for the durable documents and skills in this repo. Applies
to `cmd/`, `scan/`, `.zazz/`, and `.agents/skills/`.

## 1. Package layout

The [architecture package map](../architecture/README.md#11-implemented-package-boundaries) owns package
responsibilities; new boundaries are finalized in greenlit specs. The map is not an instruction to
scaffold packages. Keep the canonical CLI entrypoint under `scan/cmd/scan` (with the thin root
compatibility wrapper at `cmd/scan`), shared CLI orchestration in `scan/cli`, and Scan
implementation under `scan/internal/`.

Rules:

- Everything lives under `scan/internal/` (or a future module's `internal/`) until there is a
  demonstrated external consumer. Do not create `pkg/` speculatively.
- `scan/cmd/` and `cmd/` packages contain only thin `main` wrappers calling `scan/cli.Run`.
  `scan/cli/` owns argument handling, dependency wiring, and exit codes; analysis logic belongs
  in `scan/internal/`.
- A package owns one concern. If describing a package needs the word "and", split it.
- Shared analysis records and provenance MUST live in `scan/internal/analysis`, independent of
  Tree-sitter and HTTP. `parse` is the language core shared by the `scan/internal/lang*` adapters
  (code at least two adapters, `Assemble` or `pipeline` use; code one language uses lives in
  that language's package); the adapters own bounded flow/evidence assembly; `judge` owns
  model transport and claim gates. `walk` MUST remain independent of those stages. Future
  IR/graph/flow packages require actual consumers and a scoped contract.
- Import cycles are a design error. Fix the boundary rather than hiding it behind an interface.
- Interfaces are declared by the consumer, not the producer, and stay small — one or two methods.
  Define an interface when there is a second real implementation (for example, a stubbed semantic adapter in
  tests), not in anticipation of one.

## 2. File size thresholds

Thresholds are guidance for when to act, not hard limits:

- **Go source file:** 400 lines is comfortable; 700 lines means split now.
- **Single function:** 60 lines is comfortable; 100 lines means extract.
- **Document (`docs/`, `standards/`, `specifications/`):** 300 lines is comfortable; 500 lines means
  split by concern.
- **`SKILL.md`:** keep the always-loaded body under 200 lines; push detail into `references/`.

A file that exceeds a threshold for a real reason (a generated table, a golden fixture) is fine — say
so in a comment so the next reader does not try to split it.

## 3. Contextual splitting

Split by **concern**, not by line count. A split is good when each resulting file can be read and
understood on its own:

- one pipeline stage per file group inside `scan/internal/langjs`, `scan/internal/judge`, and so on
- one standard per concern in `.zazz/standards/`
- one deliverable per specification directory in `.zazz/specifications/`

Do not create `part1.go` / `part2.go`. Do not split a cohesive type across files just to hit a number.
Prefer moving a function to the package that actually owns its concern over splitting within a file.

## 4. Anti-slop rules

- No dead code, no commented-out blocks, no unused exported symbols "for later".
- No speculative abstraction: no interface, option struct, or generic type without a present caller.
- No duplicated logic. If two rules or two stages need the same walk, extract it once.
- No placeholder files. A file that exists but does nothing is worse than no file.
- Every exported identifier in `scan/internal/` is exported only because another package in the same
  module needs it. `scan/internal/` is not a public API.

## 5. Compute once

Parsing and graph construction dominate runtime; do not redo either.

- Parse each file exactly once per run. Cache the syntax tree for the lifetime of the file's job, and
  the extracted nodes/edges after that.
- Build relation indexes once for an analysis snapshot and reuse them across source queries.
- Retain a shared source snapshot or bounded source store for snippet extraction; do not duplicate
  full snippets on every graph node or re-read changed files against stale spans.
- Treat the compiled query set per language as process-wide state, compiled at registration.
- Reuse derived facts under complete dependency/context keys. Keep context-dependent guard and flow
  state per analysis; do not store a global safe/reachable bit on a shared node.

## 6. Determinism

Graph output must be reproducible for identical input, independent of goroutine scheduling:

- never iterate a Go map when producing ordered output — sort keys explicitly first
- never let worker completion order determine slice order; sort or index by a stable key
- no wall-clock time, random seed, or host-specific value in graph or findings output
- when parallelism is added to a stage, assert the same output as the sequential version in a test

Determinism is a correctness requirement here, not a nicety: semantic evidence bundles and the JSON report both
depend on a stable graph.

## 7. Comment and naming discipline

- Exported identifiers get doc comments starting with the identifier name.
- Comments explain *why*, not *what*. A comment restating the code is noise.
- Do not cite specifications, task IDs, or PR numbers in source comments — those live in the
  specification and the PR, not in code that outlives them.
