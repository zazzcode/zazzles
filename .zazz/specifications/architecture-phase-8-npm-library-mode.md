# Architecture phase 8 — npm library mode with existing analyzers

**Worktree / branch:** `npm-library-mode`
**Plan:** [architecture update plan](architecture-update-plan.md), phase 8. Objective: new feature on the foundation
**Depends on:** phase 2 merged (`internal/pipeline`), phase 7 merged (corpus pins and answer keys)
**Delivery topology:** one deliverable, one branch, one draft PR into `stage`
**Coordination:** Lead Agent. One Contributor Agent may own the `package.json` export resolver and its tests
**Run log:** `.zazz/ephemeral/architecture-phase-8-npm-library-mode-run-log.md`
**Product scope source:** container-root `3-npm-library-rce-mvp-proposal.md`, "Phase 1: Library mode
with existing analyzers", "Source and entry points", "Result model", and "Candidate policy". The
parameter-trust judge question and the feasibility consumer are deferred (plan "Explicitly later").
**Drafted:** 2026-11-17

## 1. Capability

`scan --analyze --library <repo>` scans one JS/TS npm package at a pinned commit, without
installing or running it.

- **Entries.** `package.json` `exports`, `main`, `module`, and `bin` resolve through CommonJS and
  ESM re-exports to defining functions. Each one becomes a `library_export` entry.
- **Inputs.** Each parameter becomes a caller-argument input.
- **Analyzers.** The existing command, argument-injection, and code-injection analyzers run unchanged.
- **Results.** A source-established path with no protection evidence is a **conditional weakness**.
  Missing evidence is Review, and full control coverage is Protected. Library mode is never Confirmed.

Application scans are byte-identical. In library mode the judge is disabled until a library
question contract exists.

## 2. Required reading

- The proposal sections named in the header, plus the phase 7 corpus and answer keys.
- [Phase 2 spec](architecture-phase-2-pipeline-runners.md) (pipeline and runner seam), and phase 1 D-7 (mechanism table).
- [Entry/dispatch decision](../architecture/README.md#multiple-entry-and-dispatch-mechanisms),
  [acquisition and value facts](../architecture/README.md#acquisition-and-value-facts).
- Code: `internal/parse/modules.go` and `commonjs.go` (current import and export resolution and
  its stated re-export limits), `command_claims.go`, `code_*`, `internal/report` classification.
- [Reporting design](../architecture/reporting-and-sarif.md), [interpreting results](../../docs/interpreting-results.md).

## 3. Invariants

- `TestArchitectureBaseline` is unchanged. Without `--library`, nothing in this phase runs.
- Library mode is JS/TS only. Python and PHP runners are not run.
- An unresolvable export (computed `module.exports[x]`, native addon, missing file) is an entry with
  `resolution=unresolved` and a gap. It is not dropped.
- Caller arguments are not assumed attacker-controlled. Every parameter's trust class is recorded
  as `undetermined`, and candidates are kept rather than dropped (recall-leaning, per the proposal).
- `--library` combined with `--judge` is a usage error in this phase.
- No candidate is labeled Confirmed in library mode.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `internal/parse/library_exports.go`, `library_exports_test.go` | new | `package.json` entry fields, conditional `exports` maps (`import`/`require`/`default`, subpaths), re-export following (`export * from`, `export {x} from`, `module.exports = require(…)`, `exports.x = …`), preferring `.ts` source over emitted `.js` when `types`/`source` point to it |
| `internal/parse/library_entries.go` | new | `library_export` entries, registrations (mechanism `export_binding`), dispatch, caller-argument inputs |
| `internal/parse/testdata/library/<case>/` | new | Synthetic packages (§8) |
| `internal/analysis/entries.go`, `entry_validation.go`, `entry_graph.go` | modified | `LibraryEntryMetadata{Package, Version, Export, Condition}`; input origin kind `caller_argument`; mechanism table entry |
| `internal/pipeline/pipeline.go` | modified | `Options.Library`: JS/TS runner only, library entry discovery |
| `internal/report/*` | modified | `conditional_weakness` presentation in JSON, HTML, and SARIF (SARIF level `warning`) for library entries only |
| `cmd/scan/main.go`, `analysis.go`, tests | modified | `--library` flag; `--judge` conflict |
| `docs/running-scans.md`, `docs/interpreting-results.md`, `docs/detection-capabilities.md`, `.zazz/project/implementation-plan.md` | modified | Library mode usage, result meanings, limits |
| `.zazz/evaluation/npm-library-rce/library-mode-results.md` | new | Corpus results against phase 7 keys and baseline |

Out of scope (proposal phases 2–3 and later): compile-to-JS, deserialization-to-code and
dynamic-load sinks; the prototype pollution pack; the trust judge question; the feasibility
consumer; cross-package chains; bundled or minified follow-through; paid calls.

Review shape: one PR.

## 5. Decisions

- **D-1 Library mode is a pipeline option with its own entry producer.** It is not a fork of the
  report model. It reuses the analyzers and claims, and adds an entry kind, an input origin, and
  one presentation status.
- **D-2 Re-export following is bounded.** It covers literal specifiers only, with a depth cap of 8
  recorded as a gap when reached, and cycles detected by visited `(file, export name)`. Today's
  limitation text says re-exports "remain uncertain" in application mode. That text is unchanged,
  because this resolver is used only in library mode.
- **D-3 Conditional weakness is deterministic.** A use is a conditional weakness when its claim's
  required evidence is complete, its source is a caller argument, and it has no protection evidence.
  Missing required evidence makes it Review. This needs no judge, so the phase stays offline and
  measurable against phase 7.
- **D-4 The judge is off in library mode.** Existing questions presume request-origin inputs.
  Sending caller-argument evidence through them would yield answers to a question that was never
  asked. A library question contract comes later.
- **D-5 Entry identity.** The instance is `npm:<package>@<version>`. The entry ID uses the defining
  function's evidence plus the export path and condition. Two export paths reaching one function
  are two entries sharing one callable.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- Any application-mode golden change.
- Corpus checkouts are missing or at the wrong pin (phase 7 `corpus.json`).
- A needed analyzer change would alter application-mode evidence.

## 7. Acceptance criteria

1. **AC1 Exports.** Synthetic packages cover:
   - CJS `module.exports = fn`;
   - `exports.a = …`;
   - ESM `export function`;
   - `export * from`;
   - a conditional `exports` map with `import` and `require`;
   - a subpath export;
   - a `bin`;
   - a computed export (unresolved with a gap);
   - an `export *` cycle (terminates with a gap).

   Each yields the expected `library_export` entries with `export_binding`/`static` classification
   and the right resolution.
2. **AC2 Inputs.** Each exported function's parameters appear as `caller_argument` inputs with
   trust `undetermined`, including destructured object parameters with projections.
3. **AC3 Results.** On synthetic pairs, `exec(cmd)` from a parameter is a conditional weakness.
   The same call behind an allow-list guard is Protected or Review with the guard evidence, never a
   conditional weakness. An unresolved helper is Review.
4. **AC4 Corpus.** `simple-git` is fixed only if phase 7 confirms its path lies within the existing
   command and argument analyzer. In that case:
   - its vulnerable pin yields a conditional weakness or Review at the answer-key anchor;
   - its fixed pin yields neither at that anchor without protection evidence.

   `node-serialize`'s `eval` path is handled the same way if the existing code analyzer covers it.
   Corpus rows needing later sinks are listed as "out of phase", not as misses.
5. **AC5 Isolation.** `TestArchitectureBaseline` is unchanged, and `--library --judge` exits with a usage error.
6. **AC6 Outputs.** JSON, HTML, and SARIF show `conditional_weakness` for library entries only.
   SARIF uses level `warning`. Docs explain the meaning and the non-Confirmed rule.
7. **AC7 Results record.** `library-mode-results.md` compares against the phase 7 baseline:
   per-row outcome, recall on in-phase rows, Review burden, and candidates per library. Gaps are
   named. The contributor gate passes.

## 8. Test strategy

- `library_exports_test.go`: an AC1 table over `testdata/library/exports-*`.
- One pipeline test for AC2 and AC3 over `testdata/library/sinks-*` pairs.
- CLI tests for AC5 and AC6 beside the existing `cmd/scan` tests.
- Corpus checks (AC4) are recorded runs against pinned checkouts. They are not committed tests,
  because the checkouts live outside the repository.

## 9. TDD entry point and execution sequence

1. **Red:** the AC1 export-resolution table.
2. Export resolver:

```go
type libraryPackage struct{ name, version, root string; manifest analysis.Evidence }
type libraryExport struct {
	path, condition string         // "./sub", "import" | "require" | "default" | "bin:<name>"
	target          *analysis.Evidence // defining function, nil when unresolved
	gaps            []analysis.Gap
}
func readLibraryPackage(inv Inventory) (*libraryPackage, error)
func (s *moduleSet) resolveExports(p *libraryPackage) []libraryExport // bounded per D-2
```

3. Entries, inputs, and the mechanism table (AC2).
4. Report status, pipeline option, and CLI flag (AC3, AC5, AC6).
5. Corpus runs, the results record, docs, gate, draft PR.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC7 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] The PR states the deferred items (trust question, feasibility, later sinks).

## 11. Open questions

None blocking. If phase 7 shows that no corpus row is reachable with the existing analyzers, AC4
uses synthetic pairs only, and the owner is told before the PR.

## 12. Run log protocol

Use the plan's common rules. Record the corpus pins checked, the per-row outcomes, and the out-of-phase list.

## 13. Agent implementation prompt

> Work in the `npm-library-mode` sibling worktree, cut from `origin/stage` after phases 2 and 7
> merged. Read AGENTS.md, the orientation contents, the [plan](architecture-update-plan.md), this
> spec, the phase 7 corpus and keys, and the container-root npm proposal sections it names. Follow
> the plan's session start and common rules. Execute §9 TDD-first. You may delegate the export
> resolver (§9 step 2) to one Contributor Agent that owns those files. Make no paid calls. Finish
> with a draft PR into `stage` listing AC1–AC7 evidence. Verifier: a fresh-context subagent confirms
> `TestArchitectureBaseline` is unchanged, runs the library tests, and checks that no library result
> can be Confirmed and that `--library --judge` is refused. It reports PASS or FAIL.

## 14. Implementation and review change log

No changes recorded.
