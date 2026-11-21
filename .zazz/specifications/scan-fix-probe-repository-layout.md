# Scan, Fix, and Probe repository layout

- **Status:** Implemented on `update-repository-layout` (pending human review)
- **Project and Deliverable Owner:** Zazzles maintainers
- **Worktree / branch:** `update-repository-layout`
- **Milestone:** Repository organization
- **Review shape:** One draft implementation PR into `stage` with human review and merge
- **Execution tracking:** Local run log at `.zazz/ephemeral/scan-fix-probe-repository-layout-run-log.md`
- **Implementation coordination:** One lead in the assigned worktree and a fresh verifier
- **Drafted:** 2026-11-21

## 0. Capability

Give Scan, Fix, and Probe their own top-level directories and user documentation. Move the
existing scanner into Scan while preserving the current CLI, reports, and sample URLs. Give
Fix and Probe landing pages for their planned capabilities.

## 1. Required reading for the implementor

- Read [AGENTS.md](../../AGENTS.md) and its orientation sections for implementation, testing,
  and documentation. Use the matched `spec-driven` and `doc-check` skills.
- Read the [implementation plan's module boundaries](../project/implementation-plan.md#product-goals-and-capability-boundaries),
  the [implemented package boundaries](../architecture/README.md#11-implemented-package-boundaries),
  and the [architecture compatibility baseline](architecture-phase-0-compatibility-baseline.md).
- Check [the standards index](../standards/index.yaml) against the final paths. Apply the
  [testing standard](../standards/testing.md#9-evidence-expected-on-a-pr) and
  [draft PR process](../standards/pr-process.md#draft-first-human-merge).
- Inspect the [canonical command](../../scan/cmd/scan/main.go), [CLI package](../../scan/cli/main.go),
  [compatibility command](../../cmd/scan/main.go), and
  [architecture baseline test](../../scan/cli/architecture_baseline_test.go), the [setup guide](../../docs/scan/getting-started.md),
  the [contributor guide](../../docs/contributing.md), and the [sample publishing and refresh guide](../../docs/samples/README.md).

## 2. Invariants

- Keep one root Go module, its module path, Go toolchain declaration and dependencies. A clean
  checkout still builds and tests from the repository root.
- Preserve the `scan` binary name, CLI flags and aliases, environment and credential discovery,
  default behavior, exit codes, stdout/stderr semantics, report output paths and formats.
- Preserve analyzer logic, evidence and report schemas, request hashes, replay identity, and
  deterministic results. Keep embedded assets with the packages that use them.
- Preserve the published sample URLs, report content, and the legacy vuln-nextjs scoped report
  redirect. Treat saved sample reports as evidence for their original source revisions.

## 3. Scope

| Area | Target |
|---|---|
| Scan implementation | Move root `internal/` to `scan/internal/`. Move the current CLI implementation and its tests and fixtures to `scan/cli/`. |
| Executable | Add canonical `scan/cmd/scan/`. Keep root `cmd/scan/` as a compatibility entry point. Both call the same `cli.Run` function and propagate its exit result. |
| Other modules | Keep `fix/` and `probe/` as landing directories. Add `docs/fix/README.md` and `docs/probe/README.md` describing their planned scope and linking back to the project. |
| Scan user docs | Add `docs/scan/README.md` and move Scan setup, running scans, models, report interpretation, glossary, CI reporting, weakness coverage, analysis rules, language/framework guides, and the Scan-specific Semgrep comparison guide there. Keep the per-weakness pages and their index together. |
| Shared user docs | Keep the root README, `docs/README.md`, `docs/contributing.md`, `docs/technical-approach.md`, `docs/philosophy.md` and `docs/samples/`. Link from shared pages to the canonical module guides. |
| Integration | Update current path references in code, test fixtures, scripts, CI, GitHub Pages navigation, agent guides, standards, and active project documents as needed. |

Fix implementation, endpoint probing, analyzer changes, dependency upgrades, provider calls,
and migration of published report artifacts to a different URL are outside this deliverable.
Fix planning covers agent skills, standards, and playbooks for findings from Zazzles and
external SAST, audit, and DAST tools. Probe planning covers authorized endpoint checks starting
with TLS and certificates, with remediation guidance.

## 4. Decisions

- Root continues to own `go.mod`, `go.sum`, `.env.sample`, CI, the project README, and shared
  contributor documentation. Go's `internal` import rule establishes the Scan package boundary.
- Put flag handling and orchestration in one CLI package. Each executable wrapper passes its
  arguments and streams to `Run(args []string, stdout, stderr io.Writer) int` and exits with the
  returned code. Keep connection and scanner logic in the moved packages.
- The canonical setup command becomes `go build -o bin/scan ./scan/cmd/scan` from the checkout
  root. Document `go build -o bin/scan ./cmd/scan` as the supported compatibility build.
- Replace moved public Markdown pages with short links to their canonical destinations. Retain
  inbound-link fragment IDs on the old pages when in use, with links to the corresponding
  section. Keep instructions in the canonical pages. Preserve provenance in historical records
  and repair any live links they contain.

## 5. Agent implementation rules

Work in the assigned checkout after the pollution-walk-start deliverable is integrated into
`stage`. Record the actual predecessor SHA and check for intervening path changes. Follow the
repository worktree and branch rules. Capture baseline evidence before moving the tree. Preserve
unrelated edits and report any scope change through the run log and §13.

Keep semantic code edits limited to import rewrites, package boundaries, thin wrappers, and
relocation fixes. Capture unexpected baseline failures first and resolve or surface them before
attributing changes to the migration. Use offline fixtures and existing stubs for verification.
A fresh verifier should reproduce each acceptance check after the lead's checks pass.

## 6. Acceptance criteria

| ID | Required result | Required evidence |
|---|---|---|
| AC1 | Scanner implementation lives under `scan/`. Fix and Probe have independent root landing pages and user docs. Root retains one Go module. All moved packages, tests, fixtures, and embedded files are included. | Before/after file and package inventory, root module diff, and successful `go list ./...`. Verify each remaining root `cmd/scan` file belongs to the compatibility entry point. |
| AC2 | Both build paths produce a working `scan` executable. Their offline behavior matches the predecessor for representative invocations. | Compare stderr, stdout and status for help, a usage error, `--list`, analysis, and export. Check JSON, HTML, and SARIF against baseline for a fixed fixture, with identical cwd and inputs and any output path normalization recorded. |
| AC3 | The architecture baseline passes with the existing expected fixture identities, counts, candidate ordering, judge-request and equivalence hashes, and report/SARIF digests. Existing replay tests pass. | Run `TestArchitectureBaseline` and moved replay tests. Record the baseline file hash before and after. Tests may map relocated repository fixture paths to existing logical IDs. Preserve evidence and expected digests. |
| AC4 | **All tracked documentation is reviewed for the layout change.** Navigation leads to canonical pages and compatibility links resolve. Current instructions, command examples, diagrams, repo links, and anchors use valid paths. | Audit all tracked documentation, including root/module READMEs, `docs/`, `AGENTS.md`, `.zazz/` and `.agents/` guides and active specs, and sample docs. Record the file inventory, checks for links and stale path references, intentional legacy references, and any pre-existing unrelated broken links. |
| AC5 | **Setup and contributor instructions work when followed from a clean checkout root.** Readers can find the Go prerequisite, root `.env.sample`, CLI path, offline usage, repository layout, verification commands, sample refresh instructions, and doc ownership. | Follow the [setup](../../docs/scan/getting-started.md) and [contributor](../../docs/contributing.md) guides literally after the move. Record toolchain, cwd, commands and exit status. Build both commands and generate/open a local fixture report without a provider key. |
| AC6 | The published sample catalog and direct report paths still resolve, including both scopes of the single vuln-nextjs sample and its compatibility redirect. The refresh tooling works with the canonical binary. | Verify the sample index, local asset links and redirect target through the existing publishing layouts. Run an offline sample refresh in scratch output for the two vuln-nextjs scopes using the canonical binary. Preserve tracked reports and metadata byte for byte. |
| AC7 | Root format, vet, build, race tests, CI and whitespace gates still work, and the draft PR contains the migration and its evidence. | Run the verification commands in §7. Check workflow paths and inputs, and attach per-AC results and scope to the draft PR. |

## 7. Test strategy

1. On the predecessor, build `./cmd/scan` and save its offline CLI results and report artifacts
   outside the tracked tree. Run `TestArchitectureBaseline` and record the golden file hash.
   Use the same controlled environment, fixture source and invocation cwd for all comparisons.
   Use exit results and actual emitted bytes as evidence.
2. After relocation, build each command into a separate scratch directory as `scan` and repeat
   the predecessor checks. Preserve stable fixture IDs in `TestArchitectureBaseline` by
   mapping them to physical paths in the test. If a digest includes the test report's root,
   normalize only that repository fixture path to its predecessor spelling for the comparison.
   Keep the golden unchanged and run the existing report replay tests.
3. Enumerate tracked documentation with `git ls-files`. Search for the old Go paths, root doc
   filenames, moved subtrees, and other path dependencies found in the move inventory. Check
   local Markdown and HTML links and anchors using repository tooling where present. Review
   externally published routes and the standard GitHub repository links separately. Inspect
   historic references and the intentional wrapper and compatibility links before declaring a
   stale reference fixed.
4. Reproduce the setup and contributor journeys from the root using their documented toolchain
   and commands. Check Pages sample links under both the repository-root and samples-artifact
   publication layouts. Use a scratch report destination for refresh verification, following
   a scratch copy of the helper and the vuln-nextjs sample directory. Run
   `python3 <scratch>/refresh.py --scan <absolute-path-to-canonical-scan> --sample vuln-nextjs`.
5. From the root run `test -z "$(gofmt -l .)"`, `go vet ./...`, `go build ./...`,
   `go test -race ./...` and `git diff --check`. Include format, vet, build and test results
   and note tooling or unrelated baseline issues separately.

## 8. TDD entry point and execution sequence

1. Run the §7 predecessor checks and capture the file, import and documentation inventories.
2. Run the canonical build smoke check against `./scan/cmd/scan` and confirm the directory is
   missing on the predecessor. Use the actual dual-entrypoint commands as the migration check.
3. Move packages, assets and tests. Extract the command orchestration and add both wrappers.
   Fix path-sensitive fixtures using the test strategy and run parity and replay checks.
4. Move and cross-link the documentation, update CI and active path references, and verify the
   setup and contributor procedures and sample publishing and refresh paths.
5. Complete root verification, review the scope and prepare the single draft PR into `stage`.

## 9. Definition of done

- AC1–AC7 have reproducible, linked or summarized evidence in the run log and PR.
- The setup and contributor walkthroughs succeed from checkout root. The all-docs audit
  records which paths, anchors and command examples were checked and any exceptions.
- The baseline golden and saved reports are identical to the predecessor. Both command paths
  work, and the PR diff contains only the migration and supporting changes.
- A fresh verifier has independently checked the evidence, and the draft PR is ready for
  human review.

## 10. Open questions

None block this deliverable. Retiring the compatibility command or older guide paths, splitting
Go modules, or moving published samples can be considered separately with their own migration plan.

## 11. Run log protocol

Start `.zazz/ephemeral/scan-fix-probe-repository-layout-run-log.md` in the implementation
checkout. Record branch, predecessor SHA, toolchain, scoped files, commands and results,
baseline comparisons, the documentation audit, intentional compatibility paths, and QA
findings. Keep credentials and environment values out of logs. Summarize durable acceptance
evidence in the PR.

## 12. Agent implementation prompt

Read this contract, the required project context, and the implementation run log. Work in the
owner-assigned worktree and confirm the predecessor and review shape. Collect the regression
baseline, implement §3 in the order given in §8, and verify each criterion in §6. Have the fresh
verifier reproduce the acceptance checks and compare the diff to scope. Publish the draft PR
with the results for human review.

## 13. Implementation and review change log

**2026-11-21 — Documentation review added to acceptance.** The owner requested an audit of
all docs after the migration, especially setup and contributor instructions. AC4, AC5, and §7
require the inventory, path and link review, and execution of both documented journeys.
