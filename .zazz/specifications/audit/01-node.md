# Dependency Audit 01: npm and pnpm — Deliverable Specification

**Worktree / branch:** `audit-mvp` (a sibling worktree cut from `stage` after the documentation PR that adds this specification merges)
**Feature:** Dependency Audit (`audit/`)
**Milestone:** [Dependency Audit series](README.md), specification 01 of 5
**Deliverable:** The `audit` command for npm and pnpm projects, its findings file and its HTML report
**Project Owner:** zazzles owner
**Deliverable Owner:** zazzles owner
**Delivery topology:** single-deliverable branch
**Review artifact:** one draft PR into `stage`
**Approved review shape:** one PR
**Decomposition rationale:** npm and pnpm share the run, model and report code, so splitting them
would review the same code twice. Python and PHP are separate specifications because they need
tools not installed here; advisory enrichment is separate because it adds the network.
**Integration branch:** `stage`
**Merge policy:** PR review required — agents commit/push feature branches only
**Drafted:** 2026-11-28
**Shared run log:** `.zazz/ephemeral/dependency-audit-run-log.md` (section `01 npm and pnpm`)
**Execution tracking:** local run log only
**Implementation coordination:** Lead Agent, with Sonnet Contributor Agents allowed for the phases in §5
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability

A new command, `audit`, audits the dependencies of npm and pnpm projects in a target directory.
`audit run` finds each project's lockfile, runs the user's installed `npm audit` or `pnpm audit`
twice (all dependencies, then production only), and saves the raw JSON. `audit ingest` does the
same from saved JSON files. Both normalize the output into one findings file, `findings.json`
(schema `zazzles.audit/v1`), which Zazzles Agent consumes, and write `report.html`, a standalone
report in the Code Scan visual style, and `summary.md`, a short Markdown summary for CI job
summaries and pull-request comments. `audit tools` reports whether each supported audit tool is
installed, its version, and whether it is a tested version, and `run` makes the same check before
it audits anything. Each vulnerable library is recorded with its installed
version, its advisories, whether it is direct or arrives through another package, the dependency
paths to it, whether it is production or development-only, and the fix version the tool names
with its patch, minor or major size. `audit report` re-renders the HTML from a run directory. The
command never installs, upgrades or edits anything in the target.

---

## 1. Required Reading For The Implementor

### 1.a This Specification

Read this specification end to end first.

### 1.b Feature / Milestone Context

- [Series index](README.md) — the shared rules for every Dependency Audit specification.
- [SCA design](../../architecture/sca-design.md) — §Adapter boundary and §Findings and graph
  correlation. This specification is milestones SCA-1 and SCA-2 for npm and pnpm.
- [Implementation plan](../../project/implementation-plan.md#next-up) — order 2 and order 3 (the
  Agent is this findings file's consumer).

### 1.c Prior Specifications In This Delivery Effort

N/A. This is the first specification in the series.

### 1.d Standards

| Standard | What it governs here |
| --- | --- |
| [code-structure.md](../../standards/code-structure.md) | Package layout (§1, read `scan/` as "a module" and apply the same shape to `audit/`), file size (§2), anti-slop (§4), determinism (§6) |
| [testing.md](../../standards/testing.md) | Table-driven tests, golden files, no network in unit tests, PR evidence |
| [pr-process.md](../../standards/pr-process.md) | Draft PR into `stage`, bracketed scope labels (`[AUDIT]`, `[DOC]`, `[CI]`) |
| [docs-hygiene.md](../../standards/docs-hygiene.md) | `.zazz/` documents edited by this specification |
| [spec-hygiene.md](../../standards/spec-hygiene.md) | Updates to this specification during implementation |

**Verification step before writing code:** run the standards lookup yourself against the file list
in §3. The standards index names `scan/` and `cmd/` paths but not `audit/`; apply code-structure
and testing to `audit/` as written for `scan/`, and record that reading in the run log.

### 1.e Existing Code References

- `scan/cmd/scan/main.go` — the thin `main` that calls `cli.Run(args, stdout, stderr)`; mirror it.
- `scan/cli/main.go` — `Run` with a `flag.FlagSet` and returned exit codes; mirror the shape, not
  the flags.
- `scan/internal/report/report.html` and `report-sort.js` — the visual style and sort behavior to
  copy (they cannot be imported across `internal/`). Keep the Content Security Policy pattern: no
  external resources and the script allowed by hash.
- `scan/internal/report/sarif_test.go`, `html_test.go` — report test patterns.
- `vuln-nextjs` (sample catalog in `.zazz/project/vulnerable-sample-apps.md`): its
  `tests/expected-audit.json` is the committed `pnpm audit --prod --json` snapshot, and
  `docs/vulnerabilities/dependencies.md` describes it.

### 1.f Project Orientation

- [AGENTS.md](../../../AGENTS.md) — worktree, branch, credentials and verification rules.
- [Contributor guide](../../../docs/contributing.md) — build, test, vet and format commands.
- [Sample reference policy](../../../docs/samples/reference-policy.md) — samples are read-only; run
  audits on copies.

---

## 2. Invariants

### INVARIANT 1 — The target is never changed

`audit` executes only `npm audit --json`, `npm audit --json --omit=dev`, `npm --version`,
`npm audit --help`, `pnpm audit --json`, `pnpm audit --json --prod`, `pnpm --version` and
`pnpm audit --help`, each with its working
directory set to a project directory, with no shell, and with no other arguments. It never runs an
install, a fix, a script or any other program, and it never installs an audit tool: when one is
missing it prints the command for the user to run. It writes only under the `--out` directory.

### INVARIANT 2 — A failure is never a clean result

A missing tool, a missing lockfile, a tool error object (such as npm's `ENOLOCK`), output that is
not JSON, or a JSON shape the reader does not recognize gives that project a non-`audited` status
with the reason, appears in the report, and makes the exit code 3. No project with that status is
counted as having zero vulnerabilities.

### INVARIANT 3 — Facts come from the tool

Every advisory field (identifiers, title, severity, CWE, CVSS, ranges, patched versions, fix
target) is copied from the tool output. `audit` adds only: the production or development label,
the patch/minor/major classification, the installed version read from the lockfile (npm), hashes,
and run metadata. It makes no network request of its own.

### INVARIANT 4 — Pure Go, no cross-module imports

`audit/` uses the Go standard library only, builds with `CGO_ENABLED=0`, and imports nothing from
`scan/` or any other module directory.

### INVARIANT 5 — Deterministic output

The same inputs produce a byte-identical `findings.json` apart from `generated_at`, and a
byte-identical `report.html` apart from the rendered time. Projects, libraries, advisories and paths
are sorted by documented keys.

### INVARIANT 6 — Third-party text is data

Advisory titles and package names are stripped of control, invisible and bidirectional characters
and limited to 200 characters in `findings.json`. The report renders them through `html/template`
escaping only, and links advisories rather than copying their text.

---

## 3. Scope

### Approved Review Shape

This specification is approved for one PR. If implementation surfaces a need to split, stack or
combine it differently, stop for Deliverable Owner sign-off, update the affected sections in place,
and record the change in §13 before continuing.

**Rationale.** One reviewer can follow one command from runner to report in one PR. The roadmap,
module pages and this specification land first in their own documentation PR.

### Strict Scope Constraint

Every code change lives under `audit/`. Documentation changes are limited to the files listed
below. If implementation surfaces a need to modify anything else, stop and surface it.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `audit/cmd/audit/main.go` | New | Thin entry point |
| `audit/cli/` (`main.go`, `run.go`, `ingest.go`, `report.go`, `tools.go`, tests) | New | Subcommands, flags, exit codes, wiring |
| `audit/internal/model/` (`findings.go`, `scope.go`, `version.go`, `clean.go`, tests) | New | The `zazzles.audit/v1` types, scope labelling, version-change classification, text cleaning |
| `audit/internal/run/` (`detect.go`, `exec.go`, `tools.go`, tests) | New | Project detection, the tool check, and running the tools |
| `audit/internal/parse/npm/` (`npm.go`, `lockfile.go`, tests) | New | npm audit report version 2 reader; installed versions from `package-lock.json` |
| `audit/internal/parse/pnpm/` (`pnpm.go`, tests) | New | pnpm audit JSON reader |
| `audit/internal/report/` (`json.go`, `html.go`, `summary.go`, `report.html`, `report-sort.js`, tests) | New | Findings writer, HTML report, Markdown summary |
| `audit/testdata/` (`npm/`, `pnpm/`, `golden/`, `fake-tools/`) | New | Captured outputs, lockfiles, golden files, fake tool scripts |
| `audit/README.md` | Modified | Module page: from planned to the implemented npm and pnpm boundary |
| `docs/audit/README.md` | Modified | User guide: running an audit, scope, exit codes, reading the report |
| `docs/audit/findings-schema.md` | New | The `zazzles.audit/v1` field reference for Zazzles Agent and other consumers |
| `docs/contributing.md` | Modified | `go build -o bin/audit ./audit/cmd/audit` and the `audit/` format and test commands |
| `.github/workflows/ci.yml` | Modified | A `CGO_ENABLED=0 go build ./audit/...` step |
| `.zazz/architecture/README.md` | Modified | The `audit/` packages in the package map |
| `.zazz/project/implementation-plan.md` | Modified | Order 2 state |
| `.zazz/specifications/spec-index.md`, `.zazz/specifications/audit/README.md` | Modified | State of this specification |

### Out Of Scope

- `pip-audit` (specification 03) and `composer audit` (specification 04).
- Advisory lookups (OSV, NVD, KEV, EPSS) and any network request made by `audit` itself
  (specification 02).
- Yarn, Bun, Poetry and uv; a project with only `yarn.lock` is recorded as `unsupported`.
- SARIF output.
- Parsing `pnpm-lock.yaml`; pnpm's audit output already carries versions and paths.
- Reachability, remediation plans, and anything under `agent/`.
- Ignore lists of any kind, beyond what the tools apply themselves.
- Release workflow, published binaries and promotion to `main` (the separate first-release
  specification described in the [series index](README.md)).

---

## 4. Decisions

### D-1 — A separate `audit/` module and `audit` binary

**Decision.** `audit/` with `audit/cmd/audit`, built as `./bin/audit`, beside `scan/`.
**Why.** It produces findings as Code Scan does, can run in CI with no agent, and keeps tree-sitter
and judge code out of a pure-Go binary.
**Rejected alternative.** An `audit` subcommand of `scan` — lost because `scan` links CGo grammars
and its report model is built around source entries.

### D-2 — Development-only by difference, pnpm's flag as a cross-check

**Decision.** `run` audits all dependencies and production dependencies. A library is `dev` when it
appears in the first result and not the second. pnpm's per-finding `dev` field is compared with
that label; a disagreement is listed under `limits` and the difference result is kept.
**Why.** npm's report has no development marker, so the difference is the one rule that works for
both tools and for Python and PHP (specifications 03 and 04). pnpm's flag catches a wrong difference.

### D-3 — `--out` is required

**Decision.** `run` and `ingest` refuse to start without `--out`, and refuse an `--out` that
already holds a `findings.json` unless `--replace` is given.
**Why.** A default inside the target would write into pinned samples and into the user's tree
without being asked. Zazzles Agent passes `.zazzles/runs/<id>` explicitly.

### D-4 — npm installed versions come from `package-lock.json`

**Decision.** For npm, read only the `packages` map of `package-lock.json` (lockfile versions 2
and 3) to get the `version` at each `nodes` path the audit names.
**Why.** npm's audit JSON names the vulnerable range and the `node_modules` paths but not the
installed version, which the plan and the Agent need. A lockfile version 1, or a node missing from
the map, gives `installed: []` and a `limits` entry rather than a guess.

### D-5 — Advisories belong to the library that has them; parents become paths

**Decision.** A library record holds only advisories the tool attaches to it directly. npm entries
whose `via` lists only names (a parent affected through a child) are not separate records: they
become the dependency path and, when `fixAvailable` names them, the fix target. pnpm paths come
from `findings[].paths`.
**Why.** It keeps one record per vulnerable package, which is what an upgrade acts on, and still
shows the parent the user may need to raise.

### D-6 — One project per lockfile; pnpm workspaces as path roots

**Decision.** A project is a directory holding `package-lock.json` or `pnpm-lock.yaml`. In a pnpm
workspace the root lockfile is one project, and each path records the workspace it starts from
(pnpm writes `targets__react2shell>next`; `__` becomes `/`, `.` is the root).
**Why.** pnpm audits a whole workspace from the root lockfile, and the Agent upgrades per workspace.

### D-7 — Fix target and change size only when exact

**Decision.** The fix target is npm's `fixAvailable.version` when `fixAvailable.name` is the same
package, or the parent named otherwise; for pnpm, the version in a `patched_versions` range of the
form `>=X`. The change is `patch`, `minor` or `major` by comparing semantic versions; any other
range form, `fixAvailable: true` or `false`, or an unparseable version gives `unknown`.
**Why.** A wrong size would misgroup PRs downstream; `unknown` makes the Agent look.

### D-8 — Strict format recognition

**Decision.** npm output is read only when `auditReportVersion` is `2`; pnpm output only when it
has `advisories` and `metadata.vulnerabilities`. Anything else gives the project status `failed`
with reason `unrecognized format`.
**Why.** A half-read report would look like fewer vulnerabilities.

### D-9 — The HTML report copies Code Scan's style

**Decision.** Copy the stylesheet rules and the sort script the audit report needs from
`scan/internal/report` into `audit/internal/report`, and note the copy in a comment.
**Why.** `internal/` forbids importing them, and a shared style package belongs with the planned
report-outputs standard. The copy is small and the two reports look like one product.

### D-10 — Exit codes

**Decision.** `0` report written; `1` `--fail-on` threshold met; `2` usage error; `3` at least one
project not `audited`. When `1` and `3` both apply, `3` wins.
**Why.** CI needs to tell "found vulnerabilities" from "could not audit".

### D-11 — Install hints are printed, never run

**Decision.** For a missing tool, `audit tools` and `run` print the install commands from a fixed
table in `audit/internal/run/tools.go`, chosen by operating system, for the user to run:

| Tool | macOS | Linux | Anywhere |
| --- | --- | --- | --- |
| `npm` | `brew install node` | the distribution's `nodejs` package | install Node.js from nodejs.org |
| `pnpm` | `corepack enable pnpm` | `corepack enable pnpm` | `npm install -g pnpm` |

Specifications 03 and 04 add rows for `pip-audit` and `composer`. No hint pipes a download into a
shell.
**Why.** Installing software on someone's machine is their decision, and an agent running `audit`
must not do it silently. A fixed table keeps the hints reviewable.

### D-12 — Built for CI as well as local use

**Decision.** `audit` never prompts, needs no terminal, prints no color or progress when standard
output is not a terminal, and needs no credentials. Every run writes `summary.md` beside
`findings.json` and `report.html`: the counts by severity and scope, project statuses, the
critical and high libraries with their fix versions, and the note that `report.html` holds the
detail. A CI job can append it to the job summary or post it as a pull-request comment, and upload
the run directory as a build artifact.
**Why.** The same binary then works on a laptop, for the Agent, and in GitHub Actions or any other CI
with no extra mode. A standalone `report.html` cannot be shown inside a pull request, so a short
Markdown summary is what reviewers see first.

---

## 5. Agent Implementation Rules

### Team Integration

Commit and push only to `audit-mvp`. Do not merge to `stage`; integration happens through human PR
review. Verify `git config user.name` is `zazzcode` before committing.

### Command Working Directory

Run every command from the worktree root:

```bash
go test ./audit/... -count=1
CGO_ENABLED=0 go build ./audit/...
gofmt -l audit
go vet ./audit/...
go run ./tools/mdlint -base "$(git merge-base stage HEAD)"
```

### Commit And Push

One coherent green commit per phase is allowed as a recovery point. Push when the specification is
complete or at an explicit handoff.

### Scope Verification

`git diff stage --stat` lists exactly the files in §3.

### Autonomy Boundaries

Hard constraints: §2 invariants, §3 scope, the `zazzles.audit/v1` fields in §8, the subcommands,
flags and exit codes in §4 D-10 and §8, the standards in §1.d, the ACs in §6, and the halt
conditions below. Adaptive guidance: helper names, file splits inside a package, test organization,
skeleton bodies, report layout details that keep the listed sections.

### Run Log

Maintain `.zazz/ephemeral/dependency-audit-run-log.md`, section `01 npm and pnpm`. Append after OQ
answers, each phase, deviations, manual evidence and QA findings.

### Execution Tracking

Local run log only. Fallback: none needed.

### Lead Agent / Contributor Agent Coordination

| Phase / task | Responsible agent | Allowed scope | Required evidence |
| --- | --- | --- | --- |
| 1 Fixtures | Lead Agent | `audit/testdata/` | Capture commands and tool versions in the run log |
| 2 Model | Lead Agent | `audit/internal/model/` | Unit tests green |
| 3 npm reader, 4 pnpm reader | Sonnet Contributor Agents, one each, after phase 2 | Their own `parse/` package and its testdata | Tests green; changed-file list |
| 5 Runner | Sonnet Contributor Agent, after phase 2 | `audit/internal/run/` | Tests green |
| 6 Report, 7 CLI, 8 docs and CI | Lead Agent | Remaining §3 files | Tests, golden files, lint |

Phases 3, 4 and 5 own disjoint directories and may run at once. The Lead Agent reviews each diff
and runs the gates.

### Independent QA / Verification Agents

One fresh-context verifier for functionality and invariants (§9).

### Halt Conditions

1. An Open Question in §10 is unresolved.
2. The same test fails 3 iterations in a row.
3. `gofmt`, `go vet` or the Markdown lint fails for a reason not fixed in 2 iterations.
4. Scope verification shows a file outside §3.
5. A needed change outside `audit/` and the listed documents.
6. A standard not in §1.d matches the file list.
7. The installed npm or pnpm writes a JSON shape the captured fixtures do not cover.
8. Any step would run a command other than those in INVARIANT 1 against a target.

---

## 6. Acceptance Criteria

- **AC1 — npm reader.** From npm report version 2 fixtures, the reader produces one library record
  per vulnerable package with its own advisories, and covers: a direct library (`semver` 7.3.7,
  GHSA-c2qf-rxjj-qqgw); a transitive library reached through a parent (`minimist` through
  `mkdirp` 0.5.1, two advisories, fix target `mkdirp` 0.5.6 with change `patch`); several advisories
  on one library; `fixAvailable` as an object, `true` and `false`; CVSS score and vector and CWE
  copied; installed versions read from the lockfile, and `installed: []` with a `limits` entry for
  lockfile version 1. Verified by `TestNPMReader` in `audit/internal/parse/npm`.
- **AC2 — pnpm reader.** From the `vuln-nextjs` fixtures, the reader produces records for `next`
  13.4.19 and 15.0.4, `postcss` 8.4.14 and 8.4.31, `sharp` 0.33.5, `zod` 3.21.4 and `minimatch`
  9.0.3, with 71 advisories in the all-dependencies file and 67 in the production file, paths rooted
  at `.` and `targets/react2shell`, and `patched_versions` mapped per D-7. Verified by
  `TestPNPMReader`.
- **AC3 — Scope labels.** With paired all and production results, a library in both is `prod`, one
  only in all is `dev` (`minimatch` 9.0.3; `semver` 7.3.7 in the npm fixture), and a pnpm `dev` flag
  that disagrees adds a `limits` entry. `--scope prod` and `--scope dev` filter `findings.json` and
  the report; `--scope prod` runs only the production audit. Verified by `TestScopeLabels` and
  `TestRunScopeFlag`.
- **AC4 — Runner.** With fake `npm` and `pnpm` executables on `PATH` that record their arguments and
  working directory: only the INVARIANT 1 commands run, each in its project directory; a non-zero
  exit with valid JSON is read normally; `ENOLOCK`, output that is not JSON, an unrecognized shape and
  a missing executable each give the project a non-`audited` status with the reason and exit code 3.
  Verified by `TestRunCommands` and `TestRunFailures` in `audit/cli`.
- **AC5 — Detection.** Nested projects are found; `node_modules` and `.git` are skipped; a pnpm
  workspace is one project; a directory with only `yarn.lock` is recorded `unsupported`; a
  `package.json` with no lockfile is recorded `no_lockfile`. Verified by `TestDetectProjects`.
- **AC6 — Ingest matches run.** `ingest` on the files `run` saved writes a `findings.json` equal to
  `run`'s apart from `generated_at`. Verified by `TestIngestMatchesRun`.
- **AC7 — Findings file contract.** `findings.json` for the `vuln-nextjs` fixture equals
  `audit/testdata/golden/vuln-nextjs.findings.json` after masking `generated_at`; two runs are
  byte-identical after the same masking; every field in the file is documented in
  `docs/audit/findings-schema.md`. Verified by `TestFindingsGolden`, `TestDeterministic` and
  `TestSchemaDocumented` (the last walks the golden file's keys and checks each appears in the
  document).
- **AC8 — HTML report.** `report.html` holds: header (target, time, scope, tools and versions);
  summary counts by severity, by production and development-only, and fix available or not; one
  sortable table per project with expandable advisory rows; a "No fix available" section; a project
  status section listing every non-`audited` project; and a scope and limits section stating that
  reachability was not assessed and an empty report is not a safety verdict. It loads no external
  resource. A title and a package name holding `<script>`, a bidirectional override and a 5,000
  character string are escaped, cleaned and cut. Verified by `TestReportSections`,
  `TestReportNoExternalResources` and `TestReportHostileText`.
- **AC9 — Target unchanged.** After `run` against a temporary copy of the npm fixture project, a
  hash of every file in the copy is unchanged. Verified by `TestRunLeavesTargetUnchanged`.
- **AC10 — Pure Go.** `CGO_ENABLED=0 go build ./audit/...` succeeds, and `go list -deps ./audit/...`
  lists no `github.com/zazzcode/zazzles/scan` or tree-sitter package. Verified by the CI step and
  `TestNoForbiddenImports`.
- **AC11 — Exit codes and flags.** Missing `--out`, an existing `findings.json` without `--replace`,
  an unknown scope and an unknown flag exit 2; `--fail-on high` exits 1 when a high or critical
  advisory is present and 0 otherwise. Verified by `TestCLIExitCodes`.
- **AC15 — Tool check.** `audit tools` prints one row per supported tool (`npm`, `pnpm`) with: found
  or not, its path, its version, `tested` when the version is one the fixtures were captured with
  (npm 12.2.0, pnpm 12.23.0), `untested` otherwise, and whether `audit --help` lists every flag
  INVARIANT 1 uses. It exits 0 when every tool is found and accepts the flags, otherwise 3. `run`
  performs the same check for each project's tool before auditing: a missing tool or a missing flag
  gives the project status `failed` with the reason and the D-11 install commands for the current
  operating system, printed to standard error and recorded in `findings.json` and the report, and
  runs nothing else for it; an `untested` version adds a `limits` entry and continues. No install
  command is ever executed. Verified by `TestToolsCommand` and `TestRunToolPreflight` with fake
  executables that report tested, untested, missing-flag and absent, and by `TestInstallHints`,
  which checks each D-11 row for macOS and Linux and that no hint contains a pipe into a shell.
- **AC16 — CI use.** With standard input closed, no terminal and `CI=true`, `run` completes without
  waiting for input, prints no color or progress codes, and writes `summary.md` holding the severity
  and scope counts, every non-`audited` project with its reason, and each critical and high library
  with its fix version. The summary for the `vuln-nextjs` fixture equals
  `audit/testdata/golden/vuln-nextjs.summary.md`. Verified by `TestRunNonInteractive` and
  `TestSummaryGolden`.
- **AC12 — Live check on sample copies.** `./bin/audit run` on a copy of `vuln-nextjs` reports 67
  production advisories, matching the lab's `tests/expected-audit.json`, and the 4 `minimatch`
  advisories as development-only; on a copy of `nodejs-goof` it writes a report the owner reviews.
  These runs call the npm registry through the tools and cost nothing. Verified by the run log's
  manual evidence entry with the report paths.
- **AC13 — Clean.** `gofmt -l audit` prints nothing; `go vet ./audit/...`, `go test -race ./...`
  and the Markdown lint pass. Verified by those commands.
- **AC14 — Scope clean.** `git diff stage --stat` matches §5 Scope Verification.

---

## 7. Test Strategy

Reference data, all created in phase 1 and committed under `audit/testdata/`:

- `pnpm/vuln-nextjs/`: `package.json`, `pnpm-workspace.yaml`, `targets/react2shell/package.json`,
  `pnpm-lock.yaml` copied from `vuln-nextjs` at commit `335a717`, and `all.json` and `prod.json`
  from `pnpm audit --json` and `pnpm audit --json --prod` run on a copy (pnpm 12.23.0).
- `npm/mixed/`: a synthetic project with `mkdirp` 0.5.1 and dev dependency `semver` 7.3.7, its
  `package-lock.json` from `npm install --package-lock-only --ignore-scripts`, and `all.json` and
  `prod.json` from npm 12.2.0. Plus hand-trimmed variants for `fixAvailable: true` and `false` and a
  lockfile version 1, each with a one-line note of what was trimmed.
- `npm/errors/`: the `ENOLOCK` error object captured from npm, a non-JSON file, and a JSON file with
  `auditReportVersion: 1`.
- `fake-tools/`: small scripts installed on a temporary `PATH` by the tests, which print a named
  fixture, record argv and working directory to a file, and exit with a chosen code.
- `golden/`: `vuln-nextjs.findings.json` and `vuln-nextjs.report.html`, regenerated only with an
  `-update` flag and reviewed by eye on change.

Automated tests:

- `TestNPMReader` — AC1. Table over the `npm/` fixtures; asserts library names, versions, advisory
  IDs, paths, fix target and change.
- `TestPNPMReader` — AC2. Asserts the record set, advisory counts, workspace roots and fix mapping.
- `TestScopeLabels` — AC3. Paired inputs, including a forced pnpm `dev` disagreement.
- `TestVersionChange` — D-7. Table: patch, minor, major, prerelease, `>=X` range, other range forms,
  unparseable.
- `TestCleanText` — INVARIANT 6. Control, zero-width and bidirectional characters, length cut.
- `TestDetectProjects` — AC5. Temporary directory trees.
- `TestRunCommands`, `TestRunFailures`, `TestRunScopeFlag` — AC3, AC4 through the CLI with fake tools.
- `TestIngestMatchesRun` — AC6.
- `TestFindingsGolden`, `TestDeterministic`, `TestSchemaDocumented` — AC7.
- `TestReportSections`, `TestReportNoExternalResources`, `TestReportHostileText` — AC8, parsing the
  HTML rather than comparing whole strings, plus the HTML golden.
- `TestRunLeavesTargetUnchanged` — AC9.
- `TestNoForbiddenImports` — AC10, from `go list -deps` output.
- `TestCLIExitCodes` — AC11, table.
- `TestToolsCommand`, `TestRunToolPreflight`, `TestInstallHints` — AC15, with fake executables.
- `TestRunNonInteractive`, `TestSummaryGolden` — AC16.

Intentionally not tested: npm report version 1 parsing (rejected by D-8, covered by the error
fixture), and network failures inside the tools (they surface as tool errors, covered by AC4).

Manual verification: AC12 on sample copies, recorded in the run log.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

### TDD Entry Point

```go
func TestPNPMReader(t *testing.T) {
	// The vuln-nextjs production audit is the lab's committed ground truth: 67 advisories.
	got, err := pnpm.Read(readFixture(t, "pnpm/vuln-nextjs/prod.json"))
	if err != nil {
		t.Fatal(err)
	}
	if n := countAdvisories(got); n != 67 {
		t.Fatalf("advisories = %d, want 67", n)
	}
}
```

### Prescriptive Execution Sequence

**Phase 1: Fixtures.** Capture §7 reference data on copies, never in the samples. Record each
command and tool version in the run log. Run `go test ./audit/...` (no packages yet is fine).

**Phase 2: Model.** Write `audit/internal/model` from the skeleton below: types, sorting, scope
labelling, version change, text cleaning, with `TestScopeLabels`, `TestVersionChange`,
`TestCleanText`.

**Phase 3: npm reader** and **Phase 4: pnpm reader**, in parallel. Each returns
`[]model.Library` plus `[]string` limits, or an error for an unrecognized shape.

**Phase 5: Runner.** `run.CheckTool(ctx, name)` for the tool check, then `run.Detect(root)` and
`run.Audit(ctx, project, scope)`, using
`exec.CommandContext` with an argument list, the project directory as `Dir`, and a timeout of 5
minutes per command.

**Phase 6: Report.** `report.WriteFindings`, `report.WriteHTML` and `report.WriteSummary`, golden
files, hostile-text tests.

**Phase 7: CLI.** `run`, `ingest`, `report` and `tools` subcommands; flags `--target` (run), `--npm-all`,
`--npm-prod`, `--pnpm-all`, `--pnpm-prod` each as `[dir=]file` and repeatable (ingest), `--out`,
`--replace`, `--scope all|prod|dev` (default `all`), `--fail-on <severity>`. Exit codes per D-10.

**Phase 8: Documentation and CI.** `docs/audit/findings-schema.md` from the golden file,
`docs/audit/README.md`, `audit/README.md`, contributing commands, the CI step, architecture package
map, plan and index state. Then AC12 on sample copies.

### Skeleton: `audit/internal/model/findings.go`

```go
// Package model holds the zazzles.audit/v1 findings file and the labels audit computes.
package model

const Schema = "zazzles.audit/v1"

type Findings struct {
	Schema      string    `json:"schema"`
	GeneratedAt string    `json:"generated_at"`
	Target      string    `json:"target"`
	Scope       string    `json:"scope"` // all | prod | dev
	Projects    []Project `json:"projects"`
	Limits      []string  `json:"limits"`
}

type Project struct {
	Dir       string    `json:"dir"`       // relative to target, "." for the root
	Ecosystem string    `json:"ecosystem"` // npm
	Tool      Tool      `json:"tool"`
	Status    string    `json:"status"` // audited | failed | no_lockfile | unsupported
	Reason    string    `json:"reason,omitempty"`
	Lockfile  *File     `json:"lockfile,omitempty"`
	Inputs    []Input   `json:"inputs"`
	Counts    Counts    `json:"counts"`
	Libraries []Library `json:"libraries"`
}

type Tool struct{ Name, Version string }               // pnpm, 12.23.0 (json tags lower-case)
type File struct{ Path, SHA256 string }
type Input struct{ Path, SHA256, Scope string }        // raw/pnpm-all.json, all
type Counts struct{ Critical, High, Moderate, Low, Info, Unknown int }

type Library struct {
	Name       string     `json:"name"`
	Installed  []string   `json:"installed"`
	Scope      string     `json:"scope"` // prod | dev
	Direct     bool       `json:"direct"`
	Paths      []Path     `json:"paths"`
	Advisories []Advisory `json:"advisories"`
	Fix        Fix        `json:"fix"`
}

type Path struct {
	Workspace string   `json:"workspace"` // ".", "targets/react2shell"
	Chain     []string `json:"chain"`     // ["next", "postcss"]
}

type Advisory struct {
	IDs      []string `json:"ids"` // GHSA first, then CVE and tool IDs as given
	Severity string   `json:"severity"` // critical | high | moderate | low | info | unknown
	CVSS     *CVSS    `json:"cvss,omitempty"`
	CWE      []string `json:"cwe"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	Affected string   `json:"affected"`
	Patched  string   `json:"patched,omitempty"`
	Source   string   `json:"source"` // the tool that reported it
}

type CVSS struct{ Score float64; Vector string }

type Fix struct {
	Available bool   `json:"available"`
	Package   string `json:"package,omitempty"` // the package to raise; a parent for D-5
	Target    string `json:"target,omitempty"`
	Change    string `json:"change"` // patch | minor | major | unknown | none
}
```

Exact JSON tags for the short structs follow the lower-case `snake_case` style above; the golden
file and `docs/audit/findings-schema.md` are the contract once written.

### Skeleton: `audit/cli/main.go`

```go
// Package cli owns argument handling, wiring and exit codes for the audit command.
package cli

const (
	exitOK       = 0
	exitFailOn   = 1
	exitUsage    = 2
	exitNotClean = 3
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return exitUsage
	}
	switch args[0] {
	case "run":
		return runCommand(args[1:], stdout, stderr)
	case "ingest":
		return ingestCommand(args[1:], stdout, stderr)
	case "report":
		return reportCommand(args[1:], stdout, stderr)
	case "tools":
		return toolsCommand(args[1:], stdout, stderr)
	}
	usage(stderr)
	return exitUsage
}
```

---

## 9. Definition Of Done

- [ ] §1 required reading consumed; standards-index verification recorded.
- [ ] §10 Open Questions resolved and logged.
- [ ] `go test -race ./... -count=1` green.
- [ ] AC12 live check on sample copies recorded with report paths.
- [ ] `gofmt -l audit` prints nothing; `go vet ./...` and the Markdown lint pass.
- [ ] `git diff stage --stat` matches §5 Scope Verification.
- [ ] One PR, as approved in §3.
- [ ] AC1–AC16 verified, with evidence cited.
- [ ] Run log section `01 npm and pnpm` up to date, including Contributor Agent outcomes.
- [ ] Verifier sub-agent returned all-pass.
- [ ] Draft PR body links this specification and lists each AC's verification.

---

## 10. Open Questions

Each has a recommended answer; confirm or change before code is written.

- **OQ-1** — Binary name in the repository: `./bin/audit`, as `scan` is `./bin/scan`? The installed
  release name (`zazzles-audit`) is decided in the first-release specification. Recommended: yes.
- **OQ-2** — `--out` required (D-3), rather than a default under the target? Recommended: required.
- **OQ-3** — Default `--scope all`, with each library labelled? Recommended: yes.

---

## 11. Run Log Protocol

Run log: `.zazz/ephemeral/dependency-audit-run-log.md`, shared by the series, section
`01 npm and pnpm`. It is ignored by Git. Append only. Required sections: Standards Verification, OQ
Resolutions, Phase Completions, Deviations, Manual Evidence Locations, QA Findings & Rework, Issues &
Recoveries, Verifier Sub-Agent Report.

Session start: read this specification, read the run log, confirm the next phase from the latest
Phase Completion entry, resolve open questions, then begin.

---

## 12. Agent Implementation Prompt

```text
You are starting fresh in the zazzles worktree `audit-mvp` (branch audit-mvp). Verify pwd,
branch, status and `git worktree list` per AGENTS.md before editing.
Your task is to implement Dependency Audit 01: the audit command for npm and pnpm.

Specification: .zazz/specifications/audit/01-node.md
Shared run log: .zazz/ephemeral/dependency-audit-run-log.md (section "01 npm and pnpm")
Execution tracking: local run log only
Implementation coordination: Lead Agent; Sonnet Contributor Agents allowed for phases 3, 4 and 5
Companion skills to load: spec-driven, doc-check

Read the specification end to end, then the run log. Resolve §10 open questions with the owner.
Verify standards via .zazz/standards/index.yaml against §3 and record the result.

LEAD AGENT / CONTRIBUTOR AGENTS
- Work only in this worktree. Contributor Agents share it and own the disjoint directories in §5.
- Give each Contributor Agent its phase, scope, ACs, evidence and the §5 halt conditions. Review
  every diff and run the gates yourself before accepting it.

NON-NEGOTIABLE RULES
1. Follow §5. Never run any command against a target other than those in INVARIANT 1.
2. Samples are read-only: capture fixtures and run AC12 on copies.
3. No network requests from audit itself. The tools contact the npm registry; that is expected.
4. Every AC needs evidence.

ORDER OF WORK
1. Read; resolve OQs; verify standards.
2. Phase 1 fixtures; then the TDD entry point in §8.
3. Phases 2 to 8.
4. DoD in §9; dispatch the verifier; prepare the draft PR into stage. Do not merge.

VERIFIER SUB-AGENT
"You are verifying Dependency Audit 01 in the audit-mvp worktree. Read
.zazz/specifications/audit/01-node.md and .zazz/ephemeral/dependency-audit-run-log.md.
For each AC, run the cited test or command and check the result yourself. Check INVARIANTs 1 to 6
against the code, including every exec call. Check `git diff stage --stat` against §5. Do not modify
code or the run log. Return PASS or FAIL per AC with evidence."

Only declare done after the verifier reports all-pass.
```

---

## 13. Implementation And Review Change Log

No changes recorded.

---

*End of specification. Implementation proceeds from this specification and the run log; no
separate execution document is created.*
