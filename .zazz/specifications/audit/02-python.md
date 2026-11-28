# Dependency Audit 02: Python (`pip-audit`) — Deliverable Specification

**Worktree / branch:** `audit-mvp`, branch `audit-02-python`, cut from `stage` after 01 merges (or
stacked on 01's branch with `gh-stack` if 01 is still in review)
**Feature:** Dependency Audit (`audit/`)
**Milestone:** [Dependency Audit series](README.md), specification 02 of 5
**Deliverable:** `pip-audit` support in `audit run`, `audit ingest` and `audit tools`
**Project Owner:** zazzles owner
**Deliverable Owner:** zazzles owner
**Delivery topology:** single-deliverable branch
**Review artifact:** one draft PR into `stage`
**Approved review shape:** one PR
**Decomposition rationale:** Python is its own specification because its inputs are unlike any
lockfile: requirements files that may not be pinned, scope that only file names reveal, and a
resolver that can run package build code. PHP is simpler and is [specification 03](03-php.md).
**Integration branch:** `stage`
**Merge policy:** PR review required — agents commit/push feature branches only
**Drafted:** 2026-11-28
**Shared run log:** `.zazz/ephemeral/dependency-audit-run-log.md` (section `02 Python`)
**Execution tracking:** local run log only
**Implementation coordination:** Lead Agent, with one Sonnet Contributor Agent allowed for the reader
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability

`audit` audits Python projects with the user's installed `pip-audit`. It finds pinned requirements
files, works out which are production and which are development-only from their names and their
`-r` includes, runs `pip-audit` on each without resolving anything, and records every vulnerable
package in the same `zazzles.audit/v1` findings file and HTML report as npm and pnpm. Files that are
not fully pinned, and projects with only `pyproject.toml` or `setup.py`, are recorded as not
audited with the reason and the command that would make them auditable. `audit tools` reports
`pip-audit` like the other tools.

---

## 1. Required Reading For The Implementor

### 1.a This Specification

Read this specification end to end first.

### 1.b Feature / Milestone Context

- [Series index](README.md) — the shared rules.
- [SCA design](../../architecture/sca-design.md) — §Adapter boundary: "resolution/build metadata may
  execute ecosystem tooling and needs explicit handling in that contract". D-2 below is that
  handling.

### 1.c Prior Specifications In This Delivery Effort

- [01 npm and pnpm](01-node.md) — read all of it. This specification reuses its findings model
  (§8 skeleton and `docs/audit/findings-schema.md`), invariants 2 to 6, exit codes (D-10), `--out`
  rule (D-3), report, and tool check (AC15). It changes none of them except where §2 and §4 say so.

### 1.d Standards

The same as [01 §1.d](01-node.md#1d-standards).

### 1.e Existing Code References

- `audit/internal/parse/npm/`, `audit/internal/parse/pnpm/` (from 01) — the reader shape to mirror.
- `audit/internal/run/` (from 01) — detection, tool check and execution to extend.

### 1.f Project Orientation

As [01 §1.f](01-node.md#1f-project-orientation).

---

## 2. Invariants

### INVARIANT 1 — The target is never changed, and nothing is built

`audit` executes only `pip-audit --version`, `pip-audit --help`, and
`pip-audit --requirement <file> --no-deps --disable-pip --format json --progress-spinner off`,
with the working directory set to the project directory, no shell, and no other arguments. Because
`--disable-pip` and `--no-deps` stop `pip-audit` from creating an environment or resolving packages,
no package is downloaded, built or installed, and no package code runs. Any requirements file that
those flags cannot audit is recorded and skipped, never resolved. It writes only under `--out`.

The exact flag names are from `pip-audit`'s documentation and MUST be confirmed against the
installed version in phase 1 before any code is written (halt condition 7).

### INVARIANTs 2 to 6

As in [01 §2](01-node.md#2-invariants): failures are never clean, facts come from the tool, pure Go,
deterministic output, third-party text is data.

---

## 3. Scope

### Approved Review Shape

One PR. Stop for Deliverable Owner sign-off if a different shape is needed.

### Strict Scope Constraint

Code changes live under `audit/`. Documentation changes are limited to the files below.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `audit/internal/parse/pipaudit/` (`pipaudit.go`, tests) | New | `pip-audit` JSON reader |
| `audit/internal/run/` (`python.go`, `detect.go`, `tools.go`, tests) | New / Modified | Requirements-file discovery, pin check, scope by file name and includes, `pip-audit` execution and tool check |
| `audit/internal/model/` | Modified | Python ecosystem value and the two new project reasons (§4 D-2, D-5) |
| `audit/cli/` (`ingest.go`, tests) | Modified | `--pip-all` and `--pip-prod` ingest flags |
| `audit/testdata/pip-audit/` | New | Captured outputs and requirements fixtures |
| `docs/audit/README.md`, `docs/audit/findings-schema.md` | Modified | Python inputs, the pin rule, how scope is decided |
| `.zazz/project/implementation-plan.md`, `.zazz/specifications/spec-index.md`, `.zazz/specifications/audit/README.md` | Modified | State |

### Out Of Scope

- Resolving unpinned requirements, in any form. A later specification may add an explicit opt-in
  resolve mode with its own isolation rules.
- Auditing an installed environment (`pip-audit` with no requirements file).
- Poetry, Pipenv and uv lockfiles, and exporting them to requirements files. A project with only
  those is recorded `unsupported` with the export command in the reason.
- Composer (specification 03), OSV enrichment (04), SARIF, anything under `agent/`.

---

## 4. Decisions

### D-1 — Audit only what the file lists

**Decision.** Run `pip-audit` with `--no-deps --disable-pip` on each pinned requirements file.
Packages the file does not list (transitive dependencies of a top-level-only file) are not audited,
and the project's `limits` says so.
**Why.** It is the only `pip-audit` mode that installs and builds nothing. A fully locked file (from
`pip-compile`, `uv pip compile` or `pip freeze`) lists every package, so nothing is lost there; a
top-level-only file gets an honest limit instead of a guess.

### D-2 — Unpinned files are reported, not resolved

**Decision.** A requirements file is pinned when every requirement line is `name==version` or
`name[extras]==version`, optionally with `--hash` and environment markers; `-r` and `-c` includes
are followed; comments, blank lines and index options are ignored. A file with any other line gives
that input status `unpinned` with the first offending line, and the project status `failed` with
reason `requirements not pinned`, and the reason names `pip-compile` or `uv pip compile` as the way
to produce a pinned file.
**Why.** Resolving runs pip, and pip can build a source distribution, which runs its code. The
owner's samples show the case is common: Vulnerable-Flask-App lists `flask` unpinned, and
python-insecure-app has only ranged `.in` files.

### D-3 — Scope from file names and includes, recorded per project

**Decision.** Development-only files are those whose name, or directory, contains `dev`, `test`,
`tests`, `lint`, `docs` or `ci` as a word (`requirements-dev.txt`, `requirements/test.txt`,
`dev-requirements.txt`). Every other requirements file is production. A library is `dev` when it
appears only through development files, following `-r` includes, so a `dev.txt` that includes
`base.txt` does not make `base.txt`'s packages development-only. The project records the rule used
(`scope_rule: "file names"`), and a project with one requirements file and no development file
records `scope_rule: "single file, all production"`.
**Why.** Python has no standard split; this matches the common layouts, the include rule avoids the
obvious wrong label, and recording the rule lets the reader judge it.
**Rejected alternative.** Reading `pyproject.toml` dependency groups — lost because without a lock
they are unpinned, so D-2 would reject them anyway.

### D-4 — Severity is `unknown` unless the tool gives one

**Decision.** `pip-audit`'s JSON gives vulnerability IDs, aliases and fix versions but usually no
severity. Record `unknown`; specification 04 fills it from OSV.
**Why.** INVARIANT 3: no guessing.

### D-5 — No requirements file

**Decision.** A directory with `pyproject.toml`, `setup.py`, `setup.cfg`, `Pipfile`, `poetry.lock`
or `uv.lock` and no requirements file is a project with status `unsupported`, and the reason names
the file found and the export command (`poetry export`, `uv export`, `pip-compile pyproject.toml`).
**Why.** It tells the user what to do instead of silently skipping a Python project.

### D-6 — Fix target

**Decision.** The fix target is the lowest version in `fix_versions` above the installed version;
the change size follows [01 D-7](01-node.md#d-7--fix-target-and-change-size-only-when-exact), and an
empty `fix_versions` gives `available: false`.
**Why.** Same rule as the other ecosystems, so the Agent groups PRs the same way.

---

## 5. Agent Implementation Rules

As [01 §5](01-node.md#5-agent-implementation-rules), with these changes:

- Branch `audit-02-python` in the `audit-mvp` worktree. Scope verification:
  `git diff stage --stat` lists exactly the files in §3.
- Contributor Agent: one Sonnet agent may write `audit/internal/parse/pipaudit/` after phase 1.
- Additional halt conditions:
  7. The installed `pip-audit` does not accept every INVARIANT 1 flag, or its JSON shape differs
     from the captured fixtures.
  8. `pip-audit` is not installed and the owner has not answered OQ-1.
  9. Any step would let `pip-audit` resolve, download or build a package.

---

## 6. Acceptance Criteria

- **AC1 — Reader.** From captured `pip-audit` JSON, the reader produces one library per vulnerable
  package with its version, every vulnerability ID and alias (CVE, GHSA, PYSEC), and fix versions;
  descriptions are not copied into `findings.json`. Fixtures cover: no vulnerabilities, several on one
  package, a package with no fix version, and a skipped-package entry. Verified by `TestPipAuditReader`.
- **AC2 — Pin check.** A table of requirements lines classifies pinned and unpinned per D-2,
  including extras, markers, hashes, `-r` and `-c` includes, include cycles, comments and index
  options; an unpinned file gives the D-2 status and reason. Verified by `TestPinned`.
- **AC3 — Scope.** Fixture trees give: `requirements.txt` plus `requirements-dev.txt` (dev label
  applied); `requirements/base.txt`, `requirements/dev.txt` with `-r base.txt` (base packages stay
  production); a single file (all production, rule recorded). Verified by `TestPythonScope`.
- **AC4 — Runner.** With a fake `pip-audit` on `PATH`, only the INVARIANT 1 commands run, each in
  the project directory, never without `--no-deps` and `--disable-pip`; a non-zero exit with valid
  JSON is read; invalid JSON and a missing executable give `failed`. Verified by `TestRunPipAudit`.
- **AC5 — Detection.** Requirements files are found by name pattern, `.venv`, `venv`,
  `site-packages` and `.git` are skipped, and D-5 projects are recorded `unsupported`. Verified by
  `TestDetectPython`.
- **AC6 — Tool check.** `audit tools` includes `pip-audit` with the AC15 fields from 01; `run`
  refuses a `pip-audit` that lacks `--disable-pip` or `--no-deps`. Verified by `TestToolsPipAudit`.
- **AC7 — Ingest.** `--pip-all` and `--pip-prod` accept saved JSON with the `[dir=]file` form and
  give the same findings as `run`. Verified by `TestIngestPip`.
- **AC8 — Golden.** The ThreatByte fixture produces a `findings.json` equal to
  `audit/testdata/golden/threatbyte.findings.json`, with the "transitive dependencies not listed"
  limit. Verified by `TestPipFindingsGolden`.
- **AC9 — Live check on sample copies.** On copies: ThreatByte (pinned `requirements.txt`) is audited
  and its report reviewed; Vulnerable-Flask-App and python-insecure-app are `failed` with
  `requirements not pinned`; vulnpy is `unsupported` with the export hint. `pip-audit` contacts its
  vulnerability service; no package is installed (checked by listing the copy before and after).
  Verified by the run log's evidence entry.
- **AC10 — Clean and in scope.** As 01 AC13 and AC14.

---

## 7. Test Strategy

Reference data, created in phase 1 after OQ-1, committed under `audit/testdata/pip-audit/`:

- `threatbyte/`: `requirements.txt` copied from ThreatByte at `ede28f2` and `pip-audit` JSON from it.
- `layouts/`: small synthetic trees for AC3 and AC5, with `pip-audit` JSON captured from each.
- `outputs/`: hand-trimmed JSON variants for AC1, each with a note of what was trimmed.
- The installed `pip-audit` version and `--help` output, recorded in the run log.

Tests: `TestPipAuditReader`, `TestPinned`, `TestPythonScope`, `TestRunPipAudit`, `TestDetectPython`,
`TestToolsPipAudit`, `TestIngestPip`, `TestPipFindingsGolden`. The report needs no new test: 01's
report tests cover the shared model, and one Python row in the golden HTML is enough.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

### TDD Entry Point

```go
func TestPinned(t *testing.T) {
	// An unpinned line must never reach pip-audit: resolving it could run build code.
	if pinned("flask") {
		t.Fatal(`"flask" must not be pinned`)
	}
	if !pinned("Flask==2.2.5") {
		t.Fatal(`"Flask==2.2.5" must be pinned`)
	}
}
```

### Prescriptive Execution Sequence

**Phase 1: Tool facts and fixtures.** After OQ-1, record `pip-audit --version` and `--help`, confirm
every INVARIANT 1 flag, and capture the §7 outputs on copies. Halt on any difference from §2.

**Phase 2: Pin check and scope** (`TestPinned`, `TestPythonScope`).

**Phase 3: Reader** (`TestPipAuditReader`).

**Phase 4: Detection, tool check and runner** (`TestDetectPython`, `TestToolsPipAudit`,
`TestRunPipAudit`).

**Phase 5: Ingest, golden, docs** (`TestIngestPip`, `TestPipFindingsGolden`), then AC9.

### Skeleton: `audit/internal/run/python.go`

```go
// requirementsFile is one requirements file found in a Python project.
type requirementsFile struct {
	Path     string   // relative to the project
	Dev      bool     // by D-3 name rule
	Includes []string // -r and -c targets, relative to the project
	Pinned   bool
	Unpinned string   // the first line that is not pinned, when Pinned is false
}

// pinned reports whether one requirements line names an exact version (D-2).
func pinned(line string) bool

// pythonProject discovers requirements files under dir and classifies them.
func pythonProject(dir string) ([]requirementsFile, error)
```

---

## 9. Definition Of Done

As [01 §9](01-node.md#9-definition-of-done), with AC1–AC10 of this specification and the AC9 live
check recorded.

---

## 10. Open Questions

- **OQ-1** — `pip-audit` is not installed on the owner's machine. Install it (recommended:
  `pipx install pip-audit`, or `brew install pip-audit`), or provide captured outputs? An agent
  does not install tools without the owner's word.
- **OQ-2** — The D-3 development name list (`dev`, `test`, `tests`, `lint`, `docs`, `ci`): complete
  enough? Recommended: yes, and an unusual name is reported as production with the rule recorded.

---

## 11. Run Log Protocol

As [01 §11](01-node.md#11-run-log-protocol), section `02 Python`.

---

## 12. Agent Implementation Prompt

```text
You are starting in the zazzles worktree `audit-mvp`. Verify pwd, branch and status per AGENTS.md.
Create branch audit-02-python from stage (01 merged) or stack it on 01's branch with gh-stack.
Implement Dependency Audit 02: pip-audit support.

Specification: .zazz/specifications/audit/02-python.md (read 01-node.md first; this builds on it)
Run log: .zazz/ephemeral/dependency-audit-run-log.md, section "02 Python"
Coordination: Lead Agent; one Sonnet Contributor Agent may write the reader after phase 1.
Companion skills: spec-driven, doc-check.

Resolve OQ-1 and OQ-2 with the owner first. Never let pip-audit resolve, download, build or install
a package: every run uses --no-deps and --disable-pip on a pinned file, or does not run. Samples
are read-only; use copies. Follow §5 halt conditions. Finish with the DoD and a verifier:

"Verify Dependency Audit 02 in audit-mvp. Read 02-python.md, 01-node.md and the run log. Run each
AC's test or command. Check every exec call against INVARIANT 1, and that no code path can reach
pip-audit without --no-deps and --disable-pip. Check git diff stage --stat against §3. Do not modify
anything. Return PASS or FAIL per AC with evidence."

Prepare a draft PR into stage. Do not merge.
```

---

## 13. Implementation And Review Change Log

No changes recorded.
