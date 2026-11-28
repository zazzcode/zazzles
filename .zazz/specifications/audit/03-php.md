# Dependency Audit 03: PHP (`composer audit`) — Deliverable Specification

**Worktree / branch:** `audit-mvp`, branch `audit-03-php`, cut from `stage` after 01 merges (it does
not depend on 02, and may be built before or beside it)
**Feature:** Dependency Audit (`audit/`)
**Milestone:** [Dependency Audit series](README.md), specification 03 of 5
**Deliverable:** `composer audit` support in `audit run`, `audit ingest` and `audit tools`
**Project Owner:** zazzles owner
**Deliverable Owner:** zazzles owner
**Delivery topology:** single-deliverable branch
**Review artifact:** one draft PR into `stage`
**Approved review shape:** one PR
**Decomposition rationale:** Composer audits its own lockfile without installing anything, and the
lockfile marks development packages, so this is a small, separate review from Python's harder rules.
**Integration branch:** `stage`
**Merge policy:** PR review required — agents commit/push feature branches only
**Drafted:** 2026-11-28
**Shared run log:** `.zazz/ephemeral/dependency-audit-run-log.md` (section `03 PHP`)
**Execution tracking:** local run log only
**Implementation coordination:** Lead Agent working alone
**Companion skills for implementation:** `spec-driven`, `doc-check`

---

## 0. Capability

`audit` audits PHP projects that have a `composer.lock`, with the user's installed `composer`. It
runs `composer audit` against the lockfile for all packages and for production packages only, reads
installed versions and the development split from `composer.lock`, and records every vulnerable
package, and every package its maintainers have marked abandoned, in the same `zazzles.audit/v1`
findings file and HTML report. A `composer.json` with no lockfile is recorded `no_lockfile`.
`audit tools` reports `composer` like the other tools.

---

## 1. Required Reading For The Implementor

### 1.a This Specification

Read this specification end to end first.

### 1.b Feature / Milestone Context

- [Series index](README.md) — the shared rules.

### 1.c Prior Specifications In This Delivery Effort

- [01 npm and pnpm](01-node.md) — read all of it. This specification reuses its model, invariants 2
  to 6, exit codes, `--out` rule, report and tool check, changing them only where §2 and §4 say so.

### 1.d Standards

The same as [01 §1.d](01-node.md#1d-standards).

### 1.e Existing Code References

- `audit/internal/parse/npm/` and its `lockfile.go` (from 01) — reader and lockfile-version pattern.
- `audit/internal/run/` (from 01) — detection, tool check and execution to extend.

### 1.f Project Orientation

As [01 §1.f](01-node.md#1f-project-orientation).

---

## 2. Invariants

### INVARIANT 1 — The target is never changed

`audit` executes only `composer --version`, `composer audit --help`,
`composer audit --locked --format=json --no-interaction --no-plugins`, and the same with
`--no-dev`, with the working directory set to the project directory, no shell, and no other
arguments. `--locked` audits `composer.lock` without reading `vendor/`, and `--no-plugins` stops
Composer from loading plugin code from the project. Nothing is installed or updated. It writes only
under `--out`.

The exact flag names MUST be confirmed against the installed `composer` in phase 1 (halt condition 7).

### INVARIANTs 2 to 6

As in [01 §2](01-node.md#2-invariants).

---

## 3. Scope

### Approved Review Shape

One PR. Stop for Deliverable Owner sign-off if a different shape is needed.

### Strict Scope Constraint

Code changes live under `audit/`. Documentation changes are limited to the files below.

### In Scope

| Path | New / Modified | Reason |
| --- | --- | --- |
| `audit/internal/parse/composer/` (`composer.go`, `lockfile.go`, tests) | New | `composer audit` JSON reader; versions and dev split from `composer.lock` |
| `audit/internal/run/` (`composer.go`, `detect.go`, `tools.go`, tests) | New / Modified | Lockfile detection, tool check, execution |
| `audit/internal/model/` | Modified | PHP ecosystem value and the optional `abandoned` library field (§4 D-3) |
| `audit/internal/report/` | Modified | An "Abandoned packages" section |
| `audit/cli/` (`ingest.go`, tests) | Modified | `--composer-all` and `--composer-prod` ingest flags |
| `audit/testdata/composer/` | New | Captured outputs and lockfiles |
| `docs/audit/README.md`, `docs/audit/findings-schema.md` | Modified | PHP inputs and the `abandoned` field |
| `.zazz/project/implementation-plan.md`, `.zazz/specifications/spec-index.md`, `.zazz/specifications/audit/README.md` | Modified | State |

### Out Of Scope

- Projects with no `composer.lock`; they are recorded `no_lockfile`, never resolved.
- Composer's own ignore settings beyond what `composer audit` already applies.
- Python (specification 02), OSV enrichment (04), SARIF, anything under `agent/`.

---

## 4. Decisions

### D-1 — Development split from the lockfile, difference as cross-check

**Decision.** A library listed under `packages-dev` in `composer.lock` is `dev`; under `packages` it
is `prod`. The all-packages and `--no-dev` results are also compared as in
[01 D-2](01-node.md#d-2--development-only-by-difference-pnpms-flag-as-a-cross-check), and a
disagreement adds a `limits` entry while the lockfile label is kept.
**Why.** The lockfile states the split directly and exactly; the difference catches a lockfile and
audit result that do not match.

### D-2 — Installed versions from `composer.lock`

**Decision.** Read only the `name` and `version` of each entry in `packages` and `packages-dev`. A
version that starts with `v` is recorded as written and compared without the `v`.
**Why.** `composer audit` names the affected range, and the plan needs the installed version.

### D-3 — Abandoned packages are recorded, not counted as vulnerabilities

**Decision.** Each package in the output's `abandoned` map gets `abandoned: {"replacement": "<name>"}`
(or `null` for no replacement) on its library record, whether or not it has advisories. A package
with no advisories appears only in the report's "Abandoned packages" section and is not counted in
the vulnerability totals. The field is optional and additive, so the schema stays
`zazzles.audit/v1`.
**Why.** An abandoned package will get no security fixes, which the Agent needs when choosing between
an upgrade and a replacement; counting it as a vulnerability would be wrong.

### D-4 — Severity and identifiers

**Decision.** Copy each advisory's `advisoryId`, `cve` and every `sources[].remoteId` (such as a
GHSA) into `ids`, `title`, `link` as `url`, `affectedVersions` as `affected`, and `severity` when
present, else `unknown`.
**Why.** INVARIANT 3; 04 fills missing severity from OSV.

### D-5 — Fix target is not stated by Composer

**Decision.** `composer audit` does not name a fixed version. Record `fix: {available: false,
change: "unknown"}` unless `affectedVersions` is a single `<X` or `<=X` upper bound, in which case the
fix target is left empty and `limits` notes that 04 will supply it.
**Why.** Guessing the next release from a range would be wrong as often as right.

### D-6 — Install hint for `composer`

**Decision.** Add this row to [01 D-11](01-node.md#d-11--install-hints-are-printed-never-run)'s
table: macOS `brew install composer`; Linux the distribution's `composer` package (for example
`sudo apt install composer`); anywhere, the instructions at `https://getcomposer.org/download/`,
linked rather than copied, because that page's installer checks a signature that changes. In CI, the
common PHP setup actions install Composer. `audit` prints these and never runs them.
**Why.** Composer's own installer is a download-and-run script, which the hint must not ask the user
to pipe into a shell.

---

## 5. Agent Implementation Rules

As [01 §5](01-node.md#5-agent-implementation-rules), with these changes:

- Branch `audit-03-php` in the `audit-mvp` worktree. Scope verification: `git diff stage --stat`
  lists exactly the files in §3.
- Lead Agent works alone.
- Additional halt conditions:
  7. The installed `composer` does not accept every INVARIANT 1 flag, or its JSON shape differs from
     the captured fixtures.
  8. `composer` is not installed and the owner has not answered OQ-1.

---

## 6. Acceptance Criteria

- **AC1 — Reader.** From captured `composer audit --format=json` output, the reader produces one
  library per vulnerable package with all advisories and the D-4 fields; fixtures cover several
  advisories on one package, an advisory with no CVE, the `abandoned` map with and without a
  replacement, and no advisories. Verified by `TestComposerReader`.
- **AC2 — Lockfile.** Versions and the dev split come from `composer.lock`, including `v`-prefixed
  versions and a package present in both all and `--no-dev` results; a disagreement adds a `limits`
  entry. Verified by `TestComposerLockfile`.
- **AC3 — Runner.** With a fake `composer` on `PATH`, only the INVARIANT 1 commands run, each in the
  project directory, always with `--locked` and `--no-plugins`; Composer's non-zero exit with valid
  JSON is read; invalid JSON and a missing executable give `failed`. Verified by `TestRunComposer`.
- **AC4 — Detection.** `composer.lock` projects are found, `vendor/` and `.git` are skipped, and a
  `composer.json` with no lockfile is `no_lockfile`. Verified by `TestDetectComposer`.
- **AC5 — Tool check.** `audit tools` includes `composer` with the 01 AC15 fields, and a missing
  `composer` prints the D-6 hints for the current operating system and runs none of them. Verified
  by `TestToolsComposer` and the `composer` rows of `TestInstallHints`.
- **AC6 — Abandoned in the report.** The HTML report lists abandoned packages in their own section
  with the replacement, and the vulnerability totals exclude abandoned packages with no advisory.
  Verified by `TestReportAbandoned`.
- **AC7 — Ingest.** `--composer-all` and `--composer-prod` accept saved JSON with the `[dir=]file`
  form and give the same findings as `run`. Verified by `TestIngestComposer`.
- **AC8 — Golden.** The `vuln-symfony` fixture produces a `findings.json` equal to
  `audit/testdata/golden/vuln-symfony.findings.json`. Verified by `TestComposerFindingsGolden`.
- **AC9 — Live check on a sample copy.** On a copy of `vuln-symfony` (96 production and 35 development
  packages in its lockfile at `086f81f`), `run` writes a report the owner reviews, and the copy's
  files are unchanged. Verified by the run log's evidence entry.
- **AC10 — Clean and in scope.** As 01 AC13 and AC14.

---

## 7. Test Strategy

Reference data, created in phase 1 after OQ-1, committed under `audit/testdata/composer/`:

- `vuln-symfony/`: `composer.json` and `composer.lock` copied from `vuln-symfony` at `086f81f`, and
  `composer audit --locked --format=json` output with and without `--no-dev`.
- `outputs/`: hand-trimmed variants for AC1, each with a note of what was trimmed.
- The installed `composer` version and `audit --help` output, recorded in the run log.

Tests: `TestComposerReader`, `TestComposerLockfile`, `TestRunComposer`, `TestDetectComposer`,
`TestToolsComposer`, `TestReportAbandoned`, `TestIngestComposer`, `TestComposerFindingsGolden`.

---

## 8. TDD Entry Point + Prescriptive Execution Sequence

### TDD Entry Point

```go
func TestComposerLockfile(t *testing.T) {
	// composer.lock states the development split; packages-dev entries must be labelled dev.
	versions, dev, err := composer.ReadLockfile(readFixture(t, "composer/vuln-symfony/composer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if len(versions) != 131 || countTrue(dev) != 35 {
		t.Fatalf("packages = %d, dev = %d; want 131 and 35", len(versions), countTrue(dev))
	}
}
```

### Prescriptive Execution Sequence

**Phase 1: Tool facts and fixtures.** After OQ-1, record `composer --version` and `audit --help`,
confirm every INVARIANT 1 flag, and capture the §7 outputs on a copy. Halt on any difference.

**Phase 2: Lockfile and reader** (`TestComposerLockfile`, `TestComposerReader`).

**Phase 3: Detection, tool check, runner** (`TestDetectComposer`, `TestToolsComposer`,
`TestRunComposer`).

**Phase 4: Report, ingest, golden, docs** (`TestReportAbandoned`, `TestIngestComposer`,
`TestComposerFindingsGolden`), then AC9.

### Skeleton: `audit/internal/parse/composer/lockfile.go`

```go
// ReadLockfile returns each package's version and whether it is a development package.
func ReadLockfile(data []byte) (versions map[string]string, dev map[string]bool, err error)
```

---

## 9. Definition Of Done

As [01 §9](01-node.md#9-definition-of-done), with AC1–AC10 of this specification and the AC9 live
check recorded.

---

## 10. Open Questions

- **OQ-1** — `composer` is not installed on the owner's machine (`php` is). Install it (recommended:
  `brew install composer`), or provide captured outputs? An agent does not install tools without the
  owner's word.

---

## 11. Run Log Protocol

As [01 §11](01-node.md#11-run-log-protocol), section `03 PHP`.

---

## 12. Agent Implementation Prompt

```text
You are starting in the zazzles worktree `audit-mvp`. Verify pwd, branch and status per AGENTS.md.
Create branch audit-03-php from stage after 01 merges. Implement Dependency Audit 03: composer audit.

Specification: .zazz/specifications/audit/03-php.md (read 01-node.md first; this builds on it)
Run log: .zazz/ephemeral/dependency-audit-run-log.md, section "03 PHP"
Coordination: Lead Agent working alone. Companion skills: spec-driven, doc-check.

Resolve OQ-1 with the owner first. Every composer run uses --locked and --no-plugins; nothing is
installed or updated. Samples are read-only; use copies. Follow §5 halt conditions. Finish with the
DoD and a verifier:

"Verify Dependency Audit 03 in audit-mvp. Read 03-php.md, 01-node.md and the run log. Run each AC's
test or command. Check every exec call against INVARIANT 1. Check git diff stage --stat against §3.
Do not modify anything. Return PASS or FAIL per AC with evidence."

Prepare a draft PR into stage. Do not merge.
```

---

## 13. Implementation And Review Change Log

No changes recorded.
