# Dependency Audit specifications

Dependency Audit is the `audit` command under `audit/`: a pure-Go program beside Code Scan that
runs the target's own package-manager audit, normalizes the output into one findings file, adds
advisory detail, and writes an HTML report. Zazzles Agent reads the findings file to plan and carry
out remediation. The [implementation plan](../../project/implementation-plan.md#next-up) owns the
roadmap position (next up, order 2) and the [SCA design](../../architecture/sca-design.md) owns the
architecture direction.

The series is five specifications. Each is one draft PR into `stage`, built in the `audit-mvp`
worktree. 02 and 03 each need only 01, and 04 needs only 01, so 02, 03 and 04 can be built in any order
after 01.

| Order | Specification | Delivers | Depends on | State |
|---:|---|---|---|---|
| 01 | [npm and pnpm](01-node.md) | `audit run`, `audit ingest`, `audit report`, `audit tools`; npm and pnpm readers; the `zazzles.audit/v1` findings file; the HTML report | none | Drafted 2026-11-28 |
| 02 | [Python](02-python.md) | `pip-audit` on pinned requirements files only, with no resolving or building; development scope from file names and includes | 01 | Drafted 2026-11-28. Needs `pip-audit` installed |
| 03 | [PHP](03-php.md) | `composer audit` on `composer.lock` with plugins off; development split from the lockfile; abandoned packages | 01 | Drafted 2026-11-28. Needs `composer` installed |
| 04 | Advisory enrichment | `audit enrich`: OSV lookup by advisory ID, optional NVD by CVE, a cache in the run directory, the added report fields | 01 | Not written |
| 05 | Documentation and sample report | The rest of `docs/audit/` and a published sample report of `vuln-nextjs` | 02, 03, 04 | Not written |

**After the series: the first release.** A separate specification, `first-release.md`, in its own
worktree cut from `stage` once 05 merges. It is not part of this series because it releases both
`scan` and `audit`, and its changes are CI, release workflow and documentation, not audit code. It
covers:

- a tag-triggered GitHub Actions workflow that builds `audit` for macOS and Linux on `amd64` and
  `arm64` from one runner (pure Go), and `scan` on a native runner per platform (its tree-sitter
  grammars need CGo), and publishes archives with SHA-256 checksums;
- a reusable GitHub Action and a documented CI example, so a repository can run `audit` (and
  `scan`) on pull requests;
- the version string each binary reports, release notes, and installation docs;
- the promotion PR from `stage` to `main`.

Per [AGENTS.md](../../../AGENTS.md#branch-model), the owner merges the promotion PR and creates the
version tag. The specification prepares both; no agent merges to `main` or tags a release.

Shared rules for every specification in the series:

- The command reads and reports. It never installs, upgrades or fixes a dependency, never edits
  the target's files, and never lets an audit tool resolve or build packages.
- `audit tools`, and the same check at the start of `audit run`, confirm each audit tool is
  installed, report its version, and confirm it accepts the flags the command uses.
- A tool failure, a missing lockfile or an unrecognized output format is reported as such. It is
  never shown as a clean result.
- Every advisory fact comes from the audit tool or, from 04 on, from a named advisory database. The
  command adds only labels it can compute exactly (scope, version-change size, hashes).
- `audit/` is pure Go with the standard library only, builds with `CGO_ENABLED=0`, and imports
  nothing from `scan/` or `agent/`.
- The findings file is a versioned contract. A change to a field's meaning bumps the schema version.
