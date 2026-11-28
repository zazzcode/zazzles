# Dependency Audit specifications

Dependency Audit is the `audit` command under `audit/`: a pure-Go program beside Code Scan that
runs the target's own package-manager audit, normalizes the output into one findings file, adds
advisory detail, and writes an HTML report. Zazzles Agent reads the findings file to plan and carry
out remediation. The [implementation plan](../../project/implementation-plan.md#next-up) owns the
roadmap position (next up, order 2) and the [SCA design](../../architecture/sca-design.md) owns the
architecture direction.

The series is four specifications, delivered in order. Each is one draft PR into `stage`.

| Order | Specification | Delivers | Depends on | State |
|---:|---|---|---|---|
| 01 | [npm and pnpm](01-node.md) | `audit run`, `audit ingest`, `audit report`; npm and pnpm readers; the `zazzles.audit/v1` findings file; the HTML report | none | Drafted 2026-11-28 |
| 02 | Python and PHP | `pip-audit` and `composer audit` readers and runners; Python dependency-scope rules | 01 | Not written. Needs `pip-audit` and `composer` installed, or captured outputs |
| 03 | Advisory enrichment | `audit enrich`: OSV lookup by advisory ID, optional NVD by CVE, a cache in the run directory, the added report fields | 01 | Not written. Can be built beside 02 |
| 04 | Documentation and sample report | The rest of `docs/audit/` and a published sample report of `vuln-nextjs` | 02, 03 | Not written |

**After the series: the first release.** A separate specification, `first-release.md`, in its own
worktree cut from `stage` once 04 merges. It is not part of this series because it releases both
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

- The command reads and reports. It never installs, upgrades or fixes a dependency, and never
  edits the target's files.
- A tool failure, a missing lockfile or an unrecognized output format is reported as such. It is
  never shown as a clean result.
- Every advisory fact comes from the audit tool or, from 03 on, from a named advisory database. The
  command adds only labels it can compute exactly (scope, version-change size, hashes).
- `audit/` is pure Go with the standard library only, builds with `CGO_ENABLED=0`, and imports
  nothing from `scan/` or `agent/`.
- The findings file is a versioned contract. A change to a field's meaning bumps the schema version.
