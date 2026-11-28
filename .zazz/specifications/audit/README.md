# Dependency Audit specifications

Dependency Audit is the `audit` command under `audit/`: a pure-Go program beside Code Scan that
runs the target's own package-manager audit, normalizes the output into one findings file, and
writes an HTML report. Its main value over running the audit tools alone is the advisory detail it
adds: each advisory looked up in OSV, NIST's National Vulnerability Database, CISA's Known Exploited
Vulnerabilities catalog and FIRST's EPSS scores, so the report shows how severe each flaw is by every
source, whether attackers are using it now, and how likely they are to soon. Zazzles Agent reads the findings file to plan and carry
out remediation. The [implementation plan](../../project/implementation-plan.md#next-up) owns the
roadmap position (next up, order 2) and the [SCA design](../../architecture/sca-design.md) owns the
architecture direction.

The series is five specifications. Each is one draft PR into `stage`, built in the `audit-mvp`
worktree. Advisory enrichment comes straight after 01 because it is the module's main value. 02, 03
and 04 each need only 01, so they can also be built side by side.

| Order | Specification | Delivers | Depends on | State |
|---:|---|---|---|---|
| 01 | [npm and pnpm](01-node.md) | `audit run`, `audit ingest`, `audit report`, `audit tools`; npm and pnpm readers; the `zazzles.audit/v1` findings file; the HTML report | none | Drafted 2026-11-28 |
| 02 | [Advisory enrichment](02-enrichment.md) | OSV, NIST NVD, CISA KEV and FIRST EPSS for every advisory; severities by source, plain-language CVSS, known-exploited flags, exploitation likelihood, fix commits; report ordered by CVSS severity, critical and high first; `audit enrich`, `--offline`, a cache | 01 | Drafted 2026-11-28 |
| 03 | [Python](03-python.md) | `pip-audit` on pinned requirements files only, with no resolving or building; development scope from file names and includes | 01 | Drafted 2026-11-28. Needs `pip-audit` installed |
| 04 | [PHP](04-php.md) | `composer audit` on `composer.lock` with plugins off; development split from the lockfile; abandoned packages | 01 | Drafted 2026-11-28. Needs `composer` installed |
| 05 | Documentation and sample report | The rest of `docs/audit/`, including a CI guide with a tested GitHub Actions workflow, and a published sample report of `vuln-nextjs` | 02, 03, 04 | Not written |

## Running locally and in CI

`audit` is one binary that runs the same way on a laptop, for Zazzles Agent, and in a CI job. It
never prompts and needs no credentials, and every run writes three files: `findings.json` for tools
and the Agent, `report.html` for people, and `summary.md` for a CI job summary or a pull-request
comment. `--fail-on <severity>` makes the job fail on findings; exit code 3 means a project could not
be audited, so a broken audit is never a green build.

The four audit tools all run in CI. `audit` never installs them; when one is missing, `audit tools`
and `audit run` print the install command for the user, as [01 D-11](01-node.md#d-11--install-hints-are-printed-never-run)
and specifications 03 and 04 list. On GitHub Actions the usual setup is:

| Tool | How a CI job gets it |
| --- | --- |
| `npm` | Included with Node.js from the Node setup action |
| `pnpm` | `corepack enable pnpm` after the Node setup, or the pnpm setup action |
| `pip-audit` | `python -m pip install pip-audit` after the Python setup action |
| `composer` | Included by the common PHP setup action |

A job then runs `audit run --target . --out audit-results --fail-on high`, appends
`audit-results/summary.md` to the job summary, and uploads `audit-results/` as a build artifact. The
HTML report is a standalone file, so it opens from the downloaded artifact with no server.
Generating it in CI is as easy as generating it locally.

Specification 05 writes the CI guide with a workflow tested on this repository's samples, pinning
each action to a version it checked. The first-release specification below publishes the binaries
and a reusable GitHub Action, so a repository can run `audit` without building it.

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
  installed, report its version, and confirm it accepts the flags the command uses. A missing tool
  gets an install command printed for the user, never run.
- The command works without a terminal or credentials, so the same run works locally and in CI.
- A tool failure, a missing lockfile or an unrecognized output format is reported as such. It is
  never shown as a clean result.
- Every advisory fact comes from the audit tool or, from 02 on, from a named advisory source. The
  command adds only labels it can compute exactly (scope, version-change size, hashes).
- `audit/` is pure Go with the standard library only, builds with `CGO_ENABLED=0`, and imports
  nothing from `scan/` or `agent/`.
- The findings file is a versioned contract. A change to a field's meaning bumps the schema version.
