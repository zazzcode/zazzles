# Dependency Audit

[Zazzles modules](../README.md#modules) · [Dependency Audit user docs](../docs/audit/README.md)

**Dependency Audit** (`audit/`) is the planned module for finding known-vulnerable dependencies, a
software composition analysis (SCA) tool. Its command, `audit`, runs the package manager's own audit
tool already installed for the project and turns the result into one findings file and a
standalone HTML report in the Code Scan style.

What it adds over the audit tools alone is detail on every advisory, from four public sources:

- **OSV**: the CVE and other identifiers, the description, the affected and fixed versions, and the
  commit that fixed the flaw;
- **NIST's National Vulnerability Database**: NIST's CVSS scores with the vector explained in plain
  terms, and references tagged as patches or exploits;
- **CISA's Known Exploited Vulnerabilities catalog**: whether attackers are using the flaw now, and
  CISA's remediation due date;
- **FIRST's EPSS**: the estimated chance the flaw is exploited in the next 30 days.

The report puts critical and high findings first, ordered by CVSS score with NIST's score
preferred, and shows known exploitation and exploitation likelihood in each finding's details when
available. Each vulnerable library is also reported with its installed version, the dependency path to
it, whether it ships in production or is used only in development, and the fix version with its
patch, minor or major size. Planned ecosystems, in order: npm and pnpm, then `pip-audit` and
`composer audit`.

The command reads and reports. It never installs, upgrades or fixes a dependency, and a missing
lockfile or a failed audit is reported as such, never as a clean result. It is a pure-Go program,
separate from Code Scan. [Zazzles Agent](../agent/README.md) reads its findings file to plan and
carry out the remediation.

[Implementation plan](../.zazz/project/implementation-plan.md#next-up) ·
[Specifications](../.zazz/specifications/audit/README.md)
