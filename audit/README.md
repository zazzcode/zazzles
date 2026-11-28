# Dependency Audit

[Zazzles modules](../README.md#modules) · [Dependency Audit user docs](../docs/audit/README.md)

**Dependency Audit** (`audit/`) is the planned module for finding known-vulnerable dependencies, a
software composition analysis (SCA) tool. Its command, `audit`, runs the package manager's own audit
tool already installed for the project and turns the result into one findings file and a
standalone HTML report in the Code Scan style.

Planned coverage, in order: npm and pnpm, then `pip-audit` and `composer audit`, then advisory detail
from the OSV database (CVE aliases, CWE, CVSS vector and the commit that fixed the flaw). Each
vulnerable library is reported with its installed version, its advisories, the dependency path to
it, whether it ships in production or is used only in development, and the fix version with its
patch, minor or major size.

The command reads and reports. It never installs, upgrades or fixes a dependency, and a missing
lockfile or a failed audit is reported as such, never as a clean result. It is a pure-Go program,
separate from Code Scan. [Zazzles Agent](../agent/README.md) reads its findings file to plan and
carry out the remediation.

[Implementation plan](../.zazz/project/implementation-plan.md#next-up) ·
[Specifications](../.zazz/specifications/audit/README.md)
