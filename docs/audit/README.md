# Dependency Audit user documentation

[Zazzles documentation](../README.md) · [Dependency Audit module](../../audit/README.md) · [Project introduction](../../README.md)

**Status:** Planned, next after the current Code Scan work.

Dependency Audit finds known-vulnerable dependencies in your project, a software composition
analysis (SCA) tool. Its `audit` command runs the audit tool your package manager already provides
and writes two files: `findings.json`, a stable format that [Zazzles Agent](../agent/README.md) and
other tools read, and `report.html`, a standalone report you open in a browser.

## Planned scope

- **Ecosystems:** npm (`npm audit`) and pnpm (`pnpm audit`) first, then Python (`pip-audit`) and
  PHP (`composer audit`).
- **Scope:** all dependencies by default, each library labelled production or development-only, or
  production only, or development only.
- **For each vulnerable library:** installed version, advisories with their identifiers and
  severity, direct or through another package with the path to it, and the fix version with its
  patch, minor or major size.
- **Advisory detail** from the OSV database, which the audit tools leave out: CVE aliases, CWE,
  the CVSS vector and the commit that fixed the flaw.
- **Local and CI use:** the same command runs on your machine and in a CI job, with no prompts
  and no credentials. A non-zero exit when advisories at or above a chosen severity are found, a
  distinct exit when a project could not be audited, and a short `summary.md` for the job summary
  or a pull-request comment. Upload the run folder as a build artifact to keep the HTML report.
- **Missing tools:** `audit tools` shows which audit tools are installed, and when one is missing
  prints the command to install it. You run that command; `audit` never installs anything.

The command never installs, upgrades or fixes a dependency, and never changes your files.

## Related documentation

- [Dependency Audit module landing page](../../audit/README.md)
- [Zazzles Agent user documentation](../agent/README.md)
- [Code Scan user documentation](../scan/README.md)
- [Implementation plan](../../.zazz/project/implementation-plan.md#product-goals-and-capability-boundaries)
