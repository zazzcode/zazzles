# Zazzles Agent

[Zazzles modules](../README.md#modules) · [Zazzles Agent user docs](../docs/agent/README.md) · [Remediation philosophy](../docs/philosophy.md)

**Zazzles Agent** (`agent/`) is the planned companion to the Zazzles commands. It is a set of
skills, playbooks, guides and agent definitions installed into a repository, which the user's own
coding agent follows to read Zazzles reports and carry out the remediation, ending in draft pull
requests a person reviews. This module was previously planned under the name Fix.

Its first input is the findings file from [Dependency Audit](../audit/README.md). The agent:

- checks whether the application uses the functions an advisory affects, and labels each finding
  with the evidence, without ever dropping one;
- plans the work as batched small dependency bumps, one bump per pull request, or a bump with the
  refactoring a newer library needs;
- writes tests on the current version before changing code, where the affected calls have none;
- asks the committer at fixed checkpoints and records the answers in the plan.

Code Scan findings follow, then other scanners' SARIF output (SAST, DAST, endpoint probes). The
remediation follows the [remediation philosophy](../docs/philosophy.md): connect each change to
its finding, preserve intended behavior and existing protections, and verify.

Zazzles Agent follows Dependency Audit and comes before [Endpoint Probe](../probe/README.md).
[Implementation plan](../.zazz/project/implementation-plan.md#next-up)
