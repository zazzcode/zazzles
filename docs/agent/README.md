# Zazzles Agent user documentation

[Zazzles documentation](../README.md) · [Zazzles Agent module](../../agent/README.md) · [Remediation philosophy](../philosophy.md) · [Project introduction](../../README.md)

**Status:** Planned. It follows [Dependency Audit](../audit/README.md) and comes before
[Endpoint Probe](../probe/README.md).

Zazzles Agent is the planned companion to the Zazzles commands. You install it into your
repository, and your coding agent uses it to read Zazzles reports and remediate the findings
through pull requests you review. It was previously planned under the name Fix.

## Planned scope

- Read the Dependency Audit findings file first, then Code Scan findings, then other scanners'
  SARIF output.
- Check whether the application calls the functions an advisory affects, and label each finding
  with that evidence. A label changes a finding's priority, never removes it.
- Plan the pull requests in Dependency Audit's order, critical and high CVSS severity first:
  batched small dependency bumps, one bump per pull request, or a bump together with the
  refactoring a newer library needs.
- Write tests on the current version first, where the code a change touches has none, so the
  change can be shown to keep behavior.
- Ask you before the decisions that are yours: what to fix now, how to split the pull requests,
  which tests to add, and before anything is pushed.
- Install under `.zazzles/` in your repository, with entry files for the agent tools it finds there.

## Related documentation

- [Zazzles Agent module landing page](../../agent/README.md)
- [Dependency Audit user documentation](../audit/README.md)
- [Code Scan user documentation](../scan/README.md)
- [Implementation plan](../../.zazz/project/implementation-plan.md#product-goals-and-capability-boundaries)
