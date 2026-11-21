# Fix user documentation

[Zazzles documentation](../README.md) · [Fix module](../../fix/README.md) · [Remediation philosophy](../philosophy.md) · [Project introduction](../../README.md)

**Status:** Planned (expected before [Endpoint Probe](../probe/README.md)).

Fix is the planned Zazzles module for remediating security findings and poor coding practices with
coding agents. It consists of agent skills, remediation standards, and playbooks that take a
finding's evidence through a targeted repair and verification.

## Planned scope

- Accept findings from Zazzles modules (**Code Scan** and **Endpoint Probe**) as well as external
  scanners — including SAST, dependency audit, DAST, and endpoint probe / TLS and certificate
  scanners such as Nuclei.
- Work from the finding's source locations, endpoint details, data paths, observed controls, and
  evidence gaps.
- Guide coding agents to preserve intended application behavior and existing protections while
  addressing the reported defect, following the [remediation philosophy](../philosophy.md).
- Run scoped verification checks and summarize the change and verification evidence for human
  review.

## Related documentation

- [Fix module landing page](../../fix/README.md)
- [Code Scan user documentation](../scan/README.md)
- [Endpoint Probe user documentation](../probe/README.md)
- [Implementation plan](../../.zazz/project/implementation-plan.md#product-goals-and-capability-boundaries)
