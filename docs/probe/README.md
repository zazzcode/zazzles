# Endpoint Probe user documentation

[Zazzles documentation](../README.md) · [Endpoint Probe module](../../probe/README.md) · [Project introduction](../../README.md)

**Status:** Planned (expected after [Zazzles Agent](../agent/README.md)).

**Endpoint Probe** (`probe/`) is the planned Zazzles module for checking externally observable
security settings on authorized endpoints (similar to TLS and certificate scanners such as Nuclei)
and pairing each observation with evidence and remediation guidance.

## Planned scope

- Perform authorized, read-only checks against endpoints you own or are authorized to assess.
- Start with TLS versions and configuration, expired certificates, and certificate trust-chain
  issues.
- Report the affected endpoint, observed evidence, remediation recommendations, and verification
  steps.
- Expand later to additional externally visible endpoint settings such as HTTP security
  configuration.

## Related documentation

- [Endpoint Probe module landing page](../../probe/README.md)
- [Code Scan user documentation](../scan/README.md)
- [Dependency Audit user documentation](../audit/README.md)
- [Zazzles Agent user documentation](../agent/README.md)
- [Implementation plan](../../.zazz/project/implementation-plan.md#product-goals-and-capability-boundaries)
