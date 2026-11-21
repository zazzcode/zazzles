# Fix

[Zazzles modules](../README.md#modules) · [Fix user docs](../docs/fix/README.md) · [Remediation philosophy](../docs/philosophy.md)

Fix is the planned collection of agent skills, remediation standards and playbooks for
turning documented security findings into verified repairs.

A finding can come from any Zazzles module (**Code Scan** or **Endpoint Probe**) or an external
scanner — including static application security testing (SAST), dependency audit, dynamic
application security testing (DAST), and endpoint probe / TLS and certificate scanners such as
Nuclei. Fix will work from the finding details, including the affected code, endpoint, dependency
or configuration and the evidence supporting the finding.

The playbooks will guide agents through selecting a repair, preserving intended behavior and
existing protections, and running checks that demonstrate the issue is addressed. Agents will
summarize the change and verification for human review.

Fix is expected to be developed before [Endpoint Probe](../probe/README.md).
