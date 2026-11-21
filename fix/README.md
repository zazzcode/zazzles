# Fix

[Zazzles modules](../README.md#modules) · [Remediation philosophy](../docs/philosophy.md)

Fix is the planned collection of agent skills, remediation standards and playbooks for
turning documented security findings into verified repairs.

A finding can come from any Zazzles module or an external static application security testing
(SAST), dependency audit or dynamic application security testing (DAST) tool. Fix will work
from the finding details, including the affected code, dependency or configuration and the
evidence supporting the finding.

The playbooks will guide agents through selecting a repair, preserving intended behavior and
existing protections, and running checks that demonstrate the issue is addressed. Agents will
summarize the change and verification for human review.

Fix is expected to be developed before [Probe](../probe/README.md).
