# Endpoint Probe

[Zazzles modules](../README.md#modules) · [Endpoint Probe user docs](../docs/probe/README.md)

**Endpoint Probe** (`probe/`) is the planned module for assessing the externally visible security
configuration of endpoints you own or are authorized to assess, similar in scope to TLS and
certificate scanners such as Nuclei. It will report the finding, the endpoint and the observed
evidence, with recommendations for remediation and verification.

Initial coverage will focus on supported TLS versions, certificate expiration and trust-chain
problems. Later checks can cover other externally visible endpoint settings, such as HTTP
security configuration. The goal is to independently verify issues of the kind reported by
services such as SecurityScorecard. [Example TLS issue types](https://support.securityscorecard.com/hc/en-us/articles/26542438988827-Why-IPs-not-attributed-to-the-digital-footprint-appear-under-observations)

Endpoint Probe is planned after [Fix](../fix/README.md).
