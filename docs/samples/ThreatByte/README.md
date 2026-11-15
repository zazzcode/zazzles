# ThreatByte Python sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-14)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Every analyzer was run on the pinned revision `ede28f27e7e5` with OpenAI `gpt-6-luna`, using the scanner from the analyzer-engine-hardening branch. The target stayed clean. Static source judgments only; nothing was run or exploited.

- **Records:** 62. **Judged:** 61, in 61 requests (464,233 input tokens).
- **Outcomes:** 4 confirmed vulnerabilities, 1 poor practice, 34 protected, 22 inconclusive (Review).
- **Path traversal (5 judged):** the upload `FileStorage.save` at `server/routes.py:264` is a **confirmed vulnerability**; the `send_from_directory` calls at lines 302 and 334 are **protected** for that claim only; line 309 and the `os.remove` at line 364 stay **Review**.
- **Not assessed by design (1):** one outbound HTTP observation.

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

