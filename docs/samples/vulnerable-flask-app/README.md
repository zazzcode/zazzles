# Vulnerable Flask App (Erlik 2) sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-14)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Every analyzer was run on the pinned revision `a67cbe590698` with OpenAI `gpt-6-luna`, using the scanner from the analyzer-engine-hardening branch. The target stayed clean. Static source judgments only; nothing was run or exploited.

- **Records:** 30. **Judged:** 30, in 30 requests (138,679 input tokens).
- **Outcomes:** 8 confirmed vulnerabilities, 0 poor practice, 0 protected, 22 inconclusive (Review).
- **Path traversal (3 judged):** the `open` calls at `vulnerable-flask-app.py:77` and `:129` are **confirmed vulnerabilities**; the `FileStorage.save` upload at line 209 stays **Review**.
- **Command injection:** two records are **confirmed vulnerabilities**.

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

