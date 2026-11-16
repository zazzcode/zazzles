# ThreatByte Python sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-15)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Fresh **all-family** OpenAI `gpt-6-luna` assessment after the shared Python input refactor,
including standalone input validation, at pinned target revision `ede28f27e7e5`.
Canonical JSON and both exported views preserve the same source evidence and model decisions.

- **Records / completed assessments:** 62 / 62.
- **Provider requests:** 62 (302,537 input tokens); no fallback or automatic retries.
- **Report outcomes:** 6 confirmed_vulnerability, 20 needs_evidence, 3 poor_practice, 33 protected_for_claim.
- **Unassessed / failed:** 0 / 0.
- **Verification:** every decision replays against fresh source; JSON/HTML/SARIF statuses agree.

These are static source judgments, with existing Review gaps retained. Future routine Python
comparisons use `--skip-family input-validation`; this full run includes it.
See [Python refactor verification](../../../.zazz/evaluation/python-input-refactor-results.md).

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

