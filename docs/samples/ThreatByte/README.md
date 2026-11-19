# ThreatByte Python sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 24 entries, 62 analysis records: **5 Confirmed, 22 Review, 34 Protected, 1 practice**.
- 58 requests plus 1 follow-up, 58 completed assessments, 298,903 input tokens. No provider failures. 1 records are not sent because their scanner blocker has no question the model could answer.
- **Answer key:** 5 of 5 expected positives found; no keyed control is a finding.
- Every keyed positive is found (the dashboard XSS as a construction-practice finding) and no protected control is red.

## Previous report (rebuilt 2026-11-15)

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

