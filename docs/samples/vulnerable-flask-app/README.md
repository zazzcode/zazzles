# Vulnerable Flask App (Erlik 2) sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`50d4a8f`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 19 entries, 30 analysis records: **8 Confirmed, 22 Review, 0 Protected**.
- 11 requests, 11 completed assessments, 45,750 input tokens. No provider failures. 2 records are not sent because their scanner blocker has no question the model could answer.
- **Answer key:** 4 of 4 expected positives found; no keyed control is a finding.
- Every keyed positive is Confirmed and no keyed control is red.

## Previous report (rebuilt 2026-11-15)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Fresh **all-family** OpenAI `gpt-6-luna` assessment after the shared Python input refactor,
including standalone input validation, at pinned target revision `a67cbe590698`.
Canonical JSON and both exported views preserve the same source evidence and model decisions.

- **Records / completed assessments:** 30 / 30.
- **Provider requests:** 30 (98,624 input tokens); no fallback or automatic retries.
- **Report outcomes:** 8 confirmed_vulnerability, 22 needs_evidence.
- **Unassessed / failed:** 0 / 0.
- **Verification:** every decision replays against fresh source; JSON/HTML/SARIF statuses agree.

These are static source judgments, with existing Review gaps retained. Future routine Python
comparisons use `--skip-family input-validation`; this full run includes it.
See [Python refactor verification](../../../.zazz/evaluation/python-input-refactor-results.md).

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

