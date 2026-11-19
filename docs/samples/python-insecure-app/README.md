# Python insecure app sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-19)

Fresh full scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence resolution
scanner (`df540c3`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are static
source judgments, not runtime exploit confirmation.

- 1 entries, 2 analysis records: **1 Confirmed, 1 Review, 0 Protected**.
- 1 requests, 1 completed assessments, 4,520 input tokens. No provider failures.
- **Answer key:** 1 of 2 expected positives found, 1 Review; no keyed control is a finding.
- The HTML construction is Confirmed. The name-field validation defect is not sent: undecidable validation records stay Review.

## Previous report (rebuilt 2026-11-15)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Fresh **all-family** OpenAI `gpt-6-luna` assessment after the shared Python input refactor,
including standalone input validation, at pinned target revision `b188493768ca`.
Canonical JSON and both exported views preserve the same source evidence and model decisions.

- **Records / completed assessments:** 2 / 2.
- **Provider requests:** 2 (7,067 input tokens); no fallback or automatic retries.
- **Report outcomes:** 1 confirmed_vulnerability, 1 needs_evidence.
- **Unassessed / failed:** 0 / 0.
- **Verification:** every decision replays against fresh source; JSON/HTML/SARIF statuses agree.

These are static source judgments, with existing Review gaps retained. Future routine Python
comparisons use `--skip-family input-validation`; this full run includes it.
See [Python refactor verification](../../../.zazz/evaluation/python-input-refactor-results.md).

Sections below this one describe earlier published snapshots; where their counts differ, this section is current.

Target: [trottomv/python-insecure-app](https://github.com/trottomv/python-insecure-app), pinned at
`b188493`. Final verification used a fresh clean upstream clone at the same revision, matching
the initial source hashes. Upstream source excerpts retain their authorship.

The report has one FastAPI route and two records, both assessed with `gpt-6-luna`. Request parameter
`name` enters HTML/template source, which is returned under an explicit HTML response contract.
The resulting static XSS finding is source-supported. Business validation remains uncertain rather
than treating a string type as HTML protection. The configured public-IP URL is a negative for
request-controlled destinations; response text is a separate external source.

The [three-case inventory](cases.json) passes (one reviewed positive discovery case).
[Source review](reference.md), [hashes](source-hashes.json), [metadata](metadata.json),
[Semgrep](semgrep/baseline.json) and [Bearer](bearer/baseline.json) are retained. Both comparator
snapshots report zero. The README's SSTI, dependency and secret claims are distinct from this XSS
slice; SCA/secrets/SSTI verdicts are not implemented here. No runtime exploit was executed.

```sh
python3 docs/samples/evaluate-python.py python-insecure-app docs/samples/python-insecure-app/findings.json
```

Upstream license: [source license text](SOURCE-LICENSE.txt).
