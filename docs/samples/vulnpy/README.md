# VulnPy Python sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

Target: [Contrast-Security-OSS/vulnpy](https://github.com/Contrast-Security-OSS/vulnpy), MIT,
reviewed at `b81885e58283a3449b578d20c20557aff637e5ea`. The target remained clean and unchanged.
Its vulnerable function library is exposed through several frameworks and dynamically built routes.

## Current report: command-injection acceptance scan (2026-11-07)

Full source-transmitting scan with OpenAI Decisions `gpt-6-luna` at scanner revision `6f5cb711fe06…`
(binary SHA-256 in [metadata](metadata.json)); the target stayed clean at the pin. The scan models the
Flask, FastAPI, Quart, Django (sync/ASGI), Falcon (sync/ASGI), Bottle, Pyramid, aiohttp and WSGI entries:
2,214 entries and 2,977 candidate records. **Command injection:** both core sinks (`trigger/cmdi.py:6` `os.system`, `:10` `subprocess.Popen(shell=True)`) are confirmed in every adapter context (Flask, FastAPI, Quart, Django sync/ASGI, Falcon sync/ASGI, Bottle, Pyramid, aiohttp, WSGI), plus the five app-specific witnesses (FastAPI loop and upload, Quart upload, Falcon upload and thread): 61 contexts, all completed `confirmed_vulnerability`. These are repeated exposures of two shared defects, not 61 defects.

**Input validation was deliberately not used for this run** (`--skip-family input-validation`, on explicit
instruction because the full scan would need about 3,000 further requests). Its 2,830 records are unjudged
and remain Review; this says nothing about validation adequacy. The scan judged the other 147 records with
147 provider requests (1,789,377 input tokens): 61 command, 78 SQL (63 confirmed injection, 15 poor-practice construction findings)
and 8 XSS (7 confirmed, 1 Review). The published HTML/JSON/SARIF omit those unjudged records and the entries that
carried only them (the full report is over 100 MB); the omission is stated in the report limitations.
The complete report is retained with the review package. Statuses are static judgments, not runtime exploitation.

Published copy: 147 entries, 147 records (146 Findings, 1 Review, 0 Protected).
See the [acceptance results](../../../.zazz/evaluation/command-injection-results.md).

## Previously published historical baseline (superseded for the links above)

The offline Zazzles scan records 11 static entries, six unassessed records and four explicit
registration/path coverage warnings. The core generated SQL/XSS routes remain coverage gaps.
This is not a completed semantic calibration or a clean result. No new source was sent to a model.

Six source-positive cases remain known misses. Four controls check explicit coverage warnings.
The evaluator intentionally exits nonzero while those positives are missing:

```sh
python3 docs/samples/evaluate-python.py vulnpy docs/samples/vulnpy/findings.json
```

Pinned local Semgrep CE found eight results and Bearer found 21; neither baseline identifies the
three SQL trigger variants. Broader findings cover future vulnerability families. Counts are not
precision/recall. The first sandbox-blocked Bearer attempt is not used as a baseline.

See the living [detection guide and checklist](../../../.zazz/evaluation/vulnpy-detection-guide.md),
[source reference](reference.md), [expected cases](cases.json), [hashes](source-hashes.json),
[metadata](metadata.json), [Semgrep baseline](semgrep/baseline.json),
[Bearer baseline](bearer/baseline.json), and [upstream license](SOURCE-LICENSE.txt).

## D5 follow-up

A later full source-only scan and code inspection confirmed the three SQLite constructions and
generated Flask/FastAPI raw-HTML responses. See the
[confirmed-findings table](reference.md#findings-confirmed-by-scan-and-code-inspection--d5) and
[D5 results](../../../.zazz/evaluation/common-entry-dispatch-results.md). The HTML/JSON/SARIF links
above still identify the original published baseline; this follow-up does not overwrite its evidence.
