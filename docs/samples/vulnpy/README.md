# VulnPy Python sample

[Samples](../README.md) · [Full HTML](findings.html) · [JSON, gzip](findings.json.gz) · [SARIF, gzip](findings.sarif.gz) · [Provenance](metadata.json)

## Current report (rebuilt 2026-11-19)

Fresh all-family scan at the same pin with OpenAI `gpt-6-luna` on the model-assisted evidence
resolution scanner (`614e435`, [results](../../../.zazz/evaluation/model-resolution-results.md)). The reference checkout stayed clean. These are
static source judgments, not executed exploits.

- 2,214 entries, 3,350 analysis records: **455 Confirmed, 2,895 Review, 0 Protected**.
- 456 requests, 2,920,785 input tokens (16,014,526 before), no provider failures. The 2,830
  input-validation records are undecidable and are no longer sent.
- Confirmed by family: 195 path, 90 code execution, 78 SQL, 61 command and 31 XSS.
- **Answer key:** all 6 source-reviewed positives are found. The 369 Confirmed records outside the
  key are unreviewed; repeated contexts share sinks across adapters and are not distinct defects.
- 64 path records with flow-gap questions exceeded the 64KB request limit and stayed Review
  without a request. A later fix (`7e333aa`) sends such records without their resolution
  questions.

## Previous report (rebuilt 2026-11-15)

Fresh all-family OpenAI `gpt-6-luna` assessment after the shared Python input refactor,
at pinned revision `b81885e58283a3449b578d20c20557aff637e5ea`. Every discovered supported context was assessed,
including standalone input validation. No record was omitted from this published copy.

- **Entries:** 2,214. **Records / completed assessments:** 3,260 / 3,260.
- **Provider requests:** 3,260 (16,014,526 input tokens); no fallback or automatic retries.
- **Report outcomes:** 346 confirmed_vulnerability, 2,899 needs_evidence, 15 poor_practice.
- **Unassessed / failed:** 0 / 0. **Exact fresh-source replays:** 3,260; mismatches/missing traces: 0.
- **Families:** 61 command, 78 SQL, 31 XSS, 260 path and 2,830 input-validation contexts.

These are static source judgments, not executed exploits or a complete framework/security certification.
Repeated contexts expose shared sinks through different adapters and are not distinct defects.
The 61 command contexts preserve both shared process sinks and app-specific loop/upload/thread witnesses
across the existing eleven-adapter corpus. Source-case checks pass 10/10, including the Jinja raw
output at `apps/templates/jinja/xss.html:30` and explicit registration-disposition controls.

## Comparison with the known source-reviewed set

| Family | Known/reviewed scope | Current result |
| --- | --- | --- |
| Command injection | Two shared process sinks plus app-specific loop/upload/thread witnesses | All 61 contexts confirmed |
| SQL injection | `execute`, `executemany`, `executescript` at `trigger/sqli.py:37/48/59` | Each pattern: 21 confirmed contexts and 5 construction-only findings; 63/78 injection confirmations overall |
| XSS | Generated raw responses plus the separate Jinja `safe` output | All 31 contexts confirmed, including Jinja |
| Path traversal | Supported file/archive destination operands | 191 confirmed; 69 remain Review |
| Standalone input validation | Applicable business field requirements | All 2,830 assessed; Review where no business policy is established |
| XXE, deserialization and other unsupported trigger families | Broader advertised corpus | Not covered; this scan does not claim those vulnerabilities are absent |

The 10/10 source checks cover six positive source locations and four registration-disposition
controls. They are not ten vulnerability categories or an exhaustive recall score. Contexts repeat
shared defects across registrations/adapters; 61 command contexts do not mean 61 distinct defects.

## Complete downloads and offline refresh

The normal HTML contains the entire result. Full canonical JSON and SARIF are stored as lossless gzip
because their uncompressed sizes exceed GitHub's per-file limit. Decompress before using tools that
require plain SARIF/JSON; the sample evaluator and refresh helper accept the compressed canonical file.

```sh
python3 docs/samples/evaluate-python.py vulnpy docs/samples/vulnpy/findings.json.gz
python3 docs/samples/refresh.py --scan ./bin/scan --sample vulnpy
```

Future routine Python comparisons use `--skip-family input-validation`. This complete scan includes
all 2,830 standalone validation contexts. They remain Review when no applicable business policy is
established; model completion does not turn missing policy into a validation defect or protection.

## Source and history

Target: [Contrast-Security-OSS/vulnpy](https://github.com/Contrast-Security-OSS/vulnpy), MIT.
The checkout remained clean, including ignored files, at the pin before and after evaluation.
No application execution, dependency installation or target edits were performed.

The preceding published snapshot contained 170 assessed command/SQL/XSS contexts and omitted path
and input-validation records. Its model answers remain historical in Git and metadata; no old answer
was transplanted onto changed requests. The larger count here comes from scope, not a refactor-caused
increase in candidate discovery or distinct request signatures.

See the [refactor verification](../../../.zazz/evaluation/python-input-refactor-results.md),
[living detection guide](../../../.zazz/evaluation/vulnpy-detection-guide.md),
[source reference and corrections](reference.md), [expected cases](cases.json),
[source hashes](source-hashes.json), and [upstream license](SOURCE-LICENSE.txt).
