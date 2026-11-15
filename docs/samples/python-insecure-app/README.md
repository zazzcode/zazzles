# Python insecure app sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Current report (rebuilt 2026-11-15)

[HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif) · [Provenance](metadata.json)

Security sink families; standalone input validation excluded were run at pinned revision `b188493768ca` with OpenAI `gpt-6-luna` and evidence wire v7 on the analyzer-assessment-coverage branch. The target remained clean. These are static source judgments.

- **Records:** 2. **Judged:** 1, in 1 requests (4,029 input tokens).
- **Outcomes among judged records:** 1 confirmed vulnerabilities, 0 poor practice, 0 protected, 0 not applicable, 0 inconclusive (Review).
- **Unassessed records shown:** 1; provider/decoder failures: 0.

[Wire v7 verification and limits](../../../.zazz/evaluation/wire-bundle-v7-results.md).

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
