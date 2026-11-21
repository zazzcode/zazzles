# CI/CD reports

[Documentation index](../README.md) · [Running scans](running-scans.md)

## CI/CD artifacts

Set `SCAN_FINDINGS_DIR` to a runner-local output root or pass `--output-dir`. Configure a
decision-provider key in the CI secret store and select that provider with `--judge`. A judged scan retries
transient provider failures and exits 0 when it runs to the end, even if some assessments are
incomplete. It exits 1 only when the decision-model account fails or the model stops responding,
after writing the available bundle; an earlier setup/parse failure may produce no bundle. See
[judged-scan reliability](decision-models.md#judged-scan-reliability). Upload artifacts even after a failed scan. This example assumes the scanner binary has been
built and the target is checked out at `target/` with its entry file at `server.ts`:

```yaml
- name: Scan target
  env:
    SCAN_FINDINGS_DIR: ${{ runner.temp }}/scan-findings
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    JUDGE_DECISION_MODEL: gpt-6-luna
  run: ./bin/scan --analyze --judge openai --entry server.ts target

- name: Save scan reports
  if: always()
  uses: actions/upload-artifact@v7
  with:
    name: scan-findings-${{ github.run_id }}-${{ github.run_attempt }}
    path: ${{ runner.temp }}/scan-findings/
    if-no-files-found: warn
    retention-days: 7
```

For Google Gemini, use the `GEMINI_API_KEY` secret, `JUDGE_DECISION_MODEL=gemini-decision-1`,
and `--judge gemini`. Evidence-only development jobs can omit `--judge` to avoid paid requests.
Those jobs leave semantic assessments unrun. [Provider setup](decision-models.md#credentials-and-local-environment)

Download the artifact to open the HTML locally and retain JSON for agent analysis. Uploading an
artifact does not automatically import SARIF into a code-scanning service; use that service's SARIF
ingestion step separately when enabled. Review artifact access/retention because reports contain
source excerpts. Exit codes distinguish a completed run from a stopped judge. Finding severity
does not currently gate CI. See GitHub's
[artifact guide](https://docs.github.com/en/actions/tutorials/store-and-share-data) and
[upload action](https://github.com/actions/upload-artifact) for supported runner/edition requirements.
