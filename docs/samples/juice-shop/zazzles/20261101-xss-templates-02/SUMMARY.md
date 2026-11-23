# Server template construction increment

2026-11-01; offline. Source/tool identities and hashes are in [metadata](metadata.json).
Open [HTML](https://zazzcode.github.io/zazzles/juice-shop/zazzles/20261101-xss-templates-02/findings.html), [JSON](findings.json), or [SARIF](findings.sarif).

Juice Shop profile username and video subtitle flows now have source-backed storage-read,
template-replacement, compile and response witnesses. Both remain Review: request-to-storage write
origins and some transformations/configuration remain unresolved. No challenge labels drive verdicts.
There are 152 route entries, 164 uses and two XSS records.
