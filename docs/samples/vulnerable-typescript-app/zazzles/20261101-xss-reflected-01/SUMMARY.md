# Reflected server XSS increment

2026-11-01; offline, no model calls. Source identities and hashes are in [metadata](metadata.json).
Open [HTML](https://zazzcode.github.io/zazzles/vulnerable-typescript-app/zazzles/20261101-xss-reflected-01/findings.html), [JSON](findings.json), or [SARIF](findings.sarif).

The GET /api/search HTML response at src/server.ts:117 is an orange XSS finding.
There are 19 route entries, 16 use records, and one XSS record. No live model answers were reused.
