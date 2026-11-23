# Reflected server XSS increment

2026-11-01; offline, no model calls. Source identities and hashes are in [metadata](metadata.json).
Open [HTML](https://zazzcode.github.io/zazzles/nodejs-goof/zazzles/20261101-xss-reflected-01/findings.html), [JSON](findings.json), or [SARIF](findings.sarif).

Goof login raw EJS attribute output is an orange finding (GOOF-XSS-01). Six escaped Handlebars
outputs are Protected; the custom Dust engine remains Review. There are 17 selected route entries
and 18 use records, including eight XSS records. Stored todo and browser flows are not completed
by this increment.
