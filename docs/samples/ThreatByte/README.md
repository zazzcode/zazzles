# ThreatByte Python sample

[Samples](../README.md) · [HTML](findings.html) · [JSON](findings.json) · [SARIF](findings.sarif)

## Path traversal and Zip Slip results (2026-11-14)

[HTML](path-traversal/findings.html) · [JSON](path-traversal/findings.json) · [SARIF](path-traversal/findings.sarif) · [Provenance](path-traversal/metadata.json)

A separate scan of the pinned revision with only the path-traversal analyzer enabled and OpenAI
`gpt-6-luna` (`--only-family path`). Other analyzers were not run for this report, so use it alongside
the main report above. Static source judgments only; nothing was run or exploited.

Five file operations were judged in five requests (38,347 input tokens).

- **Confirmed vulnerability (1):** the upload `FileStorage.save` at `server/routes.py:264`.
- **Protected (2):** the `send_from_directory` calls at lines 302 and 334. Protection applies to those calls only.
- **Review (2):** `send_from_directory` at line 309 and `os.remove` at line 364.

Target: [anotherik/ThreatByte](https://github.com/anotherik/ThreatByte), MIT, pinned at
`ede28f2`. The source checkout was clean before and after analysis. Upstream source excerpts retain
their authorship; this is a scanner evaluation, not a remediation of the vulnerable application.

The report inventories 23 route/method entries plus one browser entry and 56 result records.
All 56 records have completed `gpt-6-luna` assessments. Four source-supported static vulnerabilities
are retained: dashboard SQL injection, reflected search output, stored country output and inline
jQuery comment DOM XSS. One additional construction-practice record for dynamic column names stays
unconfirmed for injection; its key allow-lists require better structural modeling. Input-validation
facets and protected bound-query/escaped-output controls remain separate.

The [18-case source inventory](cases.json) passes, including four reviewed SQL/XSS positives and the separate email-format practice defect.
[Reference review](reference.md), [source hashes](source-hashes.json),
[Semgrep baseline](semgrep/baseline.json), [Bearer baseline](bearer/baseline.json), and
[metadata](metadata.json) preserve the comparison. Semgrep's seven results include two locations for
one dashboard SQL case, plus MD5/IaC findings. Bearer's six results concern traversal, MD5 and debug
configuration. Neither baseline reports these three XSS flows or the request-influenced outbound URL.
Those totals span different scopes and are not accuracy percentages.

Source-backed form policy establishes a separate signup email-format defect; the required-only
login/signup fields have enforced presence guards. The parameterized insert still protects SQL syntax. Whole-session
logging, unresolved field origins, unknown transformations and outbound-destination semantics remain
Review where evidence is incomplete. This is not exhaustive coverage of the README's vulnerabilities,
independent findings-review completion, runtime exploitation, or whole-program soundness.

Reproduce the scoped comparison offline:

```sh
python3 docs/samples/evaluate-python.py ThreatByte docs/samples/ThreatByte/findings.json
```

Upstream license: [source license text](SOURCE-LICENSE.txt).
