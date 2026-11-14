# Finding categories and terminology

[Documentation index](README.md) · [Interpret results](interpreting-results.md) · [Philosophy](philosophy.md)

## Categories are not verdicts

Categories group related concerns. **Findings**, **Review**, and **Protected** describe the evidence
and required action. A finding can be an established vulnerability or a poor practice worth fixing
without a demonstrated exploit. A Review category is a question, not an established defect.

| Category | Meaning | Current scope |
|---|---|---|
| **SQL Injection** | Input can affect SQL structure; review executable text separately from bound values | Bounded SQL construction/binding analysis; string-built query practice can merit refactoring without an established exploit |
| **NoSQL Injection** | Input can affect operators, selectors, or executable expressions | Initially bounded MongoDB/Mongoose and MarsDB-compatible `$where`/document analysis; other engines need separate models; executable string construction is a practice finding, unknown document constraints are Review |
| **Input Validation** | A server-side field policy governs presence, runtime type, format, range, or length | Bounded validation evidence; absent modeled checks alone are Review |
| **Account Creation Validation** | Required fields and guards must hold before persistence | Declared account-creation cases; general bypass discovery is incomplete |
| **Outbound Request Safety** | Destination, headers, or request values need appropriate constraints | Bounded use evidence; not complete SSRF detection |
| **Reflected XSS** | Request content executes as script when reflected into a browser response | Planned; not assigned by the current detectors |
| **Sensitive Data Logging** | Logs expose secrets or other sensitive values | Bounded: verified console/winston calls in route handlers and morgan access logs of query credentials; see [logging rules](analysis/sensitive-data-logging.md). A constant startup message is not a leak |
| **Sensitive Operation Review** | A possible operation does not map to a more specific supported family | Review fallback |

XSS means cross-site scripting. NoSQL is one word. **Poor Input Validation** is a conclusion requiring
an applicable business requirement and evidence of inadequate enforcement. The neutral Input
Validation category can also accompany unresolved checks or protection; it should not imply that
valid free text must reject punctuation.

## Other terms

- **Poor practice:** an established construction or rule violation worth remediation/refactoring;
  demonstrated exploitability is not required.
- **True positive:** the named finding is supported against its actual rule/claim. A true-positive
  practice finding is not automatically proof of a related injection exploit.
- **Claim:** a specific question about a field, operation slot, validation rule, or protection.
- **Source / transfer / use:** where a value originates, how the supported analysis carries it, and
  where an operation consumes it. These are bounded static relationships, not an execution trace.
- **Blocker:** a missing fact needed to decide the named claim. A coverage gap may affect a broader
  analysis without blocking every local conclusion.
- **Protected:** sufficient protection for one named claim, not a route-wide security certification.

In HTML, select a category pill for the full definition, interpretation, coverage, and remediation
approach. The inline glossary provides the same information without a side panel. JSON carries the
shared definition registry for agents, and SARIF retains it in namespaced scan properties. Type
counts overlap; do not sum them as independent findings.
