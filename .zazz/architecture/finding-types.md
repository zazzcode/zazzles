# Finding-type glossary and result status

## Purpose

The public philosophy and result meanings live in [root user documentation](../../docs/README.md),
with [category guidance](../../docs/scan/glossary.md) and [remediation philosophy](../../docs/philosophy.md).
This document owns the internal taxonomy contract.

Use one project vocabulary across canonical JSON, standalone HTML, and SARIF. A type describes the
risk family under review; the result status describes what the evidence establishes. Type labels
must not independently promote an observation or unresolved analysis item to a vulnerability.
This taxonomy is zazzles's terminology contract, not a claim that every listed detector is implemented.

The authoritative definition registry is
[`scan/internal/report/finding_types.go`](../../scan/internal/report/finding_types.go). Each definition has a
stable `id`, display `label`, plain-English `description`, `interpretation`, `remediation` approach,
and `coverage`. Human findings reference it through `type_ids`. Presentation version 2 introduced the
registry as `finding_types`; schema-v1 raw evidence remains unchanged and compatible.

## Initial vocabulary

| Stable ID | Display label | Coverage |
|---|---|---|
| `sql-injection` | SQL Injection | Bounded query/use analysis |
| `nosql-injection` | NoSQL Injection | Bounded expression/document analysis |
| `input-validation` | Input Validation | Bounded field/check evidence |
| `account-creation-validation` | Account Creation Validation | Declared account-creation checks |
| `outbound-request-safety` | Outbound Request Safety | Bounded outbound-use evidence; not complete SSRF detection |
| `reflected-xss` | Reflected XSS | Planned; no current assignment |
| `sensitive-data-logging` | Sensitive Data Logging | Planned; logger-leak detection follows the reporting work |
| `sensitive-operation-review` | Sensitive Operation Review | Fallback for unresolved operation kinds |
| `information-exposure` | Information Exposure | Bounded PHP diagnostic-output analysis (CWE-200, CWE-215); listed only when a record of the kind exists |
| `mass-assignment` | Mass Assignment | Bounded PHP key-controlled write analysis (CWE-915); listed only when a record of the kind exists |
| `missing-authorization` | Missing Authorization | Bounded PHP authorization analysis (CWE-862, CWE-639); listed only when a record of the kind exists |
| `address-based-access` | Address-Based Access | An operation limited by the caller's network address (CWE-291); listed only when the only guard is an address check |

XSS is cross-site scripting; the spelling is XSS, not XXS. NoSQL remains one word. Use neutral
**Input Validation** for the family: **Poor Input Validation** is a conclusion requiring an applicable
field requirement and evidence of insufficient enforcement. Protected, unassessed, and unresolved
validation records must not receive that conclusion by default.

For example, a SQL Injection pill may accompany observed string construction, an ORM binding question,
or a protected parameterized operation. The status and evidence distinguish those cases. A NoSQL pill
can cover executable `$where` construction or unresolved type/operator behavior in a document; merely
using a structured document does not establish injection. Planned glossary entries never create
findings, row pills, or detection-coverage claims.

## Mapping and aggregation

Map from the use/check kind and evidence gaps, never source filenames or target-specific challenge
names. SQL and NoSQL uses can also carry Input Validation when field/check evidence is present.
A record may therefore reference several types. Keep all raw use IDs, route IDs, gaps, assessments,
and completeness evidence intact; this is presentation classification, not another detector.

Rows show each type once, counting associated records. Pill labels preserve poor-practice,
review, protected, or mixed state. Mixed-state aggregation must not conceal protected or unresolved
records by assigning the entire family the most severe state. Type counts overlap across families
and must not be summed into a unique-finding count.

The [HTML design](html-reporting.md#finding-type-pills-and-glossary) owns presentation. Native popover
panels show definitions separately from finding details; an inline expandable glossary provides the
same descriptions. JSON retains the full definitions for agents, and SARIF uses `scan.findingTypes`
plus each result's existing `scan.finding` record. Descriptions are escaped text and cannot supply
markup, scripts, or remote resources.

## Extension and verification

Add definitions with stable IDs and explicit coverage as detector contracts develop. Changing a label
or description does not authorize detection work. Revisit presentation versioning if field semantics
change; preserve raw schema compatibility and document changes in the reporting contract.

Tests cover mapping, optional field-validation types, unique and complete registry definitions,
planned-type exclusion, row aggregation with mixed statuses, JSON/SARIF references, native panel
controls, separate route/finding locations, escaping, and deterministic output. Actual interactive
behavior still needs browser/human UI verification; static tests do not replace that acceptance.
