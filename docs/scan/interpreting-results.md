# Interpreting zazzles results

[Documentation index](../README.md) · [Philosophy](../philosophy.md) · [Categories](glossary.md)

## Findings, Review, and Protected

| Column | What it establishes | What an agent should do |
|---|---|---|
| **Findings** | A named problem exists: a vulnerability or poor practice supported by the rule's evidence | Remediate or refactor it and verify the correction |
| **Review** | A problem or sufficient protection has not been established | Resolve the evidence or policy question; decide whether a change is needed |
| **Protected** | Adequate protection for the named claim is supported by the assessment/evidence | Preserve it and check other claims separately |

Poor practice is actionable. It does not need a demonstrated exploit to justify a correct refactor.
Review is uncertainty about the problem or protection, not an instruction to postpone an established
problem until someone proves exploitation.

**Inconclusive** means the available evidence does not support a definitive judgment for that
question. It is a result within Review, not a safe verdict. The human view uses this label for raw
`unknown`, `uncertain`, and `needs_evidence` values. JSON preserves those machine values for
compatibility and audit; `not_run` remains **Not assessed** and `failed` remains **Assessment failed**.

A CWE-502 finding describes the impact of the verified deserializer. A code-capable format
supports code execution by design. PHP object injection depends on the classes available to the
application. Unresolved loaders, schemas or required versions leave the record in Review.
[Unsafe deserialization coverage](detection-capabilities/unsafe-deserialization.md)

## Status colors

The HTML uses soft fills with readable text and explicit labels:

- **Soft red:** a definitive vulnerability judgment supported by scanner analysis.
- **Soft orange:** established poor practice to remediate or refactor.
- **Soft blue:** Review; the problem or adequate protection remains unresolved.
- **Soft green:** protection supported for the named claim.
None reported uses plain muted text without a shaded box; it means no category records for the
source entry.

Red is reserved for a definitive scanner verdict. The bounded query classifier can emit a
source-supported static vulnerability when its injection-specific assessment and evidence gates
pass. This is not runtime exploit confirmation or a claim of general detection accuracy.
A user-confirmed example is an acceptance target for improving analysis, not an automatic red override.
An advisory model answer alone is also insufficient to promote a record. Labels remain visible so
color is never the only way to understand status.

## Model-resolved records

Some records reach their status through a **model-resolved** fact: the scanner could not establish
a flow, a stored origin or a witness itself, asked the decision model a specific question, and
verified the evidence chain the model cited against the request. Such a finding has the same
status as a scanner-proven one and carries a **Model-resolved** badge (JSON `model_resolved`, SARIF
`scan.modelResolved`) naming the provider, model, question version, cited evidence IDs and spans,
and the blockers it resolved. Every answer, verified or rejected, stays in
`assessment.resolutions`.

Treat the mark as a review pointer: read the cited spans before remediating. A model-resolved fact
does not make a record Protected unless the scanner holds the coverage fact itself.

## Current presentation statuses

| JSON status | Display | Placement |
|---|---|---|
| `confirmed_vulnerability` | Confirmed vulnerability · static analysis | Findings; requires injection-specific judgment and claim evidence |
| `poor_practice` | Poor practice · remediate | Findings; current rules recognize string-built SQL and executable NoSQL `$where` construction when at least one built-in value has an external origin |
| `needs_review` | Analysis needs review | Review; e.g. unmodeled document types, unclear validators, unknown APIs |
| `needs_evidence` | Inconclusive | Review unless a separate deterministic poor-practice conclusion already holds |
| `supported_potential` | Potential vulnerability · review | Review; preserve the model's answer without presenting it as an established vulnerability |
| `protected_for_claim` | Protection supported for this claim | Protected, scoped to the named claim |
| `not_applicable` | Not applicable to this claim | Review/reference record; not a general safety pass |

The renderer preserves the evidence-gated scanner judgment; an advisory practice answer alone
does not establish a vulnerability. See the [analysis rules](analysis/database-injection.md).
Its deterministic poor-practice findings remain actionable if assessment was omitted, failed, or
cannot decide exploitability. A model-supported protected injection claim also does not automatically
remove a separately established string-construction practice finding: the two address different
properties. Raw model answers and statuses stay in the evidence record.

## Counts and categories

Categories identify related risk families and may overlap. One query-construction record can carry
SQL Injection and Input Validation labels without proving two independent defects. A category name
is not a vulnerability verdict. Select a pill for a definition and its coverage.

JSON keeps one presentation record per raw use. HTML, text and SARIF show one row per **sink
group**: records of one kind at one sink span with one presented status. The first record in report
order represents the group; it lists the others in `grouped_use_ids`, they carry `grouped_into`, and
its summary names the record count, the entry count and the origins across them. Records with
different statuses never share a row, so a finding is never hidden behind a Review row. A grouped
SARIF result carries `partialFingerprints.zazzlesSinkGroup/v1` (kind and sink span), the other
entries as related locations, and `properties.scan.groupedUseIds`. Findings/Review/Protected count
the shown rows; category counts count associated records and must not be added together.
One record may contain multiple field or protection concerns. Distinct claim-level counting is a
planned improvement: independent established problems should ultimately count separately, with
shared operation/evidence links. Shared helper records can also repeat for multiple routes.

Each record carries `assessment_state`: `not_run` (unjudged), `completed` or `failed`. An unjudged
Poor practice or Review is an offline scanner result, not a model judgment; HTML shows a "Not judged"
badge and SARIF an `assessmentState` property. Review records list `blocking_evidence` entries
(`kind`, `detail`, `source` = `policy` for judged verdict gates or `scanner` for candidate gaps and
missing required evidence). Independent claims of different families on one operation, such as an
open redirect and a DOM XSS on the same navigation, stay separate and list each other in
`linked_use_ids`. SARIF carries both lists under `properties.scan`.

## Locations and evidence

**Declaration location** points to the entry registration or schema declaration. **Finding location** inside the expanded row
points to the recorded operation; it can be in another file. Inspect the operation excerpt, inputs,
transfers, relevant context, guards, and gaps before applying a change. No resolved request dependency
means external control is unknown, unless there is positive evidence of a constant or trusted source.
A string-built query whose values have no request, storage, file, fetched, browser or API-response
origin presents as Review with `external_origin_not_established`, not as a poor-practice finding.
An XSS record whose output context is `unknown` shows protection `unknown`; per-path protection keeps
what each path showed.

A record held at Review by `storage_origin_unresolved` carries `stored_origin`: for each storage key
it reads, every write found in scanned source (with `literal` when the written values are source
literals), `static_read` when the read query is a literal, and `closed_store` (`closed` when the
schema and every writer are in scanned source, `open` when the schema is not, otherwise `unknown`).
These are evidence for review; they never change the status by themselves.

A field's business validation and its destination protection are separate questions. SQL binding,
NoSQL operator/type constraints, numeric conversion, escaping, and arbitrary string filters have
different effects. An ORM search value containing interpolation is not automatically executable SQL.
Missing modeled validation alone does not establish that every runtime path lacks validation.

## Remediation workflow

- For Findings, identify the named practice/weakness and its source evidence. Apply the smallest
  correct remediation, including complementary improvements when each is independently established.
- For Review, resolve the specific unknown first. Examples include confirming the actual driver,
  reading a validator body, checking middleware order, and defining the field's business policy.
- Preserve existing supported protection. Test intended normal input, malformed input, and the
  operation-specific safety property after making a change.

Report examples are illustrative, not applied or verified patches. JSON includes `entries`, `uses`,
`gaps`, `files`, `limitations`, presentation `findings`, `finding_types`, and `presentation_version`.
Human records reference `use_id`, `entry_id` and `invocation_context_id`; raw assessments preserve provider/model, answers,
completion status, blockers, and scope. HTML and SARIF are offline views of that evidence.

## Request size and omitted evidence

A decision request is limited to 65,536 bytes. A request under the limit is sent unchanged. Over the
limit the scanner first uses its lossless compact form, then leaves out whole context evidence items
(text already inside another item first, then context in other files, then same-file context furthest
from the operation). Dependency, control and required evidence is never left out. The request states
the omissions in an `evidence_omitted_for_size` gap as counts by kind and one line range per file,
and the record lists each one in `assessment.evidence_omissions`. If the required evidence alone is
too large, no request is sent and the record stays **Inconclusive** with a reason starting `evidence_too_large:` and the bytes by section.

## Outbound observations and SSRF

Outbound observations carry `outbound.destination_origin` (`request`, `external_data`, `constant`,
`environment` or `unestablished`) for the destination argument only. Observations of one call reached
from several entries are shown once (the sink grouping above; outbound observations group by call
site and keep their own summary); request-derived destinations stay separate. SSRF claims report destination control, restriction and
coverage separately; see [SSRF analysis](analysis/ssrf.md).

## Completion and compatibility

`not_run`, `failed`, and `completed` describe semantic-assessment execution, independently of whether
static analysis establishes poor practice. Exit 0 means the scan ran to the end; incomplete assessments
are warned about on stderr and explained per record. Exit 1 indicates a setup or execution failure,
or a judge stopped by an account failure or an unresponsive decision model; a retained report may
still contain useful findings.
Exit 2 means invalid CLI usage. There is currently no finding-severity CI gate.

Presentation version 3 introduces this distinction. Older schema-v1 evidence remains exportable:
regenerating HTML/SARIF rebuilds the current interpretation from raw uses. Legacy `observed_pattern`
is not a new verdict. Saved source evidence and model assessments are preserved; previously generated
views remain snapshots until regenerated. Independent review and runtime confirmation are separate.

## Entry identities and coverage

HTML, text, JSON findings and SARIF share the same contextual statuses. HTML groups by
entry ID: HTTP method/path, GraphQL schema coordinate, gRPC service/method, or browser
component/source identity. Unknown kinds and legacy unresolved associations remain
inspectable with a fallback label. Declaration locations and registration/dispatch/context
details are separate from the sensitive operation's finding location.

Zero-use entries and unresolved alternatives remain coverage records. Hiding protected
results retains rows with coverage gaps. A Protected count names scoped claims; it never
certifies an entire entry, including its unexamined alternatives. Counts are contextual
uses, so a shared callable can appear under several independently assessed entries.

SARIF keeps the operation/sink primary, with entry declaration, registration/schema/proto
and callable locations related. Namespaced properties retain typed entry and invocation
metadata. Entry/scan gaps without uses appear in invocation metadata/notifications, without
fabricated security results. Saved report exports preserve raw historical answers and do
not rerun analysis or transfer those answers onto changed requests.

## Evidence wire versions and historical judgments

Current model requests use evidence wire version 8. Compact evidence rows retain file
and line ranges, put source text last and omit trailing empty columns; context facts
refer to evidence IDs, and dependencies preserve each source, transfer, operand slot and
storage key (a transfer run shared by several dependencies is stated once in
`shared_transfer_tails`). Entry, invocation, dispatch and candidate identifiers are sent
as request-local aliases (`i0`, `i1`, …) where they occur more than once and left out
where they occur once; identifier lists such as `xss.related_entries` become a count plus
the aliases that recur. Full identifiers, source hashes, byte coordinates and selected
component digests remain in local report and trace provenance.

Wire representation changes invalidate exact saved-request replay. Historical reports
remain readable with their original model answers; a current scan needs a fresh
judgment when its evidence or protocol changed. Source-proven transparent JavaScript
and TypeScript wrappers can resolve dispatch, while wrappers with mutations,
argument changes, repeated calls or unknown effects retain coverage limits.
