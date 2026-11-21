# Standalone HTML reports for CLI runs

## Purpose and ownership

Public philosophy and report instructions live in root [user documentation](../../docs/README.md),
including [philosophy](../../docs/philosophy.md) and [interpretation](../../docs/scan/interpreting-results.md).
This document owns renderer design, not the sole copy of user-facing semantics.


HTML is zazzles's core human-facing report for CLI runs. The canonical JSON is the richer agent-readable
artifact; SARIF remains the standard interchange output. See [reporting and SARIF](reporting-and-sarif.md)
for shared statuses and evidence ownership. HTML contains zazzles's own results only. Comparisons to
other tools belong in evaluation documents, never in the product report.

## Inconclusive judgments

The human-facing label for raw `unknown`, `uncertain`, and `needs_evidence` values is
**Inconclusive**. It describes an unresolved judgment within Review, independently of an established
poor-practice finding on the same operation. Assessment execution remains separate: `not_run` is
Not assessed, and `failed` is Assessment failed. The renderer MUST preserve raw JSON/provider values
and source excerpts; display terminology does not change the protocol or assessment outcome.

## Data path

```text
Source analysis → raw uses / assessments → human-readable finding records → canonical JSON
                                                                         ├→ standalone HTML
                                                                         └→ SARIF 2.1.0
```

`--analyze --json` includes additive human-readable `findings` and `presentation_version` fields.
`--export-html <saved.json>` reads a schema-1, schema-2, schema-3 or schema-4 analysis report and renders HTML offline; no target-source
read, key, model request, application execution, or server is needed. `--export-sarif` uses the same
saved report. `--analyze --output-dir <base>` or `SCAN_FINDINGS_DIR` writes all three formats under
`<base>/<repo-name>/run-<id>/`. The explicit flag overrides the environment; an empty flag disables file
output. Repository names come from the target basename; clones with equal basenames share a repository
folder but never a run folder. Run directories use private permissions, and output files are created
exclusively with mode 0600. Existing runs are never overwritten. The output base is configurable,
without a machine-specific default. The local workspace convention is a sibling `_test-findings/`.

The CLI keeps stdout JSON/SARIF redirectable while reporting the bundle path on stderr. Text mode
prints bundle paths instead of the full text report when file output is active. Without file output,
existing stdout behavior remains available. Export and list modes ignore the output environment
variable; an explicit output-dir flag is valid only for analysis scans. `.env` is not auto-loaded.
The user places regenerated JSON, HTML, and SARIF in the same run folder. Each generated view is a snapshot and must be regenerated after JSON changes.

The exporter rebuilds deterministic presentation from saved raw uses, supporting older schema-v1
reports without human fields. It preserves raw assessments and blockers; it does not invent a model
answer or reclassify a finding as confirmed. `scan/internal/report/findings.go` is the common presentation
rule layer. Driver-specific remediation comes from `guidance.go`; illustrative examples are not patches.
The CLI rejects invalid JSON, unsupported schema versions, route-only reports, and incompatible flags.
Saved input is capped at 64 MiB by the shared JSON export reader.

## Entry grid and disclosure

Show one expandable entry per inventoried source, grouped by entry ID rather than path alone. Columns:
source type, typed entry identity, **Declaration location**, finding count, analysis-review count,
protected-claim count, and row-end finding-type pills in **Categories**. Declaration location is the source declaration,
not a finding location. An unresolved entry displays “Not resolved”; operation locations remain
in the expanded records labeled **Finding location**. Default to descending Findings, Review, Protected counts, then entry label A–Z and method. Two keyboard-accessible header buttons sort entry label or
the grouped Findings/Review/Protected counts. The grouped descending order compares those three
counts in that priority, then path A–Z and method, leaving empty rows last. Repeated activation
reverses the selected order. The count block is one control, not three independent sorts. Keep stable input order for ties and place unresolved entries last. Distinct HTTP methods sharing a path remain separate. Presentation version 6 uses typed HTTP/browser/GraphQL/gRPC labels and generic unknown-kind
fallbacks from `scan/internal/report/entries.go`. Each entry discloses registration, dispatch alternatives,
callable locations and invocation bindings. Zero-use coverage gaps remain visible, including while
hiding protected records. Only final claim-level protection is green. A use without a matching
entry appears under an explicit unresolved entry. Presenters do not imply adapter support.

Native `details` / `summary` elements use CSS Grid to align row summaries. This is a disclosure list
with column styling, not an ARIA interactive grid. Keyboard activation, visible focus, and native
expand/collapse behavior work without JavaScript. Narrow layouts stack the columns and label counts.
The expanded row contains:

- Established practice findings, incomplete analysis items, and scoped protection with distinct status labels.
- Plain-English behavior and separate input-validation / use-protection explanations.
- Source locations, operation excerpt, resolved inputs and transfer evidence, and additional context.
- Raw assessment state/provider/model, declared checks, gaps, blockers, and scope limitations.
- Remediation actions and optional explicitly unverified illustrative examples.

Zero-finding entries remain visible with “No findings reported within the analyzed scope,” plus their
analysis gaps. They do not receive a safety badge. Counts describe route/use records, not unique
vulnerabilities; shared helper observations can appear under several routes. No severity or exploit
confirmation is invented for offline observations. The review and runtime-confirmation stages remain
unimplemented; opening an HTML report does not perform either stage.

## Remediation-first presentation classification

Version 3 implements the [public philosophy](../../docs/philosophy.md): Findings include established
poor practice to remediate/refactor, even without exploit confirmation. String-built SQL and executable
NoSQL `$where` construction receive **Poor practice · remediate**. Incomplete validator/document type
evidence stays Review. Potential model answers alone also stay Review. A deterministic practice
finding survives inconclusive/failed assessment and a model's protected result for a separate claim.
Raw assessments remain visible; no new exploit confirmation is invented.

The shared `describe` classification drives row totals, category pill states, JSON, and SARIF. Findings
show Remediation and Fix scope headings; Review records show investigation and unresolved questions.
Categories overlap and do not define independent counts. Atomic multi-claim counting remains planned.

## Finding-type pills and glossary

Presentation version 2 introduced `type_ids` to each human-readable finding and a report-level
`finding_types` registry. The canonical definitions live in
[`scan/internal/report/finding_types.go`](../../scan/internal/report/finding_types.go); [finding-type design](finding-types.md)
owns their interpretation. JSON carries definitions and references; SARIF retains definitions in
`scan.findingTypes` and references in `scan.finding`. Existing saved schema-v1 input is reinterpreted
from raw uses at export time with the current presentation, without upgrading raw assessment state.

Deduplicate type pills per row. Each pill shows the family, record count, and poor-practice/review/
protected/mixed status. A family label such as SQL Injection identifies what is being reviewed, not a
confirmed vulnerability. Planned types are documented in the glossary but never attached by existing
detectors. Counts are per use and type; one record can belong to both SQL Injection and Input Validation.

Pill buttons use `popovertarget` to open a native `popover="auto"` side panel outside the row's disclosure.
One panel per registry type includes a definition, interpretation, coverage, and remediation approach.
A native hide button closes it; the browser provides light dismissal and Escape handling. Rows retain
native `details` controls. No JavaScript is required, and source text remains escaped. The complete
registry is also available in an inline expandable glossary for reference, printing, and browsers
without popover support. Popover panels themselves are hidden when printing.

The native behavior follows [MDN's declarative popover guide](https://developer.mozilla.org/en-US/docs/Web/API/Popover_API/Using).

## Soft status palette

Use soft red for scanner-supported definitive vulnerability judgments, orange for established poor
practice, blue for Review, and green for Protected. Plain muted text says None reported, without a shaded box. Protected and Categories have explicit spacing. Row backgrounds remain unchanged.
Keep explicit status labels and readable contrast. The red CSS treatment is reserved for
`confirmed_vulnerability`, emitted only from the evidence-gated injection judgment described in
[query judgment design](query-judgment.md). User statements and practice answers must not become
scanner confirmation through a presentation override. Palette styling is not detection logic.
The verdict is a bounded static judgment; independent review/runtime confirmation remain separate.

## Standalone behavior and source safety

Go `html/template` escapes report text, code, source paths, and locations. Source excerpts are untrusted
text and must never be cast to trusted HTML. CSS and markup are bundled with the scanner, with no
remote fonts, CDN dependencies, automatic JSON fetch, or analytics. A small compiled-in script
reorders existing rows only, preserving open state and source text. Escaped data attributes carry
counts/path/method; report values never become JavaScript. CSP permits the exact script SHA-256 hash
and blocks other scripts and network resources. Controls are disabled when the script cannot run;
default findings-first rendering, expansion, and glossary controls remain usable. The generated file can be opened directly
with `file://`; browser access to a neighboring JSON file is unnecessary.

Reports contain source excerpts and must be handled with the target source's access controls. The
current viewer does not link to or execute arbitrary source paths. Optional future filtering
and expand-all controls would require a separate UX decision; they are not needed for native row
expansion. Standard browser find remains available, although matching inside collapsed disclosures is
browser-dependent. Printing follows the current disclosure state; expand required rows before printing.

## CI/CD retention

Point the output root at the runner's temporary storage. Upload the complete tree with an always-run
artifact step, retaining JSON for agents, HTML for human download, and SARIF for standard ingestion.
Keep the scan step's failure visible: bundle creation does not mask a requested-assessment failure.
Early setup/analysis failure may produce no bundle; artifact upload must handle that case explicitly.
SARIF ingestion is separate from artifact upload, and a finding-based CI gate is not implemented.
Use CI-managed secrets only for deliberately configured paid runs; offline export needs none.

## Verification

Tests cover source/method grouping, orphan uses, zero-finding entries, source-text escaping,
recommendations and evidence, deterministic output, old schema-v1 input, invalid input, and incompatible
flags. Detector baselines are compared against fresh offline runs on the two pinned target repositories;
presentation changes must not alter raw use or gap totals. Browser inspection checks real expanded
findings and remediation. JSON/HTML/SARIF pairs and verification notes belong in ignored local run
artifacts; reusable rendering and classification tests belong in Go test sources.

Curated public samples live under [docs/samples](../../docs/samples/README.md), with canonical JSON
and offline-generated HTML/SARIF. Public root labels replace local absolute target paths.

Current analysis JSON uses schema4 and `analysis_guidelines`; schemas1–4 remain readable
through private compatibility decoding, retaining original source/schema/answer provenance.
See [naming and compatibility](README.md#naming-and-compatibility).

## Common entry associations

Existing HTTP and browser rows now project from one canonical entry/context model rather
than separate route/client ID authorities. HTTP presentation remains familiar; browser roots
remain in their own section. Entry rows include registration, dispatch and invocation gaps
even when no candidate use exists. Unknown associations retain explicit unresolved rows.
The shared template now presents typed entry labels, declaration/dispatch metadata and common
selectors without fabricated HTTP fields. JSON/HTML/SARIF status, identity and source-location parity
is covered by [cross-entry acceptance](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05).
Rendered sorting, disclosures, keyboard focus and390px layout passed bounded inspection through the
user-opened localhost HTTP tab. The initial file-preview restriction remains historical evidence;
actual reviewed HTML hashes and screenshots are indexed in the ignored acceptance artifacts.
