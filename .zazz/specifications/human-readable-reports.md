# Human-readable scan reports

Historical contract/evidence below retains its original names. Current package, CLI and report
names are documented in the [implemented architecture](../architecture/README.md#naming-and-compatibility).

## Outcome and authorization

The user requested clearer input-validation and database-sink results, fresh offline scans of Juice
Shop and the vulnerable TypeScript app, and an expandable standalone HTML report generated from saved
JSON. Implement in the assigned `logger-leak` worktree before logger-leak detection.

## Scope and decisions

- Add optional `findings` and report-presentation version fields to schema-v1 evidence JSON. Preserve
  raw entries, uses, gaps, and assessments. Human findings reference the originating use and route IDs.
- Root `docs/` owns the public philosophy and user/contributor guides, indexed by `docs/README.md`.
  The repo README remains a standalone introduction and quick-start. `.zazz/` retains engineering
  design, planning, contracts, evaluation evidence, and SDLC processes; internal docs link to user
  guidance instead of serving as its only home.
- Findings name established vulnerabilities or poor practice worth remediation/refactoring, without
  requiring proof of exploitation for a practice violation. Review means uncertainty about whether
  a problem or sufficient protection exists. Version 3 labels deterministic SQL and NoSQL executable
  string construction `poor_practice`. Missing modeled document constraints or validator calls alone
  remain Review. A model's `supported_potential` alone remains Review; it does not prove a vulnerability.
  Independent practice findings remain actionable even if model assessment fails, is inconclusive,
  or supports a separate protected injection claim. Preserve raw evidence and model answers.
- Preserve the existing detector and judge eligibility; do not promote findings based on display text.
- SARIF remains the standard interchange output and preserves human context in namespaced properties.
- Use soft red/orange/blue/green for definitive scanner vulnerability/poor practice/Review/Protected,
  with labels as well as color; None reported appears as plain muted text without a shaded box. Reserve red until
  scanner evidence supports a definitive verdict. Do not use a manual-confirmation override.
- The HTML contains only scan results; tool comparisons stay in evaluation documents.
- Use NoSQL consistently; comparator cells say “NoSQL: no finding reported.”
- Provide `--export-html <saved-json>` using Go `html/template`, embedded CSS, and native details/summary
  rows. One small embedded script handles sorting only; no CDN, browser JSON fetch, or server. The HTML is regenerated from saved JSON and
  lives beside it; regeneration must require no target-source access or model call.
- Add stable finding-type IDs and a shared glossary to JSON/SARIF/HTML presentation. Row-end pills
  summarize distinct types and preserve observed/review/protected state. Type names identify risk
  families, not confirmed vulnerabilities. Future Reflected XSS and sensitive-data logging definitions
  are marked planned and never assigned by existing detectors. Rename Registration to Route location;
  expanded records explicitly label Finding location. Native HTML popovers show one glossary panel
  per type with descriptions, interpretation, remediation, and a close button, without JavaScript.
- Default HTML rows to descending Findings/Review/Protected counts, then route path A–Z/method;
  blank rows last. Preserve stable ties and place unresolved paths after resolved paths within ties. Provide two sort controls: route path and one grouped Findings/Review/Protected
  count control (descending counts in that priority, then route path A–Z; empty rows last). Repeated
  activation reverses the selected order. Preserve expanded states and raw report data.
- Rows group by source entry, showing source type, method/path signature, location, counts, and analysis
  state. Expand for human findings, source excerpts, input/transfer/sink evidence, assessment state,
  limitations, and remediation. Retain entries without findings and unmatched uses without inventing routes.
- `--strings --output-dir <base>` writes a fresh private `<base>/<repo-name>/run-<id>/` folder with all three
  artifacts. `SCAN_FINDINGS_DIR` supplies the default base, overridden by the flag; an explicitly empty
  flag disables file output. Export/list modes ignore the environment variable. Explicit output-dir
  is accepted only for strings scans. Existing stdout JSON/SARIF modes remain machine-readable;
  text mode prints bundle paths. Requested-assessment failures retain the bundle and exit 1.
- Existing saved schema-v1 reports without presentation fields remain exportable. Invalid/schema-wrong
  input is rejected. Unknown properties remain compatible. Export must not mutate saved assessments.
- Update README compile/run/results guidance, comparison prose, and embedded JS/TS practice rules.
  No new detectors, paid calls, target execution, or target edits in this increment.

## Acceptance and verification

- Tests distinguish actionable construction practice from unknown ORM/document/validator behavior,
  and prove incomplete/failed/protected model outcomes do not hide an independent practice finding.
  HTML, JSON, and SARIF agree on record classification while retaining raw assessments.
- HTML escapes hostile source/path text, preserves provenance and remediation, groups by route ID,
  retains zero-finding rows and orphan uses, and permits only its hash-pinned bundled sorting script
  with no network resources.
- Verify taxonomy references, deduplicated row pills, independent status labels, registry coverage,
  planned-type exclusion, native popover targets/close controls, and route versus finding locations.
- CLI tests cover valid saved JSON, invalid input, output modes, and conflicting flags.
- Test output-dir precedence, disabled file output, separate successive runs, JSON/SARIF validity,
  private file permissions, unavailable paths, and the retained exit-1 bundle after assessment failure.
- Rerun both pinned targets offline; compare detector use/gap totals against baseline, validate finding
  references, and export JSON/HTML pairs. Inspect representative expanded rows in a browser.
- Run Go tests with race detection, vet, build, format, and documentation checks. Use scoped tests
  during development. Evidence and generated reports live under ignored `.zazz/ephemeral/`.

## Execution rules

Use [AGENTS.md](../../AGENTS.md), [testing](../standards/testing.md),
[code structure](../standards/code-structure.md), and [docs hygiene](../standards/docs-hygiene.md).
Work serially in this checkout, preserve existing edits, and record evidence in
`.zazz/ephemeral/human-reports-run-log.md`. Stop for unresolved evidence or scope changes; do not
fabricate security judgments to complete the presentation. Human UX feedback guides the next iteration.

## Implementation and review change log

### 2026-11-01 — Finding-type pills and glossary panels

User UI feedback requests row-end type pills, plain descriptions in a separate panel, and clearer
location labeling. Add shared presentation taxonomy and native HTML popovers; no new detectors or
upgraded vulnerability verdicts. Verify mappings, row aggregation, locations, and regenerated reports.

### 2026-11-01 — Remediation-first findings and public documentation

User steering clarifies that established poor practice requires remediation even without a demonstrated
exploit. Version 3 uses Poor practice findings versus Review for unestablished problems, keeps the
Findings/Review/Protected headers, and renames the type column Categories. Root `docs/` becomes the
user-guide and philosophy home with a linked index; internal designs and project planning stay in
`.zazz/`. Verification covers classification consistency and documentation migration/link integrity.

### 2026-11-01 — Grouped result sorting and spacing

User requests plain None reported text, space between Protected/Categories, and two sortable header
controls. The result-count block sorts Findings, Review, Protected together, then route path; the
other control sorts route path. Minimal bundled JavaScript reorders existing disclosure elements
without changing their state or source data; CSP permits only that exact script by SHA-256 hash.

### 2026-11-01 — Public samples and findings-first default

User requests publishing both target examples under root user docs, README links near the top,
default grouped findings-first ordering, and refreshable samples. Added docs/samples with paired
JSON/HTML/SARIF, source/version/assessment coverage, attribution, normalized public root labels, and
an offline refresh command. Default ordering is rendered server-side and matches script state, so
it also works with JavaScript disabled. Routine scan output stays outside the checkout.
