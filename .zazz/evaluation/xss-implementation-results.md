# XSS first-pass implementation and evaluation

**2026-11-01, `xss-response`.** Discovery/reporting is implemented and the user requested that
additional analysis/judging hardening continue with a different agent in the same worktree.
The [handoff](../ephemeral/xss-analysis-handoff.md) is the entry point for that session.

## Current samples

| Target | Server entries | Client entries | Use records | Findings | Review | Protected |
|---|---:|---:|---:|---:|---:|---:|
| [Goof](https://zazzcode.github.io/zazzles/nodejs-goof/findings.html) | 19 | 0 | 33 | 2 | 29 | 2 |
| [Juice Shop](https://zazzcode.github.io/zazzles/juice-shop/findings.html) | 152 | 9 | 208 | 8 | 200 | 0 |
| [Vulnerable TypeScript app](https://zazzcode.github.io/zazzles/vulnerable-typescript-app/findings.html) | 19 | 0 | 20 | 1 | 19 | 0 |

These are use-level results, not confirmed-vulnerability totals. Categories overlap. Goof's login
has a source-complete static Luna XSS judgment; its stored Markdown output is an orange construction
finding with separate per-write-path protection; its earlier model answer no longer applies to that changed evidence. The two Protected records are the edit
template's content text/quoted-attribute outputs. Its account-details whole-object render options
remain Review, despite observed Handlebars escaping. Its `/about_new` query log is not labeled a
sensitive-data leak without data-class evidence. Input-validation and Mongoose NoSQL records and
the static `/users` mount are included; TypeORM object operations are not invented as raw SQL.

Juice Shop's client finding is the browser query → verified Angular trust bypass → search template
flow. Unresolved API producer fields, JWT/gallery/table/component/dialog links and trusted-wrapper
return types remain Review. The TypeScript sample's HTML search response is a reflected-XSS finding;
its SQL-looking login log remains distinct from an executed query. No current historical SQL model
answers were copied onto changed evidence/rules in the two offline targets.

## Hardening 08: stored write-path separation

Saved as `20261101-xss-hardening-08-paths` for all three targets and promoted to the canonical reports.
Offline, no model calls. Unsupported-statement traversal previously explored only direct block
children and merged just the last explored body: `else` clauses, single-statement branches and
`catch`/`finally` bodies were skipped, and an unchanged value merged with its pre-branch copy produced
duplicate dependencies. Now every body that can fall through contributes its exit; returning branches
do not. Identical source paths are one dependency, and a branch-only path carries its
`branch_consequence`/`branch_alternative` condition as a precondition. Each dependency is classified
by itself; `xss.paths` lists per-path protection and writing entry when siblings differ.

Goof against the [answer key](../../docs/samples/nodejs-goof/xss-answer-key.md):

| Case | Hardening 08 result |
|---|---|
| `GOOF-XSS-02` create | Two create paths: the image branch stores content unchanged (ineffective `marked` 0.3.5 path, with its branch condition); the non-image branch through `parse` is **unknown**. The key's documented bypass uses the non-image path; the scanner does not yet support that claim, because `parse` contains an untraversed `if` and is not precisely modeled. |
| `GOOF-XSS-03` update | Separate ineffective path written by `POST /update/:id`; it survives the merge. The sink stays one orange finding, with no claim of two unrelated vulnerabilities. |
| `N01`/`N02` | Still Protected: escaped output for these contexts on all three paths. |
| `N03`, `N04`, login `01` | Unchanged; the reflected, render-options, logging and NoSQL requests replay exactly. |

The stored Markdown request changed (20,366 bytes), so its saved Luna answer is not applied
(`not_run`); a fresh judgment needs separate authorization. Every other dependency change in the
three targets collapsed exact duplicates (Juice Shop Angular outputs from 64 to one) or added a
newly traversed branch; a key comparison found no distinct path lost. Newly traversed bodies add
Review records: Juice Shop whoami, continue-code, b2b and snippet JSON data edges and two webhook
outbound requests, and the TypeScript `/api/files` file-content response, which has an unresolved origin.

Remaining blockers at that point (helpers were addressed in hardening 09): `parse`-style helpers with
internal branches were imprecise, so their paths stayed unknown; branch feasibility (for example the image regex) is not evaluated; `switch` bodies are not
traversed; Juice Shop has 38 outbound-HTTP records sharing 11 IDs (36 before this change), a
pre-existing identity issue outside XSS.

## Hardening 09: helpers, string building, gates and same-sink merging

Saved as `20261101-xss-hardening-09` and promoted to the canonical reports. Offline, no model calls.

- **Branching helpers.** A helper with `if` branches is now entered precisely when every condition is
  content-neutral: lengths, `typeof`, literals, comparisons/logic over those, and `indexOf`/`includes`/
  `startsWith`/`endsWith` tests for a literal (or single unreassigned constant) without HTML-significant
  characters (`<>"'&` `` ` `` `=/:`), and no branch returns or throws. Any other condition may guard
  content, so the helper stays unknown. Goof `parse` qualifies: its unchanged path (no ` in ` token) is
  now a supported ineffective path, which matches `GOOF-XSS-02`. Paths through `slice`/`hms` stay unknown.
- **String building.** `a += b` now keeps `a`'s dependencies and adds `b`'s. Previously
  `h += req.query.q; res.send(h)` and `el.innerHTML += location.hash` produced no XSS record.
- **Sanitizer gates.** Plain `dompurify` counts only in browser flows; in Node without a window it returns
  its input, so server use is unknown (`isomorphic-dompurify` stays a sanitizer). A verified Handlebars
  or `hbs.handlebars` `SafeString` reaching escaped `{{…}}` output is raw; a look-alike object is not.
- **Angular per path.** Each path to a one-way binding is classified on its own: a matching
  `bypassSecurityTrust*` is unsafe, a plain path keeps default sanitization, a mismatched bypass or
  unknown wrapper is unknown. `bypassSecurityTrustStyle` is recognized.
- **Same-sink browser records** from module, function and class flows are merged rather than
  first-wins. Juice Shop's search-result sink previously dropped a later DOM record behind a cross-tier
  one. The merge keeps the strongest claim and retains siblings and an unlinked-API gap.

Goof now matches every answer-key case: `01` red (replayed), `02`/`03` as separate supported paths on
one orange Markdown finding, `N01`/`N02` Protected, `N03` Review and `N04` no finding. The stored request
changed again, so its saved answer stays `not_run`. Across the three targets, no use lost a source compared
with hardening 08, and statuses and counts are unchanged.

Fresh offline runs of the three real checkouts (Goof scanned directly at `<DEV_ROOT>/nodejs-goof`, not
the filtered snapshot) are under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/<app>/run-<id>/`.

Remaining blockers: branch feasibility is not evaluated; `switch` bodies are not traversed; numeric
facts such as `indexOf` results still carry content dependencies, which adds unknown sibling paths;
cross-tier producer/model/JWT/dialog links (handoff priority 3) are not yet linked, so the Juice Shop
product-description dialog sink remains unestablished; EJS custom `escape` options are not modeled;
duplicate outbound-HTTP IDs remain.

## Hardening 10: cross-tier response-field links

Saved as `20261101-xss-hardening-10` and promoted. Offline, no model calls.

- Server promise continuations (`.then`/`.catch`/`.finally`) are followed with the handler's request,
  response and closure bindings; their parameters are external results, not request data.
- Writes such as `result.data[0] = {orderId: id}` update local object fields. Branch conditions are also
  attached to nested fields.
- Each server JSON response is kept with its fields. A browser read of an API response records its
  JSON path (`data[].orderId`). The linker joins a cross-tier browser record to its origin only when
  exactly one route matches the method and path pattern and that field carries request-derived data.
  Unmatched, ambiguous, constant or merged fields stay Review with `response_producer_unresolved` or
  `response_field_unresolved`.
- Regex `replace` is classified: a global negated allow-list (`[^\w-]+` to `''`) is sanitization in
  HTML text, attribute, unquoted-attribute and URL contexts; removing only line breaks or tabs is neutral;
  anything else, including partial escaping, stays unknown.

Juice Shop `JS-XSS-02` (track order) is now a finding, linked to `GET /rest/track-order/:id`. Its three paths
match the answer key: the disabled branch's allow-list is sanitized, the enabled branch's truncation is
raw when the ID is short, and the `substr` path is unknown. Each carries the `result.data[0] === undefined`
precondition. `JS-XSS-N04` (CAPTCHA) stays Review: there is no request-derived producer field. The
application-configuration and feedback outputs stay Review: no matching producer, or a merged field.

Goof: modeling `profile.firstname = validator.rtrim(...)` as a local field write changed the
render-options request (4 paths instead of 1), so that saved answer, like the stored one, is no longer
applied. Three of five saved decisions still replay. No use lost a source; the only status change is
`JS-XSS-02`. Juice Shop gains two JSON data records from newly followed continuations.

Still open: stored and JWT origins behind API producers (`JS-XSS-03`/`04`/`06`); component input,
gallery `args` and dialog data aliases (`JS-XSS-05`/`06`); `switch` traversal; branch feasibility.

## Decisions and source references

Five specifically approved `gpt-6-luna` requests completed: **23,436 input tokens, 0 output tokens**.
[Raw requests/responses and scored answers](../../docs/samples/nodejs-goof/decisions/20261101-five-case-01/README.md)
are saved. No more live calls were made to preserve response confidence/probabilities or render
reports. Exact matching requests were replayed offline. The API supplied no narrative reasons;
policy explanations are scanner-authored. Scores are uncalibrated audit metadata, not evidence.

Source-reviewed expected outcomes and hashes are maintained separately for
[Goof](../../docs/samples/nodejs-goof/xss-answer-key.md),
[Juice Shop](../../docs/samples/juice-shop/xss-answer-key.md), and
[TypeScript](../../docs/samples/vulnerable-typescript-app/xss-answer-key.md).
These references are not detector input, runtime confirmation or a held-out accuracy benchmark.
Original target checkouts remain clean and pinned. Remediation uses independent copies.

## Increment and validation record

Saved report snapshots under each sample's `zazzles/` directory cover reflected output, template
construction, stored rendering, judgment, browser discovery and the current combined analyzers.
Earlier protection labels are historical and superseded by the audited current canonical reports.
Metadata records scanner working-source hashes, binary SHA256, target revision and source hashes.
The initial Bearer comparison is preserved separately; no raw comparator outcomes were rewritten.

Validation: native Go 1.27.3 darwin/arm64; `go test -race ./...`, `go vet ./...`, build and changed-Go
format checks passed. Tests cover positive/protected/unknown contexts, CommonJS/router bindings,
stored field links, templates, DOM/Angular/React/Vue, protocol consistency, retained response scores,
identical-request replay and client identity/export headings. The remediation filter was exercised
offline against mixed and protected-only sources, including reset behavior. HTML/JSON/SARIF were
regenerated from canonical JSON. Visual browser QA was not performed because file URLs were blocked
by the browser tool; structural/export checks do not replace a visual review.

Further hardening priorities and exact disagreements are in the local, gitignored handoff. No broader language
or whole-program accuracy claim is made; Python extraction is the next planned adapter after XSS.
