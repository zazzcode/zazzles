# Architecture phase 5 — Measured recall gaps and first closure

- **Worktree and branch** `recall-gap-inventory`
- **Plan** [Architecture update plan](architecture-update-plan.md#phase-sequence), phase 5
- **Prerequisite** Phase 1 integrated. Use current `origin/stage` and reconcile the phase 3
  package paths. Phase 4 changes assessment scheduling and is independent of this offline
  delivery. Follow the owner's phase order.
- **Delivery** One assigned worktree and one draft PR into `stage`. Separate inventory and
  closure commits when a closure is eligible.
- **Run log** `.zazz/ephemeral/architecture-phase-5-accuracy-gaps-run-log.md`

## 1. Capability

Produce a reproducible offline inventory of source-reviewed positive candidates and expected
registration outcomes, then close at most one bounded structural miss. Measure candidate presence
and evidence quality independently of model assessment. A source-established positive that already
has a candidate may still need better evidence, policy, or assessment coverage. Record that
diagnosis for the relevant follow-on and keep this delivery focused on candidate and registration
recall.

Reconcile known historical results before choosing work. The current VulnPy guide still groups
`VP-XSS-JINJA` with deferred work. The existing case key, language adapter and XSS evaluation
document the delivered support. Check the current pin offline and correct the historical guide
sentence, documenting any current regression separately if one is observed.
[VulnPy guide](../evaluation/vulnpy-detection-guide.md#d5-confirmation-and-remaining-gaps) ·
[XSS evaluation](../evaluation/xss-hardening/final-evaluation.json)

## 2. Required reading

- [Plan and shared rules](architecture-update-plan.md#shared-rules-for-every-phase), [implementation plan](../project/implementation-plan.md), and [architecture baseline](../evaluation/architecture-baseline.md#guard-test).
- [Sample catalog](../project/vulnerable-sample-apps.md#applications) and [sample handling](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps).
- [Source index](../architecture/repository-graph.md#implementation-direction-source-index-not-a-graph-store-2026-11-17), [D5 results](../evaluation/common-entry-dispatch-results.md#d5--bounded-dynamic-http-registration-2026-11-04), and [summary witness completion](architecture-phase-1-summary-completion.md#1-capability).
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [calibration controls](../../docs/analysis/calibration.md#regression-pairs), the selected family's [analysis guide](../../docs/analysis/README.md), and [testing standards](../standards/testing.md).
- [Python evaluator and keys](../../docs/samples/evaluate-python.py), [DVWA structural checks](../evaluation/dvwa-detection-guide.md#coverage-boundaries-and-acceptance), and the source keys in §5.

## 3. Invariants

- The source oracle stays independent of scanner output. Record disputed rows with source evidence
  and their disposition pending source review. Preserve existing answer keys.
- Sample checkouts are read-only at the exact pins. Offline runs use no provider or discovery.
- Candidate evidence stays specific to the operation, operand, entry and value path. A relevant
  missing binding or guard stays visible and blocks the affected claim under existing policy.
- Changed evidence gets its own request and proof. Exact replay applies only to matching requests
  under the existing protocol and component checks.
- Every unrelated compatibility fixture and source-reviewed case stays stable. The selected
  fixture and sample deltas are listed before refreshing the golden.

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `.zazz/evaluation/recall-gap-inventory.md` | New | Pinned expected-case matrix, verification commands, exclusions, ranking and results |
| `.zazz/evaluation/recall-gap-inventory/cases.json`, `check.py` | New | Frozen rows for keys without machine-readable cases, and the structural checker that reproduces the matrix |
| `.zazz/project/vulnerable-sample-apps.md`, `.zazz/evaluation/{vuln-nextjs,oss-oopssec-store,dvwa}-detection-guide.md` | Modified | Correct stale coverage claims and gate commands found by reconciliation |
| `.zazz/evaluation/vulnpy-detection-guide.md` | Modified | Reconcile the historical Jinja note with delivery and current evidence |
| This spec | Modified | Record the selected scope, fixtures and expected deltas before code |
| One of `internal/langjs/`, `internal/langpy/`, `internal/langphp/`, or `internal/parse/` and the selected fixture owner | Conditional | One localized closure and its regression controls. Selected: `internal/langjs/xss_web_response.go` (new), `internal/langjs/xss_response.go` (shared HTML-response tail), `internal/langjs/flow.go` (constructor hook and shorthand destructuring default) and `internal/langjs/xss_web_response_test.go` (new) |
| `internal/langjs/next_gssp.go`, `internal/langjs/next_handlers.go`, `internal/langjs/next_gssp_order_test.go` | Modified | Determinism defect found by the AC5 comparison: `getServerSideProps` context inputs follow pattern source order |
| `docs/analysis/xss.md`, `docs/analysis/node-inputs.md`, `docs/nextjs-support.md` | Modified | Document the web `Response` HTML sink and shorthand destructuring defaults |
| `internal/analysispacks/xss.go`, `internal/analysispacks/xss_test.go` | Conditional | Selected: the `html-output-v1` contract for library `fetch-response`, so selection accepts the new records. Existing Express records and descriptor material are unchanged |
| `cmd/scan/testdata/architecture-baseline.json` | Conditional | Add the new fixture rows and update individually listed affected rows |
| Selected analysis and detection guides | Conditional | Document the recovered subset and remaining limits |

The inventory is a reviewable commit. The optional closure stays in the same PR as a separate
commit. Framework expansion, new vulnerability families, policy or prompt calibration, Protected
recognition work, scheduling, new graph schemas, and equivalence or wire protocol redesign belong
in separate contracts.

## 5. Decisions

**D-1. Freeze the evaluation set before running.** Enumerate every explicit supported positive,
registration expectation and relevant control in the source-reviewed keys at the selected pins.
Record intentional exclusions and their reasons. Deduplicate overlapping sources by case and record
all cited keys. Use the following minimum corpus and carry the cited historical records for comparison.

| Cohort | Samples and authority |
|---|---|
| JavaScript / TypeScript | vuln-demo-app, vulnerable-typescript-app, nodejs-goof, Juice Shop, OSS OopsSec Store and vuln-nextjs. Follow each pin and expected reference in the [catalog](../project/vulnerable-sample-apps.md#applications), including the cited XSS keys, living lab test key and the source-reviewed supported-family expectation tables. |
| Python | VulnPy, ThreatByte, python-insecure-app and Vulnerable Flask App. Use `docs/samples/<app>/cases.json` with each app's published `metadata.json`; use the [Python results](../evaluation/python-support-results.md#pinned-corpus-and-final-results) for pin cross-checks. |
| PHP | DVWA, with pin and controls from the [DVWA guide](../evaluation/dvwa-detection-guide.md) and [metadata](../../docs/samples/dvwa/metadata.json). |

Two pins need explicit handling. vuln-demo-app has no `docs/samples/` metadata, and the catalog
gives only the short pin `d27b35b`, so resolve and record the full SHA from the checkout. vuln-nextjs
is a living lab. Measure at the catalog pin and read the lab key
`tests/expected-scanner-findings.json` at that same revision, not at the lab's current head.

Record full target SHA, scanner SHA, command, scope, output path and pre/post status for each run.
If a checkout is unavailable, off-pin or has changes including ignored files, preserve it and use an
existing clean pinned copy or an uncontaminated source snapshot if available. Verify snapshot
provenance and scanner input scope, including any Git metadata needed by that target. Otherwise
mark the sample unmeasured and exclude its rows from rates and ranking. Continue with verified
samples. Report what could affect the priority order.

**D-2. Evaluate each expectation at its actual stage.** A candidate witness is identified by family
or kind, source anchor, entry/dispatch context and operand/source when the key distinguishes them.
Pin alone establishes the file revision and a same-line match alone establishes location. Multi-entry
or stored-flow rows require the corresponding context on both sides when specified by the key.

| Row kind | Offline outcomes |
|---|---|
| Expected positive | `candidate_with_witness`, `candidate_evidence_gap`, or `missing_candidate`. Capture the observed use, evidence or blocker. Both candidate-present states count as candidate presence. |
| Expected registration | `resolved`, `explicit_gap`, or `missing_registration`. Verify source anchor and registration → binding → callable → invocation when resolution is expected. An explicit gap satisfies a registration-or-gap key only. A gap on a key requiring resolution remains a resolution miss. |
| Controls and other rows | Record the expected bounded/encoded/absent or unresolved structural outcome. Label judge-dependent outcomes and unsupported, disputed or unavailable cases separately. |

The existing Python evaluator is supporting evidence. Its location matcher and aggregate positive
count cannot identify all entry/operand distinctions. `not_confirmed`, `validation_enforced` and
similar rows may depend on assessment state. Inspect the saved report per row to establish whether
the oracle is structural or assessment-dependent, and record a present candidate separately from
whether the assessment satisfies its expectation. Record the evaluator exit status and distinguish
an expected row mismatch from a command or parse failure. Use equivalent manual structural checks
for Markdown keys. Report positive candidate presence, complete witness coverage and registration
resolution as separate counts with denominators. List unmeasured rows explicitly.

Account for these known evaluator limits in `docs/samples/evaluate-python.py`:

| Expectation | Offline behavior | Inventory treatment |
|---|---|---|
| All non-registration rows | `matches` keys only on kind, file and line | Check entry and operand from the saved report when the key distinguishes them |
| `raw_xss`, `construction` | Tests the protection label or `query_text_interpolated` gap, not a source-to-sink witness | Establish `candidate_with_witness` from the use's value path and entry, not from the evaluator pass |
| `not_confirmed` (five rows) | Passes whenever a matching candidate exists, because `not_run` is not `confirmed_vulnerability` | Count as candidate presence only. Mark the assessment outcome unmeasured |
| `validation_enforced` (six ThreatByte rows) | Cannot pass without a judged `protected_for_claim` | Mark assessment-dependent. Expect a nonzero ThreatByte exit and don't count it as a regression |
| `form_policy`, `validation_defect` | `form_policy` is structural. `validation_defect` needs a judged `poor_practice` | Record `validation_defect` as candidate presence plus an unmeasured assessment |

Two more counts are recorded without ranking them:

- **Control outcomes.** Report the pass count and denominator for the structural `bound`,
  `encoded` and `absent` controls. This gives later precision and Protected work a baseline from the
  same runs.
- **Candidate fan-out.** For each matched positive, record how many uses match it and how many
  distinct entries they cover. For example, VulnPy's five D5 source cases produced 28 contextual
  findings. This separates multi-entry reporting from duplicate candidates at the same entry.

**D-3. Diagnose and rank distinct fixes.** Assign one primary cause at the first proven failure per
miss and link any contributing blockers. Use `registration`, `call_binding`, `value_transfer`,
`sink_model`, `framework_adapter` or `out_of_family`. Record input/parse or work-limit failures
explicitly and map to a cause only when the first failing stage is established. Preserve prior
delivery evidence and distinguish a newly observed miss from a reproduced regression.

Group eligible misses by a shared root cause with a source-backed explanation of how one change
recovers them. Eligible changes affect one owning language adapter or a tightly scoped core seam
for one adapter, reuse an existing analyzer family and fit the compatibility contract. Rank by
distinct expected positive cases recovered (descending), then expected registration outcomes
satisfied (descending), adapter-local before core, estimated files touched (ascending), then
lexicographic order of the sorted case-ID list. Count each case once. Record the top five or all
eligible groups if fewer, and show why higher-impact groups were deferred. A gap-only
improvement behind an existing candidate goes to the evidence follow-on. For each
`candidate_evidence_gap` row, record the blocking gap kind so the follow-on can be ranked the same
way.

A group is eligible only when its proposal lists the existing controls and compatibility rows
whose resolution path the change touches. Changes to shared call binding or registration resolution
are the usual case. Those listed rows are the at-risk set checked in AC5. Missing at-risk analysis
makes the group ineligible, but it doesn't lower the group's rank.

Where a key's history shows a row was written or corrected after the scanner behavior it tests,
tag the row `post_delivery`, and tag all other rows `independent`. Report recall for both tags
separately so tuning to the corpus stays visible. Ranking still counts every row.

**D-4. Close one measured miss with three controls.** Lock the patch scope and expected fixture
deltas at the checkpoint. A recovered positive must carry the source-to-sink witness, or the
complete source-backed registration chain for a registration closure. The safe sibling proves
bound, encoded or otherwise relevant protection evidence where applicable. The unresolved sibling
proves the relevant gap remains visible and blocks a decisive claim. An offline `not_run`
assessment alone supplies no evidence for either control.

## 6. Agent implementation rules

Use the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Post the ranked inventory and the proposed exact patch scope before writing production code. Proceed
with rank 1 from the verified population if eligible and there is no owner redirect. If the data
supports no eligible closure, deliver the measured inventory and explain what remains. If scope
expands or an unrelated golden delta appears, stop that closure and preserve the inventory for review.

The Lead Agent owns the matrix, selection and writes. Assigned Contributor Agents, if used, may
collect disjoint sample outputs read-only, each in its own run folder. Serialize shared file edits.

## 7. Acceptance criteria

1. **AC1 — Oracle coverage.** The inventory accounts for every source-key row from the frozen
   corpus. Each checked row records case ID, app and pin, family, anchor, entry/operand discriminator
   when applicable, expectation, current result, evidence locator, `independent` or `post_delivery`
   tag, and fan-out for matched positives. Assessment-dependent rows record structural presence
   separately from the unmeasured assessment, as in the D-2 evaluator table. Every unmeasured row
   has a reason. Control pass counts are reported with denominators. Commands, observed denominators and evidence locations are reproducible from the run log.
2. **AC2 — Reconciliation.** The inventory verifies historical delivered claims against current
   evidence and distinguishes delivered, regressed and unmeasured. For `VP-XSS-JINJA`, inspect the
   raw XSS record at `apps/templates/jinja/xss.html:30` and its Flask source path, and update the
   guide to reflect the historical delivery and current measurement.
3. **AC3 — Selection.** The checked-in inventory includes ordered eligible groups with counts and
   exclusions. The run log and §14 identify one chosen group with its proposed file/fixture deltas,
   or the inventory-only outcome and reason.
4. **AC4 — Closure, when selected.** The targeted adapter test fails on baseline, then proves the
   recovered witness plus the safe and unresolved controls. A fresh offline scan at the same sample
   pin verifies the recovered expectation. Selected closure: `OOPS-XSS-R01`, a web-standard
   `Response`/`NextResponse` constructor with an HTML `Content-Type` as an HTML response sink.
   `go test ./internal/langjs -run '^TestWebResponseHTMLSink$' -count=1` covers these cases:
   - **Recovered.** A Next.js route reads a query value into a template, and either returns
     `new NextResponse(html, { headers: { "Content-Type": "text/html" } })` or passes the value
     through a local helper as the VCS route does. Each yields an `xss_candidate` with protection
     `raw`, sink kind `html_response`, the request source in its dependencies, no completeness
     blockers, and an API model that passes `analysispacks.Select`.
   - **Safe controls.** `application/json`, `text/plain`, a `new Headers` non-HTML type, and an
     omitted init all yield no `xss_candidate`. The Fetch default for a string body is `text/plain`.
   - **Unresolved controls.** A headers variable, a spread after the type, and a non-literal type
     each yield an `xss_candidate` with protection `unknown` and a `render_protection_unresolved`
     blocker.
   - **Binding controls.** A shadowed or non-`next/server` `NextResponse`, and a locally bound
     `Response`, yield no candidate.
   - **Destructuring default.** `go test ./internal/langjs -run '^TestDestructuringDefaultProjection$' -count=1`
     checks that `{ name = 'guest' } = req.query` and a fallback that reads the request both reach a
     raw response with their request source. A constant object default records nothing, and an
     aliased default keeps its `unsupported_binding` gap.

   Recheck `OOPS-XSS-R01` with `check.py` against a fresh scan of `oss-oopssec-store` at
   `2d530ef`. Its sink is `app/api/vcs/[[...path]]/route.ts:101`.
5. **AC5 — Compatibility.** `go test ./cmd/scan -run '^TestArchitectureBaseline$' -count=1`
   passes, with golden changes limited to the named rows. Compare before/after case outcomes for
   the verified corpus and account for every changed structural row. Every at-risk control named in
   the D-3 proposal keeps its before outcome or is listed as an approved delta. An inventory-only delivery
   has no golden change.
6. **AC6 — Evidence and gate.** Publish the inventory and matched guide changes. For a code
   closure, run the [contributor gate](../../docs/contributing.md#verification). For inventory-only
   changes, run the [documentation checks](../../.agents/skills/doc-check/SKILL.md) and retain
   AC1–AC3 and AC5 verification in the run log.

## 8. Test strategy

Use a table-driven test in the owning fixture suite and the architecture golden for collateral
changes. Name the test and its three source controls at selection. Real samples provide independent
offline verification of the oracle and recovered case. Keep those reports outside the worktree and
unit-test dependencies. Existing evaluator behavior remains independently checkable.

## 9. Execution sequence

1. Record scanner/toolchain and pins. Run the architecture baseline on the assigned branch.
2. Freeze the case universe from §5. Build once. Run each verified sample with
   `scan --analyze --output-dir <fresh-run-dir> <sample-root>` with provider keys unset, and use
   `findings.json` as the structural source. The bundle writer nests output under
   `<fresh-run-dir>/<target-name>/run-*/`, so record the resolved path. Run
   `python3 docs/samples/evaluate-python.py <app> <findings.json>` for the four Python samples.
   Verify pins and status before and after.
3. Commit the inventory and historical reconciliation. Post the D-3 checkpoint. For an eligible
   closure, signpost the exact fixture anchors, functions, expected evidence and golden deltas in
   §4, §7 and §14.
4. Start with the failing fixture assertion. Repair the first proven failing stage using existing
   flow, facts and claim policy. Run targeted tests, compare the verified corpus and golden,
   document the subset and prepare the draft PR.

## 10. Definition of done

- [ ] Case coverage, pin checks, evaluator interpretation and ranking are recorded.
- [ ] The historical Jinja note is reconciled.
- [ ] One bounded closure passes AC4–AC6, or the inventory records why AC4 does not apply.
- [ ] Sample inputs retain their pre-run pins and clean state. Evidence remains outside them.
- [ ] Independent verification checks the selected result and compatibility, or checks the
      inventory's counts and rationale when no closure ships.

## 11. Open questions

The measured corpus determines the closure. Record exact patch scope and the owner's redirects at
the checkpoint. A technically out-of-scope closure requires its own contract.

### Follow-on accuracy candidates (not in scope)

The 2026-11-19 review found these improvements in existing evaluation records. They stay out of this
delivery. Rank them with this inventory's data when they become contracts.

| Goal | Candidate | Source evidence |
|---|---|---|
| Detect | Helper argument binding for request/session values (likely a `call_binding` group here) | [ThreatByte guide](../evaluation/threatbyte-detection-guide.md) SQL helper checklist |
| Detect | Stored and second-order flow (write, then read, then output) | ThreatByte stored-country profile XSS |
| Detect | Generated or dynamic route registration beyond D5 | VulnPy `VP-COVERAGE-*` rows, [D5 results](../evaluation/common-entry-dispatch-results.md) |
| Detect | SSTI as its own claim kind, correlated with XSS | [python-insecure-app guide](../evaluation/python-insecure-app-detection-guide.md) |
| Detect | Framework access-log leakage of query credentials, generalized from `morgan('combined')` | [Juice Shop index](../evaluation/juice-shop/README.md) |
| Protected | A Review-burden inventory that classifies each `needs_evidence` record by blocking gap kind (Juice Shop 112 of 134 judged) | Juice Shop and ThreatByte `metadata.json` |
| Protected | Source-backed library contracts for imported validators and schema parsers, so guards aren't blocked offline | [Bearer capabilities](../evaluation/bearer-capabilities.md) custom-validator row |
| Protected | Narrower stored-origin uncertainty when output encoding is already established | ThreatByte guide, escaped-output checklist |
| Protected | Framework autoescape defaults as deterministic `encoded` facts | ThreatByte `encoded` and VulnPy Jinja controls |
| False positive | Constant- or literal-origin suppression for logger-leak, and public versus private key material for secrets | Juice Shop source review rows |
| False positive | Test, training and fixture scope reported separately from production counts | Juice Shop scope split: 278 test and 64 training findings |
| False positive | Root-sink grouping, so mounted instances don't inflate defect counts | VulnPy D5 fan-out, and the fan-out count above |
| False positive | Deterministic numeric and regex guard facts, so a judge can't override a bounded operand | [PHP sample analysis](../evaluation/php-sample-analysis.md) judge false positive |
| Measurement | A held-out, source-reviewed protected-control corpus for the security families, like `practice-accuracy/protected-controls.json` | [Calibration](../../docs/analysis/calibration.md#evaluation-and-audit) |

## 12. Run log protocol

Use the plan's run-log rules. Append scanner SHA, toolchain, command and output locations, full
sample pins and statuses, evaluator results, exclusions, ranking, selected patch/fixtures, checks
and verifier outcome. The tracked inventory carries the reviewable evidence and denominators.

## 13. Agent implementation prompt

> Work in the owner-assigned `recall-gap-inventory` sibling worktree based on integrated
> `origin/stage`. Read AGENTS.md, the orientation contents, this spec and the plan's session-start
> and common rules. Record standards and baseline checks in the phase run log. Execute §9,
> post the ranked checkpoint, and limit code to one eligible closure. Keep the sample inputs
> read-only and the evaluator offline. Deliver the inventory and evidence, with the optional
> closure in a separate commit, as a draft PR into `stage`. For independent verification, rerun
> the selected case and inspect its safe and unresolved controls, spot-check two unrelated oracle
> rows, and verify the golden diff against the declared scope. For inventory-only delivery,
> independently spot-check the row totals, exclusions, ranking rationale and Jinja reconciliation.
> Record PASS or FAIL and the supporting evidence in the run log.

## 14. Implementation and review change log

### 2026-11-18 — Paths after architecture phase 3B

Phase 3B moved JS/TS to `internal/langjs` and Python to `internal/langpy`. `internal/parse` is
the language core. [Phase 3B](architecture-phase-3-js-ts-python-package.md)

### 2026-11-18 — Architecture review

Retained the offline inventory and single-closure sequence. Reconciled corpus and package
references, separated registration and candidate outcomes from judgment, defined per-case matching
and ranking, and made the controls and partial-corpus handling explicit. §7 now requires
structural witnesses and before/after evidence.

### 2026-11-19 — Pre-implementation review

Verified the Jinja premise: `VP-XSS-JINJA` passes as `confirmed_vulnerability` in the XSS final
evaluation, while the VulnPy guide checklist and its D5 note still list it as open. Added explicit
handling for the vuln-demo-app full SHA and the living vuln-nextjs pin, the per-expectation evaluator
limits, control and fan-out counts, `independent` and `post_delivery` row tags, the at-risk control
gate for eligibility and AC5, the nested output path, and an out-of-scope follow-on table (§11). The
single-closure scope is unchanged.

### 2026-11-19 — Inventory checkpoint and selection

Measured all eleven samples offline. All 91 required positives have witnessed candidates, and all 30
structural controls pass. The one miss is the Review-expected `OOPS-XSS-R01`, caused by `sink_model`.
§4 now adds the frozen case file and checker, the stale-claim corrections, and the selected closure
files, including the analysispacks contract seam. AC4 names the test, controls and anchor. The
golden delta is limited to new records from fixtures that construct a web `Response` with an HTML
type; none is expected. The owner asked for implementation in this session, so rank 1 proceeds
without waiting for a redirect, as §6 allows.

### 2026-11-19 — Closure, diagnosis correction and determinism fix

Implementing rank 1 showed an earlier failing stage. `const { path = [] } = await params` at
`route.ts:63` dropped the route parameter (`value_transfer`), and the HTML sink (`sink_model`) also
had to change. The group now covers both, adapter-local in `flow.go`. Six base records carried that
gap, which bounds the blast radius. The AC5 comparison then surfaced a pre-existing
nondeterminism: `getServerSideProps` inputs came from Go map iteration. The owner asked to loop on
issues found during this work, so the fix ships here as its own commit, with
`TestGSSPInputOrderDeterministic`. §4 and AC4 list the added files and tests. Corpus deltas are four
OopsSec records, each accounted for in the inventory, and the architecture golden is unchanged.
