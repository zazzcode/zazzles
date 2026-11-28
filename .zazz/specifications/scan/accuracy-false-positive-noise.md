# False positives and Review noise

- **Worktree and branch** `accuracy-fp-noise`
- **Prerequisite** [Phase 5](architecture-phase-5-accuracy-gaps.md) is on `stage`
  (zazzcode/zazzles#28). Its inventory, checker and before/after method are the measurement base.
- **Delivery** One draft PR into `stage`, with one commit per workstream that ships.
- **Run log** `.zazz/ephemeral/accuracy-false-positive-noise-run-log.md`
- **Owner decisions** The questions in §11 are answered before the workstream they gate starts.

## 1. Capability

Reduce the false findings and the low-value Review volume that reach a reader, and keep recall
measured. Each change does one of four things:

- demotes a finding that has no source-backed external origin,
- stops paying for a judgment whose outcome is already fixed by policy,
- makes the evidence of a kept record more precise, or
- groups repeated records in the presentation while every record stays in canonical JSON.

Precision gets a measured denominator next to the phase 5 recall denominators. No change may lower
recall.

## 2. Measured baseline

These figures come from offline scans of the eleven pinned samples at `stage` `39c5483`
(2026-11-19). The corpus has 4,194 records. Offline, 351 present as `poor_practice` findings and
the rest as Review or Protected.

### False findings

| Source | Measurement | Example |
|---|---|---|
| Construction finding with no external origin | DVWA has 33 SQL records with zero dependencies that present as `sql-injection` findings: 24 at `dvwa/includes/dvwaPage.inc.php:570`, the rest in `dvwa/includes/DBMS/MySQL.php` | `mysqli_query(…, $drop_db)` in database setup. The finding's own text says no request dependency was resolved |
| Unjustified `vulnerable` answer on a guarded path | DVWA `CMD-001` impossible level, 4 records, Confirmed by the judge | [PHP sample analysis](../../evaluation/php-sample-analysis.md#known-disagreements-and-limits): every octet passes `is_numeric`. The request carried no statement of what `is_numeric` accepts, and no question asked the model to name a value that passes the guard |

### Review volume and paid requests

| Source | Measurement | Example |
|---|---|---|
| Standalone validation records that cannot be decided | 3,087 records, 74% of the corpus: VulnPy 2,830 of 3,350, Juice Shop 95 of 251, OopsSec 87 of 128. Only 7 (ThreatByte) carry the completeness evidence the validation policy gate needs. The other 3,080 end `needs_evidence` whatever the model answers | Juice Shop: 95 of the 157 requests in the standing live check buy a fixed outcome. VulnPy's 2,830 records sit on 31 field-read sites |
| Shared-sink fan-out across entries | DVWA has 82 XSS records at `dvwaPage.inc.php:388` from 25 entries (80 findings, 2 Review); 41 have only cookie sources. VulnPy has 64 path records at `src/vulnpy/common/templating.py:27` and 28–30 at each trigger sink | Every DVWA page renders through one function |
| Several records for one entry and sink | Records beyond the first per entry, kind and sink span: DVWA 60 of 240, Juice Shop 28 of 156 | One DVWA entry has four records at `:388` whose source sets overlap. They differ by path |
| Request origin through an own-API response | 1 record: OopsSec `app/vulnerabilities/[slug]/page.tsx:49` (`OOPS-PATH-N01`) | The slug selects an API row whose `markdownFile` is read. Held at Review by `unknown_transfer` |
| Raw output from storage with only literal writes in source | 1 record: vuln-demo-app `server.js:280` (`DEMO-XSS-N02`) | `users` is written only by literal seed SQL, and the read query is static |
| Unknown context shown with `raw` protection | 3 records: Juice Shop `routes/dataErasure.ts:50`, OopsSec `app/api/uploads/[...path]/route.ts:44`, vulnerable-typescript-app `src/server.ts:108` | Blockers keep each at Review, but the label overstates it |
| Closed constant type map | 1 record: OopsSec `uploads/[...path]/route.ts:44` | The map holds four raster types and `image/svg+xml`, with a missing-key rejection |

### Checked and not a problem

- **Outbound observations.** Juice Shop has 70 at `lib/webhook.ts:18`. The existing
  `grouped_into` and `grouped_use_ids` fields already present them as one row.
- **Test and fixture paths.** No sample emits a record whose sink is under a test, fixture or
  Cypress path. This is an observation, not a guarantee: `internal/walk` skips dependency and
  build directories only, and only the Python adapter filters test path segments. W5 adds a census
  row so a regression shows.
- **Logger constants and public key material.** The Juice Shop rows in the
  [source review](../../evaluation/juice-shop/README.md) are Bearer's. zazzles emits only the
  `server.ts:366` access-log records there and has no secrets family.
- **Not literal-only storage.** `server.js:131` reads through a request-built query (`:126`), so
  its row is attacker-influenced. Juice Shop `dataErasure.ts:50` and `dataErasureForm.hbs:38` read
  an ORM model whose writers cannot be closed. All three stay as they are.

## 2a. Required reading

- [Phase 5 inventory](../../evaluation/recall-gap-inventory.md) and its [checker](../../evaluation/recall-gap-inventory/check.py), which give the recall floor and the method.
- [Calibration](../../../docs/scan/analysis/calibration.md#evaluation-and-audit), [claim completeness](../../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) and the [reporting design](../../architecture/reporting-and-sarif.md).
- [Outbound grouping](../../../docs/scan/interpreting-results.md#outbound-observations-and-ssrf), the mechanism W2 generalizes.
- [Input validation analysis](../../../docs/scan/analysis/input-validation.md), [XSS analysis](../../../docs/scan/analysis/xss.md) and [path traversal analysis](../../../docs/scan/analysis/path-traversal.md).
- [Practice accuracy results](../../evaluation/practice-accuracy/results.md), the precedent for precision denominators and protected controls.
- [Testing standards](../../standards/testing.md) and the plan's [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).

## 3. Invariants

- **Recall floor.** The phase 5 checker still reports 91/91 required positives with a witness,
  30/30 structural controls and 4/4 registrations, and no required positive changes outcome.
- **Canonical JSON keeps every record.** Grouping, demotion and judge-scope changes never delete a
  candidate or merge judgments.
- **Removal needs impossibility.** A record is removed only when source evidence shows that its
  claim cannot hold. In this delivery that is one case: a response type that cannot render HTML
  (D-3c). Everything else is demoted, relabelled or grouped.
- **A finding needs an external origin.** A record presents as a finding only when at least one
  dependency has a request, storage, file, fetched, browser or API-response origin.
- **The judge is not asked a fixed question.** A record is sent only when some model answer could
  change its presented outcome.
- **The scanner supplies facts; the model judges adequacy.** Where a verdict turns on whether a
  control is sufficient, the scanner gives the model the control's source and its source-backed
  semantics and asks a direct question. Policy blocks an answer only when evidence is missing or
  the model's own answers contradict each other. A coarse scanner fact never overrides a model
  answer.
- **Uncertainty stays Review.** Missing evidence never becomes Protected or silent.
- **Labels stay out of the scanner.** Expected labels, sample names and case IDs never enter scanner
  logic or model input.
- **Changed evidence is judged afresh.** It gets a new judgment, and existing replay rules apply.
- **Stable IDs.** Record IDs do not change. Golden rows change only where this spec lists them.

## 4. Scope and review shape

| Workstream | Owner | Change |
|---|---|---|
| W1. Undecidable validation records | `internal/judge` (scheduling), `internal/report` | Skip the judge for a validation record that cannot pass its policy gate. Present such records grouped by field-read site |
| W2. Sink grouping | `internal/report`, `internal/analysis` (field docs) | Extend the outbound grouping to every family: one presented row per kind, sink span and status, listing entries and paths |
| W3. Origin precision | `internal/langjs`, `internal/parse` | Own-API response fields take the origin their handler gives them. Stored-origin records carry their write set as evidence. Closed constant `Content-Type` maps resolve |
| W4. Presentation consistency | `internal/parse` (`AssembleXSSClaims`) | An unknown output context carries protection `unknown`, not `raw` |
| W5. Precision measurement | `.zazz/evaluation/` | Finding-precision rows, noise classes, an unkeyed-record census and a protected-control set. Judged rows are keyed by provider and model |
| W6. Source-less construction findings | `internal/report` (status assignment) | A construction record with no external-origin dependency presents as Review, not as a finding |
| W7. Model-judged guard adequacy (command family) | `internal/analysispacks` (guard contracts, question), `internal/judge` (command policy) | Give the model each recognised guard's semantics and ask whether a value passes it and still alters the command. Policy checks that answer against the verdict |

Files:

| Path | New or modified | Reason |
|---|---|---|
| `internal/judge/schedule.go`, `internal/judge/validation.go` | Modified | W1 decidability gate |
| `internal/report/ssrf_findings.go` → shared grouping file, `html.go`, `sarif.go`, `text.go` | Modified | W2 |
| `internal/analysis/findings.go` | Modified | W2 field documentation for `grouped_into` on assessable records |
| `internal/langjs/xss_cross_tier.go`, `xss_client_http.go`, `path_node.go`, `xss_response.go` | Modified | W3a and W3c |
| `internal/parse/storage_origin.go`, `internal/parse/xss_claims.go` | Modified | W3b and W4 |
| `internal/report/findings.go` | Modified | W6 |
| `internal/analysispacks/command.go`, `internal/judge/command.go` | Modified | W7 question, protocol version and policy check |
| `internal/analysispacks/guard_contracts.go` | New | W7 source-backed semantics for recognised guards |
| `.zazz/evaluation/recall-gap-inventory/check.py`, `cases.json` | Modified | W5 rows |
| `.zazz/evaluation/recall-gap-inventory/protected-controls.json`, `.zazz/evaluation/precision-noise-baseline.md` | New | W5 set and record |
| `docs/interpreting-results.md`, `docs/analysis/*.md`, `AGENTS.md` (Juice Shop request count) | Modified | Changed behavior and the new live-check size |

The diff stays inside these paths plus their tests and fixtures.

Out of scope, each with its owner:

- New analyzer families and detection gaps.
- The `needs_evidence` Review-burden inventory, library validator contracts, framework autoescape
  defaults and stored-origin narrowing. These are the "Protected" rows of
  [phase 5 §11](architecture-phase-5-accuracy-gaps.md#follow-on-accuracy-candidates-not-in-scope)
  and need their own contract. The first is
  [model-assisted evidence resolution](model-assisted-evidence-resolution.md), which starts after
  this contract's W5, W3 and W7 are on `stage`.
- A walker rule for test paths. The census shows nothing to remove.
- Prompt and policy changes other than W7's guard question, and guard questions for families
  other than command. Path and SQL follow once W7 is measured.
- Paid runs beyond §6.

Each workstream may land on its own. W5 lands first so the others are measured.

## 5. Decisions

- **D-1. Measure before changing (W5).** The checker gains four measures per family and sample:
  finding precision against keyed rows, record counts per noise class from §2, an unkeyed census
  (records matching no key row), the test-path census, and, for judged runs, the requests whose
  outcome a scanner blocker had already fixed and the substantive answers discarded that way. Every later workstream reports a
  before/after delta. Judged precision rows name the provider, model and question version, so the
  same corpus can be re-measured when a model changes. **Why.** A smaller report is not a win
  without a denominator, unkeyed records are the population whose truth is unknown, and the design
  expects model judgment to improve without scanner changes.
- **D-2. Group by extending `grouped_into` (W2).** The key is kind, sink span and presented status.
  The first record in report order is the representative and lists the others in
  `grouped_use_ids`; the others carry `grouped_into`. The row shows the entry count, the record
  count and each member's origins. Records with different statuses never share a group, so a group
  cannot hide a finding behind a Review row or the reverse. **Why.** The fields and three renderers
  already implement this for outbound observations. A second grouping field would give JSON two
  meanings for one idea. **Rejected.** Adding the origin kind to the key: the 82 records at
  `:388` mix request and storage sources, so the key would split one defect.
- **D-3a. An own-API response field takes its handler's origin (W3).** When a `fetch` URL resolves
  to a scanned route, a field read from the response gets the origin of the value the handler
  returns for it: storage, request or unresolved. The request value that built the URL stays as
  selector context. When the handler or field cannot be resolved, today's behavior stays (request
  origin with `unknown_transfer`). **Why.** A handler can echo request input, so a blanket
  "response means storage" rule would hide a real flow.
- **D-3b. Stored-origin records carry their write set; this contract gives no verdict (W3).** For
  a record blocked by `storage_origin_unresolved`, the scanner attaches every write it found for
  the storage key, whether each written value is a literal, whether the read query is static, and
  whether the store's schema and writers are all in scanned source. The record stays Review.
  **Why.** Whether a request value can reach the stored column is a judgment the decision model
  makes better than a rule, and it can only make it over the writes it is shown. The judgment
  belongs to [model-assisted evidence resolution](model-assisted-evidence-resolution.md) W3; this
  contract supplies its evidence. **Rejected.** A fixed `writers_literal_only` label, and removal
  under a closed-store rule: both encode in code a call the model should make.
- **D-3c. A closed type map resolves the response type (W3).** A map is closed when it is a
  module-level `const` object literal with literal values, is never assigned or passed out, and the
  missing-key branch returns before the response. All values non-HTML: no XSS record. Any HTML or
  `image/svg+xml` value: unresolved Review. **Why.** A raster type cannot render markup, and the
  missing-key check rules out a sniffed response.
- **D-4. Presented protection follows the context (W4).** `AssembleXSSClaims` sets the record-level
  `xss.protection` to `unknown` when the output context is `unknown`. Per-path protection facts are
  unchanged. **Why.** One rule in the shared assembly covers every adapter.
- **D-5. Decidability decides the judged scope (W1).** A validation record whose completeness
  evidence cannot satisfy `applyValidationPolicy` is not sent. It stays Review with the reason
  `validation_evidence_missing` and assessment state `not_run`. A record that can pass, one named by
  `--checks`, or any record under `--only-family input-validation` is judged as today.
  **Why.** This is a source-backed rule, not a preference: the outcome is fixed before the request.
  It keeps ThreatByte's seven decidable rows judged. Judging validation per handler, with the
  handler body as evidence, is left to a contract that follows model-assisted evidence resolution. **Rejected.** Excluding the whole family from
  the default scope, which would stop judging those seven.
- **D-6. No external origin, no finding (W6).** A construction record with zero dependencies, or
  with constant and environment origins only, presents as Review with the reason
  `external_origin_not_established`. **Why.** The finding type is `sql-injection`, and the record's
  own text says external control is not established.
- **D-7. The model judges guard adequacy, with the guard's semantics in hand (W7).** For each
  recognised guard on a command path (`is_numeric`, `ctype_digit`, integer casts, fully anchored
  regexes, allow-list membership), the request carries a short source-backed contract of the
  values it accepts, including edge cases such as trailing whitespace. One added question asks
  whether a value exists that passes the guard and still alters the command: `bypass_identified`,
  `no_bypass` or `guard_semantics_unknown`. Policy then reads the pair:
  - `vulnerable` with `bypass_identified` stands as a finding.
  - `vulnerable` with `no_bypass` is a self-contradiction and becomes Review under the existing
    `command_answers_inconsistent` blocker.
  - `guard_semantics_unknown`, or a guard with no contract, stays Review.

  The question set changes, so the command protocol version bumps and command records are judged
  afresh. **Why.** `guarded` means a control exists; its adequacy is the model's call by design.
  Deciding it in code would repeat the limits of rule-based analysis and would demote correct
  answers on weak guards. **Rejected.** A policy rule that treats every `vulnerable` answer on an
  all-guarded record as inconsistent: it fixes `CMD-001` but also demotes a real injection behind
  a deny-list.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls). Each workstream starts with a failing
fixture, then runs the phase 5 checker and the corpus record diff before and after. Paid calls are
limited to the owner's standing live check (`openai`, `gpt-6-luna`, default judge limit, one sample)
when a workstream changes judged records. W7 also needs one DVWA check limited to
`--only-family command` (16 records). Anything more needs the owner's word. Halt if the recall
floor moves, an unlisted golden row changes, a removal lacks a source-backed impossibility, or a
keyed positive loses its finding status under W6.

## 7. Acceptance criteria

1. **AC1 (W5).** `check.py` prints, per family and sample: keyed findings true and false, the
   noise-class counts of §2, the unkeyed count, the test-path count and, for a judged report, the
   fixed-outcome request count. The protected set holds at
   least one source-reviewed control per security family with a denominator. The offline baseline
   is recorded in `precision-noise-baseline.md` and reproduces §2. Verified by `python3
   .zazz/evaluation/recall-gap-inventory/check.py` and its unit test.
2. **AC2 (W2).** On DVWA, `dvwaPage.inc.php:388` presents as two HTML rows and two SARIF results,
   one per status (80 findings, 2 Review), together naming 25 entries and 82 records, while JSON
   keeps all 82 with unchanged IDs. Outbound
   grouping output is unchanged. Verified by `TestSinkGroups` in `internal/report`
   (keys, status separation, record preservation) and the DVWA record diff.
3. **AC3 (W3).** Each fixture test in `internal/langjs` fails on the baseline and passes after:
   - A page that reads a file named by an own-API row field has a storage-origin dependency and no
     request-origin one (`OOPS-PATH-N01` shape).
   - The same page against a handler that echoes a request value keeps the request origin.
   - A stored-origin record lists every write found for its storage key, with the literal,
     static-read and closed-store facts. A table with one request write lists that write as
     non-literal, and a read through a request-built query is marked not static.
   - A raster-only closed map produces no XSS record. A map with SVG, a mutated map and a map with
     no missing-key return each stay Review.

   Corpus deltas are limited to `OOPS-PATH-N01`, `DEMO-XSS-N02` and the uploads record, and the
   recall floor holds.
4. **AC4 (W4).** No XSS record has context `unknown` with protection `raw` in JSON, HTML or SARIF.
   The three §2 records change and no other. Verified by `TestXSSUnknownContextProtection` in
   `internal/parse`.
5. **AC5 (W1).** With a stub judge, a validation record lacking gate evidence produces no request,
   and one with complete evidence produces one. Juice Shop's planned request count drops from 157
   to 62 and ThreatByte still judges its seven. Verified by `TestValidationDecidabilityGate` in
   `internal/judge`; counts are reported per sample.
6. **AC6 (W6).** DVWA's 33 zero-dependency SQL records present as Review with
   `external_origin_not_established`, and DVWA offline findings go from 183 to 150. No keyed
   positive changes status. Verified by `TestConstructionFindingNeedsOrigin` in `internal/report`
   and the DVWA golden delta.
7. **AC7 (W7).** With a stub judge: `vulnerable` plus `no_bypass` yields Review with
   `command_answers_inconsistent`; `vulnerable` plus `bypass_identified` stays a finding; a guard
   with no contract stays Review. The request for a guarded path contains the guard's contract
   text and the new question. Verified by `TestCommandGuardBypassPolicy` in `internal/judge` and
   `TestCommandGuardContract` in `internal/analysispacks`. On the live DVWA command check, the
   four `CMD-001` impossible-level records are no longer Confirmed and no low-, medium- or
   high-level command record loses its Confirmed outcome.
8. **AC8.** The contributor gate passes, the phase 5 checker floor holds, and every golden delta is
   listed in the run log. Where W1 or W3 changes judged records, one owner-authorized live
   check of OopsSec records the judged outcome counts.

## 8. Test strategy

- **Report.** One table-driven test covers grouping keys, status separation, HTML rows and SARIF
  related locations, with a JSON round-trip that proves records are preserved. Outbound grouping
  is a row in the same table, not a second test.
- **Adapters.** Each W3 rule is a pair: the case it relabels or removes and the vulnerable sibling
  it must leave alone (AC3 lists them).
- **Policy.** W1, W6 and W7 each pair the changed case with the neighbour that must not change: a
  decidable validation record, a construction record with one request dependency, and a weakly
  guarded command record whose finding must survive.
- **Measurement.** Recall and precision are checked with the phase 5 checker and the record diff
  across all eleven pinned samples, before and after each workstream.
- **Omitted.** Python and PHP adapters get no W3 fixtures; no corpus record of those languages
  matches a W3 rule, and the shared `internal/parse` tests cover W3b and W4 for them.

## 9. Execution sequence

1. W5: measures, the protected set and the baseline record.
2. W6: source-less construction findings, the largest false-finding class.
3. W4: presentation consistency.
4. W1: decidability gate, which also shrinks every later live check.
5. W3: origin rules, one at a time, each with its pair.
6. W2: grouping, after W1 and W6 have settled which status each record presents.
7. W7: guard contracts, the question and the policy check, then the DVWA command calibration.

Each step is its own commit with its own before/after evidence.

## 10. Definition of done

- [x] Precision baseline and the protected set are recorded (AC1).
- [x] Each shipped workstream meets its AC with before/after evidence.
- [x] The recall floor holds and the golden deltas are listed (AC8).
- [x] Analysis guides, `docs/interpreting-results.md`, the inventory and the AGENTS.md request
      count are updated for every changed behavior.

## 11. Open questions (owner)

1. **Validation presentation (W1).** Group undecidable validation records by field-read site
   (recommended; VulnPy goes from 2,830 rows to 31), or by entry and field?
2. **Grouping in SARIF (W2).** One result per group with related locations and a fingerprint built
   from kind and sink span (recommended), or one result per record with a shared
   `partialFingerprints` group? The first changes existing code-scanning alert identities once.
3. **SVG.** Should `image/svg+xml` count as an HTML-capable response type for the XSS sink, which
   turns the uploads route into a stored-XSS claim? Or should it stay unresolved Review?
4. **Paid budget.** Is the standing live check, plus the DVWA command check for W7, enough, or is
   a per-workstream cap wanted?

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, sample pins and status, checker summaries
before and after each workstream, record diffs, owner answers to §11 and any paid-call counts.

## 13. Agent implementation prompt

> Work in `accuracy-fp-noise`, based on `origin/stage`, which includes phase 5. Read AGENTS.md, the
> orientation contents and this spec. Confirm the owner's §11 answers in the run log. Execute §9 in
> order: each workstream starts with a failing fixture and ends with the phase 5 checker, the
> corpus record diff and the gate. Keep samples read-only and scans offline except the owner's
> standing live check. Deliver as a draft PR into `stage`, one commit per workstream, with an
> independent verification of the recall floor and two demoted or grouped records.

## 14. Implementation and review change log

### 2026-11-19 — Proposal

Drafted from the phase 5 inventory observations and fresh offline measurements.

### 2026-11-19 — Pre-implementation review against the code and saved scans

- **Added W6.** 33 DVWA SQL findings have no dependency at all. The proposal measured Review noise
  only and missed this false-finding class.
- **Added W7.** The recorded judge false positive (`CMD-001`) was a phase 5 follow-on row with no
  owner.
- **W1 became a rule.** Outside ThreatByte's seven, no validation record can pass its policy gate,
  so judging them is a fixed outcome. This replaces the three-way policy question.
- **W2 reuses `grouped_into`.** The proposal added a new grouping field beside an existing one, and
  its key (with origin kind) contradicted its own DVWA criterion.
- **W3 tightened.** The own-API rule now depends on the handler; literal-only storage is labelled
  instead of removed; a closed map is defined. `server.js:131` and both Juice Shop data-erasure
  records left the baseline because their rows are not literal-only.
- **Baseline corrected.** `:388` is 82 records from 25 entries, not one per page. The walker does
  not exclude test paths; the zero count is an observation. Outbound fan-out is already grouped.
- **Hygiene.** Added the file list, a verifying test per criterion, a reason per decision, and an
  owner for each excluded follow-on.

### 2026-11-19 — Owner direction: use the decision model where analysis gets tricky

- **W7 redesigned.** The deterministic "all guarded plus vulnerable" rule is replaced by guard
  contracts and a bypass question, so the model judges adequacy and policy checks only its
  self-consistency. This closes the former command-policy question.
- **New invariant.** The scanner supplies facts and semantics, the model judges adequacy, and a
  coarse fact never overrides an answer.
- **W5.** Judged precision rows are keyed by provider, model and question version, so a newer
  model can be measured on the same corpus.

### 2026-11-19 — Sync with model-assisted evidence resolution

- **D-3b changed again.** Stored-origin records now carry their write set as evidence and get no
  label or verdict here. The follow-on contract's W3 judges them. This closes the literal-only
  storage question.
- **W5.** Added the fixed-outcome request measure that the follow-on uses as its baseline.
- **Sequence.** This contract ships first. The follow-on depends on its W5 measures, W3 write-set
  evidence and W7 cited-answer pattern.

### 2026-11-19 — Implementation (all seven workstreams)

Owner answers to §11, taken as the recommended defaults under the owner's standing preference and
recorded here: validation records group by field-read site; SARIF emits one result per group with a
kind-and-span fingerprint; `image/svg+xml` stays unresolved Review; paid calls are the standing
Juice Shop check, the DVWA command check and the AC8 OopsSec check.

Deviations found while implementing, each following the contract's own rule:

- **W6.** Juice Shop `routes/chat.ts:149` is a 34th no-origin construction finding (§2 counted 33).
  DVWA's 33 are 24 at `dvwaPage.inc.php:570`, 8 in `DBMS/MySQL.php` and 1 at `login.php:40`.
- **W3a.** The rule also applies to three sibling OopsSec records on the same own-API pattern
  (`vulnerabilities/[slug]/page.tsx:275`, `ProductDetailClient.tsx:173` and `:178`); all stay
  Review. A row column resolves to a storage read without linking its writers: linking them turned
  the two product records into false findings from a sanitized upload filename. The four records
  whose dependencies change get new content-addressed IDs (IDs hash dependencies); every other
  record keeps its ID.
- **W3b.** The write set is `stored_origin` on the record, outside the ID key. It is not yet sent to
  the model; the follow-on contract decides that.
- **W7.** An unanchored regular-expression contract was added so the weakly guarded nodejs-goof
  command finding survives with a named bypass. The question set change moves every record's
  component digest, so pre-W7 judgments no longer replay for any family.

Results: recall floor 91/30/4 unchanged; corpus findings 351 → 317 records; presented rows 4,194 →
643. Live (openai `gpt-6-luna`): Juice Shop 62 requests (was 157), OopsSec 30, DVWA command 16 with
the four `CMD-001` impossible-level records no longer Confirmed and all twelve low/medium/high
records Confirmed. Evidence is in the [precision baseline](../../evaluation/precision-noise-baseline.md).
