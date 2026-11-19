# Model-assisted evidence resolution (proposal)

- **Worktree and branch** To be assigned by the owner. Suggested: `model-evidence-resolution`.
- **Prerequisite** [False positives and Review noise](accuracy-false-positive-noise.md)
  (zazzcode/zazzles#29) on `stage`. Its W5 checker measures give this contract its baseline, its W3
  `stored_origin` write sets are W3's starting evidence, and its W7 shows the
  scanner-supplies-semantics, model-judges, policy-checks-consistency pattern on the command
  family. W7 checks no citation: citations start in this contract's W1.
- **Delivery** One draft PR into `stage`, with one commit per workstream that ships.
- **Run log** `.zazz/ephemeral/model-assisted-evidence-resolution-run-log.md`
- **Owner decisions** The §11 questions were answered by the owner on 2026-11-19; the answers are
  recorded there and applied below.

## 1. Capability

Let the decision model resolve evidence the scanner could not, and judge adequacy where rules are
weak, without letting an unsupported answer become a verdict. The scanner asks a specific question
about each unresolved point, the model answers and cites the evidence it relied on, and the
scanner verifies the citation before the answer counts. A resolved fact is marked as
model-resolved wherever it appears. The outcome is fewer Review records caused by analysis limits,
and accuracy that improves with the model instead of with more adapter code.

## 2. Measured baseline

Offline figures come from the eleven pinned samples with the false-positive contract applied
(scanner `638b991`, 2026-11-19). Judged figures come from that contract's live checks on the same
scanner, openai `gpt-6-luna`, measured with its [checker](../evaluation/recall-gap-inventory/check.py)
(`fixed_outcome_requests`, `substantive_discarded`, `judged_by`). The standalone validation records
whose outcome was fixed are already no longer sent; what remains is below.

| Where the model is under-used | Measurement |
|---|---|
| A scanner blocker fixes the outcome, yet the record is judged | Juice Shop 34 of 62 requests, 10 of them discarding a definite answer (path 9 and 6, NoSQL 3 and 3, SSRF 1 and 1, XSS 19 and 0, redirect 1, SQL 1). OopsSec 5 of 30 |
| Code the scanner stops at but a reader can follow | Offline blockers by record: `python_comprehension_unresolved` 65, `python_call_unresolved` 65, `python_dispatch_unresolved` 64 (path records at one VulnPy sink), `php_value_unresolved` 31, `php_loop_unresolved` 8, `transfer_limit` 6, `unknown_transfer` 4 |
| Stored-data origin judged without the writes | `storage_origin_unresolved` blocks 45 records offline: Juice Shop 17 XSS, DVWA 16 SQL and 2 XSS, OopsSec 4 XSS and 1 path, vuln-demo-app 2, ThreatByte 2, vulnerable-typescript-app 1. Only 5 carry a `stored_origin` write set and only 2 of those list a write (vuln-demo-app, both `closed`). See W3 |
| A disagreement is discarded | `*_answers_inconsistent` on Juice Shop 4, OopsSec 2 and DVWA command 4 judged records (the DVWA four are correct `CMD-001` demotions). The model is not asked for the flow it saw |
| The model cannot name what it lacks | Juice Shop 28 of 62 and OopsSec 8 of 30 judged records have at least one `unknown` answer. Example: Juice Shop URL-context XSS records where the model agreed on the context and answered `unknown` on encoding |

## 2a. Required reading

- [Judgment gates](../architecture/trace-judgment.md#separate-judgments-and-gates), which state the rule this contract revises: model confidence cannot close a static blocker.
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes) and [calibration](../../docs/analysis/calibration.md#evaluation-and-audit).
- [False positives and Review noise](accuracy-false-positive-noise.md) §3, D-3b and D-7, the invariant, the write-set evidence and the pattern this contract generalizes, and its [implementation change log](accuracy-false-positive-noise.md#2026-11-19--implementation-all-seven-workstreams).
- [Precision and noise baseline](../evaluation/precision-noise-baseline.md#method), the measures W6 reports against.
- [Decision-model user guide](../../docs/decision-models.md) and [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls) for request and retry limits.
- [Path traversal analysis](../../docs/analysis/path-traversal.md) and [XSS analysis](../../docs/analysis/xss.md).
- [Testing standards](../standards/testing.md) and the plan's [shared rules](architecture-update-plan.md#shared-rules-for-every-phase).

## 3. Invariants

- **The model proposes; the scanner verifies.** A model answer changes a record's evidence only
  when every span it cites exists in the scanned snapshot and the cited items connect the points
  the answer claims to connect. An answer with no verifiable citation changes nothing.
- **Confidence is not evidence.** This contract revises the architecture rule only for verified
  citations. A bare `vulnerable` or `safe` still cannot close a blocker.
- **Resolution is visible.** A blocker resolved this way stays in the record as resolved, with the
  provider, model, question version and cited spans. Reports show it. Nothing is silently dropped.
- **Protection needs scanner proof.** A model-resolved fact may move a record from Review to a
  finding, with the same status as a scanner-proven finding and a visible model-resolved mark. It may move a record to Protected only when the scanner independently holds the
  coverage fact that makes protection complete. A wrong finding costs a review; a wrong Protected
  hides a defect.
- **Bounded requests.** A record gets its assessment request and at most one follow-up, and
  follow-ups are at most 25% of a scan's requests. The follow-up is not a retry and adds no stop
  condition. Transport retry rules are unchanged.
- **Labels stay out of the scanner.** Expected labels, sample names and case IDs never enter
  scanner logic or model input.
- **Changed questions are judged afresh.** A changed question set bumps the protocol version, and
  old answers are never replayed onto it. Today the family registry descriptor lists every family's
  question names and its digest is part of every record's component selection, so one family's
  bump re-judges all families (seen in the false-positive contract's W7). W1 scopes that digest per
  family so a bump re-judges only its own family.
- **Recall floor.** The phase 5 checker floor holds, and no keyed positive loses a finding.

## 4. Scope and review shape

| Workstream | Owner | Change |
|---|---|---|
| W1. Resolution protocol and provenance | `internal/analysis`, `internal/judge`, `internal/analysispacks` | A resolution record on the assessment, a citation verifier, one policy hook that treats a verified resolution as discharging its blocker, and a per-family component digest |
| W2. Flow-gap questions | `internal/analysispacks`, `internal/judge` (path, injection) | For each flow blocker in §2, send the unresolved span and ask whether the value passes through it. Path traversal and SQL first |
| W3a. Write census for every store | `internal/langphp`, `internal/langpy`, `internal/langjs`, `internal/parse/storage_origin.go` | Fill `stored_origin` for PHP (`php-sql:`, `php-session:`), Python (`python-sql:`), Sequelize, Prisma, keyed stores and own-API row reads, which today carry none. No status change |
| W3b. Stored-origin judgment | `internal/analysispacks`, `internal/judge` (xss, injection, bundle) | Send `stored_origin` and the read query in the request, and ask whether a request value reaches the stored column |
| W4. Cited witness on disagreement | `internal/judge` (path) | When the model's verdict contradicts the scanner's facts, a verified cited flow stands as a finding; otherwise the existing inconsistency blocker applies |
| W5. One evidence request | `internal/judge` (scheduling), adapters' source index | The model may name one missing item (a helper body, a template, a middleware). When the snapshot resolves it, one follow-up request carries it |
| W6. Measurement | `.zazz/evaluation/` | Per provider and model: blockers resolved, citations rejected, follow-ups sent, outcome moves, and a source review of model-resolved findings |
| W7. Project and design documentation | `README.md`, `.zazz/project/`, `.zazz/architecture/` | The README explains in more detail how the decision model is used and why it is useful for judging a record as a vulnerability or as protected; the implementation plan lists this contract and the false-positive contract; the `.zazz/` design and architecture documents describe the resolution protocol |

Files:

| Path | New or modified | Reason |
|---|---|---|
| `internal/analysis/findings.go`, `internal/analysis` assessment types | Modified | W1 resolution record and its JSON fields |
| `internal/judge/resolution.go`, `internal/judge/citation.go` | New | W1 question builder, verifier and policy hook |
| `internal/judge/path.go`, `injection.go`, `xss.go` | Modified | W2 to W4 policy use of verified resolutions |
| `internal/analysispacks/path*.go`, `xss.go`, storage component | Modified | W2 and W3 questions and protocol versions |
| `internal/judge/schedule.go`, `bundle.go` | Modified | W5 follow-up scheduling; W3b sends `stored_origin` |
| `internal/analysispacks/families.go`, `descriptors.go` | Modified | W1 per-family component digest |
| `internal/langphp`, `internal/langpy` storage modeling, `internal/langjs/xss_sql_storage.go`, `xss_cross_tier.go` | Modified | W3a write census and storage keys for own-API row reads |
| `internal/report` (JSON, HTML, SARIF) | Modified | Present model-resolved provenance |
| `.zazz/architecture/trace-judgment.md`, `docs/decision-models.md`, `docs/interpreting-results.md`, `docs/analysis/calibration.md` | Modified | The revised gate rule and how to read a model-resolved record |
| `.zazz/evaluation/model-resolution-results.md`, `.zazz/evaluation/recall-gap-inventory/check.py` | New, modified | W6 record and its resolution columns |
| `README.md` | Modified | W7 decision-model explanation |
| `.zazz/project/implementation-plan.md` | Modified | W7 plan entries for the false-positive and evidence-resolution contracts |
| `.zazz/architecture/evidence-and-claims.md`, `analysis-packs.md`, `README.md` and other affected `.zazz/` design documents | Modified | W7 resolution record, citation verifier, per-family digest and follow-up design |

The diff stays inside these paths plus their tests and fixtures.

Out of scope, each a later contract that reuses W1:

- Output context and encoding adequacy from template and sanitizer source.
- Library validator and guard semantics supplied from model knowledge.
- Handler-level validation judgment, one request per entry, for the validation records the
  false-positive contract no longer sends (Juice Shop 95, OopsSec 87, VulnPy 2,830).
- Flow-gap questions for command, code, redirect, SSRF, NoSQL and logging.
- Model-assisted route discovery, which already exists behind `--discover-routes`.
- New adapter flow analysis. This contract adds no deterministic flow modeling; W3a's write census
  is evidence collection, not flow.

## 5. Decisions

- **D-1. One resolution record, one verifier (W1).** Every model-resolved fact is the same shape:
  the blocker it answers, the answer, the cited evidence item IDs and the verification result.
  One function checks citations for every family. **Why.** Per-family resolution code would repeat
  the adapter sprawl this contract exists to avoid, and one verifier is one place to audit.
- **D-2. The model cites items, not line numbers (W1).** Each evidence item in the request has a
  stable ID: the request's existing compact-wire IDs (`eN` evidence rows, `sN` source excerpts,
  `gN` gaps), so no second ID scheme is added. A citation names IDs, and for a flow, an ordered
  chain from source to sink.
  Verification checks that each ID was in the request and that each adjacent pair is either a
  scanner edge or the single gap the question asked about. **Why.** Free-text line references
  cannot be checked, and a chain with two invented hops is a guess.
- **D-3. A flow-gap question is specific (W2).** It names the unresolved span and offers
  `value_preserved`, `value_constrained`, `value_replaced` or `cannot_tell`. Only `value_preserved`
  with a verified chain discharges the blocker toward a finding. `value_constrained` records the
  constraint and stays Review. **Why.** A constrained value is an adequacy judgment that needs the
  guard pattern from the false-positive contract's D-7, not a flow fact.
- **D-4. Stored origin is judged over a stated write set (W3a, W3b).** The request carries the
  record's `stored_origin` (for each storage key: every write found with its `literal` flag,
  `static_read`, `closed_store` and the schema evidence) and the read query. A record without a
  write set is not sent for this question; W3a exists so that is rare. Answers are `request_write_cited`, `no_request_write_in_evidence`
  and `cannot_tell`. A cited request write that verifies makes the record a stored-flow finding
  candidate. `no_request_write_in_evidence` yields Protected only when every key's `closed_store` is
  `closed`; otherwise it stays Review with that reason. **Why.** The model can reason only over the
  writes it is shown, so absence of a write is meaningful only when the store is closed.
- **D-5. Disagreement asks for the witness (W4).** When the verdict contradicts the facts, the same
  request's cited chain decides it: verified, the finding stands as model-resolved; unverified,
  the existing `path_answers_inconsistent` blocker applies. **Why.** Today the answer is discarded
  without learning whether the model saw a flow the scanner missed.
- **D-6. One follow-up, scanner-resolved (W5).** The model may return one `needed_evidence` item by
  kind and symbol. The scanner fetches it only when the snapshot resolves the symbol exactly, then
  sends one follow-up. An unresolvable request is recorded and the record stays Review. Follow-ups
  stop at 25% of the scan's assessment requests, in priority order; a record over the cap records
  `follow_up_cap_reached` and stays Review.
  **Why.** One round covers the common case of a helper body just outside the expansion limit and
  keeps cost predictable. **Rejected.** An open tool loop, which makes request counts unbounded.
- **D-7. Blocked records are sent only when a question can resolve them (W1).** A record whose
  blockers all have a resolution question is judged with those questions. A record with a blocker
  that has none is not sent. **Why.** The false-positive contract applied this rule to standalone
  validation records only. This extends it to every family and turns the remaining fixed-outcome
  requests (Juice Shop 34 of 62) into resolution questions or no request.
- **D-8. W7's bypass answer gains a citation (W1).** `bypass_identified` cites the value and the
  evidence items that carry it to the operand, verified like any other chain. **Why.** W7 accepts
  the answer on consistency alone. A citation is the cheapest first use of the verifier on a family
  whose live behavior is already measured.
- **D-9. A protocol bump re-judges only its family (W1).** The family registry contributes a
  per-family digest to each record's component selection instead of one digest over all families.
  **Why.** Every question change in this contract would otherwise re-judge every record on the
  next live run and inflate the §11 Q4 budget.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls). Build W1 against a stub judge
before any live call. Paid calls are the owner-authorized W6 runs in §11 Q4, each one judged scan
on `openai` `gpt-6-luna` with the AGENTS.md pacing: VulnPy `--only-family path`, OopsSec in full and
DVWA in full. State each run's planned request count from the offline stub planner before it
starts. No second model and no other run without the owner's word. Halt if the
recall floor moves, a keyed positive loses its finding, a model-resolved fact yields Protected
without the scanner's coverage fact, or the source review in AC6 finds a false finding.

## 7. Acceptance criteria

1. **AC1 (W1).** With a stub judge, an answer whose citations verify discharges its blocker and
   records provider, model, question version and cited IDs; an answer citing an ID not in the
   request, or a chain with a hop that is neither a scanner edge nor the asked gap, changes
   nothing and records the rejection. A `bypass_identified` command answer without a verified
   citation stays Review. Bumping one family's protocol leaves every other family's request digest
   unchanged. Verified by `TestResolutionCitationVerifier`, `TestResolutionDischargesBlocker` and
   `TestCommandBypassCitation` in `internal/judge`, and `TestFamilyDigestIsolation` in
   `internal/analysispacks`.
2. **AC2 (W2).** For a fixture with a Python comprehension between a request value and a path
   sink, the request names the comprehension span and the four answers. `value_preserved` with a
   verified chain yields a finding marked model-resolved; `cannot_tell` leaves the blocker.
   Verified by `TestFlowGapQuestionPath` in `internal/judge`.
3. **AC3 (W3a, W3b).** Offline, at least 40 of the 45 stored-origin records carry a write set, the
   DVWA SQL and ThreatByte records list their writes, and no status changes (record diff and
   checker). The request for a stored-origin record contains its `stored_origin` and the read
   query. A verified `request_write_cited` yields a stored-flow finding candidate;
   `no_request_write_in_evidence` yields Protected when every key is `closed` and Review otherwise.
   Verified by `TestStoredWriteCensus` in each adapter and `TestStoredOriginJudgment` in
   `internal/judge`.
4. **AC4 (W4).** A contradicting verdict with a verified chain stands as a model-resolved finding;
   the same verdict without one gets `path_answers_inconsistent`. Verified by
   `TestDisagreementNeedsWitness` in `internal/judge`.
5. **AC5 (W5).** A `needed_evidence` item that the snapshot resolves produces exactly one
   follow-up containing it; an unresolvable item produces none; no record gets a second
   follow-up. Follow-ups never exceed 25% of the scan's assessment requests, and a record over the
   cap records `follow_up_cap_reached`. The run reports follow-up counts beside request counts.
   Verified by `TestSingleEvidenceFollowUp` and `TestFollowUpCap` in `internal/judge`.
6. **AC6 (W6).** After the authorized live runs, the results record lists, per sample and model
   (the checker's `judged_by`): fixed-outcome requests and substantive answers discarded against
   the §2 baseline, blocked records sent, blockers resolved, citations rejected, follow-ups, and
   records moved from Review to finding or Protected. Every model-resolved finding, up to 40, is source-reviewed, and
   none is a false finding. The phase 5 checker floor holds.
7. **AC7.** A model-resolved finding keeps the ordinary finding status; JSON, HTML and SARIF each
   show its model-resolved provenance mark (provider, model, question version, cited IDs), the
   architecture and user docs state the revised gate, and the contributor gate passes.
8. **AC8 (W7).** The project README describes how the decision model is used (the scanner builds
   the case and asks specific questions, the model answers, the scanner checks the answers and
   citations against its facts) and why that makes it useful for judging a record as a
   vulnerability or as protected, including what model confidence cannot do. The implementation
   plan lists the false-positive contract and this contract with their status, and the `.zazz/`
   design and architecture documents that own the affected topics describe the resolution
   protocol. Verified by `doc-check` on the changed documents.

## 8. Test strategy

- **Verifier.** One table-driven test: valid chain, unknown ID, extra invented hop, chain that
  skips the asked gap, empty citation.
- **Policy.** One test per workstream pairing the discharged case with the neighbour that must
  not move: `cannot_tell`, an unverified citation, and an open store.
- **Scheduling.** Follow-up count and ordering with a stub judge; no live call.
- **Live.** Bounded runs per §11 Q4, with every model-resolved finding source-reviewed.
- **Census.** One write-census fixture per adapter (W3a): a literal-only table, one request write
  and a request-built read, the pair that `TestStoredOriginWriteSet` already covers for JS.
- **Omitted.** No new flow fixtures: this contract changes no flow modeling, and the existing
  adapter goldens prove the offline records are unchanged.

## 9. Execution sequence

1. W1 with a failing verifier test, then the policy hook, all against a stub judge.
2. W4, the smallest use of the verifier.
3. W2 for path traversal, then SQL.
4. W3a write census (offline only, no status change), then W3b.
5. W5.
6. W6 live runs and source review.
7. W7 project README, implementation plan and `.zazz/` design documents.

Each step is its own commit with its own evidence.

## 10. Definition of done

- [ ] The verifier and policy hook pass their stub tests (AC1).
- [ ] Each shipped workstream meets its AC.
- [ ] Live results and the source review are recorded with no false finding (AC6).
- [ ] The architecture rule, user docs and analysis guides are updated (AC7).
- [ ] The recall floor holds.
- [ ] The README, implementation plan and `.zazz/` design documents are updated (AC8).

## 11. Owner decisions

Answered by the owner on 2026-11-19.

1. **Presentation.** A model-resolved finding carries the same status as a scanner-proven one,
   with a visible model-resolved provenance mark in JSON, HTML and SARIF (AC7). A distinct status
   was not chosen.
2. **Protected.** Protected from a model-resolved fact is allowed only when the scanner
   independently holds the coverage fact, for stored origin every key's `closed_store` being
   `closed` (D-4, AC3).
3. **Follow-up budget.** At most one follow-up per record, and follow-ups at most 25% of a scan's
   assessment requests (D-6, AC5).
4. **Paid budget.** Authorized on `openai` `gpt-6-luna`: VulnPy `--only-family path`, OopsSec in
   full and DVWA in full, each one run, with the planned request count stated before it starts.
   A second model is not authorized (§6).
5. **Scope split.** W3a and W3b stay in this contract and run after W1, W2 and W4 (§9).

## 12. Run log protocol

Use the plan's run-log rules. Record the scanner SHA, sample pins, provider, model and question
versions, request and follow-up counts, owner answers to §11 and the source-review outcome per
model-resolved finding.

## 13. Agent implementation prompt

> Work in the owner-assigned worktree based on `origin/stage` with the false-positive contract
> integrated. Read AGENTS.md, the orientation contents and this spec. Copy the owner's §11
> decisions into the run log. Execute §9 in order, building each workstream against a stub judge
> before any live call. Keep samples read-only. Make paid calls only as §11 Q4 authorizes. Deliver
> a draft PR into `stage`, one commit per workstream, with an independent source review of every
> model-resolved finding.

## 14. Implementation and review change log

### 2026-11-19 — Proposal

Drafted from the owner's direction to use the decision model where rule-based analysis is weak,
and from measurements of saved judged runs.

### 2026-11-19 — Sync with the implemented false-positive contract

- **Baseline replaced.** §2 now uses that contract's checker and live runs on scanner `638b991`:
  fixed-outcome requests are Juice Shop 34 of 62 (validation already gone), stored-origin records
  are 45, and inconsistency and `unknown` answers are counted per sample.
- **Prerequisite corrected.** W7 proved consistency checking over supplied semantics, not cited
  answers. Added D-8 so the bypass answer is this contract's first citation.
- **W3 split.** The shipped `stored_origin` covers only JS SQL; 40 of 45 records have no write set.
  Added W3a (write census for PHP, Python, ORM, keyed and own-API stores) before W3b, and D-4/AC3
  now name the shipped fields and `closed_store` values. Q5 updated.
- **Re-judging cost.** Added D-9 and an invariant note: one family's protocol bump currently
  re-judges every family through a shared descriptor digest.
- **D-2** reuses the existing `eN`/`sN`/`gN` request IDs. **D-7** now states what it adds beyond
  the validation gate. **AC6** measures against the checker's judged columns. Q4 budget figures
  updated.

### 2026-11-19 — Owner answers to §11

The owner chose the recommended option on every question and authorized three W6 runs (VulnPy
path family, OopsSec full, DVWA full) on `openai` `gpt-6-luna`, without a second model. §11 now
records the decisions; the invariants, D-6, AC5, AC7 and §6 carry the 25% follow-up cap, the
same-status provenance mark and the authorized runs.


### 2026-11-19 — Owner adds project and design documentation (W7)

**Source.** Owner steering during implementation.

**Changed Sections.** §4 (W7 row and files), §7 AC8, §9 step 7, §10.

**Rationale.** The owner asked for a fuller README explanation of how the decision model is used
and why it helps judge vulnerable or protected, an implementation plan that lists the
false-positive and evidence-resolution contracts, and updated `.zazz/` design and architecture
documents.

**Summary.** Added W7 with its files, AC8 and an execution step after W6.

**Verification Impact.** `doc-check` on the changed documents; no code or test change.

### 2026-11-19 — Implementation (W1–W5, W7; W6 runs pending)

**Source.** Implementation-discovered constraints.

**Changed Sections.** None of the contract's requirements; deviations within adaptive guidance.

**Summary.**

- **Choice-encoded citations (D-2).** The decision APIs accept only choice questions, so each
  resolution question has a `_cite` companion whose choices are ordered `eN`/`gN` chains built from
  the request, plus `none`. The one verifier still checks every cited ID against the request sent
  and every hop against scanner edges or the asked gap. Resolution answers are optional in the
  response; an off-list answer is kept raw so the verifier records why it fails.
- **W5 choices.** The model names a missing item by choosing among symbols the scanner names in the
  record's own gap details; the snapshot must hold exactly one definition. The question is asked
  only by path, SQL, command and XSS, whose protocols this contract bumps.
- **W3a placement.** One shared census in `internal/parse/stored_census.go` (snapshot files checked
  by hash) covers PHP and Python SQL tables, PHP session keys and Prisma own-API reads instead of
  per-adapter code. Offline it covers 29 of the 45 records, short of AC3's 40: the 13 Juice Shop
  `/application-configuration` records and 3 file reads have no storage read to census.
- **Commits.** The SQL flow-gap discharge landed with W1 because AC1 exercises it; W2 (path) and W4
  share one commit because both edit `applyPathPolicy`.
- **Protocols.** `sql-components-v4`, `command-components-v4`, `path-components-v3`,
  `xss-components-v3`.

**Verification Impact.** AC1, AC2, AC4, AC5, AC7 and AC8 have offline evidence; AC3 is partial
(write sets 29/45, judgment tests pass); AC6 awaits the authorized live runs.
