# Judge request size reduction

- **Worktree and branch** `judge-request-size-reduction`
- **Baseline** `stage` at `8dd0460` (PR #31, close findings gaps)
- **Delivery** One draft PR into `stage`, one commit per execution step (§9).
- **Run log** `.zazz/ephemeral/judge-request-size-reduction-run-log.md`
- **Owner decisions** All three §11 questions were answered on 2026-11-19. Implementation has not
  started.
- **Related** [Per-hop judgment](per-hop-judgment.md) (proposal, not yet merged; drafted on branch
  `per-hop-judgment-spec`) reduces repetition between requests. This contract reduces the fixed
  part inside each request and does not depend on it.

## 1. Capability

Send less text to the decision model in every request without removing source code or any fact the
model can reason about, and prove on DVWA and Juice Shop that requests are smaller and accuracy is
unchanged. Four workstreams change only the model-facing wire projection:

| ID | Workstream | What leaves the request |
|---|---|---|
| A | Local identity | Hash-based identifiers, replaced by short aliases or counts |
| B | Structural repetition | Empty row placeholders and repeated transfer tails |
| C | Size notices | Per-span and per-path lists inside the omission and path-group gaps |
| D | Choice labels | Boilerplate choice descriptions in the XSS questions |

The request limit, the shedding order, the path-group cap, every gate and every policy rule stay as
they are. Bytes the wire no longer spends are used by the existing budget, which then sheds less.

### Measured baseline

Measured offline at `8dd0460` by building every request without sending it. Requests are counted
after path grouping.

| Measure | DVWA `a1978a2` | Juice Shop `f189f52` |
|---|---:|---:|
| Assessable records | 247 | 157 |
| Planned requests | 263 | 157 |
| Records over 65,536 bytes before grouping | 8 (24 group requests) | 0 |
| Total request bytes | 9,388,206 | 3,193,060 |
| Median / p95 / largest request | 29,760 / 62,006 / 64,805 | 16,613 / 41,307 / 57,915 |
| Requests over 58,982 bytes (90% of the limit) | 25 | 0 |
| Source excerpt text | 2,130,488 (22.7%) | 509,181 (15.9%) |
| Hash-based identifiers | 836,413 (8.9%) | 79,883 (2.5%) |
| Equivalence classes | 244 | 157 |

One near-limit request in detail: the `sqli` render record at `dvwa/includes/dvwaPage.inc.php:388`,
path group `vulnerabilities/sqli/source/medium.php`, 64,310 bytes.

| Part | Bytes | Workstream |
|---|---:|---|
| Source excerpt text, 56 excerpts | 15,456 | none |
| 86 hash-based identifiers; `xss.related_entries` alone is 65 identifiers, 4,941 bytes | 6,382 | A |
| Empty placeholders in 148 evidence rows | 603 | B |
| Five dependency paths of 43 transfers whose last 36 are identical | 1,696 | B |
| Omission gap (43 spans listed) and path-group gap (17 withheld paths listed) | 3,421 | C |
| 25 choice descriptions of the form "Apply the definition of *X* in this question…" | 2,070 | D |

That request fits only because the budget left out 43 context items (2,937 source bytes) and its
three resolution questions. Juice Shop has no request near the limit. It is the regression sample:
it shows the saving on ordinary requests and that answers do not move.

## 2. Required reading

- [Request size and evidence relevance](../../architecture/request-size-and-evidence-relevance.md):
  [principles](../../architecture/request-size-and-evidence-relevance.md#principles),
  [W8](../../architecture/request-size-and-evidence-relevance.md#w8-model-facing-spans-without-byte-offsets-or-hashes--implemented)
  (the rule A extends),
  [path-group requests](../../architecture/request-size-and-evidence-relevance.md#path-group-requests-over-the-floor--implemented-xss)
  and the [ablation protocol](../../architecture/request-size-and-evidence-relevance.md#ablation-protocol-for-lossy-changes).
- [Close findings gaps](close-findings-gaps.md) W4 (D-13 to D-17) and its
  [live check](../../evaluation/close-findings-gaps-results.md#live-check-ac11), the DVWA accuracy
  baseline.
- [Model-assisted evidence resolution](model-assisted-evidence-resolution.md): resolution
  questions and citation chains, which B must not disturb.
- [Decision models](../../../docs/scan/decision-models.md) and
  [interpreting results](../../../docs/scan/interpreting-results.md): exact-replay and limit wording.
- [XSS analysis rules](../../../docs/scan/analysis/xss.md) and
  [calibration pairs](../../../docs/scan/analysis/calibration.md#regression-pairs).
- [Recall inventory](../../evaluation/recall-gap-inventory.md), with `check.py`, `accuracy.py` and
  `cases.json` under `.zazz/evaluation/recall-gap-inventory/`.
- Code: `wireBundle` (`internal/judge/bundle.go`), `wireInvocation`
  (`internal/judge/entry_context.go`), `compactBundleIDs` (`internal/judge/compact_bundle.go`),
  `omissionGap` and `groupUse` (`internal/judge/budget.go`), `payloadWith`
  (`internal/judge/client.go`), `normalizeIdentity` (`internal/judge/equivalence.go`), and the
  choice builder in `internal/analysispacks/xss.go`.

## 3. Invariants

- Only the model-facing projection changes. `CandidateUse`, saved traces, reports, SARIF and
  bundles keep every identifier, span, omission and path they hold today.
- No source excerpt, evidence row, dependency, control edge, gap, blocker or fact is removed from
  a request by this contract. A request may gain evidence because the budget sheds less.
- Gates and policy read the unreduced `CandidateUse`. No file that decides an outcome changes
  (§6 lists them).
- `requestLimit`, the shedding order and `maxPathGroups` do not change.
- The same input gives the same request bytes. Alias numbering follows a fixed traversal order,
  never map iteration.
- No rule names a sample, a file or an identifier.
- All four workstreams ship under one protocol bump. Saved exact replays stop matching once.
- Sample checkouts are read-only at their pins. Offline runs use no provider key. Paid calls follow
  [AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls) and §11 OQ-1.

## 4. Scope and review shape

| Path | Change | Workstream |
|---|---|---|
| `internal/judge/request_inventory_test.go` | New | Measurement tool (D-1) |
| `internal/judge/wire_identity.go`, `wire_identity_test.go` | New | A |
| `internal/judge/bundle.go`, `entry_context.go`, `compact_bundle.go` | Modified | A, B |
| `internal/judge/equivalence.go` | Modified | A: read the new identity shape |
| `internal/judge/budget.go` | Modified | C: notice text only |
| `internal/judge/client.go` | Modified | Instruction wording for the new row and alias schema |
| `internal/analysispacks/xss.go`, `families.go` | Modified | D and the XSS protocol version |
| Tests and goldens under `internal/judge/`, `internal/analysispacks/`, `cmd/scan/testdata/` | Modified | Only rows that state request bytes, digests or versions |
| `.zazz/architecture/request-size-and-evidence-relevance.md` | Modified | Strategy entries and ledger rows |
| `.zazz/evaluation/judge-request-size-reduction-results.md` | New | Before and after measures |
| `docs/decision-models.md`, `docs/interpreting-results.md`, `docs/analysis/xss.md` | Modified | Only where a changed field or notice is described |
| `.zazz/specifications/README.md`, `.zazz/project/implementation-plan.md` | Modified | Index and plan entries |

One PR. The four workstreams share one protocol bump, so splitting them would invalidate saved
replays more than once.

Out of scope: plain-text evidence instead of JSON inside JSON, statement-level slicing (S1),
per-hop judgment, the unit or value of the request limit, the relevance filters S2 and S5, the
guideline and instruction prose other than the schema sentences named in §5, and choice
descriptions outside the XSS pack.

## 5. Decisions

### D-1 — A tracked inventory tool produces both sides of every comparison

`TestRequestInventory` builds every planned request of one sample offline and writes one TSV row
per request. It runs only when `ZAZZLES_SAMPLE` names a checkout and writes to
`ZAZZLES_INVENTORY_OUT`. Columns: record ID, kind, sink file and line, entry file, group key,
request bytes, whole-record bytes before budgeting, source excerpt bytes, identifier bytes,
question bytes, notice bytes, lossy omitted source bytes, count of omitted items, whether
resolution questions were dropped, and equivalence signature. It is committed first, on the
unchanged wire.

**Why.** The earlier digest tool was local and is gone. Before and after must come from the same
code and be reproducible by a reviewer. **Rejected alternative.** Extending `TestDVWARequestSizes`:
it is DVWA-only and reports only over-limit records.

### D-2 (A) — Identifiers become request-local aliases or counts

A hash-based identifier is any value of the form `<kind>:v1:<64 hex>`, the entry `instance_id`,
and `candidate_id`. In the model-facing projection:

- An identifier that occurs twice or more in the request is replaced everywhere by one short
  alias (`i0`, `i1`, … in order of first occurrence).
- An identifier that occurs once is omitted with its key.
- A list of identifiers keeps only the aliases of members that occur elsewhere and gains a count
  of all members. `xss.related_entries` becomes `related_entry_count` plus the surviving aliases.
- After projection no 64-character hexadecimal run remains in the request outside source excerpt
  and evidence text. Source text is never rewritten, even when it contains a hash literal.

**Why.** The only information a hash carries for the model is whether two of them are equal. An
alias keeps exactly that, so a control bound to another invocation context stays distinguishable.
`normalizeIdentity` already treats these fields as identity, not evidence.
**Rejected alternative.** Deleting every identifier: simpler, but it erases the equality between
a control and its invocation context in records that carry more than one.

Records that differ only in which entries are related become one equivalence class when their
counts match. Their requests are then byte-identical after identity normalization, so one answer
serves both. The class count is recorded before and after (AC3).

### D-3 (B) — State repeated structure once

- Evidence rows put `text` last and omit trailing empty columns. `compact_wire.evidence_columns`
  states the order, and a short row means the missing trailing columns are empty.
- When two or more dependencies end with the same run of four or more transfer references, the
  run is stated once in `shared_transfer_tails` and each dependency ends with its `tN` reference.

Both are applied as the last projection step, after resolution questions and citation chains are
built from the unfactored rows.

**Why.** Both are reversible, so nothing is lost, and applying them last keeps citation checking
on the form it already validates. **Rejected alternative.** Merging rows that share a span: their
kinds and columns differ, so merging would need a new row shape the model has never seen.

### D-4 (C) — Size notices state counts, not lists

The `evidence_omitted_for_size` gap states the number of omitted items by kind, the count that
only repeats supplied text, the source bytes removed, and one `file: first–last line (n)` entry
per file. The `path_group_omitted` gap states the group key, how many of the record's paths the
request carries, and the withheld count per source file. Both keep their closing sentences
unchanged: omitted context is neither absent protection nor absent risk, and a withheld path is
neither absent nor protected. `assessment.evidence_omissions`, the path-group plan and the trace
keep the full lists.

**Why.** The lists describe code the model cannot see and grow as more is shed, so the notice
competes with evidence. **Rejected alternative.** Dropping the notices: the model would then read
a reduced request as complete.

### D-5 (D) — XSS choice descriptions become short labels

Each choice description produced by the "Apply the definition of *X* in this question to the
supplied source evidence." template becomes the value written as words (`html_text` becomes
`html text`). Choice values and question instructions do not change. Descriptions that carry
their own meaning (the resolution questions) are untouched.

**Why.** The sentence repeats the value and adds no definition; the definitions are in the
question instructions. A non-empty label is used because whether the provider accepts an empty
description is unverified, and a rejected request would fail the scan.

### D-6 — One bump: `evidence_version` 8 and `xss-components-v4`

**Why.** [Principle 7](../../architecture/request-size-and-evidence-relevance.md#principles): each
bump invalidates every saved exact replay, so request-moving changes are batched.

### D-7 — "Smaller" is measured on totals and on whole-record size

The budget fills freed space with evidence it used to shed, so a single near-limit request can
stay near the limit while carrying more. Size is therefore judged on total planned bytes, on each
record's size before budgeting, and on how much is shed, not on each capped request.

### D-8 — "Same accuracy" is three checks, the last one paired and paid

1. **Offline invariance.** Unjudged reports from the baseline and the candidate scanner are equal.
2. **Keyed accuracy.** `accuracy.py` rows are equal between a fresh baseline run and the
   candidate run.
3. **Per-record comparison against a noise floor.** Presented-status differences between the two
   arms are listed with their answers and compared with the differences between two baseline runs
   of identical requests.

**Why.** D changes question text and C changes notice text, so offline evidence alone cannot show
that answers hold. A paired run on the same day and model separates the change from model drift.
**Rejected alternative.** Comparing the candidate with the saved 2026-11-19 DVWA run only: that
run used a path-group cap of 4 and an older scanner, so differences could not be attributed.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../../docs/agent-execution-discipline.md). In addition:

- Start each workstream with a failing test from §8.
- These files decide outcomes and MUST NOT change: `internal/judge/policy.go`, `resolution.go`,
  `validation.go`, `followup.go`, the family policy code in `xss.go`, `command.go`, `path.go`,
  `ssrf.go`, `injection.go`, `upload.go` and `code_redirect.go`, and everything under
  `internal/parse/` and the language adapters.
- Build the baseline scanner binary at the step 1 commit and keep it outside the worktree, under
  the container's `_test-findings/judge-request-size-reduction/`. Arm B1 (§7 AC8) uses that binary.
- Do not tune toward a size target by removing anything this contract does not name.

Halt and ask when:

- an outcome-deciding file appears to need a change;
- any unjudged report differs between baseline and candidate beyond request-derived fields (AC6);
- a measured saving is below an AC1 or AC2 threshold;
- model-facing prose (instruction, guidelines, question text) refers to an identifier D-2 removes;
- D-3 cannot be applied after resolution questions are built without touching `resolution.go`;
- a paid call is needed beyond the four AC8 scans (OQ-1) and the one XSS rerun (OQ-2).

## 7. Acceptance criteria

Baseline and candidate inventories are the D-1 TSVs for DVWA `a1978a2` and Juice Shop `f189f52`,
written at the step 1 commit and at the final commit.

1. **AC1 (total size).** Candidate total request bytes are at most 90% of baseline on DVWA and at
   most 97% on Juice Shop. Verified by summing the request-bytes column of both inventories.
2. **AC2 (whole-record size).** Each of the 8 DVWA records over the limit at baseline is at least
   8,000 bytes smaller before budgeting. No record of either sample is larger before budgeting.
   Verified from the whole-record column, joined on record ID.
3. **AC3 (shedding and grouping).** On DVWA: no `evidence_too_large` and no `path_group_cap`; at
   most 24 group requests in total and no record plans more groups than at baseline; total lossy
   omitted source bytes are lower; no request drops its resolution questions, or each one that
   still does is listed with its bytes. A capped request may be larger than at baseline only when
   its lossy omitted bytes fell. The equivalence class count of each sample is recorded, and each
   merged pair is listed. Verified by `TestDVWARequestSizes` and the inventories.
4. **AC4 (A).** `go test ./internal/judge -run '^TestWireIdentity'` proves: a single-occurrence
   identifier is absent; a recurring identifier has one alias at every occurrence; two distinct
   recurring identifiers get distinct aliases; a related-entry list becomes a count plus
   recurring aliases; the `CandidateUse` passed in is unchanged; a hash literal inside a source
   excerpt is kept byte for byte; and across every judge fixture use no request contains a
   64-character hexadecimal run outside source excerpt and evidence text.
5. **AC5 (B, C, D).**
   - `TestWireStructureRoundTrip` expands the version 8 rows and dependencies of every judge
     fixture use back to the version 7 form and finds them equal.
   - `TestSizeNotices` builds a record with 43 omissions and a group with 17 withheld paths. Each
     notice is under 700 bytes, states the counts by kind and by file, and contains its closing
     sentence. `EvidenceOmissions` on the assessment still lists all 43.
   - `TestXSSChoiceLabels` finds no description containing "Apply the definition of", no empty
     description, unchanged choice values, and `XSSProtocol == "xss-components-v4"`.
   - A request carries `evidence_version` 8. A saved version 7 trace does not replay as exact.
6. **AC6 (offline invariance).** Unjudged scans of DVWA and Juice Shop by the baseline binary and
   by the candidate produce `findings.json` files that are equal after removing fields derived
   from request bytes. Each removed field is named in the run log with the reason it derives from
   the request. `check.py` over all eleven sample reports gives the same counts for both scanners.
7. **AC7 (gate).** The [contributor gate](../../../docs/contributing.md#verification) passes.
   `TestArchitectureBaseline` passes with no row changed, or only rows that state a protocol
   version, listed in the run log before the golden is refreshed.
8. **AC8 (live, paired).** Authorized by the owner (OQ-1). On one day, with
   `--judge openai --judge-model gpt-6-luna`, the default judge limit, `JUDGE_RPM=4500`,
   `JUDGE_TPM=1800000`, `--trace-dir` set and only the OpenAI key passed:
   - **Arm B1.** The baseline binary judges DVWA and Juice Shop.
   - **Arm C.** The candidate judges DVWA and Juice Shop.
   - **Arm B0 (no cost).** The saved run under the container's
     `_test-findings/dvwa/run-cfg-live/traces`, restricted to requests whose digest equals a B1
     request digest. For Juice Shop, use a saved run with matching digests if one exists.

   The criterion passes when all of these hold:
   - `accuracy.py` gives arm C the same Found, Review, Missed and False positives as arm B1 for
     both samples. The published rows are DVWA 11 / 11 / 0 / 0 / 0 and Juice Shop
     15 / 15 / 0 / 0 / 0; if B1 differs from them, B1 governs and the difference is reported.
   - No keyed positive presents lower in C than in B1. No keyed control or protected control is a
     finding in C.
   - The share of records judged in both arms whose presented status differs between B1 and C is
     at most the B0-to-B1 share plus 2 percentage points. If no B0 exists for Juice Shop, DVWA's
     share is used.
   - Every B1-to-C difference is listed in the results document with both arms' answers per
     question and whether the record's omissions changed.
   - Provider-reported input tokens for arm C are lower than for arm B1 on each sample.
9. **AC9 (docs).** The architecture document gains one strategy entry per workstream and one
   ledger row per measurement. The results document holds the AC1–AC3 tables, the AC6 statement
   and the AC8 comparison. User docs describe the alias scheme and the shorter notices where they
   describe the old fields. [doc-check](../../../.agents/skills/doc-check/SKILL.md) passes.

Expected sizes after the change, estimated from the baseline parts. They are not criteria:

| Measure | Baseline | Estimate |
|---|---:|---:|
| DVWA total request bytes | 9,388,206 | about 8.2 MB (−13%) |
| Juice Shop total request bytes | 3,193,060 | about 3.0 MB (−5%) |
| DVWA `bac` record before budgeting | 67,703 | about 57 KB, judged whole |
| DVWA `sqli` record before budgeting | 83,340 | about 72 KB, four groups |

## 8. Test strategy

- **Projection tests (A, B).** Table tests on small hand-built `CandidateUse` values, plus one
  sweep over the existing judge fixture uses for the no-hash and round-trip properties. The sweep
  replaces per-family copies.
- **Notice test (C).** One synthetic record and one synthetic group at the sizes DVWA reached.
- **Pack test (D).** One table over every XSS question.
- **Existing tests.** `TestRequestBudget*`, `TestPathGroup*`, the replay tests and the scheduler
  goldens keep their intent. Only expected bytes, digests, notice text and versions move.
- **Samples.** The inventory, `TestDVWARequestSizes`, `check.py` and `accuracy.py`. Sample reports
  and traces stay outside the worktree.
- Not tested: model wording, and token counts offline (no tokenizer; AC8 reads provider usage).
  Python and the other samples are covered offline by `check.py` and by fixtures, not by a live
  run.

## 9. Execution sequence

Each step is one commit and starts from a failing test where it changes code.

1. **Inventory.** Add `TestRequestInventory`. Write baseline inventories for DVWA and Juice Shop;
   confirm they reproduce the §1 table. Build and save the baseline binary. Write baseline
   unjudged reports for all eleven samples and the baseline `check.py` output.
2. **A.** `wire_identity.go` and its tests; `evidence_version` 8; equivalence normalizer.
3. **B.** Row column order and shared transfer tails; schema sentences in the instruction.
4. **C.** Notice text in `omissionGap` and `groupUse`.
5. **D.** XSS choice labels and `xss-components-v4`.
6. **Offline measurement.** Candidate inventories, AC1–AC3, AC6, AC7. Write the results document.
   Stop here if any offline criterion fails.
7. **Live.** Arms B1 and C on the same day, then the AC8 comparison.
8. **Docs.** Architecture entries and ledger, user docs, index and plan, draft PR.

Shape of the two new projection functions (bodies are the implementer's):

```go
// localIdentity rewrites hash-based identifiers in a decoded request bundle:
// recurring ones become aliases, single ones are removed, lists gain a count.
func localIdentity(bundle map[string]any) map[string]any

// factorStructure reorders evidence rows, trims trailing empty columns and
// states shared transfer tails once. expandStructure reverses it for tests.
func factorStructure(bundle map[string]any) map[string]any
func expandStructure(bundle map[string]any) map[string]any
```

### PR #33 acceptance decision

Evaluate AC1–AC8 on the size-only implementation. The separately specified
[evidence-quality follow-on](judge-evidence-quality.md) intentionally changes PHP evidence and
derived record IDs. Its measurements are reported separately. For this PR, the reviewer accepts
the two recorded AC8 exceptions (status-change rate and JS-LOG-01 presentation). Keep the
original thresholds and measured failures in the record. The acceptance applies only to the
published comparison. It establishes no tolerance for future status changes or keyed misses.
The [review decisions](../../evaluation/judge-request-size-reduction-results.md#pr-33-review-decisions)
also accept the citation decoder and digest/replay test changes needed for the new wire format.

## 10. Definition of done

- [x] AC1–AC9 reviewed with the release exceptions documented above.
- [x] OQ-1 to OQ-3 answered by the owner and recorded (§11, 2026-11-19).
- [x] Scope checked against both contracts and the accepted deviations above.
- [x] Sample checkouts clean at their pins before and after.
- [x] Fresh-context verification completed for the size-only and combined implementations (§13).
- [x] PR #33 into `stage` links the acceptance evidence.

## 11. Open questions

- **OQ-1 (answered 2026-11-19: authorized).** AC8 needs four judged scans: baseline and candidate
  for DVWA (about 200 requests each) and Juice Shop (about 62 each), about 525 requests in all.
  The owner authorized this paired comparison on the AC8 terms (`openai`, `gpt-6-luna`, default
  judge limit). It covers those four scans once. A rerun, another sample, another model or a
  materially higher request count needs the owner's word again.
- **OQ-2 (answered 2026-11-19: authorized, once).** If AC8 fails on XSS records only, the agent
  may rerun DVWA with `--only-family xss` and D reverted, to tell D from A–C (about 110 more
  requests). One rerun; anything further needs the owner's word.
- **OQ-3 (answered 2026-11-19: keep the allowance).** A changed status on a record outside the
  answer key is judged by AC8 as written. The model's answers vary a little between two runs of
  identical requests, and records outside the key have no known right answer, so the criterion
  passes when such changes are no more frequent than that run-to-run variation plus 2 percentage
  points (about 4 records on DVWA). Every change is listed in the results document for the owner
  to review. Source review of each changed record is not required for sign-off.

## 12. Run log protocol

Use the common run-log rules. Record the scanner SHA and toolchain, sample pins and clean status,
the path of each inventory and report, the baseline binary's SHA, each workstream's failing-first
evidence, golden deltas, and for each live arm the run identifier, request count and
provider-reported input tokens.

## 13. Agent implementation prompt

> Work in the `judge-request-size-reduction` sibling worktree on its branch. Read AGENTS.md, the
> orientation contents, this spec and its §2 reading. §11 is fully answered; do not
> reopen it. Execute §9 in order, one commit per step,
> each code step starting from a failing §8 test. Change only the model-facing projection: never
> edit a file §6 lists as deciding outcomes. Keep samples read-only. The only paid calls allowed
> are the four AC8 scans, once, after the step 6 offline criteria pass, and the one OQ-2 rerun.
> Stop on any §6 halt and report the measurement that triggered it; do not tune toward a
> threshold. Finish with a draft PR into `stage` that lists AC1–AC9 evidence.
>
> Verifier: a fresh-context subagent regenerates both candidate inventories, recomputes AC1–AC3
> from the TSVs, reruns the AC4 and AC5 tests, diffs the baseline and candidate unjudged DVWA
> report as AC6 describes, and confirms from `git diff origin/stage --stat` that no
> outcome-deciding file changed. It reports PASS or FAIL per criterion in the run log.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Drafted from an offline measurement of DVWA and Juice Shop at `8dd0460`. No code changed.

### 2026-11-19 — OQ-1 answered

The owner authorized the paired live comparison (§11 OQ-1; AC8, §6 halts, §9 step 7 and §13
updated). OQ-2 and OQ-3 remain open. No change to scope, criteria or tests.

### 2026-11-19 — OQ-2 answered

The owner authorized one XSS-only bisect rerun on DVWA if AC8 fails on XSS records only (§11
OQ-2; §6 halts and §13 updated). OQ-3 reworded for clarity and still open.

### 2026-11-19 — OQ-3 answered

The owner kept the AC8 allowance for records outside the answer key (§11 OQ-3; §10 and §13
updated). All open questions are answered. No change to scope, criteria or tests.
