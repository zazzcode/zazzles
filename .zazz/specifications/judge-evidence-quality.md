# Judge evidence quality for low-confidence records

- **Worktree and branch** `judge-request-size-reduction`, the owner's assignment for this
  follow-on.
- **Baseline** That branch at `4e59f1d` (the [request size reduction](judge-request-size-reduction.md)
  candidate, not yet merged to `stage`).
- **Delivery** It ships in the same draft PR as the request size reduction: one code commit for
  P, O, T and K, which share their files and test file, then one results commit. The scanner and evidence changes join that contract's unreleased bump (`evidence_version`
  8, `xss-components-v4`), so saved replays are invalidated once.
- **Run log** `.zazz/ephemeral/judge-request-size-reduction-run-log.md`, section "Evidence quality".
- **Owner direction** On 2026-11-20 the owner said to improve the scanner so it sends the important
  information to the judge, and to iterate on it unattended.

## 1. Capability

Send the decision model the facts it needs on records where it is now unsure, so vulnerability
verdicts become confident without making them less correct. Four fixes:

| ID | Fix | Defect it removes |
|---|---|---|
| P | Prepared-statement provenance | A PHP `execute()` claim shows the query literal, `bindParam` and `execute()`, but not the `$stmt = $db->prepare(…)` that makes the literal the statement |
| O | Per-path output context | A PHP XSS record states one context for the whole `echo`, so values that land in quoted attributes are stated as `html_text` |
| T | One transfer per concatenation site | A left-nested `.` chain records one `string_construction` per level, and each repeats the template from its start (a 3 KB page template, eight times) |
| K | Cookie-source rule | The XSS guidance never says how a cookie source bears on exposure, so the model splits between vulnerable and unknown |
| V | Request-element state | Page code that allow-lists a request element and resets it when invalid (DVWA's `security` cookie, `dvwaPage.inc.php:22`) is invisible: the scanner states that path `raw`, which contradicts the code (added after live round 1) |

### Measured baseline

The baseline is the candidate arm C of the paired run, DVWA `a1978a2`, on 2026-11-20. Each record's
verdict question was scored by the provider's top-choice probability (`live/confidence.py`).

| Record set | Records | Median top probability | Share ≥ 0.70 | Answers |
|---|---:|---:|---:|---|
| SQL `execute()` of a prepared statement **with** the prepare call in the request | 8 | 0.76 | 88% | 8 protected |
| SQL `execute()` of a prepared statement **without** it | 6 | 0.85 | 67% | 4 protected, 1 vulnerable, 1 unknown |
| XSS, DVWA shared page renderer | 83 | 0.79 | 65% | 72 vulnerable, 11 unknown |
| XSS, cookie-only sources | 46 | 0.64 | 39% | 35 vulnerable, 11 unknown |

All six PDO-bound records are correct only when answered Protected. The B1 arm sent the same
evidence with other wording, and records without the prepare call there had a median of 0.57.

Offline, at the baseline:
- 6 of DVWA's 14 SQL `execute()` claims carry no `prepare(` text.
- 90 of 91 DVWA XSS records state `html_text`. An approximate scan of the interpolation sites
  places only one path in HTML text.
- 90 records repeat `string_construction` transfers that share a start byte.
- 46 XSS records have only cookie sources, and 89 have at least one.

## 2. Required reading

- [Request size reduction results](../evaluation/judge-request-size-reduction-results.md): the
  sections "Investigation of the AC8 changes" and "Attribution runs".
- [XSS analysis rules](../../docs/analysis/xss.md#output-context-and-protection).
- [Calibration pairs](../../docs/analysis/calibration.md#regression-pairs).
- Code:
  - `sqlPrepare` and `sqlExecPrepared` (`internal/langphp/sql.go`)
  - `render` and `binaryValues` (`internal/langphp/flow.go`)
  - `recordXSS` (`internal/langphp/xss.go`)
  - `linkStorage` (`internal/langphp/sql.go`)
  - the XSS policy that compares `output_context` (`internal/judge/xss.go`)
  - `parse.HTMLOutputContext`

## 3. Invariants

- Policy and gate code does not change: `internal/judge/policy.go`, `xss.go`, `resolution.go`,
  `validation.go` and the other family policy files.
- No evidence is removed except enclosing concatenation levels whose text the kept innermost level
  and the sink already supply.
- A record's stated `output_context` changes only when every raw path shares one context. The XSS
  policy compares the model's single answer with it, so a mixed record keeps its echo-level
  statement.
- `check.py` and `accuracy.py` offline output is unchanged across the eleven samples.
- Samples are read-only. Live checks follow AGENTS.md: openai, gpt-6-luna, `JUDGE_RPM=4500`,
  `JUDGE_TPM=1800000`, with explicit caps.

## 4. Scope

| Path | Change | Fix |
|---|---|---|
| `internal/langphp/sql.go` | Modified | P (`sqlPrepare`), O (`linkStorage` keeps path contexts) |
| `internal/langphp/xss_context.go` | New | O |
| `internal/langphp/flow.go`, `xss.go`, `values.go` | Modified | O, T, V |
| `internal/langphp/superglobal_state.go` | New | V |
| `internal/langphp/control.go`, `calls.go`, `guards.go` | Modified | V: branch join, helper state, `in_array` on an element |
| `internal/analysis/xss.go` | Modified | O: `XSSPath.OutputContext` (`omitempty`, so other adapters' bytes are unchanged) |
| `internal/guidelines/php.md`, `javascript.md`, `python.md` | Modified | K, and O's path sentence for PHP |
| `docs/analysis/xss.md` | Modified | K and O product rules |
| Tests and goldens under `internal/langphp/`, `internal/guidelines/`, `internal/judge/`, `internal/langpy/testdata/`, `cmd/scan/testdata/` | New or modified | Tests for P, O, T and K; digest goldens |

Out of scope:
- mysqli object-style `bind_param`. It produces no candidate today, which is a recall gap.
- Logging confidence. JS-LOG-01 carries six genuine blocking gaps.
- Relevance filtering of off-chain helper excerpts. S2 was measured and not adopted, see the
  [request-size architecture](../architecture/request-size-and-evidence-relevance.md).
- Question wording.

## 5. Decisions

### D-1 (P) — The prepare assignment is statement evidence

`sqlPrepare` records the prepare call as `statement_preparation` evidence: the enclosing assignment
when there is one, so the request shows which variable holds the statement. It rides
`sqlTextEvidence`, so every `execute()` claim carries it in its `query_text` role and context.

**Why.** That role already holds the literal, and no gate reads it. **Rejected alternative.** Moving
`sink_binding` onto the prepare call: `sink_binding` is a required role, and the gate meaning of the
operation would change.

### D-2 (O) — Context is read where the value lands

The context comes from the literal text before the value in the outermost string template that
embeds it. The adapter checks each hop of the path, in order. The first non-text context found in a
helper's template decides, because markup built there and echoed later keeps its inner context.
Failing that, the echo's own template decides, after the page's inline markup. Stored paths inherit
their read path's context through `linkStorage`.

**Why.** A value is escaped or not for the place it lands, and one context per `echo` is wrong for
templates. **Rejected alternative.** Stating `unknown` for a record with mixed contexts: the
unchanged XSS policy then blocks every such record.

### D-3 (T) — Keep the innermost concatenation level

A path whose last transfer is a `string_construction` starting at the same byte is not given another
one. **Why.** That innermost level is the template up to the value, which shows where it lands. Each
enclosing level repeats the template from its start and adds nothing the sink does not already show.

### D-4 (K) — A cookie is request input

The XSS guidance of PHP, JavaScript and Python says: "A cookie value is request input the client
sends, like a query or form field: a raw cookie value rendered into markup is a supported source
path. Whether an attacker can set another user's cookie is a delivery question the scanner does not
establish; it alone does not make exposure unknown."

**Why.** The model split 35 vulnerable against 11 unknown on cookie-only records for want of a rule.
Per the owner's preference, the model still judges each case. This is a product rule (OQ-1).

### D-6 (V) — Track writes and checks of literal request elements

A write to `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE` or `$_FILES` at a literal key is stored as flow
state in `f.globals`, under its own prefix. So are the protections a branch condition implies for
such an element (now including `in_array` on an element). Branch merges join that state. An
untouched branch keeps the element "fresh", meaning the request's own value. Helpers see the state
and return only what they changed. A read yields the state, joined with fresh input when some path
left it unchecked.

**Why.** This is the existing `$GLOBALS` mechanism, which keeps the change local and sound per branch.
**Rejected alternative.** Applying false-branch protections to every variable whether or not the
true branch terminates: it changes the semantics of all PHP variables, not only request elements.

### D-5 — No new bump

The changes join `evidence_version` 8 and `xss-components-v4`, which have not shipped. **Why.**
Principle 7: batching request-moving changes invalidates saved replays once.

## 6. Agent implementation rules

Follow the [execution discipline](../docs/agent-execution-discipline.md). Each fix starts from a
failing test. Halt when:
- a policy or gate file appears to need a change;
- offline `check.py` or `accuracy.py` output moves;
- a live keyed positive presents lower than in arm C, or a keyed control becomes a finding;
- a live round would exceed the caps in §7 AC5.

## 7. Acceptance criteria

1. **AC1 (P).** `TestPHPPreparedStatementProvenance` (PDO `bindParam` and `bindValue`) finds a
   `statement_preparation` item starting with the statement variable and containing `->prepare(`
   in the `query_text` role and in the context. Offline, 0 of DVWA's 14 `execute()` claims lack
   `prepare(`.
2. **AC2 (O).** `TestPHPXSSPathOutputContext` gives the expected path contexts:
   - a cookie in `class="…"`: `html_attribute`
   - a cookie in a helper-built `data-url='…'`: `html_attribute`
   - a query value in `<p>`: `html_text`
   - a query value in `href`: `url`
   A record with mixed raw contexts states the echo-level `html_text`. A record whose single raw path
   is in an attribute states `html_attribute`. Inline `<?php echo ?>` contexts are unchanged.
   Offline, every DVWA XSS path carries a context.
3. **AC3 (T).** `TestPHPNestedConcatenationTransfers`: a value in a four-level chain has exactly one
   `string_construction` transfer, `"<p class=\"" . $x`.
4. **AC4b (V).** `TestPHPSuperglobalElementState`:
   - A cookie checked by `in_array` at page level and reset in a helper is not `raw` where another
     helper reads it.
   - An unchecked cookie stays `raw`.
   - A written literal is not request input.

   Offline, all 82 DVWA `$_COOKIE['security']` paths are `component`, all 89 `theme` paths stay
   `raw`, and a DVWA scan finishes in seconds. An early version doubled the gap list at every merge
   and hung.
4. **AC4 (K).** `TestXSSCookieAndPathContextGuidance` finds the cookie rule in the PHP, JavaScript
   and Python XSS guidance, and the path-context sentence in PHP's.
5. **AC5 (live confidence).** At most two rounds, each one DVWA scan (`--judge-limit 200`) and one
   Juice Shop scan (`--judge-limit 40`) on the AGENTS.md terms, compared with arm C by
   `live/confidence.py`:
   - All six PDO-bound `impossible.php` SQL records answer protected, and the execute-of-prepared
     set has a median of at least 0.80.
   - Cookie-only XSS records have a median of at least 0.70, or a share ≥ 0.70 at least
     20 points above C's 39%.
   - Keyed accuracy equals C's: DVWA 11/11/0/0/0, Juice Shop 15/15/0/0/0. No keyed control is a
     finding.
6. **AC6 (gate).** The contributor gate passes. Golden moves are limited to:
   - architecture baseline: request digests, signature digests, report hashes and SARIF hashes
     (PHP evidence and XSS component digests)
   - scheduler goldens
   - the predecessor digest tables
   - the component-digest goldens

## 8. Test strategy

- One fixture-driven adapter test per fix, P, O and T, in `internal/langphp/evidence_quality_test.go`.
  O's fixture covers a helper-built attribute, a direct attribute, text and a URL in one template,
  so a single record exercises every branch of D-2.
- One guidance test, K. A wording test for the question text is not needed, because the question
  text does not change.
- The existing `TestPHPExecuteCarriesPreparedText` moves from one `query_text` item to the literal
  plus the prepare assignment.
- Samples: `check.py` and `accuracy.py` across the eleven samples, the inventory, and
  `TestDVWARequestSizes`.
- Not tested: model wording. AC5 measures its effect live.

## 9. Execution sequence

1. P, then O, then T, then K. Each starts from its failing test, followed by a golden refresh.
2. Offline measurement (AC1–AC4, AC6).
3. Live round 1 (AC5). If AC5 misses a target, iterate once on the evidence for that set. Never
   tune toward a threshold by removing evidence.
4. Record the results, then commit.

## 10. Definition of done

- [ ] AC1–AC6 verified, each with its command in the run log.
- [ ] Samples clean at their pins.
- [ ] Results recorded in the request size reduction results document.

## 11. Open questions

- **OQ-1 (decided by default, owner may revert).** D-4 makes a cookie an ordinary request source
  for XSS. The alternative is to present cookie-only XSS as Review or as a practice finding. That
  needs a policy change and is out of this contract.

## 12. Run log protocol

Append to the branch run log under "Evidence quality". Record:
- each fix's failing-first evidence
- the golden moves
- the offline measures
- each live round's run IDs, request counts and confidence table

## 13. Agent implementation prompt

> Work in `judge-request-size-reduction`. Read this contract and its §2 reading. Implement §9 in
> order, one commit per step, each starting from its failing test. Do not touch policy or gate files.
> Stop on any §6 halt. Live checks use only the §7 AC5 caps.

## 14. Implementation and review change log

### 2026-11-20 — Drafted and implemented in the same session

The owner asked for unattended iteration. P, O, T and K were implemented test-first before the
first live round.

### 2026-11-20 — Live rounds 1 and 2

Round 1 met every AC5 target except two. Cookie-only confidence was a median of 0.69 with 48% at or
above 0.70. Protected control PC-CMD-02 presented as a finding. Investigating the first found the
unmodeled allow-list reset of the `security` cookie, which became fix V (§1, §4, D-6, AC4b).
Round 2 met the cookie target: a median of 0.72, with 61% at or above 0.70. PC-CMD-02 remains a
finding. Its guard contract already states the `is_numeric` trailing-newline edge case, so it is a
close-call judgment reported to the owner, not tuned (§6 halt recorded in the results document).

