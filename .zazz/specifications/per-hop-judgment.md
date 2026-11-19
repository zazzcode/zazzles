# Per-hop judgment (proposal)

- **Worktree and branch** To be assigned by the owner. Suggested: `per-hop-judgment`. This proposal
  is drafted on `per-hop-judgment-spec`.
- **Prerequisite** [Close findings gaps](close-findings-gaps.md) (path-group requests, W4; not yet
  merged, draft PR zazzcode/zazzles#31) and
  [model-assisted evidence resolution](model-assisted-evidence-resolution.md) on `stage`.
- **Delivery** One draft PR into `stage`, with one commit per workstream that ships.
- **Run log** `.zazz/ephemeral/per-hop-judgment-run-log.md`
- **Owner decisions** §17 lists the open questions. None is answered yet.

## 1. Capability

Today one decision request carries a record's whole source-to-sink evidence. Per-hop judgment
splits that work. Each small request carries one section of code on the record's path: a helper
body, a guard, a transform or a sanitizer. It asks one narrow question about how that section
treats one tracked value. The scanner then combines the answers with its own path facts, by a
fixed rule, into the record's outcome. A section's answer is cached by its bytes and question
version. A helper that sits on many paths is judged once per scan, not once per request. Records
that cannot be split safely keep the whole-path request. Per-hop judgment is lossy: it changes
what the model sees. Before adoption it needs a paid ablation against saved whole-path judgments
(§12).

## 2. Measured baseline

DVWA `a1978a2`, scanner `0b1e109` (the close-findings-gaps branch), offline
`TestDVWARequestSizes`:

| Measure | Value |
|---|---|
| Records over the 65,536-byte limit after shedding | 8 XSS records, 67,703–83,340 bytes, all sinks at `dvwa/includes/dvwaPage.inc.php:388` |
| Path-group requests | 23 sent plus 1 past the 4-group cap (`sqli/index.php` record, `sqli/source/medium.php` group) |
| Size of each group request | 56,298–64,805 bytes; 1,428,753 bytes in all |
| On-chain excerpt bytes per group | 12,617–18,571 (338,706 in all); off-chain 3,031–5,344 |
| Estimated input tokens for the 23 groups | about 428,000, at the DVWA live ratio of 0.30 tokens per request byte |

Saved live judgments under the container's `_test-findings/<app>/run-cfg-live*/traces`
(`gpt-6-luna`, scanners `856fe70`/`fdc1148`), measured from each trace's request and `usage`:

| Sample | Saved traces | Input tokens | On-chain sections, all requests | Distinct on-chain sections | Distinct sections in opaque roles |
|---|---:|---:|---:|---:|---:|
| DVWA (`run-cfg-live`) | 179 of 195 requests | 1,835,924 | 799 | 196 (113,764 bytes) | 55 (39,573 bytes) |
| nodejs-goof (`run-cfg-live`) | 11 | 64,906 | 63 | 30 | 17 |
| python-insecure-app (`run-cfg-live2`) | 2 | 8,106 | 2 | 1 | 1 |

- **Section.** A source excerpt that an evidence row on a dependency chain points to.
- **Opaque role.** A chain row the model has to interpret: `helper_return`, `string_transform`,
  `escape_transform`, `conditional_value` and the branch preconditions.
- **Opaque section size.** Median 155 bytes, p90 1,868 bytes, largest 6,916 bytes (DVWA).
- **Page shell.** The largest section is the DVWA page shell, `dvwaPage.inc.php:281-451`. It
  appears in 69 saved requests and in every one of the 23 group requests. Four page-shell sections
  are on the chain of every page-rendered DVWA record: the branch preconditions at 192–197 and
  200–216 and the helper returns at 281–451 and 537.
- **Group requests are not in the saved traces.** The 19 group requests of the live run have no
  trace file: none of their `path_groups[].request_digest` values matches a trace. For those 7
  records, the baseline is the outcome recorded in `findings.json`.

## 3. Required reading

- [Request size and evidence relevance](../architecture/request-size-and-evidence-relevance.md):
  principles 3–6, the tiering model, path-group requests, S1 and S2, and the
  [ablation protocol](../architecture/request-size-and-evidence-relevance.md#ablation-protocol-for-lossy-changes).
  This spec applies that protocol.
- [Data-path slicing (S1)](data-path-slicing.md): the fallback list and the regression pairs. Per-hop
  judgment reuses both.
- [Model-assisted evidence resolution](model-assisted-evidence-resolution.md): §3, D-2, D-3, D-7 and
  D-8. The flow-gap `resolve_flow_*` questions already ask about one span. This spec asks about a
  span's effect, never about a missing edge.
- [Separate judgments and gates](../architecture/trace-judgment.md#separate-judgments-and-gates) and
  [model-assisted evidence resolution](../architecture/trace-judgment.md#model-assisted-evidence-resolution).
- [XSS output context and protection](../../docs/analysis/xss.md#output-context-and-protection) and
  the [replacement rules](../../docs/analysis/xss.md#sanitizer-advisories-and-replacements).
- [Command injection facets and outcomes](../../docs/analysis/command-injection.md#facets-and-outcomes):
  the shared guard engine, guard contracts and the `admits_any` capture rule.
- [Close findings gaps results](../evaluation/close-findings-gaps-results.md) (not yet merged, PR
  zazzcode/zazzles#31): the W4 measurement and the live check.
- [Calibration regression pairs](../../docs/analysis/calibration.md#regression-pairs),
  [testing standards](../standards/testing.md) and
  [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Invariants

- **A model answer never fills a missing fact.** Per-hop questions describe what a section does
  to a value whose entry into the section and exit from it the scanner already proved. They never
  supply an edge, a callee, a dispatch alternative, a source, a sink slot or an output context. A
  record with any such gap is not eligible (§5). The flow-gap questions of the
  [resolution contract](model-assisted-evidence-resolution.md) stay the only way a model answer can
  bridge a gap.
- **Vulnerable needs a complete path.** A per-hop finding needs one complete scanner path: a proven
  source, every hop a scanner edge, a proven sink slot and a known output context. No control may
  dominate the sink on that path, and no hop may reduce the value's characters for the context.
- **Protected needs a control on every path.** A per-hop Protected needs every path of the record
  to be enumerated by the scanner, with no open gap. Each of those paths needs a protecting section
  or a dominating control, and no later hop on that path may undo it.
- **Adequacy comes from the scanner's table.** No question asks whether a section is adequate for
  a sink. A question asks which characters can leave the section, for a character set the scanner
  picked for the sink context. The scanner's table decides adequacy.
- **Fallback, not guesswork.** A record the rule cannot decide takes the whole-path request (and,
  when over the limit, the existing shedding and path groups). It never takes Review merely because
  per-hop judgment was tried.
- **Deterministic.** The same input gives the same section bytes, cache keys, request bytes and
  composed outcome. Composition never depends on completion order.
- **Visible.** Every answer that a composed outcome relied on is in the record: section key,
  question and version, answer, cache hit, and request digest.
- **Bounded.** Each per-hop request counts against `--judge-limit`; cache hits do not. Transport
  retry rules are unchanged. No new stop condition.
- **Labels stay out.** Sample names, expected labels and case IDs never select sections, questions
  or character sets.

## 5. Sections and questions: what decomposes

### 5.1 Section kinds

A section is the smallest unit of source the scanner can bound, with a proven entry binding (how
the tracked value enters) and a proven exit binding (how it leaves):

| Kind | Bytes sent | Entry binding | Exit binding |
|---|---|---|---|
| Helper | One callable body | Parameter index, and field path if any | Return value, a by-reference parameter, or emitted output at a scanner-known sink |
| Transform | One call or expression applied to the value | Operand position | Expression result |
| Guard | The condition and its terminating branch | The operand the condition mentions | Execution continuing past the guard |

A section is **closed** when every call inside it that touches the value is either a verified
library contract or a section of its own. A section that is not closed is not decomposable.

### 5.2 Questions

The decision APIs take choice questions only.

| Question | Asked of | Choices |
|---|---|---|
| `hop-effect-v1` | Helper and transform sections | `preserves`, `restricts`, `encodes`, `replaces_constant`, `decodes`, `depends_on_condition`, `cannot_tell` |
| `hop-alphabet-v1` | Helper and transform sections whose effect is not `preserves` | For the character set S that the scanner names: `none_of_set`, `some_of_set`, `cannot_tell` |
| `hop-guard-v1` | Guard sections | When execution continues past this guard, can the operand contain a character from S: `none_of_set`, `some_of_set`, `cannot_tell` |

The scanner picks S from the sink context. S is listed in the request, and each family's guideline
owns the table:

| Family and context | S |
|---|---|
| XSS HTML text | `<`, `&` |
| XSS quoted non-active attribute | `<`, `&`, `"`, `'` |
| Command shell-syntax facet | `;` `\|` `&` `$` backtick `(` `)` `<` `>`, newline, and the quote characters |

A guard request also carries the guard contract that the command analyzer already supplies, such
as PHP 8 `is_numeric` accepting trailing whitespace.

### 5.3 What decomposes

| Shape | Decomposes | Why |
|---|---|---|
| A closed helper's effect on one value | Yes | The question is about one section, and the scanner proves both bindings |
| A sanitizer's output characters for one context | Yes, when adequacy for that context depends only on which characters reach the sink | The scanner's table maps `none_of_set` to adequacy (§4) |
| A guard's accepted characters | Yes, for the guard alone | Whether the guard protects the record is a dominance fact, which the guard engine proves |
| A page-shell helper that wraps the value in constant markup | Yes, when the scanner holds the final output context | The section only carries the value. Its constant markup does not decide the context |

### 5.4 What does not decompose

Each row is recognised by the planner before any request is sent, or by the composer from the
answers. Such a record falls back.

| Shape | Detected by | Why it does not decompose |
|---|---|---|
| A guard on one branch only | Composer: the guard engine shows the guard dominates some paths and not others | The section answer is true, but protection is a path property. The unguarded sibling path is judged as its own path: Confirmed if it is complete and raw, otherwise fallback. The guarded path cannot lend protection to it |
| A guard whose dominance, polarity or terminating branch is not proven | Planner | Only the guard engine may decide that a guard protects a path |
| A sanitizer followed by decoding | Composer: a later hop answered `decodes` | Each answer is locally correct, but their order undoes the protection. The rule cannot tell whether the decoder reverses that encoder, so the record falls back and never becomes Protected |
| A sanitizer followed by concatenation into a different context | Planner: a later section builds the markup or syntax around the value, and the scanner does not hold that context | The context changes inside a section. Per-hop answers do not carry context |
| A reassignment between guard and sink | Guard engine (already invalidates the guard); planner when the write is inside a section that is not closed (by-reference helper, `extract`, variable variables, alias writes) | The guard's answer describes an earlier value |
| Adequacy that depends on context in a way characters cannot express | Planner: XSS URL, script, style, active-attribute, unquoted-attribute and unknown contexts; command executable and argument facets | `javascript:` URLs, option injection and script contexts are not character questions |
| Effect that depends on state outside the section | Planner: globals, configuration reads, object properties, callbacks, loops that accumulate, or exception-driven exits on the value | The bytes alone do not determine the answer |
| Sections over 16,384 bytes | Planner | The request would not stay small. The whole-path request is the better unit |

v1 covers XSS (HTML text and quoted attributes) and the command shell-syntax facet. Those are the
families whose guard and protection rules already reduce to characters (§3). SQL (escaping depends
on quoting and charset), path (containment relates two sections) and the other families are out of
scope (§9).

## 6. Composition

The composer works on the scanner's path facts. For each dependency path P it has the ordered
hops h1…hn, the controls the guard engine proves dominate the sink on P, and the sink context. Each
hop's effect is either scanner-classified (for example a verified `htmlspecialchars` contract, a
literal concatenation, an `admits_any` capture) or one per-hop answer. The value state starts as
`raw` and moves through the hops in order:

| Hop effect | Next state |
|---|---|
| `preserves`, or a scanner-classified neutral transform | unchanged |
| `encodes`, `restricts` or `replaces_constant` with `hop-alphabet-v1` = `none_of_set` | `protected` |
| `encodes` or `restricts` with `some_of_set` | unchanged |
| `decodes`, `depends_on_condition` or `cannot_tell`, in any state | `undecided` |

Path outcome:

- **Raw.** The path is complete (§4). Every hop's effect is known, and none is `undecided`. The
  final state is `raw`. No control dominates the sink on P.
- **Protected.** The final state is `protected`. Or a dominating control on P answered
  `none_of_set` and no hop after it writes the operand.
- **Fallback.** Anything else, including a dominating control answered `some_of_set`. Per-hop
  judgment never confirms a guarded path: that needs the whole-path `guard_bypass` answer.

Record outcome:

- **Confirmed** when any path is raw. The finding is scoped to that path, as path groups are today.
- **Protected** when every path is protected and the scanner holds path completeness: every
  dispatch alternative and every dependency enumerated, and no open gap on any path.
- **Fallback** otherwise. Only the fallback paths are sent whole-path. When those are still over
  the limit, they go through shedding and path groups, which may lift the DVWA `sqli` fifth group
  under the cap.

A record whose paths need no per-hop answer is not eligible (D-3).

## 7. Section answer cache

- **Key.** SHA-256 over these parts:
  - question name and version;
  - language and the digest of the guideline section in the request;
  - the section's model-facing bytes (after W7 condensing);
  - the entry and exit bindings, in section-relative coordinates;
  - the character set id;
  - the guard contract text, if any;
  - for every inner call on the value, the id of its library contract or the key of its own
    section (a Merkle chain).

  File path and line numbers are not part of the key. Two identical copies of a helper therefore
  share one answer, unless an inner call resolves differently.
- **Scope.** One scan memoizes by key. Every record that reaches the same key reuses the first
  answer, and the record lists it as a cache hit. Across scans, the existing exact-request replay
  under `--trace-dir` applies: a per-hop request's digest is its key, so the stored response is
  bound to its exact bytes.
- **Example.** The DVWA page-shell helper (`dvwaPage.inc.php:281-451`, 6,916 bytes, `$pPage['body']`
  to emitted output) has one key for `hop-effect-v1`. Today it is sent in 69 saved requests and in
  all 23 group requests. Per-hop sends it once per scan. A `hop-alphabet-v1` request for HTML text
  follows only if the effect is not `preserves`.
- **Invalidation.** Any change to the section bytes, the bindings, an inner contract, the guideline
  section or the question version gives a new key. Old answers are never replayed onto a new key.

## 8. Request, token and cost estimates

A per-hop request carries a short static instruction, the one guideline section for its question,
the section, its bindings, S, and one or two questions. Its fixed part is estimated at 4 KB. That
is from today's requests: instruction 2,095 bytes, guideline 3,439 bytes, six questions 6,261
bytes. A per-hop request sends one or two questions and one guideline section. So a per-hop
request is about 4–11 KB, or 1,200–3,300 tokens at 0.30 tokens per byte. The offline planner
(AC3) replaces these estimates with measured bytes before any paid run.

| Scope | Today | Per-hop estimate |
|---|---|---|
| 8 over-limit DVWA records | 23 group requests plus 1 capped; 1,428,753 bytes; about 428,000 tokens | About 16–28 requests: the 4 shared page-shell sections plus up to 2 per level source file, across about 12 files. About 80–225 KB, about 24,000–67,000 tokens. The capped path is judged |
| DVWA, every saved record, if all were eligible (upper bound) | 195 requests; 1,835,924 tokens over 179 traces | 55 distinct opaque sections. Up to 110 keys once binding and character-set variants are counted. 398 section instances without the cache. About 78,000–156,000 tokens |
| nodejs-goof | 11 requests; 64,906 tokens | 17–34 requests. More requests than today. The run tests accuracy, not savings |
| python-insecure-app | 2 requests; 8,106 tokens | 1–2 requests |

- **Cost** grows with input tokens at the provider's rate. This spec assumes no price.
- **Savings** are real only for large records that share sections, which is DVWA's page shell. On
  small samples, per-hop judgment can cost more requests than whole-path judgment.
- **Fallback records** pay for both their per-hop requests and their whole-path request. §12
  measures the fallback rate.
- **Prompt caching.** The decisions provider reported zero cached tokens on DVWA. No
  prompt-caching saving is claimed
  ([W12](../architecture/request-size-and-evidence-relevance.md#w12-static-first-request-envelope--rejected-as-outer-key-reordering)).

## 9. Scope and review shape

| Workstream | Owner | Change |
|---|---|---|
| W1. Section planner | `internal/judge` | Section kinds, closedness, eligibility and fallback reasons, cache keys. Offline only |
| W2. Hop questions | `internal/analysispacks`, `internal/guidelines` | `hop-effect-v1`, `hop-alphabet-v1`, `hop-guard-v1`; the character sets for each family and context |
| W3. Composer | `internal/judge` (`xss.go`, `command.go`) | The §6 state machine and record outcome; fallback of only the undecided paths |
| W4. Scheduling and cache | `internal/judge/schedule.go`, `client.go` | Memo keyed by section; per-hop slots against `--judge-limit`; ordering independent of completion |
| W5. Strategy flag and provenance | `cmd/scan`, `internal/analysis`, `internal/report` | `--judge-strategy whole\|per-hop\|auto` (default `whole`); `assessment.hop_answers` in JSON, HTML and SARIF |
| W6. Ablation | `.zazz/evaluation/` | §12 comparison script and results record |
| W7. Design documentation | `.zazz/architecture/`, `docs/` | Strategy entry and ledger row in the request-size design; gate text in trace judgment; user and analysis guides |

Files:

| Path | New or modified | Reason |
|---|---|---|
| `internal/judge/hops.go` | New | W1 planner and cache key |
| `internal/judge/hop_compose.go` | New | W3 composer |
| `internal/analysispacks/hop.go` | New | W2 question protocols |
| `internal/guidelines/` hop sections | Modified | W2 character sets for each family and context, and question guidance |
| `internal/judge/xss.go`, `command.go`, `client.go`, `schedule.go` | Modified | W3 and W4 hooks |
| `internal/analysis/analysis.go` | Modified | W5 `HopAnswer` record |
| `cmd/scan/main.go` | Modified | W5 flag |
| `internal/report` (JSON, HTML, SARIF) | Modified | W5 provenance |
| `.zazz/evaluation/per-hop-judgment/compare.py`, `.zazz/evaluation/per-hop-judgment-results.md` | New | W6 |
| `.zazz/architecture/request-size-and-evidence-relevance.md`, `.zazz/architecture/trace-judgment.md`, `docs/decision-models.md`, `docs/analysis/xss.md`, `docs/analysis/command-injection.md` | Modified | W7 |

The diff stays inside these paths plus their tests and fixtures.

Out of scope:

- SQL, NoSQL, path, redirect, SSRF, code, upload and logging hop questions.
- A sink-context question. When the scanner does not hold the context, the record falls back.
- Changing the whole-path questions, path groups or the shedding order.
- S1 slicing and S2 relevance filtering. Per-hop judgment does not shorten whole-path requests.
- A persistent cache file beyond trace replay (§17 Q4).
- Making `per-hop` or `auto` the default. That waits for the owner's adoption decision (§17 Q1).

## 10. Decisions

- **D-1. Ask about characters, not adequacy.** **Why.** Adequacy depends on the sink context, so a
  cached "adequate" would be wrong at another sink. Which characters a section lets through is a
  property of the section alone, and the scanner already owns the context table. **Rejected.** A
  "does this sanitize for <context>" question. Its answer cannot be reused across contexts, and
  it would hide context errors inside the model's answer.
- **D-2. Per-hop judgment never confirms a guarded path.** **Why.** A guard that lets through some
  characters of S does not show that any of them alter the sink. The command family already
  requires a cited `bypass_identified` for that, and per-hop judgment has no chain to cite.
- **D-3. A record needs at least one per-hop answer to be eligible.** **Why.** The owner prefers
  model judgment where static analysis is weak. A record whose every hop the scanner already
  classifies would otherwise get a verdict with no model involvement. Per-hop judgment exists to
  make large reading tasks small, not to remove the model. §17 Q2 asks the owner to confirm this.
- **D-4. Fallback is per path.** **Why.** On DVWA most paths share the page shell and differ only
  in one level file. Falling back the whole record would resend the shared bytes that per-hop
  judgment exists to avoid.
- **D-5. Use the bytes in the cache key, not the location.** **Why.** The same helper copied
  across files, or reached from many entries, is the case that saves the most. The Merkle part over
  inner calls stops two identical bodies whose calls resolve differently from sharing an answer.
- **D-6. Opt-in strategy until the ablation is decided.** **Why.** Per-hop judgment is lossy, and
  [the ablation protocol](../architecture/request-size-and-evidence-relevance.md#ablation-protocol-for-lossy-changes)
  requires evidence before adoption. `whole` stays the default, so no saved replay changes.
- **D-7. No citation question.** **Why.** Each request carries exactly one section, and the answer
  is about that section. Unlike [D-2 of the resolution contract](model-assisted-evidence-resolution.md#5-decisions),
  there is no chain to check.

## 11. Agent implementation rules

Follow [AGENTS.md](../../AGENTS.md) and the plan's
[common rules](architecture-update-plan.md#common-agent-implementation-rules). Build W1–W5 against a
stub judge. No paid call is authorized by this spec. The §12 ablation needs the owner's explicit
word, with the cap stated beforehand. The standing live-check authorization does not cover it,
because it is not a typical judged scan. No second model and no fallback provider.

Halt and ask the owner if:

- a per-hop Protected appears on a keyed positive;
- a keyed positive loses its finding;
- a per-hop finding appears on a protected control;
- the planner's request count for the ablation exceeds the authorized cap;
- the offline planner shows that the default `whole` strategy changed any request byte.

## 12. Ablation plan

1. **Baseline arm (no new calls).** The saved whole-path judgments:
   - DVWA `run-cfg-live`, with the six upload records from `run-cfg-live2` (upload is out of scope
     and is reported as not eligible);
   - nodejs-goof `run-cfg-live`;
   - python-insecure-app `run-cfg-live2`.

   For the 7 grouped DVWA records, the baseline is each group's outcome in `findings.json`.
2. **Same evidence.** On the implementation commit, rebuild every whole-path request offline and
   compare its digest with the saved trace, or with `path_groups[].request_digest` for grouped
   records. Only records whose digests match are compared. Records whose evidence changed are
   listed. If the owner wants them covered, they need an owner-authorized fresh whole-path arm.
3. **Per-hop arm.** One scan per sample with `--judge-strategy per-hop`:
   - `openai`, `gpt-6-luna`, the AGENTS.md pacing, only the OpenAI key passed;
   - the planner's exact per-hop request count stated before the run;
   - cap at 150 requests in all. The estimates are DVWA ≤ 110, nodejs-goof ≤ 34 and
     python-insecure-app ≤ 2, so 146 at most;
   - fallback records use the baseline arm's outcome, so they add no calls.
4. **Optional repeat.** Re-ask only the sections behind a disagreement, at most 30 requests, to
   separate model variance from decomposition error. Run it only on the owner's word.
5. **Compare, for each record:**
   - eligible or not, with the reason;
   - fallback paths and their reasons;
   - composed outcome against the baseline outcome, at record and path level;
   - the label from `accuracy.py` and `check.py`;
   - input tokens per record in each arm, from `usage`;
   - cache hits.
6. **Pass thresholds, fixed before the run:**
   - no record moves toward a wrong verdict against its label;
   - the recall floor holds;
   - at least 90% of per-hop-decided records agree with the baseline outcome;
   - every disagreement is source-reviewed, with at most 2 in which per-hop is wrong and none of
     those toward Protected;
   - the 8 over-limit DVWA records are decided per-hop or fall back with a reason, and the capped
     `sqli` path is judged;
   - per-hop input tokens are at most 50% of the baseline tokens for the decided records.
7. **Record** both arms, the comparison and the source reviews in
   `.zazz/evaluation/per-hop-judgment-results.md`, and add a ledger row to the request-size design.

## 13. Acceptance criteria

1. **AC1 (W1).** For each §5.4 shape, a fixture makes the planner report the record as not
   eligible, or the path as fallback, with that shape's reason. A closed helper, a transform and a
   proven dominating guard are eligible. A section over 16,384 bytes is not. Verified by
   `TestHopPlannerEligibility` in `internal/judge`.
2. **AC2 (W1).** Two byte-identical helpers in different files share one key. The same bytes with a
   different parameter binding, character set, guideline digest, question version or inner-call
   resolution give different keys. Verified by `TestHopCacheKey`.
3. **AC3 (W1).** An offline planner report over DVWA `a1978a2`, nodejs-goof and python-insecure-app
   gives, for each sample: eligible records, per-hop keys, cache hits, measured request bytes and
   the planned request count. With `--judge-strategy whole`, every request is byte-identical to the
   base commit. Verified by `TestHopPlannerReport` (with `ZAZZLES_DVWA`) and the digest diff
   recorded in the results.
4. **AC4 (W2).** Each question's request carries only one section, its bindings, S and the static
   guidance, and stays under 16 KB on every planner-reported request. Every per-hop request in AC3
   is under 16 KB. Verified by `TestHopRequestShape`.
5. **AC5 (W3).** A table-driven composer test with a stub judge covers:
   - raw path → Confirmed for that path;
   - sanitizer answered `none_of_set` → Protected only when every path is protected;
   - sanitizer then `decodes` → fallback;
   - a guard on one branch → that path protected and the sibling judged alone;
   - a guard answered `some_of_set` → fallback, never Confirmed;
   - a reassignment after the guard → fallback;
   - an unknown context → not eligible;
   - a record with no per-hop answer → not eligible.

   Verified by `TestHopComposition`.
6. **AC6 (W4).** In one scan, a key reached by several records sends one request. The records list
   it as a hit. `--judge-limit` counts only sent requests. Output is identical with concurrency 1
   and 8. Verified by `TestHopScheduleCache` and `TestHopScheduleOrder`.
7. **AC7 (W5).** A composed record lists every answer it relied on, in JSON, HTML and SARIF:
   section key, question, version, choice, cache hit and digest. Verified by `TestHopProvenance`
   in `internal/report`.
8. **AC8 (W6).** After the authorized ablation, the results record has every §12 step 5 column
   and states pass or fail against each step 6 threshold. Every disagreement has its source-review
   verdict.
9. **AC9 (W7).** The request-size design lists per-hop judgment with its status and ledger row. The
   trace-judgment gates and the XSS and command guides state the per-hop rule. `doc-check` is clean
   on the changed documents.

## 14. Test strategy

- **Planner.** One table over the §5.4 shapes and the §5.3 positives (AC1). Each case is a small
  PHP and JS fixture pair, reusing the [S1 regression pairs](data-path-slicing.md): writes and
  decoding after a check, reassignment after a check, both branch polarities and sibling paths.
- **Key.** One table that varies one key input per row (AC2).
- **Composer.** One table over the state machine and the record rule (AC5), with a stub judge.
  It needs no family fixtures beyond the planner's.
- **Scheduling.** Cache sharing and order independence with a stub judge (AC6).
- **Offline report.** DVWA and the two small samples (AC3). It measures; it is not a golden.
- **Omitted.** No live test in CI. The ablation is the only paid evidence.

## 15. Execution sequence

1. Write `TestHopComposition` first and watch it fail, against a stub composer interface.
2. W1 planner and key, with AC1–AC3 offline, including the `whole` digest check.
3. W2 questions and guidance (AC4).
4. W3 composer (AC5).
5. W4 scheduling and cache (AC6).
6. W5 flag and provenance (AC7).
7. Present the AC3 planner counts to the owner and ask for the ablation authorization (§17 Q3).
8. W6 ablation and results (AC8), then §17 Q1.
9. W7 documentation (AC9).

Skeleton (illustrative; names may change):

```go
// internal/judge/hops.go
type hopSection struct {
	Kind     string // helper, transform, guard
	Bytes    []byte // model-facing text
	Entry    hopBinding
	Exit     hopBinding
	CharSet  string
	Inner    []string // contract ids or nested section keys
	Contract string   // guard contract text, if any
}

func (s hopSection) key(question, version, guidelineDigest string) string

type hopPlan struct {
	Eligible bool
	Reason   string                     // why not, when not eligible
	Paths    map[int][]hopSection       // dependency index -> ordered sections
	Fallback map[int]string             // dependency index -> reason
}

// internal/judge/hop_compose.go
func composeHops(use analysis.CandidateUse, plan hopPlan, answers map[string]hopAnswer) (outcome, []int)
```

## 16. Definition of done

- [ ] AC1–AC7 pass offline with a stub judge.
- [ ] With the `whole` strategy, request bytes are unchanged against the base commit.
- [ ] The owner authorized the ablation and its cap, and AC8 is recorded.
- [ ] The owner has decided adoption (§17 Q1), and the default matches that decision.
- [ ] AC9 documentation is updated, and the contributor gate passes.

## 17. Open questions for the owner

1. **Adoption scope, if the ablation passes.**
   - (a) `auto`: per-hop judgment only for records over the limit, replacing path groups where
     eligible. Recommended.
   - (b) Per-hop judgment for every eligible record.
   - (c) Not adopted.
2. **Records that need no per-hop answer.** Keep them whole-path (D-3, recommended), or let the
   scanner compose their outcome alone.
3. **Ablation budget.** Up to 150 per-hop requests on `openai` `gpt-6-luna` across the three
   samples, plus an optional repeat of at most 30. Also: is a fresh whole-path arm authorized for
   records whose evidence changed since the saved traces?
4. **Cache across scans.** Trace replay only (recommended), or a persistent local answer cache.

## 18. Run log protocol

Use the plan's run-log rules. Record:

- the scanner SHA and sample pins;
- provider, model and question versions;
- the planner counts before each paid run;
- requests sent and cache hits;
- owner answers to §17, verbatim;
- the source-review verdict for each disagreement.

## 19. Agent implementation prompt

> Work in the owner-assigned worktree based on `origin/stage` with close-findings-gaps integrated.
> Read AGENTS.md, the orientation contents and this spec, and copy the owner's §17 answers into the
> run log. Execute §15 in order against a stub judge. Keep `whole` as the default and prove its
> requests unchanged. Make no paid call until the owner authorizes the §12 ablation with a cap.
> Deliver a draft PR into `stage`, one commit per workstream.

## 20. Implementation and review change log

### 2026-11-19 — Proposal

Drafted at the owner's request, after the DVWA path-group measurement showed every group repeating
12.6–18.6 KB of on-chain page-shell code. Baseline figures come from the offline DVWA request-size
test at `0b1e109` and the saved live traces of the close-findings-gaps check.
