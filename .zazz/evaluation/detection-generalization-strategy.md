# Detection generalization: strategy and architecture options

[Research note](detection-generalization-research.md) · [Series contract and
index](../specifications/detection-generalization/README.md) · [Architecture](../architecture/README.md)

2026-11-25. Offline only: no scanner change and no paid model call. Scanner source `021bad2`.

## 1. Answer

1. **Adopt first: make existing models and drivers recognizable** (specs 01 and 03). Eight of twelve
   ordinary ways to define a Sequelize or Mongoose model record nothing. Of nineteen ways to run one
   injected SQL string, ten have no record and six have a record that can never be sent.
2. **Adopt: checks as facts** (spec 02). It serves recall and precision with one change.
3. **Test before adopting: operations by effect** (spec 00, an offline experiment). It is the only option
   that could replace several specs, and its noise is unknown.
4. **Defer: entry-level model review for missing controls.** It may be the strongest recall option. It
   cannot be tested offline, and it is the largest cost and repeatability risk.
5. **Defer: file keys for stored values.** Three records in ten samples.
6. **Reject: a typed graph store and a rule that decides a verdict.** Already tried or ruled out (§4).

## 2. Evidence

| Measurement | Result |
|---|---|
| Model definition forms recording a plain update and create | 4 of 12: one file (Sequelize, Mongoose), named ES export (Sequelize, Mongoose). None for CommonJS exports, a default export, `sequelize.define`, a destructured `model`, or a definition function |
| SQL string built from a request value, 19 driver or wrapper forms | 3 with a contract (better-sqlite3, Sequelize, Prisma raw). 6 with the blocker `sink_binding_unverified` (`pg`, `mysql2` `query`, `mssql`, TypeORM, ClickHouse, a local wrapper over `pg`). 10 with nothing (`mysql2` `execute`, `sqlite3`, Oracle, `postgres`, Knex raw, Drizzle raw, libSQL, DuckDB, `node:sqlite`, an imported wrapper) |
| Can the model settle that blocker? | No. `resolvable` in `judge/resolution.go` lists flow gaps and stored origin. A SQL record with any other blocker is not sent |
| How a SQL record starts | A call whose name ends in `.query`, or a listed driver method. A NoSQL record needs `Collection` in the receiver's name, `$where` or `$set` in the text, or a verified collection binding |
| Awaited calls in HTTP handlers, six Node samples | 343. 42 are on a line with any security or outbound record (12%) |
| HTTP entries with at least one security record | Juice Shop 54 of 137, OopsSec 13 of 115, vuln-demo-app 9 of 14, vulnerable-typescript-app 8 of 19, nodejs-goof 11 of 18, vuln-nextjs 25 of 35 |
| Lists of storage method names in `langjs` (maps and `case` lists) | 19, in 9 files |
| `if` arms that answer and exit, outside Juice Shop | 59 in five Node samples |
| `if` arms that answer and continue, outside Juice Shop | **0** (two matches, both read: not such arms). Juice Shop: one true arm found, in one middleware; its other 17 matches are mostly an outer `if` around an answering one |
| Records blocked on stored origin, ten samples | 45. No storage key at all 17; PHP session 16; SQL columns 6; `file:unresolved` 3; keyed store 2; Sequelize 1 |
| Handler and callee source per entry | Juice Shop 92,907 characters over 137 entries, OopsSec 218,992 over 115 |

The awaited-call, arm and entry counts come from text and syntax patterns. They are orders of magnitude. "No
storage key at all" is mostly a value that reaches a client template through an API.

## 3. The hypotheses

### H1. Is sink-specific discovery the limiting stage?

**Partly confirmed.** The premise "12 of 13 have no record" is too strong: 8 have none, 3 stop at evidence,
2 at claim scope ([trace](detection-generalization-research.md#3-trace)). But all 8 are operations that
exist in source and no family inventories: create, read for the caller, send a projection, send script,
change a credential, set a cookie, set an origin policy, write through a generated endpoint. None lacks an
operation. An obligation view therefore does not need a new kind of reasoning. It needs an inventory of
operations by effect, and a table from effect to question.

It would not find `VALID-01` (the requirement is in the client), nor `UPLOAD-01` (there is no missing
control).

### H2. Could the model judge a bounded entry summary for missing controls?

**Uncertain. Not testable offline.** The deciding lines are inside the entry's own handler, middleware and
registration for about 10 of the 13 rows, so the summary would contain the evidence. That is an upper bound
on recall, not an estimate.

Cost: an authorization request is 13 to 16 KB, most of it fixed instruction. The published run used 381,728
tokens for 84 requests. One review request per Juice Shop entry is 137 requests and, at the DVWA ratio of
0.30 tokens per byte, roughly 440,000 tokens: more than double the run. OopsSec is similar.

Risks. The owner's earlier review proposal rules out "send the file to the model". Evidence rules say
missing evidence stays unknown and no requirement is invented. Open questions are less repeatable than
closed ones: `DELETE /api/BasketItems/:id` moved between Confirmed and Review with no change of evidence. A
similar idea, one request per entry for validation, is already listed as a later contract in [model-assisted
resolution](../specifications/model-assisted-evidence-resolution.md#4-scope-and-review-shape).

If tried, its output must be *proposals*: closed choices from the effect table, each citing a source span,
verified by the scanner, never a finding by itself. `discovery_proposals` is the pattern. That makes H2 a
discovery helper for H1 and not a second path to a verdict.

### H3. Do shared framework and storage semantics close more gaps than new analyzers?

**Confirmed for storage.** Four families (authorization, mass assignment, account, stored XSS) start from
`modelIdentity`. A form it cannot read removes all four. One change widens them together, and no existing
decision changes. Not confirmed for cookies, uploads and setters: each serves one or two rows and appears in
few local samples.

### H4. Are operations modelled by effect or by analyzer?

**By analyzer in JavaScript; by effect in PHP.** PHP records `StateChange` for every named stored write,
including writes that are no candidate. JavaScript has 19 method lists in 9 files. One `insert` is a NoSQL
query, not a write of a field, because the NoSQL family owns the list that knows it. This is the cause of
`MASS-07` and the first of two causes of `AUTHZ-09`.

### H5. Is the stored-value link general across storage types?

**No, and it matters little here.** Census work covered SQL, session, ORM and keyed stores. File keys are
never resolved. Most blocked records have no key, because the value comes through an API response the client
link did not match. Better file keys would change three records in ten samples.

### H6. Would the false-positive evidence help recall?

**Half of it.** The [diagnosis](detection-generalization-research.md#8-branching) has three parts.

| Part | Effect on recall |
|---|---|
| Tie a guard to its operand; order constraints after the source | Helps. It is the same record as spec 02, read by another family |
| Record slots, keep types through object placement | Neutral. No missed row stops there |
| Question wording for escapes | None expected. It could lower recall; its own controls cover that |

Spec 02's fixture pairs measure both directions. A shared check record is the one place to join the work.

## 4. Options

Effort: S days, M one branch, L several. "Judged cost" is requests per scan.

| Option | Gaps and classes | Changes or replaces | Effort | Risk to existing results | Judged cost | Cheapest experiment that could disprove it | Recommend |
|---|---|---|---|---|---|---|---|
| **A. Storage identity across module forms** | All four storage families on most Node projects; no row of the 13 | Extends `modelIdentity` and export reading | S to M | Low: adds records, changes none | Up, by the new records | Twelve-form probe and nodejs-goof, offline: if fewer than 3 of the 8 forms gain records without widening a list, stop | **Adopt, 01** |
| **B. Checks as facts** | Authorization both ways; `VALID-02`; basis for others | Extends the guard engine; replaces Node guard absence | M | Medium: authorization answers change | None to small | Spec 02's fixture pairs at one checkpoint: if answers do not follow the facts, stop | **Adopt, 02** |
| **C. Model names an unknown call's contract** | SQL on any driver; pattern for others | Adds a resolution question to an existing protocol | M to L | Low: touches blocked or absent records | One question on records now unsent | 16 SQL probe forms, judged: if fewer than 12 are answered correctly, or one non-SQL call is called SQL, stop | **Adopt, 03** |
| **D. Operation inventory by effect** | Eight undiscovered rows; discovery for 06 to 10 | Would replace 19 lists and several producers | L | High if it replaces; low as an additive layer | Depends on noise | Offline prototype on six samples (spec 00) | **Experiment, 00** |
| **E. Obligation table over D** | Missing controls with no sink | New questions per effect; no new engine | M after D | Medium: many new records | Up to several times | Count of records per entry in spec 00 | **Decide after 00** |
| **F. Entry review by the model** | The same as E, plus unknown effects | Adds a discovery request per entry | M | Low if proposals only; high if it decides | More than doubles a run | 30 entries of two keyed held-out apps, three repeats, 90 requests: stop if it finds nothing D and E do not, or repeats agree under 90% | **Defer; owner's word** |
| **G. Shared flow for operation families** | Two-step selection (`RESET-01`) and others | Replaces `requestValue` in four files | L | High: identifiers and requests move | None | Record selection only (spec 05) | **Adopt narrowly, 05** |
| **H. File keys and write links** | `XSS-09` | Extends storage origin | M | Low | Small | Already measured: three records | **Defer** |
| **I. Typed graph store** | None | Replaces the index | L | High | None | Built and removed in phase 1; it changed no candidate | **Reject** |
| **J. Per-hop judgment** | None of recall | Splits requests | L | Medium | Lower | Has its own proposal and ablation plan | **Leave to that proposal** |
| **K. Scanner rules that decide** | Any | Moves the judgment | S each | Medium | None | Contrary to the design intent | **Reject** |

## 5. How this shapes the series

- **00 runs first and blocks nothing.** Specs 01 to 05 stand whatever it finds. Specs 06 to 10 state what
  changes if it succeeds: they become rows of a table in place of producers.
- A spec that appears only in Juice Shop among the local samples is ranked last (11) or has no spec.
- C is the proposal's first candidate and the owner's aim. It ranks third because its benefit needs a judged
  answer, and 01 and 02 do not depend on one to add records.
- Where a spec touches the shared check record, it waits for the owner's decision on who owns it.

## 6. What this note does not show

No judged run. Probability estimates are judgments from the measurements above. Six Node samples are few,
and five of them have been used before. The probes were written by the session that ranked the options.
