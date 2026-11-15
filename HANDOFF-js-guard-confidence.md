# Handoff: JavaScript guard confidence, Goof Zip Slip and the Juice Shop unassessed cases

**Status:** open follow-up from slice E2 ([contract](.zazz/specifications/shared-guard-and-manifest-engine.md)), pull request 13.
**Branch where it was found:** `analyzer-engine-hardening`.
**Suggested home:** its own worktree and contract. Part of it needs the E3 wire bump (see [Options](#4-options)).

Read [AGENTS.md](AGENTS.md) first. Do not print `.env` or credentials. Live model calls need an explicit,
small request cap.

This file has three parts: the JavaScript guard confidence problem (sections 1 to 6), the Goof Zip Slip case
(section 7), and the Juice Shop records the rebuilt sample report leaves unassessed (sections 8 and 9).

## 1. The problem in one paragraph

A correctly guarded JavaScript command route is still judged `vulnerable` by the model, at low confidence.
The same guard written in Python is judged `protected_for_claim`. The guard evidence the scanner supplies is
now equivalent in both languages. The difference is noise that only the JavaScript flow produces: every `if`
statement in a JavaScript handler is recorded as an unresolved control-flow gap, and those gaps reach the
model through the shared entry context.

## 2. Evidence

All runs used OpenAI `gpt-6-luna`, one request each, on a fixture outside the repository.

```js
const ALLOWED = new Set(['uptime', 'date']);
app.get('/js/direct-guard', (req, res) => {
  const cmd = req.query.c;
  if (!ALLOWED.has(cmd)) {
    return res.sendStatus(400);
  }
  exec(cmd, (err, out) => res.send(out));
});
```

```python
ALLOWED = {"uptime", "date"}
@app.route("/py/guarded-abort")
def guarded_abort():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    return os.popen(cmd).read()
```

| Case | Evidence the scanner supplied | Model result |
|---|---|---|
| Python guard, before the allow-list definition was attached | `terminating_guard` only | `vulnerable` (0.54 vs 0.33 protected) |
| Python guard, with `allowlist_definition` | `terminating_guard` + `allowlist_definition` | `protected_for_claim` |
| JS guard, with `allowlist_definition`, gaps still coverage | same as Python | `vulnerable` (0.45), coverage `complete` |
| JS guard, gaps moved to `resolved_gaps` | same, plus resolved gaps | `vulnerable` (0.45 vs 0.32 unknown vs 0.22 protected) |

The last two rows show the remaining uncertainty: the model answers `protection_coverage: complete` but still
picks `vulnerable` for shell syntax. The wire payload for the JS case still contains these gaps at the guard's
`if` statement (`js/server.js` lines 30 to 32 in the fixture):

- `unsupported_control_flow`: "statement not traversed: if_statement"
- `branch_exit`: "a branch returns or throws; its condition may guard later code"
- `unknown_control_effect`: "value may change across unsupported control flow"
- `middleware_unresolved`: "effective middleware/guard chain is not modeled"

The first three appear twice: in `coverage_gaps`/`resolved_gaps` and in `invocation.entry_gaps`.

## 3. Root cause

- **Where the gaps come from.** `flow.statement` in [internal/parse/flow.go](internal/parse/flow.go) has no case for
  `if_statement`. It falls to `default: f.branches(n)`, and `branches` (line 170) always records
  `unsupported_control_flow` (line 172), `branch_exit` when any branch leaves (line 224) and
  `unknown_control_effect` on every merged value (line 279). The Python flow models `if` exactly in
  `conditional` ([internal/parse/python_control.go](internal/parse/python_control.go)), so Python has no such gaps.
- **Why E2 could not remove them.** The gaps are copied into the invocation context and surface as
  `entry_gaps` ([internal/judge/entry_context.go](internal/judge/entry_context.go) line 16, projected by
  `AnalysisReport.EntryGaps` in [internal/analysis/report_entries.go](internal/analysis/report_entries.go)). That is
  shared by every candidate in the entry, so a per-claim fix cannot hide it. E2 only moved the claim-level copies
  to `resolved_gaps` (`resolveGuardedControlFlow` in [internal/parse/command_claims.go](internal/parse/command_claims.go)).
- **Why changing it moves many request digests.** `branches` also decides which values stay dependencies across a
  branch. Making JS `if` precise changes evidence for SQL, NoSQL, XSS, Path, logging and validation candidates in
  JavaScript, not only Command.

## 4. Options

1. **Model JS `if` precisely, like Python's `conditional`.** Fork the flow for the consequence and alternative,
   drop a branch that always exits (`jsAlwaysExits` already exists in the guard engine), record
   `branch_precondition` evidence on the surviving path, and emit no gap when the whole statement is modeled.
   - Best fix: removes the noise at its source for every analyzer.
   - Cost: changes request bytes for many JS candidates. Do it together with the E3 wire bump, or under its own
     contract with an explicit baseline-delta list, and re-record the saved replays.
2. **Suppress only the three gaps on a statement the guard engine verified.** Needs `entry_gaps` to be filtered
   in `internal/analysis` or `internal/judge`, outside the E2 scope. Smaller blast radius, but it is a patch over
   the real defect and still leaves unverified `if` statements noisy.
3. **Prose only.** Tell the model in the command guidelines that gaps at a supplied guard are resolved.
   Cheapest, but leaves a contradiction between evidence and prose; not recommended.

Recommended: option 1, sequenced with E3.

## 5. Acceptance criteria for the fix

- The JS direct-guard fixture above carries no `unsupported_control_flow`, `branch_exit` or `unknown_control_effect`
  for the guarded `if`, in `coverage_gaps` or `entry_gaps`.
- A JS `if` that is not a verified guard still keeps an honest gap or is modeled exactly; nothing is silently dropped.
- Unit tests prove the surviving path and branch preconditions for consequence-exit, alternative-exit,
  `else if` chains and both-branches-exit statements.
- One live request on the direct-guard fixture reaches `protected_for_claim` on `gpt-6-luna`. If it does not,
  record the answer probabilities and what the model cited; do not tune the gate to force the result.
- `TestOutboundPredecessorRequests` and `TestCommandPredecessorRequests` change only as the contract lists.
  Report the number of candidates whose request digest changed per sample application, using the differential
  method in the E2 run log (`.zazz/ephemeral/analyzer-engine-hardening-run-log.md`).

## 6. How to reproduce

Fixture lives only in the local scratch directory of the session that found this. Recreate it:

1. Make a directory with `js/server.js` (the route above plus `const express = require('express'); const { exec } = require('child_process'); const app = express();`) and `py/app.py`.
2. Offline facts, no cost:

   ```bash
   go build -o bin/scan ./cmd/scan
   ./bin/scan --analyze --json --only-family command /path/to/fixture
   ```

   Check the use's `completeness.evidence.guard`, `allowlist_definition` in `context`, and the gaps listed above.
3. One paid request, with a cap and only the selected provider's key:

   ```bash
   (set -a; . ./.env; set +a; ./bin/scan --analyze --judge openai --judge-model gpt-6-luna \
     --judge-limit 1 --only-family command --route /js/direct-guard \
     --output-dir "$HOME/zazzles-findings" /path/to/fixture)
   ```

## 7. Second open item: Goof Zip Slip is Review, not a finding

`nodejs-goof` `routes/index.js:270` calls `adm-zip` `extractAllTo` on an uploaded archive. The scanner establishes
`adm-zip` 0.4.7 (before the 0.4.11 fix) and a raw archive path. Two identical live requests returned:

| Facet | Answer |
|---|---|
| `path_traversal` | `not_applicable` (0.57; vulnerable 0.33) |
| `containment_control` | `none` (0.71) |
| `protection_coverage` | `incomplete` (0.99) |

The evidence gate correctly refused to classify it: `path_answers_inconsistent` ("path facet marked not applicable
although a request-derived value reaches the effective path operand"). The published result is
`needs_evidence` in [docs/samples/nodejs-goof](docs/samples/nodejs-goof/findings.html).
Juice Shop's `unzipper` Zip Slip, with the same kind of upload, is `confirmed_vulnerability`, so this is specific to
the adm-zip prompt and facts.

Likely cause: the destination `"/tmp/extracted_files"` is a constant, and the model reads "the destination is not the
traversal operand" as "no traversal here" instead of "the archive entries are the operand". The contract text is in
`AdmZipContract` ([internal/analysispacks/path.go](internal/analysispacks/path.go) line 52) and already says the archive
is the operand, so the problem is probably the question wording or the facts shape, not missing contract text.

Suggested steps, in the E3 catalog-sync scope (prose lives outside E2's allowed files):

1. Compare the adm-zip request with the passing `unzipper` request: which role names, `path_operands` slot labels and
   `model_facts` sentences differ?
2. Make the archive-entry slot as explicit for adm-zip as it is for `unzipper`, and state that a constant destination
   does not make the traversal facet not applicable.
3. Run one live request on Goof. Keep the gate as is: a contradictory answer must stay unclassified.
4. Refresh the Goof path-traversal sample and its README note.

## 8. Files to read first

| Topic | File |
|---|---|
| JS flow and the gaps | `internal/parse/flow.go` (`statement`, `branches`) |
| Python reference behavior | `internal/parse/python_control.go` (`conditional`) |
| Guard engine and terminators | `internal/parse/guard_climb.go`, `internal/parse/guard_lang.go` |
| Command guards and gap resolution | `internal/parse/command_guards.go`, `internal/parse/command_claims.go` |
| What the model receives | `internal/judge/entry_context.go`, `internal/judge/bundle.go` |
| Command gate | `internal/judge/command.go` (policy section) |
| adm-zip contract | `internal/analysispacks/path.go` |
| MarsDB collection binding | `internal/parse/automatic_queries.go` (`collectionBinding`) |
| Component selection failures | `internal/analysispacks/select.go` (`selectUse`) |
| 64 KiB limit and payload build | `internal/judge/client.go` (`payload`, `payloadForm`), `internal/judge/bundle.go` |
| Excerpts and helper context | `internal/parse/relevant_context.go`, `internal/parse/middleware_context.go` |

## 8. Juice Shop: records the rebuilt report leaves unassessed

The rebuilt [Juice Shop report](docs/samples/juice-shop/findings.html) judged 128 of 223 records. The other 95 fall
into five groups. Each has a different cause, and only some are by design.

| Group | Records | Cause | Fix size |
|---|---:|---|---|
| Request over 64 KiB | 1 | `routes/order.ts:164` sends 119 KB | medium (8.1) |
| MarsDB binding not resolved | 3 | named import of a collection is not followed | small (8.2) |
| Sequelize chat tool | 2 | no ORM contract; one record is a misread call | medium (8.3) |
| Outbound `fetch` observations | 66 | 65 repeats of one call plus one real SSRF candidate | medium (8.4) |
| Data-only XSS | 23 | API data is not linked to a rendering claim | large (8.5) |

Work them in this order: 8.2, 8.1, 8.4, 8.3, 8.5. Every fix here can change request bytes, so list the changed
candidates per sample application, as in section 5, and keep a live run to a few capped requests.

### 8.1 The 119 KB request: do we need to send that much?

**No.** The candidate is `db.ordersCollection.insert({ ... req.body ... })` at the end of a 155-line checkout
handler. The question is small: can request data shape the stored document? The request is 119,336 bytes against a
65,536 byte limit, so it is skipped with "evidence payload exceeds 64 KiB limit" and never judged.

Measured on the current code (bytes inside the `use` object, 91,570 in total):

| Section | Bytes | What is in it | Needed for this claim? |
|---|---:|---|---|
| `source_excerpts` | 29,774 | 57 excerpts (see below) | Mostly no |
| `evidence` | 25,359 | 110 items; 5,343 middleware registrations, 3,000 helper definitions, 3,000 control statements | Partly |
| `coverage_gaps` | 11,539 | 61 gaps | Duplicated noise |
| `input_facts` | 4,616 | input origins and types | Yes |
| `model_facts` | 3,753 | fixed explanatory sentences | Partly |
| `trace_graph` | 3,615 | edges between evidence | Yes |
| `blocking_gaps` | 3,427 | 18 gaps | Partly |
| `evidence_coverage` + `evidence_roles` | 4,417 | the same role ledger twice | Duplicate (E3) |

Another 28 KB sits outside `use`: guidelines, components and instructions (about 6.6 KB) and the JSON envelope.

What the 57 excerpts contain:

- **The handler itself:** 7,247 bytes for lines 33 to 187. Only the path from `req.body` to the inserted document
  and the checks on it matter, and the handler has many unrelated Sequelize calls.
- **Helper bodies that never touch the inserted document:** `lib/insecurity.ts`, `lib/utils.ts`,
  `routes/verify.ts`, `lib/antiCheat.ts`, `lib/challengeUtils.ts`, `routes/metrics.ts`.
- **Four Sequelize model classes** (`models/basket.ts`, `delivery.ts`, `quantity.ts`, `wallet.ts`). This is a MarsDB
  insert, so they are irrelevant.
- **About 30 `app.use(...)` lines from `server.ts`.** Most only set headers or serve files: `compression`, `cors`,
  `helmet.*`, `featurePolicy`, `morgan`, `express.static`, `robots`, `i18n`. They cannot change `req.body`.
  `bodyParser`, `jsonParser` and the `security.isAuthorized` mounts do matter.

The gaps repeat. Of the 79, twelve are the same `unknown_control_effect` text and ten are the same
`unsupported_control_flow` text, caused by the JavaScript `if` problem in section 3. Seven are
`conditional_merge`, which is the same sentence at seven places.

**Suggested approach, in this order. Measure the size after each step.**

1. **Group repeated gaps.** One entry per `kind` and `detail`, with a list of spans. Expected saving: several KB.
   Fixing the JavaScript `if` handling (section 4, option 1) removes most of them at the source.
2. **Send only relevant excerpts.** Keep a helper or model definition only when a value on the claimed dependency
   path, or a control on that path, goes through it. Drop definitions of calls whose arguments never carry the
   dependency. Expected saving: 8 to 12 KB.
3. **Classify middleware.** Extend the transport-only list used for the command claim
   (`commandTransportMiddleware` in `internal/parse/command_claims.go`) into a shared notion of
   "cannot change the request body or authorize". Send those as one summary line, not one excerpt each.
4. **E3 compaction.** Always-on compaction, no duplicate `evidence_roles`, no 64-character digests in the prompt.
   The proposal estimates 25 to 35 percent. Alone it takes this record from 119 KB to about 80 KB, which is still
   over the limit, so steps 1 to 3 are needed as well.
5. **Slice the handler** to the statements that can affect the dependency or the sink. Larger change; do it only if
   steps 1 to 4 leave records over the limit.
6. **Ladder instead of a hard stop.** If a record is still too large, drop coverage-only evidence first, then
   excerpts furthest from the sink, and record an explicit gap such as "evidence omitted: 12 excerpts". Never drop
   something that blocks the claim, and never hide the omission from the report.

Acceptance: `routes/order.ts:164` builds a request under 64 KiB and receives one live judgment. No other candidate
loses evidence that the existing model answers cite; check the saved replays and the per-sample digest differences.

### 8.2 Three MarsDB records fail: named imports are not followed

Affected: `routes/orderHistory.ts` lines 17 (`find`) and 36 (`update`), and `routes/createProductReviews.ts:23`
(`insert`). All three fail with "NoSQL component selection needs verified API binding".

Cause: `data/mongodb.ts` declares `export const ordersCollection = new MarsDB.Collection('orders')`. These routes use
`import { ordersCollection } from '../data/mongodb'`. `collectionBinding` in
[internal/parse/automatic_queries.go](internal/parse/automatic_queries.go) resolves the namespace form
(`import * as db` then `db.ordersCollection`, which is why `routes/order.ts:164` resolves), and a collection declared in
the same file. It does not resolve a single identifier that is a named import. Because no binding is found, the flow
records `sink_binding_unverified` (`flow.go` line 760) and `selectUse` in
[internal/analysispacks/select.go](internal/analysispacks/select.go) refuses the candidate.

Fix: in the one-part case, when the name is an import binding of a relative module, switch `target` to
`importModule(...)`, use the exported (original) name, add the import declaration as `sink_binding` evidence like the
namespace branch does, then continue with the existing constructor and `marsdb` checks. Keep the aliasing, shadowing
and re-export checks. Do not follow a name that is reassigned or exported more than once.

Tests: named, aliased (`import { ordersCollection as orders }`) and re-exported imports resolve; a shadowed or
reassigned name does not; a non-MarsDB constructor does not.

Acceptance: the three records get the `marsdb-collection-v1` contract and are judged. Two live requests are enough
(`--route` per record).

### 8.3 Two Sequelize records in the chat tool

Affected: `routes/chat.ts` lines 117 and 123, both `sql_query_candidate`.

- **Line 123** is a `ProductModel.findAll` call whose `where` uses `Op.like` with a template string that embeds the
  request `query` between `%` signs.
  Sequelize binds `where` values, so this is not string-built SQL injection. The real issue is that `%` and `_` in
  `query` act as wildcards, which is an input-validation or resource concern. There is no contract for ORM model
  finders in the SQL family, so there is no verified binding.
- **Line 117** is the `tool({ description, inputSchema, execute })` call that wraps it. Its sink text is the
  whole `tool(...)` call, which is not a query. Find out why it became a `sql_query_candidate`. The `unsupported_callback`
  and `control_flow_unresolved` gaps show the model-visible code is an `execute` callback, not an HTTP handler.

Fix: (1) find why the `tool(...)` call is a SQL sink and stop treating it as one; (2) add a Sequelize finder contract
(`findAll`, `findOne`, `findByPk`, `where` operators, `Op.like`) that states bound values and wildcard behavior; (3) make
sure the finding names the real problem (wildcard handling), not SQL injection.

Acceptance: line 117 is no longer a SQL candidate; line 123 is judged and, if protected from injection, is not reported
as a SQL injection finding.

### 8.4 Outbound observations: 65 repeats and one real SSRF candidate

All 66 are `fetch` calls with no model assessment ("Outbound security assessment is not implemented"):

- **65 are one call site**, in `lib/webhook.ts`, reported once for each of 65 entries that reach it. The URL comes from
  configuration, not a request value.
- **One is a real candidate:** `routes/profileImageUrlUpload.ts` fetches `req.body.imageUrl`. That is the classic
  server-side request forgery (SSRF) pattern, and it is currently only an observation.

Fix, in two steps:

1. **Classify the operand.** Record whether the URL operand is constant, configuration-derived or request-derived,
   using the same dependency facts other analyzers use. Report the 65 `lib/webhook.ts` records as one grouped
   observation with its entry count, and leave the request-derived one prominent.
2. **Add an SSRF assessment** for request-derived URL operands: a contract for `fetch`/`axios`/`got`/`http.request`,
   questions about host and scheme control, allow-lists and redirects, and the same evidence gates. Start from the
   [outbound contract](.zazz/specifications/components-03-outbound.md). This needs its own specification; scope the
   first slice to operand classification and to one family, and keep "no verdict" for anything not request-derived.

Acceptance: the 65 records collapse to one observation; `profileImageUrlUpload.ts` is judged once and is not hidden by
the request limit.

### 8.5 Data-only XSS: 23 records with no rendering claim

These are API routes that return stored or computed data (for example `routes/vulnCodeSnippet.ts`,
`routes/restoreProgress.ts`, `routes/vulnCodeFixes.ts`, `routes/wallet.ts`, `routes/b2bOrder.ts`). The scanner says "API
data has no linked rendering claim to assess" because it does not know whether a browser renders the value as HTML.
That is correct as a statement, and it is only a gap if the client does render it. Juice Shop's Angular client lives in
`frontend/src/app`.

Fix: extend the existing API-to-browser linkage (`xss_cross_tier*.go`, `xss_client*.go`) so a data route is linked to the
Angular template or component that renders its response (`innerHTML`, `bypassSecurityTrustHtml`, interpolation). When a
link exists, the data record becomes a rendering claim; when the client escapes the value, it becomes protected; when no
client is found, it stays "not assessed" with that reason. Add a count of linked and unlinked routes to the report so the
reviewer sees what is still open. This is the largest item; give it its own contract.

## 9. Order of work and live-run budget

1. 8.2 named-import binding (small, three records).
2. 8.1 payload reduction, starting with grouping gaps and relevance filtering.
3. 8.4 operand classification, then the SSRF assessment contract.
4. 8.3 Sequelize finders and the `tool(...)` misdetection.
5. Sections 1 to 6: JavaScript `if` modeling, sequenced with the E3 wire bump (it also shrinks the 8.1 payload).
6. 8.5 and section 7 as separate slices.

Keep live checks small: about one capped request per fixed record, 6 to 8 in total for sections 8.1 to 8.3, using
`--route` or `--entry`. Rebuild the Juice Shop sample only after all of them land.

