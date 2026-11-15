# Handoff: JavaScript guard confidence and the Goof Zip Slip case

**Status:** open follow-up from slice E2 ([contract](.zazz/specifications/shared-guard-and-manifest-engine.md)), pull request 13.
**Branch where it was found:** `analyzer-engine-hardening`.
**Suggested home:** its own worktree and contract. Part of it needs the E3 wire bump (see [Options](#4-options)).

Read [AGENTS.md](AGENTS.md) first. Do not print `.env` or credentials. Live model calls need an explicit,
small request cap.

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
