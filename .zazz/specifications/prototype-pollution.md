# Prototype pollution analyzer (CWE-1321)

- **Status** Proposal, drafted 2026-11-20. No code is written. Implementation starts on owner assignment.
- **Worktree and branch** `prototype-pollution`, a new sibling worktree cut from `stage`. This spec
  is drafted in `precise-claim-to-judge` and moves with it.
- **Baseline** `stage` at `6e7fa1c`
- **Prerequisite** None for stage 1 (application write claim). Stage 2 (library write claim) needs
  [phase 7](architecture-phase-7-npm-corpus.md) answer keys and
  [phase 8](architecture-phase-8-npm-library-mode.md) library entries.
- **Delivery** One draft PR into `stage` per stage.
- **Run log** `.zazz/ephemeral/prototype-pollution-run-log.md`
- **Product scope source** Container-root `3-npm-library-rce-mvp-proposal.md`, "Prototype pollution
  pack", and [waypoint W3](../project/implementation-plan.md#before-library-scanning).

## 1. Capability

Add a `pollution` family for JavaScript and TypeScript. It asks whether data the caller does not
trust can choose a key that names the prototype in a write that reaches `Object.prototype`. It
uses claim kind `prototype_write_candidate`, protocol `pollution-components-v1` and finding type
`prototype-pollution` (CWE-1321).

The scanner establishes four facts and the model judges only what is left:

1. **Which write.** A verified library merge or set-by-path call with its contract, or a recursive
   merge or path walk whose source is in the scanned repository.
2. **Which operand carries the keys.** The source object of a merge, the path of a set-by-path, or
   the key expressions of a nested computed write.
3. **Where that operand comes from, and whether it can hold nested keys.** A JSON request body can;
   a scalar query value cannot.
4. **What stands in between, stated exactly.** Which of `__proto__`, `constructor` and `prototype`
   a deny-list blocks, an own-property check, a null-prototype target, or a patched library version.

The write claim is built once and used in both modes. Stage 1 delivers it for applications.
Stage 2 runs the same source-visible detection on library exports. The proposal's access and
gadget claims are named in D-10 and are not specified here.

### Baseline today

Offline, scanner `6e7fa1c`, samples at their pins. No sample report has a pollution record: the
family does not exist.

| ID | Sample and location | Operation | Expectation |
|---|---|---|---|
| `GOOF-PP-01` | Node.js Goof `routes/index.js:360` | `_.merge(message, req.body.message, {…})`, lodash 4.17.4 in the lockfile | Positive |
| `TS-PP-01` | Vulnerable TypeScript app `src/server.ts:246` | `_.merge(target, source)`, both from `req.body`, lodash 4.17.4 in the lockfile | Positive |
| `JS-PP-N01` | Juice Shop `server.ts:351`, `routes/recycles.ts:14` and its other `JSON.parse` calls | `JSON.parse` of request text | Control: no record. Parsing creates an own `__proto__` property and writes no prototype |
| `OSS-PP-N01` | OSS OopsSec Store `packages/react-toastfy/index.js:33` | `Object.assign({}, DEFAULT_OPTIONS, options)` | Control: no record. A shallow copy can change only the new object's own prototype |

Goof also holds a reader of the polluted name: `routes/index.js:372` tests `user.canDelete`. That
is an authorization effect, not code execution, and stage 1 does not claim it (OQ-2).

## 2. Required reading

- The proposal section named in the header, and the plan's waypoints.
- [Command bypass support](command-bypass-support.md): a model's bypass answer is checked against
  what the scanner lists for the guard. D-7 here applies the same rule to key deny-lists.
- [Unsafe deserialization](unsafe-deserialization.md) §4 and §5, the most recent new-family
  contract: the same registration points apply.
- [Close findings gaps](close-findings-gaps.md), the Node.js Goof table that names `GOOF-PP-01`.
- Code: the `code` family registration in `internal/analysispacks/families.go`, its policy in
  `internal/judge/code_redirect.go`, lockfile resolution in `internal/langjs/package_manifest.go`
  and `package_lock.go`, and input facts in `internal/analysis/input_facts.go`.
- [Analysis guides](../../docs/analysis/README.md) for the shared status vocabulary.

## 3. Invariants

- A write is a candidate only when a key level it does not fix can name the prototype and a later
  level assigns. A single-level write `obj[k] = v` changes one object and is never a candidate.
- What a guard blocks is a scanner fact. A model answer that contradicts it is not accepted.
- A version-dependent library behaviour needs a version read from a manifest or lockfile. An
  unknown version stays Review. A patched version has no record.
- A write finding states that `Object.prototype` is polluted. It never states that code execution
  was shown.
- The scanner does not read `node_modules/`. A library call is judged by its contract; a library's
  own source is judged only in library mode.
- A comment or label in the target is not evidence. Both sample positives carry a comment naming
  the weakness, and neither may be used.
- Every existing family is unchanged. `TestArchitectureBaseline` changes only by new fixture rows.
  The recall floor in [`check.py`](../evaluation/recall-gap-inventory/check.py) holds, and no keyed
  control becomes a finding.
- Paid calls follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/analysis/pollution.go`, `analysis.go`, `findings.go` | New, modified | `PollutionFacts`, the claim kind and the finding type |
| `internal/analysispacks/pollution.go`, `families.go`, `contracts.go`, `questions.go`, catalog material | New, modified | Family registration, library contracts, questions, protocol version |
| `internal/analysispacks/key_guard.go` | New | The names a key guard blocks and what it leaves, read by the request and by policy |
| `internal/judge/pollution.go`, tests | New | Policy and consistency gates |
| `internal/langjs/pollution.go`, `pollution_writes.go`, tests, `testdata/pollution/` | New | Library calls with version facts; source-visible recursive merge, path walk and nested computed write |
| `internal/guidelines`, `internal/report` | Modified | Guidance, labels, SARIF rule for CWE-1321 |
| `docs/analysis/prototype-pollution.md` (new), `docs/analysis/README.md`, `docs/detection-capabilities.md`, `README.md` | New, modified | Rules, supported subset and limits |
| `.zazz/evaluation/prototype-pollution-results.md` (new), `recall-gap-inventory/cases.json`, the Goof and TypeScript app guides, `.zazz/project/implementation-plan.md` | New, modified | Key rows, results, capability checklist |
| `cmd/scan/testdata/architecture-baseline.json` | Modified | New fixture rows only |

Out of scope:

- The access claim and the gadget claim (D-10).
- Any statement that pollution leads to code execution, and any cross-package link.
- Write libraries other than lodash in stage 1 (OQ-3).
- Python and PHP. Neither has a prototype chain.
- Browser entries. Client-side pollution needs its own source and gadget model.
- Dependency advisories for the packages an application installs (Audit).

## 5. Decisions

- **D-1. A separate family.** `pollution` is registered next to `code`, with its own facts,
  questions and policy, and reuses the operand-path record (`CommandPath`).
  **Why.** The operand is a key, not code or command text, and its controls (a key deny-list, an
  own-property check, a null-prototype target) mean nothing to the other families.
- **D-2. Verified library writes.** Calls resolve through imports and aliases, as the code
  family's do. Shadowed or reassigned bindings are excluded.

  | Contract | Operations | Key operand |
  |---|---|---|
  | `lodash-merge-v1` | lodash `merge`, `mergeWith`, `defaultsDeep`, and the `lodash.merge`, `lodash.mergewith`, `lodash.defaultsdeep` packages | Every source object after the first argument |
  | `lodash-set-v1` | lodash `set`, `setWith`, `zipObjectDeep`, and their per-method packages | The path argument |

  Excluded as writes that cannot reach `Object.prototype`, with no record: `Object.assign`, object
  spread, `_.assign`, `_.extend`, `_.defaults`, `JSON.parse`, and structured clone.
- **D-3. Lodash version facts.** The fixed version decides whether a call is a sink. These are
  starting values from the public advisories. Each is confirmed against its GitHub advisory and
  fix diff before the contract text is written.

  | Operations | Starting value | Advisory |
  |---|---|---|
  | `merge`, `mergeWith`, `defaultsDeep` through `__proto__` | Fixed in 4.17.5 | CVE-2018-3721 |
  | The same through `constructor.prototype` | Fixed in 4.17.11 | CVE-2018-16487 |
  | `defaultsDeep` through `constructor` | Fixed in 4.17.12 | CVE-2019-10744 |
  | `zipObjectDeep`, `set`, `setWith` | Fixed in 4.17.20 | CVE-2020-8203 |

  A version below the fix is a sink and the record states which key sequence it still accepts. A
  version at or above it has no record. No resolvable version is `version_unresolved`, Review.
- **D-4. Source-visible writes.** Three shapes are recognised from syntax, in a function whose
  source is scanned:
  - **Recursive merge.** A function that iterates the keys of one parameter (`for…in`,
    `Object.keys`, `Object.entries`), assigns `target[key]`, and calls itself, directly or through
    one helper, on `target[key]`.
  - **Path walk.** A loop over the parts of a split path that steps `obj = obj[part]` and then
    assigns through the last part.
  - **Nested computed write.** `a[k1][k2] = v` where `k1` is not a constant.

  Anything else that might write through a dynamic key is not a candidate. The limit is stated in
  the guide, not hidden.
  **Why.** These are the shapes behind the corpus rows (`express-fileupload` `parseNested`,
  `superjson` set-by-path) and behind hand-written merges in applications.
- **D-5. The key operand must be able to hold nested keys.** A parsed JSON body and a value passed
  through `JSON.parse` can. A scalar route parameter, header or cookie cannot, and has no record.
  An origin the input facts do not type is `key_control_unknown`, Review.
- **D-6. The scanner lists what a key guard blocks.** For a source-visible write, comparisons of
  the key against literals inside the loop are read as a deny-list. `key_guard.go` states which of
  `__proto__`, `constructor` and `prototype` it blocks and which it leaves. Three other controls
  are recorded as facts: an own-property test of the target at every level, a target created with
  `Object.create(null)`, and `Map` storage.
  **Why.** The proposal's bypass sibling is exactly a deny-list that blocks `__proto__` and
  leaves `constructor.prototype`. The scanner can read that; it should not be left to the model.
- **D-7. A bypass answer is checked against the listing.** `key_guard_bypass` asks whether a key
  sequence passes every guard and still names the prototype. Where the listing shows every route
  blocked, `bypass_identified` is not supported and the record stays Review
  (`pollution_bypass_unsupported`). Where the listing leaves a name, the record carries
  `key_guard_incomplete` with that name and can never be Protected. This is
  [command bypass support](command-bypass-support.md) D-2 and D-5 applied to keys.
- **D-8. Questions.** Three, each a precise claim:
  - `prototype_key_control`: can the data operand supply a key or path part at the write?
    `vulnerable`, `protected`, `not_applicable`, `unknown`.
  - `key_guard_bypass`: `bypass_identified`, `no_bypass`, `guard_semantics_unknown`,
    `not_applicable`, as defined in D-7.
  - `protection_coverage`: `complete`, `incomplete`, `unknown`.
- **D-9. Status.** Application mode: Confirmed needs a verified write (a vulnerable library version
  or a source-visible shape), a request-derived key operand on a raw path that can hold nested
  keys, and consistent answers. Protected needs a control on every path, the model's protected
  answers, and no `key_guard_incomplete`. Everything else is Review. Library mode (stage 2) never
  confirms: the same facts give a conditional weakness, per phase 8 D-3.
- **D-10. Access and gadget claims come after the corpus keys.** The proposal's second and third
  claim types need facts this contract does not have: the exact React2Shell decoder function, the
  `handlebars` lookup path, and the confirmed gadget list. Phase 7 produces all three. They are
  added by revising this contract, not by a second family.
  **Rejected.** Specifying them now from secondary sources: the proposal itself marks those
  sources as replaced by advisories and fix diffs in phase 0.

## 6. Agent implementation rules

Follow [execution discipline](../docs/agent-execution-discipline.md). Stop and ask when a D-3
version does not match its advisory, when a sample row needs a write library outside D-2, or when
a change would alter another family's request bytes. Contract texts cite the library's own
advisory or changelog, with the review date.

## 7. Acceptance criteria

1. **AC1 (library write).** `_.merge({}, req.body.settings)` with lodash 4.17.4 in the lockfile
   yields one candidate with contract `lodash-merge-v1`, the version, and a raw path. The same file
   with lodash 4.17.21 yields no pollution record. With no lockfile and a range in `package.json`
   it is Review with `version_unresolved`.
2. **AC2 (recursive merge).** A repository function matching D-4's recursive merge, called with a
   JSON body, yields one candidate. With a guard that skips only `__proto__`, the record carries
   `key_guard_incomplete` naming `constructor`, and stub answers of `protected`, `no_bypass` and
   `complete` do not make it Protected. With all three names skipped, or an own-property test at
   every level, those stub answers make it Protected.
3. **AC3 (path walk and nested write).** A path-walk setter called with a request path, and
   `store[req.body.a][req.body.b] = req.body.v`, each yield one candidate.
4. **AC4 (controls).** No pollution record for: `Object.assign({}, req.body)`; object spread of
   `req.body`; `JSON.parse(req.body.text)`; `obj[req.body.k] = v`; a merge whose source is a
   scalar route parameter. A merge into `Object.create(null)` is a candidate that the stub
   protected answers make Protected.
5. **AC5 (policy).** Against the stub judge: `vulnerable` with consistent answers on a raw path is
   Confirmed. `bypass_identified` on a guard the listing shows complete is Review with
   `pollution_bypass_unsupported`. A `protected` answer on a raw path is a contradiction, Review.
6. **AC6 (samples, offline).** `GOOF-PP-01` and `TS-PP-01` each yield one candidate at the anchor.
   `JS-PP-N01` and `OSS-PP-N01` yield none. No other sample gains a pollution record.
7. **AC7 (isolation).** Request digests of every other family are unchanged, the architecture
   baseline changes only by new fixture rows, and `check.py` output moves only by the new rows.
8. **AC8 (live, on the owner's word).** Node.js Goof and the Vulnerable TypeScript app are judged:
   both positives are Confirmed, no control is a finding, and every assessment replays exactly.
9. **AC9 (stage 2).** On the phase 7 pins, each write row (`superjson`, `express-fileupload`,
   `parse-server`, `ajv`) is a conditional weakness or Review at its key anchor on the vulnerable
   pin and is not a conditional weakness there on the fixed pin. No bypass sibling is Protected.
10. **AC10 (gate).** `gofmt -l cmd internal` prints nothing; `go vet ./...`, `go build ./...` and
    `go test -race ./... -count=1` pass. The analysis guide states the rules and the limits.

## 8. Test strategy

- A table test per write shape in `internal/langjs` over `testdata/pollution/` pairs: vulnerable,
  guarded, bypass sibling, control.
- `key_guard.go` has its own table: each subset of the three names, the own-property test, and a
  guard the scanner cannot read.
- Policy tests in `internal/judge` use stub answers, as the command bypass tests do.
- Sample and corpus rows are recorded runs against pinned checkouts, not committed tests.

## 9. Execution sequence

1. Add the key rows with their current failing status. Record the offline baseline.
2. **Red:** the AC1 fixture.
3. Facts, family registration, contracts and questions; lodash calls with version facts (AC1).
4. Source-visible writes (AC2, AC3), then the key-guard listing and controls (AC4).
5. Policy against the stub judge (AC5). Reporting and SARIF.
6. Offline samples and isolation (AC6, AC7). Docs and gate (AC10).
7. Live run on the owner's word (AC8). Draft PR. Stage 2 follows phase 8 (AC9).

```go
// PollutionFacts records one write that can reach a prototype.
type PollutionFacts struct {
	Operation  string        `json:"operation"`            // lodash.merge | recursive_merge | path_walk | nested_write
	ContractID string        `json:"contract_id,omitempty"`
	Version    string        `json:"version,omitempty"`
	KeyOperand string        `json:"key_operand"`          // source | path | computed_keys
	Blocked    []string      `json:"blocked,omitempty"`    // names a key guard blocks
	Open       []string      `json:"open,omitempty"`       // names it leaves
	Paths      []CommandPath `json:"paths"`
}
```

## 10. Definition of done

- [ ] OQ-1 to OQ-3 answered and logged.
- [ ] D-3 versions confirmed against their advisories, with the review date in the contract text.
- [ ] AC1–AC8 and AC10 verified for stage 1, with evidence in the run log. AC9 closes stage 2.
- [ ] `git diff origin/stage --stat` matches §4.

## 11. Open questions

- **OQ-1. Status of a write with no shown effect.** Should a request-controlled pollution write be
  a Confirmed CWE-1321 finding whose impact is stated as "pollutes `Object.prototype`; the effect
  depends on what reads it", or a practice finding until a reader is shown? Recommendation:
  Confirmed, impact named, as the deserialization contract does for object injection.
- **OQ-2. In-file readers.** Goof reads `user.canDelete` twelve lines below the merge. Report that
  reader as supporting evidence on the write finding in stage 1, or leave every reader to the
  gadget claim? Recommendation: leave it; a reader without a rule for which reads matter is noise.
- **OQ-3. Other write libraries.** `deepmerge`, `merge`, `jquery` deep `extend`, `dot-prop`,
  `set-value` and `minimist` have published pollution advisories. Add contracts in stage 1, or
  only when a sample or corpus row needs one? Recommendation: only when needed. Three of them
  enter as phase 7 controls and are then source-visible in library mode.

## 12. Run log protocol

Use the plan's run-log rules. Record scanner SHA, sample pins and clean status, each advisory
checked for D-3 with its date, failing-first evidence, golden deltas, and live run identifiers
with planned and actual request counts.

## 13. Agent implementation prompt

> Work in the `prototype-pollution` sibling worktree, cut from current `origin/stage`. Read
> AGENTS.md, the orientation contents, this spec and its required reading. Confirm the D-3
> versions against their advisories first and ask OQ-1 to OQ-3. Execute §9 test-first for stage 1.
> Make no paid call until the owner asks for the AC8 live check. Do not start stage 2 until phases
> 7 and 8 have merged. Finish with a draft PR into `stage` listing AC evidence. Verifier: a
> fresh-context subagent reruns `GOOF-PP-01`, `TS-PP-01` and both controls, confirms that the
> bypass-sibling fixture cannot be Protected, and reports PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-20 — Drafted

Requested by the owner while planning the work before library scanning. Written from a search of
the JavaScript and TypeScript samples for merge, set-by-path and computed-key writes, from the
`code` and `deserialization` family structure, and from the npm proposal's pollution pack. The
lodash versions in D-3 are starting values and are not yet confirmed. No code changed.
