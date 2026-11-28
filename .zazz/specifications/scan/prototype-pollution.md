# Prototype pollution analyzer (CWE-1321)

- **Status** Stage 1 implemented and verified on the assigned feature branch, including the AC8 live check. Merge is pending.
- **Worktree and branch** `prototype-polution-analyzer`, assigned by the owner.
- **Implementation baseline** `stage` at `ec29e49`. The original sample baseline used `6e7fa1c`.
- **Prerequisite** None for stage 1 (application write claim). Stage 2 (library write claim) needs
  [phase 7](architecture-phase-7-npm-corpus.md) answer keys and
  [phase 8](architecture-phase-8-npm-library-mode.md) library entries.
- **Delivery** One draft PR into `stage` per stage.
- **Run log** `.zazz/ephemeral/prototype-pollution-run-log.md`
- **Verification** [Stage 1 results](../../evaluation/prototype-pollution-results.md)
- **Product scope source** Container-root `3-npm-library-rce-mvp-proposal.md`, "Prototype pollution
  pack", and [waypoint W3](../../project/implementation-plan.md#before-library-scanning).

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

Stage 1 analyzes writes reachable from application entries. It recognizes source-visible write
shapes in the scanned repository, including through resolved imports. Those checks apply by
syntax and flow across package names. The verified npm API contracts in this stage cover Lodash.
Stage 2 reuses the source-visible checks from library exports, with affected and patched package
pairs for validation. D-10 tracks the separate access and gadget claims.

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
  [Command bypass results](../../evaluation/command-bypass-support-results.md).
- [Unsafe deserialization](unsafe-deserialization.md) §4 and §5, the most recent new-family
  contract: the same registration points apply.
- [Close findings gaps](close-findings-gaps.md), the Node.js Goof table that names `GOOF-PP-01`.
- Code: the `code` family registration in `internal/analysispacks/families.go`, its policy in
  `internal/judge/code_redirect.go`, lockfile resolution in `internal/langjs/package_manifest.go`
  and `package_lock.go`, and input facts in `internal/analysis/input_facts.go`.
- [Analysis guides](../../../docs/scan/analysis/README.md) for the shared status vocabulary.

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
  The recall floor in [`check.py`](../../evaluation/recall-gap-inventory/check.py) holds, and no keyed
  control becomes a finding.
- Paid calls follow [AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/analysis/pollution.go`, `analysis.go` | New, modified | `PollutionFacts`, the claim kind and the finding type |
| `internal/analysispacks/pollution.go`, `families.go`, and catalog selection | New, modified | Family registration, library contracts, questions, protocol version |
| `internal/analysispacks/key_guard.go` | New | The names a key guard blocks and what it leaves, read by the request and by policy |
| `internal/judge/pollution.go`, tests | New | Policy and consistency gates |
| `internal/langjs/pollution*.go`, flow integration, and `testdata/pollution/` | New | Library calls with version facts; source-visible recursive merge, path walk and nested computed write |
| `internal/guidelines`, `internal/report` | Modified | Guidance, labels, SARIF rule for CWE-1321 |
| `docs/analysis/prototype-pollution.md` (new), `docs/analysis/README.md`, `docs/detection-capabilities.md`, `README.md` | New, modified | Rules, supported subset and limits |
| `.zazz/evaluation/prototype-pollution-results.md` (new), `recall-gap-inventory/cases.json`, the Goof and TypeScript app guides, `.zazz/project/implementation-plan.md` | New, modified | Key rows, results, capability checklist |
| `cmd/scan` | Modified | Family help, architecture fixture registration, and two new golden rows |

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
- **D-2. Verified library writes.** Stage 1 verifies the listed Lodash APIs through imports and
  aliases. Shadowed or reassigned bindings are excluded. Other package names can be analyzed
  through source-visible operations within the application scan boundary under D-4.

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
  | `zipObjectDeep`, `set`, `setWith` | Main bundle affected from 3.7.0 through 4.17.18. Upstream confirms the fix in 4.17.19 and refreshed per-method files in 4.17.20 | [GHSA-p6mc-m468-83gw](https://github.com/advisories/GHSA-p6mc-m468-83gw), [release notes](https://github.com/lodash/lodash/wiki/Changelog#v41719) |

  A version below the fix is a sink and the record states which key sequence it still accepts. A
  version with a verified fix for the operation has no record. An unresolved range or distribution
  stays Review with `version_unresolved`. The advisory lists affected standalone `lodash.set`
  3.7.0–4.3.2 and `lodash.setwith` through 4.3.2, with no patched release in those package rows.
  The same advisory lists `lodash.update` and `lodash.updatewith` through 4.10.2 and `lodash.pick`
  4.0.0–4.4.0, also with no patched release. `update`, `updateWith` and `pick` are outside
  `lodash-set-v1` today (OQ-4).
  Use 4.17.19 as the patched main-bundle test and 4.17.20 as the patched per-method-file test.
  Keep an unresolved per-method import at the 4.17.19 boundary in Review when that distribution
  cannot be verified. Standalone controls include `lodash.merge` 4.6.1/4.6.2,
  `lodash.defaultsdeep` 4.6.0/4.6.1, and `lodash.zipobjectdeep` 4.2.0/4.18.0.
  [Standalone merge advisory](https://github.com/advisories/GHSA-h726-x36v-rx45),
  [defaultsDeep advisory](https://github.com/advisories/GHSA-jf85-cpcp-j695),
  [modular release](https://github.com/lodash/lodash/releases/tag/4.18.0).
  Reviewed 2026-11-20. [Main bundle](https://raw.githubusercontent.com/lodash/lodash/4.17.19/lodash.js),
  [per-method helper](https://raw.githubusercontent.com/lodash/lodash/4.17.20-npm/_baseSet.js).

  **Lodash deletion advisories for regression tests.** Lodash published CVE-2025-13465 on
  2026-01-21 and CVE-2026-2950 on 2026-03-31. Both cover deletion via paths in `unset` and
  `omit`. The GitHub Advisory Database also lists `pullAt`. These operations are controls
  for the application assignment claim. Their vulnerable and fixed pins can serve as positive
  and negative cases when a prototype-deletion claim is specified for library mode.
  [Initial advisory](https://github.com/lodash/lodash/security/advisories/GHSA-xxjr-mmjv-4gpg),
  [follow-up advisory](https://github.com/lodash/lodash/security/advisories/GHSA-f23m-r3pf-42rh),
  [affected operations](https://github.com/advisories/GHSA-f23m-r3pf-42rh).

  | Package | CVE-2025-13465 affected | Initial patch | CVE-2026-2950 affected | Patch covering both |
  |---|---|---|---|---|
  | `lodash`, `lodash-es`, `lodash-amd` | `>=4.0.0 <4.17.23` | `4.17.23` | `>=4.17.23 <4.18.1` | `4.18.1` |
  | `lodash.unset`, `lodash.omit` | `>=4.0.0 <4.18.0` | `4.18.0` | `<4.18.0` | `4.18.0` |

  Use `4.17.22` for the initial affected monolith, `4.17.23` and `4.18.0` for affected
  follow-up cases, and `4.18.1` for the patched control. Pin the standalone packages independently.
  The 4.18.1 release also fixes the separate template-injection CVE-2026-4800.
  [Release and distribution diffs](https://github.com/lodash/lodash/wiki/Changelog#v4181),
  [template advisory](https://github.com/lodash/lodash/security/advisories/GHSA-r5fr-rjxr-66jc).
  **Additional library regression candidates.** The following published cases extend the
  phase 7 source-only test inventory when the pinned export and fixed diff can be reviewed.
  Use source and manifest snapshots for the scanner tests. The application pack keeps its
  existing verified library contract scope.

  | Package | Positive pin or range | Negative pin or treatment | Claim |
  |---|---|---|---|
  | `jsonpath` | `1.1.1` (`value`, CVE-2025-61140) | `1.2.0` candidate pin. Verify the released artifact includes fix commit `9631412` | Path write. [CVE record](https://nvd.nist.gov/vuln/detail/CVE-2025-61140), [merged fix](https://github.com/dchester/jsonpath/pull/195) |
  | `dset` | `3.1.3` (CVE-2024-21529) | `3.1.4` | Path write. [Advisory and patch references](https://github.com/advisories/GHSA-f6v4-cf5j-vf3w) |
  | `object-path` (`set`) | `0.11.5` (CVE-2021-23434) | `0.11.6` | Path write with inherited-property handling enabled. [Advisory](https://github.com/advisories/GHSA-v39p-96qg-c8rf), [upstream changelog](https://github.com/mariocasciaro/object-path#0116) |
  | `object-path` (`del`) | `0.11.7` (CVE-2021-3805) | `0.11.8` | Prototype deletion. Scope control for the assignment claim. [Advisory](https://github.com/advisories/GHSA-8v63-cqqc-6r2c) |
  | `merge-deep` | `3.0.2` (CVE-2021-26707) | `3.0.3` | Recursive merge and incomplete key protection. [Advisory](https://github.com/advisories/GHSA-r6rj-9ch6-g264), [upstream fix](https://github.com/jonschlinkert/merge-deep/commit/11e5dd56de8a6aed0b1ed022089dbce6968d82a5) |
  | `json5` | `2.2.1` (CVE-2022-46175) | `2.2.2` | Returned-object prototype mutation. Scope control for the shared `Object.prototype` write claim at both pins. [Maintainer advisory](https://github.com/json5/json5/security/advisories/GHSA-9c47-m6qq-7p4h) |
  | `counterpart` | `0.18.6` per the advisory's structured npm range (CVE-2025-57354) | No patched release in the advisory. Review the source before promoting the row to a keyed positive | Translation-key processing. [Advisory](https://github.com/advisories/GHSA-2488-w585-72ch) |
  | `minimist` | `>=1.0.0 <1.2.3` and `<0.2.1` (CVE-2020-7598) | `1.2.3` fixes that advisory only. `1.2.3`–`1.2.5` remain affected by CVE-2021-44906; `1.2.6` is the patched control | Argument-key path write. `1.2.3`–`1.2.5` is a published incomplete fix, a bypass-sibling range. [First advisory](https://github.com/advisories/GHSA-vh95-rmgr-6w4m), [second advisory](https://github.com/advisories/GHSA-xvch-5gv4-984h) |
  | `yargs-parser` | `>=16.0.0 <18.1.1`, and the earlier ranges in the advisory (CVE-2020-7608) | `18.1.1`, `15.0.1`, `13.1.2`, `5.0.1` by release line | Argument-key path write. [Advisory](https://github.com/advisories/GHSA-p9pc-299p-vxgp) |
  | `merge` | `<2.1.1` (CVE-2020-28499, `_recursiveMerge`) | `2.1.1` | Recursive merge. [Advisory](https://github.com/advisories/GHSA-7wpw-2hjm-89gp) |
  | `set-in` | `<2.0.1` (CVE-2020-28273); `<2.0.3` (CVE-2022-25354) | `2.0.3` for those two. `2.0.5` for CVE-2026-26021 | Path write. `2.0.1`–`2.0.2` is a published incomplete fix. `2.0.3`–`2.0.4` is a control: the CVE-2026-26021 proof first replaces `Array.prototype.includes`, so the key check holds unless the runtime is already tampered with. [2020](https://github.com/advisories/GHSA-qr4p-c9wr-phr6), [2022](https://github.com/advisories/GHSA-6956-83fg-5wc5), [2026](https://github.com/advisories/GHSA-2c4m-g7rx-63q7). Source reading on 2026-11-21 differs for 2.0.3: its key check runs after the recursive write, a transcription of its logic still pollutes, and 2.0.4 is the first version that checks before the recursion. 2.0.2 was never published. [Reading](../../evaluation/pollution-write-shapes-results.md#real-advisory-libraries) |
  | `qs` | `<6.10.3` and the backport lines (CVE-2022-24999) | `6.10.3`, `6.9.7`, `6.8.3`, `6.7.3`, `6.6.1`, `6.5.3`, `6.4.1`, `6.3.3`, `6.2.4` | Process hang from a `__proto__` key. Scope control: the advisory reports no shared `Object.prototype` write. [Advisory](https://github.com/advisories/GHSA-hrpp-h998-j3pp) |
  | React Server Components | `react-server-dom-*` 19.2.0 (CVE-2025-55182) | 19.2.1 historical fix pin for this CVE | Decoder and access checkpoint owned by phase 7 AC2. [React advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components) |

- **D-4. Source-visible writes.** Three shapes are recognized in scanned source, including
  helpers reached through resolved imports. Syntax and data flow determine whether a write
  matches:
  - **Recursive merge.** A function that iterates the keys of one parameter (`for…in`,
    `Object.keys`, `Object.entries`), assigns `target[key]`, and calls itself, directly or through
    one helper, on `target[key]`.
  - **Path walk.** A loop over the parts of a split path that steps `obj = obj[part]` in
    a single statement or block and then assigns through the last part.
  - **Nested computed write.** `a[k1][k2] = v` where `k1` is not a constant. Earlier
    conditional writes to the receiver lookup slot require heap-flow evidence and fall outside
    the direct-write rule, except a write that only fills an absent slot
    ([write shapes](pollution-write-shapes.md) D-9).

  [Write shapes](pollution-write-shapes.md) widens each shape: more key enumerators, recursion
  through a local, array and regular-expression paths, `reduce` and `while` walks, unflatten, and
  whole-path deny-lists.

  Anything else that might write through a dynamic key is not a candidate. The limit is stated in
  the guide, not hidden.
  **Why.** These are the shapes behind the corpus rows (`express-fileupload` `parseNested`,
  `superjson` set-by-path) and behind hand-written merges in applications.
- **D-5. The key operand must be able to hold nested keys.** A parsed JSON body and a value passed
  through `JSON.parse` can. A scalar route parameter, header or cookie cannot, and has no record.
  An origin the input facts do not type is `key_control_unknown`, Review.
- **D-6. The scanner lists what a key guard blocks.** For a source-visible write, comparisons of
  the key against literals inside the loop are read as a deny-list. `key_guard.go` states which of
  `__proto__`, `constructor` and `prototype` it blocks and which it leaves. The analyzer also
  records own-property tests and null-prototype targets. A null-prototype root covers only the
  root. Each container on a deeper path needs its own protection evidence. Native `Map.set`
  writes collection entries and creates no prototype-write candidate. Bracket assignment on a map
  still uses ordinary property access.
  An operation on the same source and target arguments retains evidence from all modeled write
  sites in the helper. A key counts as blocked for that operation when its guard covers every
  modeled traversal. Different argument pairs have independent candidates.
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

Follow [execution discipline](../../docs/agent-execution-discipline.md). Stop and ask when a D-3
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
   A helper with several loops over one operand must retain evidence from every modeled site, and
   a second request-derived source argument must have its own candidate.
3. **AC3 (path walk and nested write).** A path-walk setter called with a request path, and
   `store[req.body.a][req.body.b] = req.body.v`, each yield one candidate.
4. **AC4 (controls).** No pollution record for: `Object.assign({}, req.body)`; object spread of
   `req.body`; `JSON.parse(req.body.text)`; `obj[req.body.k] = v`; a merge whose source is a
   scalar route parameter. A deep merge into `Object.create(null)` is a candidate in Review
   when nested containers can inherit prototypes. A bounded direct write with a freshly
   constructed null-prototype target and one lookup before assignment can be Protected.
   `unset`, `omit`, and `pullAt` are assignment-claim controls on the published affected and
   patched pins in D-3.
5. **AC5 (policy).** Against the stub judge: `vulnerable` with consistent answers on a raw path is
   Confirmed. `bypass_identified` on a guard the listing shows complete is Review with
   `pollution_bypass_unsupported`. A `protected` answer on a raw path is a contradiction, Review.
6. **AC6 (samples, offline).** `GOOF-PP-01` and `TS-PP-01` each yield one candidate at the anchor.
   `JS-PP-N01` and `OSS-PP-N01` yield none. No other sample gains a pollution record.
7. **AC7 (isolation).** Request digests of every other family are unchanged, the architecture
   baseline changes only by new fixture rows, and `check.py` output moves only by the new rows.
8. **AC8 (live, on the owner's word).** Node.js Goof and the Vulnerable TypeScript app are judged:
   both positives are Confirmed, no control is a finding, and every assessment replays exactly.
   The vuln-nextjs prototype pollution fixtures are judged in the same check: no exploitable
   fixture is Protected and no safe fixture is a finding.
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

- [x] Record the OQ-1 to OQ-3 implementation decisions and evidence in the run log.
- [x] Record the reviewed D-3 ranges and unresolved package boundaries with advisory references.
- [x] Verify AC1–AC7 and AC10 for stage 1. [Results](../../evaluation/prototype-pollution-results.md).
- [x] Verify AC8 when the owner authorizes a live check.
  [Evidence](../../evaluation/pollution-write-shapes-results.md#ac8-live-judgment).
- [ ] AC9 closes stage 2.
- [x] Scope the feature diff to the analyzer, its integration, tests, and documentation in §4.

## 11. Review decisions

Stage 1 applies the proposed defaults below. The review can revisit these decisions with sample
and corpus evidence.

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
- **OQ-4. Lodash `update`, `updateWith` and `pick`.** GHSA-p6mc-m468-83gw lists their standalone
  packages as affected with no patched release. Add them to `lodash-set-v1`, or leave them out
  until a sample uses one? Recommendation: add `update` and `updateWith`, which take the same
  path argument as `set`; confirm the `pick` write path from the fix diff before adding it.
- **OQ-5. Query strings as a key operand.** Express's default parser builds nested objects from
  bracket syntax, so `req.query.x` is not always a scalar. `qs` drops any parameter whose key has
  a segment naming an `Object.prototype` property unless `allowPrototypes` or `plainObjects` is
  set ([`parse.js` at 6.10.3](https://github.com/ljharb/qs/blob/v6.10.3/lib/parse.js#L171-L193)).
  Treat a query origin as unable to carry a prototype key under the default parser and as
  `key_control_unknown` when the application sets a custom query parser? Recommendation: yes,
  with the parser setting recorded as the evidence.

## 12. Run log protocol

Use the plan's run-log rules. Record scanner SHA, sample pins and clean status, each advisory
checked for D-3 with its date, failing-first evidence, golden deltas, and live run identifiers
with planned and actual request counts.

## 13. Agent implementation prompt

> Work in the assigned `prototype-polution-analyzer` sibling worktree. Read
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

### 2026-11-20 — Verified the advisory ranges

Owner requested explicit affected, initially patched, and fully patched test pins. D-3 adds the
2026 Lodash deletion advisories and distinguishes the main bundle from modular files for
CVE-2020-8203. AC4 records the difference between a null-prototype root and a control on every
level of a deep merge. [Lodash 4.17.4 merge implementation](https://raw.githubusercontent.com/lodash/lodash/4.17.4/lodash.js).

The additional `jsonpath`, `dset`, and `counterpart` examples are recorded with their evidence
status. React's maintainer advisory supplies the existing phase 7 decoder checkpoint. The
spec keeps affected ranges separate from confirmed release pins.

### 2026-11-20 — Implemented the application write claim

The `pollution` family records the verified write, key operand, version, and independent guard
paths. It uses the `pollution-components-v1` decision protocol and reports CWE-1321 in JSON and
SARIF. Pinned offline samples and in-memory decisions cover AC1–AC7. The analysis guide describes
the bounded source shapes and guard limits. AC8 and AC9 remain in the acceptance checklist.

### 2026-11-20 — Reviewed multiple write sites and additional package pairs

The application analyzer now collects all modeled write sites for the same helper operands.
Regression tests cover a later incomplete guard, two fully guarded loops, and independent source
arguments. D-3 records `object-path` and `merge-deep` as affected/patched library candidates and
`json5` and the later `object-path` deletion advisory as scope controls. Library-export verification remains in phase 7 and phase 8.

### 2026-11-20 — Verified source-visible writes beyond the Lodash contracts

A fixture exercises a recursive merge through an import alias and forwarding helper, a split-path
write with an unbraced loop, a path write with an own-property guard, and a read-only traversal
control. The test verifies the request operand and the write site in the imported module.

### 2026-11-20 — Checked an owner-supplied library list against the advisory database

The owner supplied a search list of seven packages. Each CVE was read from the GitHub Advisory
Database. D-3 gains `minimist`, `yargs-parser`, `merge`, `set-in` and `qs` rows, with two published
incomplete fixes marked as bypass-sibling ranges and two entries marked as controls. `lodash` and
`counterpart` were already recorded. OQ-4 and OQ-5 are new. No code or analyzer behaviour changed.

### 2026-11-21 — Verified AC8 and checked the library table against source

The owner authorized the live check and added the vuln-nextjs fixtures to it. Both keyed
positives are Confirmed, no control is a finding, and all 39 saved traces replay exactly. The
`set-in` row of D-3 gains a source reading that differs from its advisory range for 2.0.3.
