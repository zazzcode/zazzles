# Unsafe deserialization analyzer (CWE-502)

- **Status** Proposal, drafted 2026-11-19. No code is written. Implementation starts on owner assignment.
- **Worktree and branch** `unsafe-deserialization`, a new sibling worktree cut from `stage`. This
  spec is drafted in `close-findings-gaps-dvwa` and moves with it.
- **Baseline** `stage` at `58e94e7`
- **Prerequisite** None for Python and JS/TS. The PHP sample row needs
  [PHP Symfony support](php-symfony-support.md) slices S2 and S4 (service binding and Twig service
  globals). PHP fixtures need nothing.
- **Delivery** One draft PR into `stage`.
- **Run log** `.zazz/ephemeral/unsafe-deserialization-run-log.md`

## 1. Capability

Add a `deserialization` family. It asks whether request-derived bytes reach the data operand of a
verified deserializer that builds objects or runs code chosen by the data. It uses a new claim kind
`deserialization_candidate`, protocol `deserialization-components-v1` and finding type
`unsafe-deserialization` (CWE-502), for Python, JavaScript and TypeScript, and PHP.

The scanner establishes four facts and the model judges only what is left:

1. **Which operation.** A verified deserializer call and its contract.
2. **What the format can do.** Run code by design, build objects of data-chosen classes, or build
   plain data only. This comes from the contract and the call's options, never from the model.
3. **Where the bytes come from.** The request, a stored field, another service, or the server.
4. **What stands in between.** A restricting option, an integrity check, or a class allow-list.

### Baseline today

Offline, scanner `58e94e7`, samples at their pins. No sample has a deserialization candidate.

| ID | Sample and location | Operation | Expectation |
|---|---|---|---|
| `VP-DESER-01` | VulnPy `src/vulnpy/trigger/deserialization.py:8` | `pickle.load` on a `BytesIO` of the request value | Positive |
| `VP-DESER-02` | VulnPy `…/deserialization.py:12` | `pickle.loads` | Positive |
| `VP-DESER-03` | VulnPy `…/deserialization.py:17` | `yaml.load(…, Loader=yaml.UnsafeLoader)` | Positive |
| `VP-DESER-04` | VulnPy `…/deserialization.py:23` | `yaml.load_all(…, Loader=yaml.UnsafeLoader)` | Positive |
| `SYM-DESER-01` | vuln-symfony `src/Services/UserPref.php:36` | `unserialize` of the `USER_PREF` cookie after `urldecode` and `base64_decode` (`:30`–`35`) | Positive, once Symfony entries exist |
| `VFA-DESER-01` | Vulnerable Flask App `vulnerable-flask-app.py:97` | `pickle.loads` of bytes from a raw socket | Review-expected. The bytes are not HTTP request input (OQ-2) |
| `TS-DESER-N01` | Vulnerable TypeScript app `src/server.ts:187` | `yaml.safeLoad`, js-yaml 3.10.0 | Control: not a finding. The sample's comment calls it vulnerable, but `safeLoad` builds plain data |
| `JS-DESER-N01` | Juice Shop `routes/vulnCodeFixes.ts:83`, `routes/vulnCodeSnippet.ts:90`, `server.ts:140` | `yaml.load` of file content, js-yaml 3.x | Control: not a finding. The content comes from a file, not the request |
| `JS-DESER-X01` | Juice Shop `routes/fileUpload.ts:114` | `yaml.load(data)` written inside a constant code string run by `vm.runInContext` | Excluded: the call is text, not syntax |
| `DRUPAL-DESER-01` | vuln-drupal `modules/custom/vulnerable_auth/src/Controller/AuthController.php:47` | `unserialize` of a method parameter | Deferred to [phase 9](architecture-phase-9-drupal.md) |

VulnPy mounts each trigger under 11 framework adapters: the published report has 139 entries on
`/vulnpy/deserialization/…` routes. The four sinks will therefore appear in roughly 30 contexts
each, as its two command sinks do today.

## 2. Required reading

- [Code injection rules](../../docs/analysis/code-injection.md) and the `code` family as the
  structural precedent: `internal/analysis/interpreter_redirect.go`,
  `internal/analysispacks/code_redirect.go`, `internal/judge/code_redirect.go`.
- [Component ownership](../architecture/analysis-packs.md#boundary-and-ownership) and the family
  registry in `internal/analysispacks/families.go`.
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates) and
  [calibration pairs](../../docs/analysis/calibration.md#regression-pairs).
- [Model-assisted evidence resolution](model-assisted-evidence-resolution.md) D-4 (stored origin)
  and D-7 (which records are sent).
- [VulnPy guide](../evaluation/vulnpy-detection-guide.md) and
  [recall inventory](../evaluation/recall-gap-inventory.md).
- Version resolution: `internal/langjs/package_manifest.go`.

## 3. Invariants

- Decoding is a transfer, never a control. `base64`, URL, hex and compression decoding, `.encode()`
  and stream wrappers keep the request origin.
- What a format can do is a contract fact. A model answer that contradicts it is rejected.
- The scanner makes no gadget-chain claim. It does not read `vendor/`, `node_modules/` or installed
  packages, and a finding never states that code execution was shown for an object-injection format.
- A version-dependent behavior needs a version read from a manifest or lockfile. An unknown version
  stays Review.
- A comment or label in the target is not evidence.
- Every existing family is unchanged. `TestArchitectureBaseline` changes only by new fixture rows.
  The recall floor in [`check.py`](../evaluation/recall-gap-inventory/check.py) holds, and no keyed
  control becomes a finding.
- Paid calls follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Purpose |
|---|---|---|
| `internal/analysis/deserialization.go`, `analysis.go`, `findings.go` | New, modified | `DeserializationFacts`, the claim kind and the finding type |
| `internal/analysispacks/deserialization.go`, `families.go`, `contracts.go`, `questions.go`, catalog material | New, modified | Family registration, contracts, questions, protocol version |
| `internal/judge/deserialization.go`, tests | New | Policy and consistency gates |
| `internal/langpy/deserialization.go`, `decode.go`, tests, `testdata/deserialization/` | New, modified | Python operations, loader facts, decode and stream transfers |
| `internal/langjs/deserialization.go`, tests, `testdata/deserialization/` | New | JS/TS operations with version facts |
| `internal/langphp/deserialization.go`, tests, `testdata/deserialization/` | New | `unserialize` and its options |
| `internal/guidelines`, `internal/report` | Modified | Guidance, labels, SARIF rule for CWE-502 |
| `docs/analysis/deserialization.md` (new), `docs/analysis/README.md`, `docs/detection-capabilities.md`, `docs/python-support.md`, `docs/php-support.md`, `README.md` | New, modified | Rules, supported subset and limits |
| `.zazz/evaluation/deserialization-results.md` (new), `recall-gap-inventory/cases.json`, the VulnPy and TypeScript app guides, `docs/samples/vulnpy/cases.json`, `.zazz/project/implementation-plan.md` | New, modified | Key rows, results, capability checklist |
| `cmd/scan/testdata/architecture-baseline.json` | Modified | New fixture rows only |

Out of scope:

- XML external entities (deferred by the owner) and prototype pollution through `JSON.parse` and
  merge, which has its own planned family.
- Gadget-chain discovery and dependency advisories (Audit).
- Loads addressed by a file path: `joblib.load`, `pandas.read_pickle`, `numpy.load`, `torch.load`,
  `shelve.open`, and PHP `phar://` metadata. They need a file-content origin model first.
- Python `marshal`. It does not build objects of data-chosen classes, so it needs its own
  capability and contract.
- Java, .NET and Ruby deserializers.
- Library mode. Scanning a deserializer's own source is the npm library scan (D-14).
- New input origins beyond D-9.

## 5. Decisions

- **D-1. A separate family.** `deserialization` is registered next to `code`, with its own facts,
  questions and policy, and reuses the operand-path record (`CommandPath`).
  **Why.** The operand is data, not source text, and the controls differ: a safe loader, a class
  allow-list and an integrity check have no meaning for `eval`.
  **Rejected.** A second claim kind inside `code`: its questions ask about code operands and its
  contracts say "interprets argument 0 as code".
- **D-2. Verified operations and what each can do.** Calls resolve through imports and aliases, as
  the code family's do. Shadowed or reassigned bindings are excluded.

  | Contract | Operations | Capability |
  |---|---|---|
  | `python-pickle-v1` | `pickle.load`, `loads`, `Unpickler(…).load`; the same in `cPickle`, `dill` and `cloudpickle` | `code_execution` |
  | `python-yaml-v1` | PyYAML `load`, `load_all`, `unsafe_load`, `full_load` and their `_all` forms | By loader (D-3) |
  | `python-jsonpickle-v1` | `jsonpickle.decode` | `code_execution` |
  | `php-unserialize-v1` | `unserialize` | `object_injection`, or `data_only` by option (D-4) |
  | `node-serialize-v1` | `unserialize` from `node-serialize`; `funcster.deepDeserialize` | `code_execution` |
  | `js-yaml-v1` | js-yaml `load`, `loadAll` | By version and schema (D-5) |

  Excluded as data-only operations, with no record: `json.loads`, `JSON.parse`, `yaml.safe_load`,
  js-yaml `safeLoad`, the `yaml` npm package's `parse`, `ast.literal_eval`, `json_decode`.
- **D-3. PyYAML loader facts.** The `Loader` argument decides the capability:
  - `SafeLoader`, `CSafeLoader`, `BaseLoader`: data only, no record.
  - `UnsafeLoader`, `Loader`, `CLoader`, and `unsafe_load`: `code_execution`.
  - `FullLoader` and `full_load`: `restricted_types`, with the resolved PyYAML version as a fact.
  - No `Loader` argument: version-dependent. An unknown version is `loader_unresolved`.
  - A loader passed as a variable or parameter: `loader_unresolved`, Review.
- **D-4. PHP options.** `unserialize($d, ['allowed_classes' => false])` is `data_only` and makes
  no record. A literal class list is a class allow-list control. A missing, `true` or non-literal
  option is `object_injection`.
- **D-5. js-yaml facts.** Before 4.0.0, `load` uses the full schema, which includes
  `!!js/function`: `code_execution`. From 4.0.0, `load` is safe by default: no record. An explicit
  `schema` option overrides either way. The version comes from the nearest manifest and lockfile;
  an unknown version is Review.
- **D-6. Transfers.** These keep the operand's origin and add a transfer step: `.encode()`,
  `.decode()`, `bytes()`, `io.BytesIO` and `io.StringIO` construction, `base64` decoding, hex and
  URL decoding, `zlib` and `gzip` decompression, and their PHP and JS equivalents (`base64_decode`,
  `urldecode`, `gzuncompress`, `Buffer.from(x, 'base64')`, `atob`). A `pickle.load(stream)` operand
  is the stream's content.
- **D-7. Controls.** Each is recorded on the path with its contract. None is Protected alone.
  - **Integrity check.** A keyed verification (`hmac.compare_digest`, `hash_equals` over an HMAC,
    a signed-token verify) that dominates the sink on the same bytes. The contract states that an
    unkeyed hash is not integrity. The model judges adequacy.
  - **Class allow-list.** PHP `allowed_classes` list; a Python `Unpickler` subclass overriding
    `find_class`. The model judges adequacy.
  - **Format checks** by regular expression or prefix are recorded as guards and are model-judged.
- **D-8. Questions** (`deserialization-components-v1`):
  - `deserialization_exposure`: `vulnerable`, `protected`, `not_applicable`, `unknown`.
  - `integrity_control`: `none`, `verified_before_decode`, `present_inadequate`, `unknown`.
  - `type_restriction`: `none`, `adequate`, `inadequate`, `unknown`.
  - `protection_coverage`: `complete`, `incomplete`, `unknown`.
- **D-9. Origins.** Request origins (query, body, cookie, header, upload content, path) make a raw
  path. A stored origin follows the existing stored-origin rules and questions. A server-generated
  or literal operand makes no record. Bytes from a raw socket or another service are an
  external-source witness kept separate from request input, as the remote response body is for
  Python insecure app's XSS.
- **D-10. Policy.**
  - **Confirmed** needs a verified contract whose capability is `code_execution` or
    `object_injection`, a complete raw request-to-operand path, `vulnerable` with consistent
    answers, and no unresolved gap on that path.
  - **Protected** needs a control on every path and answers that call it adequate and complete.
  - **Contradictions.** `not_applicable` with a request path present; `protected` with no control;
    `vulnerable` when every path is unresolved. Each is kept for audit and changes nothing.
  - `loader_unresolved`, an unknown version, a `restricted_types` capability and a stored origin
    without a resolved writer stay Review.
- **D-11. The finding names its impact.** `code_execution` formats report "code execution by
  format design". `object_injection` formats report "object injection: effect depends on the
  classes available" and list the in-repository classes that declare `__wakeup`, `__destruct`,
  `__toString` or `__call` as evidence, bounded to 20. Both are CWE-502 findings.
  **Why.** The weakness is deserializing untrusted bytes into objects. Stating code execution for
  PHP would claim an exploit the scanner did not show; withholding the finding would hide a
  serious defect. See OQ-1.
- **D-12. Practice findings without a model.** An unsafe YAML loader where the safe one would do,
  and any use of `node-serialize` or `funcster`, are poor practice whatever the origin, like the
  `notevil` rule. `pickle` and `unserialize` on non-request data make no practice finding: both
  are common for trusted internal data.
- **D-13. Reporting.** Records at one sink group under it, so VulnPy's adapter fan-out reads as
  four defects with their contexts.
- **D-14. Relation to the npm library RCE scan.** The container-root npm proposal treats
  deserialization as a vector label on code and pollution candidates and builds no deserialization
  analyzer for library mode. That stands. This family covers an application calling a
  deserializer whose source is not scanned (`node_modules`, `vendor`, the standard library), where
  only a contract can say what the call does. In library mode, `node-serialize`'s own `eval` is a
  code-family sink. Findings here carry the same `deserialization` vector label, so both reports
  use one vocabulary.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md). Build the policy against a stub
judge before any live call. Halt and ask when an existing family's fixture digest changes, when a
contract's capability cannot be backed by the library's own documentation, or when a row needs a
new input origin.

Contract texts cite the library reference: the Python `pickle` warning, the PyYAML
loader documentation, the PHP `unserialize` manual page, and the js-yaml 4 migration notes. Review
each at implementation and record the date.

## 7. Acceptance criteria

1. **AC1 (Python).** Fixtures: `pickle.loads(request.data)`, `pickle.load(io.BytesIO(x.encode()))`,
   an aliased import, `base64.b64decode` before the call, and `yaml.load(x, Loader=yaml.UnsafeLoader)`
   each yield `deserialization_candidate` with the request source, the contract and
   `code_execution`. `yaml.safe_load(x)`, `yaml.load(x, Loader=yaml.SafeLoader)` and `json.loads(x)`
   yield no record. A loader variable yields `loader_unresolved`.
2. **AC2 (PHP).** `unserialize($_COOKIE['p'])` and
   `unserialize(base64_decode(urldecode($_COOKIE['p'])))` yield candidates with `object_injection`.
   `['allowed_classes' => false]` yields none. A literal class list records the control. A fixture
   class with `__destruct` appears in the gadget evidence.
3. **AC3 (JS/TS).** `require('node-serialize').unserialize(req.body.x)` yields a candidate.
   `yaml.load(req.body.y)` yields one with js-yaml 3.x in the lockfile and none with 4.x.
   `yaml.safeLoad(…)` yields none. A missing lockfile yields Review with the version gap.
4. **AC4 (controls).** A dominating `hmac.compare_digest` check over the same bytes makes the path
   `guarded` with its contract attached. An unkeyed `hashlib.sha256` comparison is recorded as a
   guard whose contract says it is not integrity.
5. **AC5 (policy).** With a stub judge: a raw path plus `vulnerable` is Confirmed; `not_applicable`
   with a request path is rejected; `protected` without a control is rejected; a guarded path
   plus adequate, complete answers is Protected; an unresolved loader stays Review whatever the
   answers.
6. **AC6 (practice).** An unsafe YAML loader on a literal string is a practice finding and not a
   vulnerability. `pickle.loads` of a constant is no finding.
7. **AC7 (samples, offline).** VulnPy at its pin has witnessed candidates at
   `trigger/deserialization.py:8`, `:12`, `:17` and `:23`. `TS-DESER-N01` and `JS-DESER-N01` have no
   record. `VFA-DESER-01` has a candidate with an external-source witness, or the recorded
   limitation from OQ-2. Pins are clean before and after.
8. **AC8 (isolation).** `TestArchitectureBaseline` passes with new fixture rows only. The recall
   floor holds. `--only-family deserialization` and `--skip-family deserialization` work.
9. **AC9 (live).** After the owner's word: one judged VulnPy scan with
   `--only-family deserialization`, and one of the TypeScript app. The planned request count is
   stated from the offline planner first. Expected: four VulnPy sinks Confirmed and no control a
   finding. Results go to `deserialization-results.md`; the README table changes only from
   `accuracy.py` output.
10. **AC10 (docs and gate).** `docs/analysis/deserialization.md` states operations, capabilities,
    controls, exclusions and limits. The [contributor gate](../../docs/contributing.md#verification)
    passes.

## 8. Test strategy

- Table-driven adapter tests per language over small synthetic fixtures. Each vulnerable case has
  a safe sibling (safe loader, restricting option, constant operand) and an unresolved sibling
  (loader variable, unknown version, shadowed import).
- Stub-judge policy pairs for AC5.
- A selection test proves the family's contracts pass `analysispacks.Select` and that no other
  family's component digest moves.
- Samples verify through `check.py`. No fixture copies sample source, and nothing tests the §4
  exclusions.

## 9. Execution sequence

1. Add the key rows with their current failing status. Record the offline baseline.
2. **Red:** the AC1 `pickle.loads` fixture.
3. Facts, family registration, contracts and questions. Python operations and transfers (AC1).
4. Policy against the stub judge (AC5), then controls (AC4) and practice findings (AC6).
5. PHP `unserialize` (AC2). JS/TS with version facts (AC3).
6. Reporting, sink grouping and SARIF. Offline samples (AC7) and isolation (AC8).
7. Docs, gate, then the live runs on the owner's word (AC9, AC10). Draft PR.

```go
// DeserializationFacts records one verified deserializer call.
type DeserializationFacts struct {
	Operation  string        `json:"operation"`
	ContractID string        `json:"contract_id"`
	Capability string        `json:"capability"`       // code_execution | object_injection | restricted_types
	Option     string        `json:"option,omitempty"` // loader, schema or allowed_classes fact
	Version    string        `json:"version,omitempty"`
	Paths      []CommandPath `json:"paths"`
}
```

## 10. Definition of done

- [ ] OQ-1 to OQ-3 answered and logged.
- [ ] AC1–AC10 verified, with evidence in the run log.
- [ ] `git diff origin/stage --stat` matches §4.
- [ ] A fresh-context verifier reran two VulnPy rows and both controls.

## 11. Open questions

- **OQ-1. Object-injection status.** Should request-controlled PHP `unserialize` be a Confirmed
  CWE-502 finding with its impact stated as object injection (D-11), or a practice finding unless
  an in-repository gadget class exists? Recommendation: Confirmed, impact named.
- **OQ-2. Raw-socket bytes.** Model `socket.recv` as an external source so `VFA-DESER-01` gets a
  witness, or leave the row Review-expected with a recorded limit? Recommendation: leave it; one
  row does not justify a new origin.
- **OQ-3. Paid budget.** VulnPy will produce about 120 deserialization records before equivalent
  contexts share decisions. Is the standing live check enough, or does the owner want a cap?

## 12. Run log protocol

Use the plan's run-log rules. Record scanner SHA, sample pins and clean status, the contract
references with their review date, failing-first evidence, golden deltas, and live run identifiers
with planned and actual request counts.

## 13. Agent implementation prompt

> Work in the `unsafe-deserialization` sibling worktree cut from `origin/stage`. Read AGENTS.md, the
> orientation contents, this spec and the code-family files it cites. Ask OQ-1 to OQ-3 first.
> Execute §9 from the failing AC1 fixture. Keep samples read-only and offline until the owner
> authorizes AC9. Stop on any §6 halt. Finish with a draft PR into `stage` listing AC1–AC10 evidence.
> Verifier: a fresh-context subagent runs the three adapter test suites and `TestArchitectureBaseline`,
> reruns `VP-DESER-02` and `VP-DESER-03` offline, confirms `TS-DESER-N01` has no record, and checks
> that no other family's digest moved. It reports PASS or FAIL in the run log.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Requested by the owner after the Symfony review found an unlisted `unserialize` of a cookie. Written
from a search of every local sample for deserializer calls and from the `code` family's structure.
No code changed.
