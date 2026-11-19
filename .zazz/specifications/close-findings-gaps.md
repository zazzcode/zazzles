# Close findings gaps — Node.js Goof, DVWA and Python insecure app

- **Status** Implemented 2026-11-19 (W1–W8; W5 partial: PHP and Werkzeug upload writes). AC11 live check run and met. Results: [close-findings-gaps-results](../evaluation/close-findings-gaps-results.md).
- **Worktree and branch** `close-findings-gaps-dvwa`
- **Baseline** `stage` at `58e94e7` (PR #30, model-assisted evidence resolution)
- **Delivery** One draft PR into `stage`, one commit per workstream (§9). W5 and W6 may split into
  their own PRs (§11 OQ-1).
- **Run log** `.zazz/ephemeral/close-findings-gaps-run-log.md`
- **Related** [PHP Symfony support](php-symfony-support.md) reuses W3, W5 and W6 of this contract.

## 1. Capability

Turn the three keyed rows that still read Review in the [README accuracy table](../../README.md)
into findings or corrected key rows, and close the misses a source review of the same three samples
found outside the key. Each fix repairs a general mechanism. No rule names a sample, a file or an
identifier.

### Measured gaps

Measured on the published reports under `docs/samples/` (scanner `50d4a8f` and `df540c3`) and by
reading each sample at its [pin](../evaluation/recall-gap-inventory.md#corpus-and-pins).

| ID | Sample | Location | Today | First failing stage | Workstream |
|---|---|---|---|---|---|
| `GOOF-CMD-01` | Node.js Goof | `routes/index.js:174`, `exec('identify ' + url)` | Review, `command_guard_semantics_unknown` | Judge policy. The model answered `vulnerable` and `bypass_identified` (0.67) but chose `none` for the single offered chain | W1, W2 |
| `DVWA-API-CMD-01` (new) | DVWA | `vulnerabilities/api/src/HealthController.php:88`, `exec("ping -c 4 " . $target)` | No candidate | `call_binding`. `new HealthController(...)` in `api/public/index.php:82` names a class declared in another file, so the method body is never walked | W3 |
| `XSSS-001` | DVWA | Stored guestbook render at `dvwa/includes/dvwaPage.inc.php:388` | Practice finding only. Four records are not judged: `evidence_too_large`, 78–82 KB against the 64 KB limit | Request budget. 26 dependency paths with 38–57 transfers each | W4 |
| `DVWA-SIZE` (new) | DVWA | Three more render records (`bac` ×2, `sqli` ×1) | Not judged, 67–75 KB | Same | W4 |
| `UPLD-001` | DVWA | `vulnerabilities/upload/source/low.php:9` | Review, `path_answers_inconsistent` | `out_of_family`. `basename()` contains the path. The defect is an unrestricted file type (CWE-434), and no analyzer asks that question | W5, W7 |
| `PI-SSTI-NAME`, `PI-SSTI-REMOTE` (new) | Python insecure app | `app/main.py:41`, `Template(content).render()` | Reported as XSS only | `out_of_family`. Request text compiled as template source (CWE-1336) has no claim kind. This is the vulnerability the sample's author demonstrates | W6 |
| `PI-VAL-NAME` | Python insecure app | `app/main.py:19` | Review, not sent | Oracle. The [detection guide](../evaluation/python-insecure-app-detection-guide.md#current-family-expected-answers) expects Review unless a policy is supplied; the scorer counts the row as a required positive | W7 |
| `GOOF-CHAT` (new) | Node.js Goof | `app.js:66`–`68`, `routes.chat.get`, `.add`, `.delete` | Three entries with `unresolved_handler` | `registration`. The handler is a shorthand method on an exported object literal | W8 |
| `GOOF-REDIR-01` (new) | Node.js Goof | `routes/index.js:74`, `res.redirect(redirectPage)` | Confirmed, outside the key | None. A true positive that the key does not count | W7 |

The published Python insecure app XSS record already carries both witnesses (`name` and the remote
response body), so `PI-XSS-REMOTE` needs no work.

### Families these samples exercise that stay uncovered

Not in scope. Each needs its own contract, and a clean row there is not a pass.

| Sample | Uncovered defects (source location) |
|---|---|
| DVWA | CSRF (`csrf/source/low.php:3`, a state change on GET with no token); weak session identifiers (`weak_id/source/low.php:9`–`11`); missing authorization (`authbypass`, `bac`); weak cryptography (`cryptography/source`); login without rate limiting (`brute`); DOM XSS in an inline script inside a PHP heredoc (`xss_d/index.php:49`–`53`) |
| Node.js Goof | Prototype pollution (`routes/index.js:360`, `_.merge(message, req.body.message)`), [next up in the plan](../project/implementation-plan.md#next-up) and unblocked by W8; hardcoded session secret (`app.js:43`); vulnerable dependencies |
| Python insecure app | Hardcoded token (`app/config.py:15`); dependency advisories; request without a timeout (`app/main.py:31`) |

## 2. Required reading

- [Model-assisted evidence resolution](model-assisted-evidence-resolution.md) D-2, D-7 and D-8, and
  its [results](../evaluation/model-resolution-results.md#accuracy-against-the-answer-keys).
- [False positives and Review noise](accuracy-false-positive-noise.md) D-7 (guard contracts).
- [Request size and evidence relevance](../architecture/request-size-and-evidence-relevance.md),
  the [relevance-tier decision](evidence-relevance-tier.md#decision) and the
  [slicing deferral](data-path-slicing.md#measurement-and-decision). W4 meets their re-open condition.
- [PHP support contract](php-support.md) D-2 to D-7 and [PHP analysis](../../docs/php-support.md).
- Analysis rules: [command injection](../../docs/analysis/command-injection.md),
  [path traversal](../../docs/analysis/path-traversal.md),
  [code injection](../../docs/analysis/code-injection.md), [XSS](../../docs/analysis/xss.md),
  [calibration pairs](../../docs/analysis/calibration.md#regression-pairs).
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes)
  and [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates).
- [Recall inventory](../evaluation/recall-gap-inventory.md), `cases.json`, `check.py` and `accuracy.py`
  under `.zazz/evaluation/recall-gap-inventory/`.
- [DVWA guide](../evaluation/dvwa-detection-guide.md) and
  [Python insecure app guide](../evaluation/python-insecure-app-detection-guide.md).

## 3. Invariants

- A model answer never fills a missing fact. W1 binds a citation only to a chain the scanner
  already holds complete.
- Vulnerable needs a source-to-operation path with no unresolved gap on it. Protected needs a
  control on every path. Neither rule is relaxed.
- No detector reads a sample name, path or identifier. Answer keys stay out of detector logic and
  model requests.
- Recall floor: 91 `candidate_with_witness`, 30 `control_pass` and 4 `resolved` in
  [`check.py`](../evaluation/recall-gap-inventory/check.py) hold or grow. None of the 55 keyed
  controls becomes a finding.
- `TestArchitectureBaseline` changes only in rows each workstream lists before the golden is refreshed.
- Sample checkouts are read-only at their pins. Offline runs use no provider key.
- Paid calls follow [AGENTS.md](../../AGENTS.md#credentials-and-live-model-calls).

## 4. Scope and review shape

| Path | Change | Workstream |
|---|---|---|
| `internal/judge/command.go`, `resolution.go`, `resolution_test.go` | Modified | W1 implied single-path citation |
| `internal/analysispacks/guard_contracts.go`, `regex_capture.go` (new), tests | Modified, new | W2 capture-group facts and contract text |
| `internal/langjs/` command flow, `internal/langpy/`, `internal/langphp/guards.go` | Modified | W2 capture extraction recorded on the dependency |
| `internal/langphp/class_index.go` (new), `calls.go`, `flow.go`, `values.go`, `modules.go`, tests, `testdata/classes/` | New, modified | W3 class, method and property binding |
| `internal/judge/budget.go`, `schedule.go`, `bundle.go`, XSS policy, tests | Modified | W4 path-group requests |
| `internal/analysis` (facts, finding types), `internal/analysispacks/upload.go` (new), `internal/judge/upload.go` (new), `internal/langphp/path.go`, `internal/langjs`, `internal/langpy`, `internal/report` | New, modified | W5 `file_upload_candidate` |
| `internal/analysispacks/code.go`, `internal/judge/code_redirect.go`, `internal/langpy/templates.go`, `internal/langjs`, `internal/langphp/code_redirect.go` | Modified | W6 `template_injection_candidate` |
| `.zazz/evaluation/recall-gap-inventory/cases.json`, `protected-controls.json`, the DVWA and Python insecure app guides, `docs/samples/python-insecure-app/cases.json`, `.zazz/project/vulnerable-sample-apps.md` | Modified | W7 key corrections and new rows |
| `internal/langjs/` export and handler resolution, tests | Modified | W8 object-literal method handlers |
| `docs/analysis/{command-injection,path-traversal,code-injection}.md`, `docs/analysis/file-upload.md` (new), `docs/php-support.md`, `docs/detection-capabilities.md`, `README.md` accuracy table, `.zazz/project/implementation-plan.md` | Modified, new | Documentation per workstream |
| `.zazz/evaluation/close-findings-gaps-results.md` | New | Before and after measures |
| `cmd/scan/testdata/architecture-baseline.json` | Modified | Listed rows only |

Out of scope: the uncovered families in §1, Symfony entries and Twig
([own contract](php-symfony-support.md)), statement-level evidence slicing (S1), raising the 64 KB
limit, prompt wording changes outside the questions named here, and prototype pollution itself.

## 5. Decisions

### W1 — A bypass on a single guarded path cites itself

- **D-1.** In `applyCommandPolicy`, when the unsafe facet has exactly one request-derived path, that
  path is `guarded`, and its chain has no gap, a `bypass_identified` answer binds to that chain
  without a model citation. The resolution is recorded with `citation: implied_single_path`,
  `verified: true` and the scanner as verifier. Two or more guarded paths keep the D-8 citation
  requirement unchanged.
  **Why.** The citation question for one path offers that chain and `none`. Every verified answer
  is the same chain, so the question only measures whether the model picks a label. Goof scored
  0.44 for the chain against 0.56 for `none` while answering `vulnerable` at 0.80. The scanner
  holds the path; the model supplies the adequacy judgment, which is its role.
  **Rejected.** Rewording the citation instruction: tried on Goof and reverted (0.44 fell to 0.06).
  Dropping D-8: it still discriminates when several guarded paths exist.
- **D-2.** The single-path citation question is not sent. That saves the tokens and keeps the
  request digest stable for records whose facet has several paths.
- **D-3.** A follow-up for a language built-in is not asked. Goof's record asked for the body of
  `item.match`, which no snapshot can supply. When `needed_evidence` names a member the guard
  contract table already describes, the follow-up is recorded as `answered_by_contract`.

### W2 — Capture-group facts for regular-expression guards

- **D-4.** When the operand value is a capture group of a literal regular expression
  (`s.match(re)[n]`, `re.exec(s)[n]`, `preg_match(re, s, $m)` then `$m[n]`, Python
  `m.group(n)`), the adapter records a `regex_capture` transform on the dependency: the pattern,
  the group index and the group's sub-pattern.
- **D-5.** `regex_capture.go` classifies the sub-pattern over a small regex AST into
  `admits_any` (contains `.`, `\S`, `\W`, `\D`, or a negated class that excludes no shell
  metacharacter), `explicit_alphabet` (only literals and positive classes, with the accepted
  characters listed) or `unknown` (backreferences, lookaround, unsupported syntax).
  **Why.** The generic `regex_match` contract tells the model that a capture "holds only what the
  group's own sub-pattern allows" and leaves the sub-pattern for it to find. The scanner can state
  it. For Goof the fact is `(http.*)`: any character except a line terminator after `http`.
- **D-6.** The classification feeds the guard contract text and one deterministic rule. A path
  whose only controls are the match test and the capture of one expression classified
  `admits_any` is `raw` for the shell facet, with the capture kept as a transform. Any other
  control on the path keeps it `guarded`. `explicit_alphabet` and `unknown` stay `guarded` and model-judged.
  **Why.** A guard that provably passes `;`, `|`, `$(` and backticks constrains nothing the shell
  cares about, and a rule is replayable where a model answer is not. This is the "deterministic
  regex guard facts" row of the [phase 5 follow-ons](architecture-phase-5-accuracy-gaps.md#follow-on-accuracy-candidates-not-in-scope),
  applied in the direction that recovers a finding.
  **Bound.** Shell facet only. Executable and argument facets, and the path and SQL families,
  follow once this is measured.
- **D-7.** W1 and W2 are independent and both ship. W2 makes Goof deterministic. W1 covers guards
  W2 cannot classify.

### W3 — PHP class, method and property binding

- **D-8.** Index every class, interface, trait and enum declaration by its declared fully
  qualified name across the scan's modules. Resolve a name in a module through its `use` clauses
  (including aliases and group use), its namespace and leading-backslash names. A name with exactly
  one declaration resolves. Zero or several is `php_class_unresolved` with the reason.
  **Why.** The declared namespace in the file is exact source evidence and needs no Composer
  mapping. DVWA's API module has its own nested `composer.json`, which the root-only reader in
  `project_resolution.go` never sees. PSR-4 stays the tie-breaker for container references.
  **Rejected.** Basename or short-name matching: the
  [graph design](../architecture/repository-graph.md) forbids similarity as a binding rule.
- **D-9.** `new C(args)` binds the object to its class across modules and expands `__construct`
  through the existing bounded helper. `$obj->m()`, `$this->m()`, `self::m()`, `static::m()` and
  `parent::m()` resolve through the class, then its in-repository `extends` chain and `use`d
  traits, to depth 4. A parent outside the repository leaves a gap only when the method is not
  found before it.
- **D-10.** Objects carry a property map. `$this->p = v` and promoted constructor parameters write
  it; `$this->p` and `$obj->p` read it. A write through an unresolved alias or a dynamic property
  name marks the map unknown.
  **Why.** `HealthController` selects its method from `$this->command`, set in the constructor
  from a URL segment. Without property state the `switch` cannot narrow, and every Symfony service
  call goes through a promoted property.
- **D-11.** Visibility does not block resolution inside a class. Existing bounds hold: helper depth
  4, 256 calls per entry, cycle guard. `property_promotion_parameter` and typed parameters bind
  like simple parameters.
- **D-12.** A file whose top-level scope only declares symbols stays an entry with no uses in
  plain PHP. Demoting such files is a framework decision owned by the
  [Symfony contract](php-symfony-support.md).

### W4 — Judge a record that is over the request limit

- **D-13.** Measure first. Build all seven DVWA requests offline with the digest inventory and
  record bytes by section and by dependency group.
- **D-14.** Preferred design: **path-group requests.** A record whose mandatory evidence exceeds
  the limit is sent as several ordinary requests for the same claim. Each carries the dependency
  paths of one group and lists the withheld sibling paths as an explicit omission. The group key is
  structural: the dispatch alternative of the dependency's source (for DVWA, the security-level
  file), then the storage key, used only when a file group alone is over the limit. Whole groups are packed into one request while it still fits (first fit, key order); a packed request carries every path of the groups it holds, so it stays lossless. Policy combines the groups: Confirmed when any group holds a
  complete raw witness with consistent answers, scoped to that path as today; Protected only when
  every group is Protected; otherwise Review. A group still over the limit keeps
  `evidence_too_large`.
  **Why.** Each request stays lossless for the paths it carries, and the combination rule is the
  existing per-path rule (`A raw witness is scoped to its own source-to-operand path`). S1 slicing
  is lossy and needs a paid ablation.
- **D-15.** Bounds: at most 4 groups per record, counted against `--judge-limit` and reported.
  Records under the limit are unchanged, so their digests and replays hold. Each group request has
  its own digest, replays alone, and shares a decision only with an equivalent group.
- **D-16.** Fallback if D-13 shows the shared page-shell excerpts dominate every group: re-open S2
  (relevance filter for helper excerpts on no dependency chain) under the
  [ablation protocol](../architecture/request-size-and-evidence-relevance.md#ablation-protocol-for-lossy-changes).
  Seven records over the hard limit meet the recorded re-open condition.
- **D-17.** XSS family first. Other families adopt path groups when a record of theirs exceeds
  the limit.

### W5 — Unrestricted file upload (CWE-434)

- **D-18.** New claim kind `file_upload_candidate` in a new `upload` family, with its own facts,
  questions and policy. It coexists with the path claim at the same call, as the code and
  filesystem claims coexist at `view_help.php`.
  **Why.** Path containment and file-type restriction are different questions. DVWA low is
  Protected for the first and vulnerable for the second, which produced `path_answers_inconsistent`.
- **D-19.** Verified operations: PHP `move_uploaded_file` and Symfony `UploadedFile::move`; Node
  `express-fileupload` `mv` and `multer` disk storage filenames; Python Flask or Werkzeug `save`
  and Starlette `UploadFile` writes.
- **D-20.** Facts, all source-backed:
  - `stored_name`: `client`, `client_basename`, `server_generated` or `mixed`, with the extension
    origin stated separately (`client`, `fixed`, `allow_listed`, `content_derived`).
  - `type_controls`: each control with its kind. `client_declared_type` (`$_FILES[...]['type']`,
    `getClientMimeType()`, `file.mimetype`) is recorded as client-controlled. `extension_allow_list`,
    `content_sniff` (`getimagesize`, `finfo`, `guessExtension()`) and `re_encode` are controls.
  - `destination_served`: `yes` when the directory is under a source-established document root,
    `no`, or `unknown`.
- **D-21.** Outcomes. A client-derived extension with no server-side type control is a practice
  finding without a model, like SQL construction. Confirmed also needs `destination_served: yes`
  and consistent answers. A client-declared type as the only control is judged, with the contract
  stating that the client supplies it. Unknown destination stays Review.
- **D-22.** DVWA expectations: low Confirmed; medium Confirmed (client type only); high Review
  (extension allow-list and `getimagesize`; the known bypass needs the include flaw); impossible
  Protected (generated name and re-encode).

### W6 — Server-side template injection (CWE-1336)

- **D-23.** New claim kind `template_injection_candidate` in the existing `code` family. The
  operand is the template source of a verified engine API, in a `template_engine` execution
  context. Request data passed only as render variables creates no claim.
  **Why.** The code family already models "request text reaches an interpreter's code operand",
  and already excludes data passed in a context object. A template compiler is such an interpreter.
- **D-24.** Verified operations: Python `jinja2.Template(src)`, `Environment.from_string(src)`,
  Flask `render_template_string(src)`, Mako `Template(src)`; PHP Twig `createTemplate(src)` and
  `template_from_string(src)`; Node `ejs.render`, `Handlebars.compile`, `pug.render` and `compile`,
  `nunjucks.renderString`, lodash `template`.
- **D-25.** A sandboxed environment is a recorded control and never Protected by itself. A constant
  template source is the protected sibling. These are contracts on an application's call into an
  engine. What happens inside the
  engine (options reaching generated JavaScript) is the compile-to-JS work of the npm library
  scan (§11 OQ-5) and is not modeled here.
- **D-26.** The SSTI and XSS records at one construction site link through `related_uses` and
  stay separate findings. The report groups them under one root construction.

### W7 — Answer-key corrections

- **D-27.** Keys change only with source evidence, and the old label stays in the guide's
  corrections.
  - `UPLD-001` becomes `file_upload_candidate`, positive. A control row records that the path
    claim at `low.php:9` must not be a finding.
  - `PI-VAL-NAME` becomes `review`-expected, matching its guide.
  - New positives: `DVWA-API-CMD-01`, `PI-SSTI-NAME`, `PI-SSTI-REMOTE`, `GOOF-REDIR-01`.
  - `XSSS-001` gains `expect_status: confirmed`, so a construction-practice finding no longer
    satisfies a stored-XSS row.
  - New controls: DVWA upload impossible level; a constant-source template pair.
- **D-28.** New rows are tagged `post_delivery`. Recall is still reported for both tags.

### W8 — Object-literal method handlers

- **D-29.** A handler reference `ns.obj.method`, where `obj` is an exported object literal and
  `method` is a shorthand method, a function-valued property or an arrow function, resolves to that
  callable. A computed key, spread or reassigned export stays `unresolved_handler`.
  **Why.** Three Goof entries are unresolved today, and prototype pollution needs them.

## 6. Agent implementation rules

Follow the [common rules](architecture-update-plan.md#common-agent-implementation-rules) and
[execution discipline](../docs/agent-execution-discipline.md). In addition:

- Start every workstream with a failing fixture test. Sample scans verify; they never drive design.
- Post the W4 measurement (D-13) and the chosen design before writing W4 code.
- Halt and ask when a workstream moves a keyed control toward a finding, when an unlisted golden
  row changes, or when W3 changes a DVWA keyed outcome.
- W5 and W6 add protocol versions. Build each against a stub judge before any live call.

## 7. Acceptance criteria

1. **AC1 (W1).** With a stub judge, a command record with one guarded shell path and answers
   `vulnerable` plus `bypass_identified` is Confirmed with an `implied_single_path` resolution and
   no citation question in its request. The same record with two guarded paths and no citation
   stays Review on `command_guard_semantics_unknown`. `no_bypass` still yields
   `command_answers_inconsistent`.
2. **AC2 (W2).** `go test ./internal/analysispacks -run '^TestRegexCaptureClass$'` classifies
   `(http.*)` as `admits_any`, `([a-z0-9.-]+)` as `explicit_alphabet` with its alphabet, and a
   lookbehind pattern as `unknown`. A JS fixture with `exec('identify ' + s.match(re)[1])` yields a
   `raw` shell path with a `regex_capture` transform for the first pattern and a `guarded` path for
   the second. PHP `preg_match` and Python `group` fixtures behave the same.
3. **AC3 (W3).** A fixture with `index.php` doing `use Src\C; $c = new C($_SERVER['REQUEST_METHOD'], $seg); $c->run();`
   and `src/C.php` holding a private method that passes `php://input` JSON to `exec` yields one
   `command_execution_candidate` at that `exec` with the body source in its dependencies. Sibling
   fixtures: two declarations of one name yield `php_class_unresolved` and no candidate; a method
   selected by `switch ($this->cmd)` is reached only on its case; an `escapeshellarg` sibling
   records the control.
4. **AC4 (W3, sample).** An offline DVWA scan at `a1978a2` has a witnessed candidate at
   `vulnerabilities/api/src/HealthController.php:88` under entry `vulnerabilities/api/public/index.php`.
   `TestDVWASourceKey` passes, extended with this row.
5. **AC5 (W4).** The offline request planner reports zero `evidence_too_large` records on DVWA, or
   lists each remaining record with its smallest group size. Every group request is under 65,536
   bytes and names its omitted paths. A stub test proves the combination rule: one Confirmed group
   yields Confirmed; all Protected yields Protected; a mix of Protected and unknown yields Review.
6. **AC6 (W5).** Fixtures for each D-19 operation produce `file_upload_candidate` with the D-20
   facts. Paired cases: client extension with no control (practice finding offline); client type
   check only (candidate, judged); extension allow-list (guarded); generated name (protected
   facts). A destination outside the document root is `destination_served: no`.
7. **AC7 (W6).** `Template(f"<h1>{name}</h1>").render()` yields `template_injection_candidate` with
   the request source and a linked `xss_candidate`. `Template("<h1>{{ name }}</h1>").render(name=name)`
   yields no template-injection record. Twig `createTemplate($src)` and `ejs.render(src)` fixtures
   pair the same way.
8. **AC8 (W7).** `check.py` and `accuracy.py` run over the refreshed reports. Every §1 row has its
   new expectation, and the guides record each correction with its source evidence.
9. **AC9 (W8).** A fixture with `exports.chat = { get(req, res) {…}, add: function (req, res) {…} }`
   and `app.get('/chat', routes.chat.get)` yields resolved entries. A computed-key sibling stays
   `unresolved_handler`. Goof offline has no `unresolved_handler` on `/chat`.
10. **AC10 (floor).** The §3 recall floor holds on all eleven samples offline. `TestArchitectureBaseline`
    passes with only listed deltas. No keyed control is a finding.
11. **AC11 (live).** One judged scan each of Node.js Goof, DVWA and Python insecure app under the
    AGENTS.md standing terms, after the owner's word (§11 OQ-2). Expected: `GOOF-CMD-01` Confirmed;
    `DVWA-API-CMD-01` Confirmed; `XSSS-001` Confirmed as stored XSS; `UPLD-001` Confirmed as
    unrestricted upload with its path claim not a finding; `PI-SSTI-NAME` Confirmed. Results and
    every status that differs go into `close-findings-gaps-results.md`, and the README table is
    updated from `accuracy.py` output only.
12. **AC12 (docs and gate).** The analysis guides and capability list describe each new fact,
    claim and limit. The [contributor gate](../../docs/contributing.md#verification) and
    [doc-check](../../.agents/skills/doc-check/SKILL.md) pass.

Target accuracy rows after AC11:

| Sample | Expected | Found | Review | Change |
|---|---:|---:|---:|---|
| Node.js Goof | 7 | 7 | 0 | Command Confirmed; open redirect keyed |
| DVWA | 11 | 11 | 0 | API command added; upload re-keyed; stored XSS Confirmed, not practice |
| Python insecure app | 3 | 3 | 0 | Two SSTI rows added; validation row is Review-expected |

## 8. Test strategy

- **Policy pairs (W1, W4, W5, W6).** Stub-judge table tests. Each changed case sits beside the
  neighbour that must not change.
- **Adapter fixtures (W2, W3, W8).** Small synthetic repositories under each adapter's `testdata/`,
  with vulnerable, safe and unresolved siblings. Expected anchors are hand-computed in the test.
- **Classifier unit test (W2).** A pattern table including PCRE, ECMAScript and Python syntax
  differences.
- **Samples.** Offline scans verify the §1 rows through `check.py`. Sample reports stay outside
  the worktree.
- No test asserts model wording, and no fixture copies sample source.

## 9. Execution sequence

Ordered by findings recovered per unit of risk. Each step is one commit.

1. **W7a.** Add the new and corrected key rows with their current (failing) status, so every later
   step shows a measured delta.
2. **W1.** Policy change and stub tests.
3. **W2.** Classifier, then adapter capture facts, then contract text.
4. **W3.** Class index, then object binding and methods, then properties. The largest step and the
   shared prerequisite of the Symfony contract.
5. **W4.** Measurement checkpoint, then path-group requests.
6. **W8.** Handler resolution.
7. **W5**, then **W6.** New claim kinds, stub judge first.
8. **W7b and AC11.** Offline floor, live runs, results document, README table.

## 10. Definition of done

- [x] AC1–AC12 verified, with evidence in the run log. AC6 is met for PHP `move_uploaded_file` and
  Werkzeug `save`; the Node, Starlette and Symfony upload adapters remain (change log, 2026-11-19).
- [x] Every §1 row is closed: all are Confirmed live or re-keyed
  ([results](../evaluation/close-findings-gaps-results.md#live-check-ac11)).
- [x] `git diff origin/stage --stat` matches §4. The verifier accepted the files outside the table
  (new adapters `langphp/upload.go`, `langpy/upload.go`, `parse/upload_claims.go`,
  `parse/regex_capture.go`; judge `client.go`/`trace.go` for path groups) as part of their workstreams.
- [x] A fresh-context verifier reran GOOF-CMD-01 and DVWA-API-CMD-01, their safe siblings, and
  PC-CMD-02 and PC-XSS-01, and compared the golden diff: PASS.

## 11. Open questions

- **OQ-1.** Do W5 and W6 ship in this PR or as two follow-up PRs? They add claim kinds, finding
  types and protocol versions, which is more review than the other workstreams together.
  Recommendation: same branch, separate PRs stacked on W1–W4.
- **OQ-2.** Is the standing live check enough for AC11 (three scans, about 190 requests plus the W4
  group requests on DVWA), or does the owner want a cap?
- **OQ-3.** Should `GOOF-REDIR-01` and the other reviewed out-of-key findings become keyed rows
  now, or wait for a full review of the 490 findings outside the key?
- **OQ-4.** W3 will add records in DVWA files that hold classes. Is a larger "findings outside the
  key" count acceptable before those are source-reviewed?
- **OQ-5.** The container-root npm library RCE proposal adds compile-to-JS sinks for the same
  engines W6 names. W6 covers the application side only. Confirm that split, so neither contract
  models the other's half.

## 12. Run log protocol

Use the plan's run-log rules. Record scanner SHA, toolchain, sample pins and clean status before
and after, the W4 measurement table, each workstream's failing-first evidence, golden deltas, live
run identifiers and request counts.

## 13. Agent implementation prompt

> Work in the `close-findings-gaps-dvwa` sibling worktree on its branch. Read AGENTS.md, the
> orientation contents, this spec and its required reading. Execute §9 in order, one commit per
> workstream, each starting from a failing test. Keep samples read-only and offline until the owner
> authorizes AC11. Post the W4 measurement before writing W4 code. Stop on any §6 halt. Finish with a
> draft PR into `stage` that lists AC1–AC12 evidence. Verifier: a fresh-context subagent reruns
> `GOOF-CMD-01` and `DVWA-API-CMD-01` offline, checks their safe siblings, spot-checks two unrelated
> controls, and compares the golden diff with §4. It reports PASS or FAIL in the run log.

## 14. Implementation and review change log

### 2026-11-19 — Drafted

Written from the published sample reports, a source review of the three samples at their pins, and
the judge and PHP adapter code at `58e94e7`. An offline scan of DVWA's API module confirmed that
`HealthController.php:88` has no candidate. No code changed.

### 2026-11-19 — Implementation deviations (pending owner sign-off)

**Source.** Implementation-discovered, recorded by the implementing agent.

**Changed Sections.** §5 W4 (D-14), W5 (D-19), W6 (D-24); §7 AC6.

**Rationale.** Measured DVWA path groups each cost 51–60 KB, so without packing two `sqli` levels fell
past the 4-group cap. Node, Starlette and Symfony upload adapters did not fit this delivery.

**Summary.** W4 packs whole structural groups into one request while it fits; D-14 now states this. W6 now also recognises `Environment.from_string` (follow-up). W5 ships PHP
`move_uploaded_file` and Werkzeug `FileStorage.save`; the other D-19 operations have registered
contracts only.
**Verification Impact.** AC6 is met for PHP and Werkzeug only; AC11 is not run.
