# PHP support (DVWA MVP) — implementation contract

**Worktree / branch:** `php-dvwa`
**Feature:** plain-PHP language adapter and core analyzer-family bindings
**Milestone:** first PHP support; Drupal/Symfony framework adapters are a separate future deliverable
**Project Owner / Deliverable Owner:** requesting human user
**Delivery topology:** single deliverable, one branch and one reviewable draft PR into `stage`
**Coordination:** Lead Agent working alone; local run log only
**Run log:** `.zazz/ephemeral/php-support-run-log.md`
**Sample:** DVWA, [zazzcode/DVWA](https://github.com/zazzcode/DVWA) fork of digininja/DVWA, pinned
`a1978a2` (master, clean tree verified 2026-11-16), local checkout `<DEV_ROOT>/zazzcode/DVWA`
**Drafted:** 2026-11-16

## 1. Capability

Add PHP as a scanned target language through a bounded `php_*` adapter that mirrors the Python
adapter's modular pattern, feeding the shared language-neutral engine: server-mapped file entries,
include-composed scopes, superglobal acquisition facts, and the core analyzer families — SQL
injection, command injection, XSS (reflected and stored), path traversal (filesystem, upload and
include operands), code injection, open redirect, and standalone input validation — through the
existing packs, judge, evidence-validation and JSON/HTML/SARIF pipeline with no report forks.
Evaluate offline against synthetic fixtures and the pinned DVWA checkout, then with one bounded
paid decision-model pass. Other agents work in sibling worktrees; this deliverable is independent
because it adds a new language without changing JS/TS/Python behavior.

## 2. Required reading

- [Orientation: working protocol](../docs/zazzles-agent-orientation.md#working-protocol),
  [available samples](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps).
- [Execution discipline: verification](../docs/agent-execution-discipline.md#verification-discipline),
  [contributor verification](../../docs/contributing.md#verification).
- [Capability checklist](../project/implementation-plan.md#supported-capability-checklist).
- [Architecture: parsing and language adapters](../architecture/README.md#3-parsing-and-language-adapters),
  [acquisition and value facts](../architecture/README.md#acquisition-and-value-facts),
  [package boundaries](../architecture/README.md#11-implemented-package-boundaries).
- [Analysis packs: boundary and ownership](../architecture/analysis-packs.md#boundary-and-ownership),
  [descriptor and selection contract](../architecture/analysis-packs.md#descriptor-and-selection-contract).
- [Evidence and claims](../architecture/evidence-and-claims.md),
  [trace judgment](../architecture/trace-judgment.md).
- Language-adapter precedent: [Python support](python-support.md); shared input pattern:
  [Python input refactor](python-input-refactor.md) §5 decisions.
- Product analysis guides for the bound families:
  [database injection](../../docs/analysis/database-injection.md),
  [command injection](../../docs/analysis/command-injection.md),
  [XSS](../../docs/analysis/xss.md),
  [path traversal](../../docs/analysis/path-traversal.md),
  [code injection](../../docs/analysis/code-injection.md),
  [open redirect](../../docs/analysis/open-redirect.md),
  [input validation](../../docs/analysis/input-validation.md),
  [calibration](../../docs/analysis/calibration.md).
- [Sample reference policy](../../docs/samples/reference-policy.md).
- Standards via the [index](../standards/index.yaml): [code structure](../standards/code-structure.md),
  [testing](../standards/testing.md), [spec hygiene](../standards/spec-hygiene.md),
  [docs hygiene](../standards/docs-hygiene.md), [PR process](../standards/pr-process.md).
- Existing code to mirror: `internal/parse/python_modules.go`, `python_flow.go`, `python_calls.go`,
  `python_command.go` (sink-table pattern), `python_sql.go`, `python_input_facts.go`;
  `internal/analysis/analysis.go`, `entries.go`, `input_facts.go`;
  `internal/analysispacks/families.go`, `select.go`, `descriptors.go`, `contracts.go`;
  `internal/lang/lang.go`; `internal/parse/analysis.go` (language dispatch);
  `cmd/scan/python_test.go` (CLI test pattern).

## 3. Invariants

- DVWA stays read-only at `a1978a2`: no fixes, formatting, dependency installation, output inside
  the tree; verify clean status before/after every evaluation. Analysis never executes target code.
- Expected labels and the DVWA detection guide stay outside model inputs; no target-name or
  module-name detector exceptions.
- Unknown bindings, guards, includes and renderer behavior MUST NOT become protection or proven
  paths; a guard in one security-level include alternative never protects a sibling alternative.
- Existing JS/TS/Python candidate identity, request bytes, saved reports and answers stay
  unchanged; changed PHP question/guideline text carries new versions and rejects stale replay.
- NoSQL stays JS/TS-only; PHP SSRF/outbound observations, PHP logging and client/DOM XSS for PHP
  pages remain outside this deliverable (existing standalone-`.js` browser analysis is unchanged).
- Only the selected provider's key reaches the scanner child; paid calls require explicit
  `--judge`, use `gpt-6-luna` with no fallback, respect the 300-request cap, and record cumulative
  usage; offline tests use no live calls.
- No integration push or merge; one draft PR into `stage` at closeout; human review owns merge.

## 4. Scope and review shape

One branch keeps the language adapter, family bindings, fixtures, DVWA evidence and docs
reviewable together. All product edits stay in this worktree; raw run artifacts go to
`_test-findings/dvwa/<run>/` outside the worktree and sample trees.

| Path | Change | Purpose |
| --- | --- | --- |
| `go.mod`, `go.sum` | modified | pin `tree-sitter-php` (v0.23.x line, `go-tree-sitter v0.24.0`-compatible) |
| `internal/lang/lang.go`, `lang_test.go` | modified | `PHP` language constant; `.php`/`.phtml` extensions |
| `internal/langphp/modules.go` (was `internal/parse/php_modules.go`) | new | `phpSet`/`phpModule`, grammar wiring, include resolution, `report()` |
| `internal/langphp/entries.go` | new | server-mapped HTTP entries; conditional include dispatch alternatives |
| `internal/langphp/flow.go` | new | bounded value/control flow, superglobals, interpolation, HTML accumulation |
| `internal/langphp/calls.go` | new | call dispatch to family models |
| `internal/langphp/sql.go`, `command.go`, `path.go` | new | SQL/command/path sink tables and claims; SQL storage keys |
| `internal/langphp/xss.go`, `code_redirect.go` | new | reflected/stored XSS rendering model; eval and `header()` redirect claims |
| `internal/langphp/input_facts.go` | new | superglobal origin mapping; `source.php-input-v1` fact assembly |
| `internal/parse/analysis.go`, `internal/pipeline/pipeline.go`, `routes.go` | modified | PHP runner selection and merge for `--routes` (`pipeline.Routes`) and analysis; entry-file error strings |
| `internal/langphp/testdata/**` | new | per-family fixtures and a trimmed DVWA-shaped module fixture |
| `internal/langphp/*_test.go`, `cmd/scan/php_test.go` | new | per-family and CLI regression tests |
| `internal/analysispacks/families.go`, `select.go`, `descriptors.go`, `contracts.go`, `command.go`, `path.go`, `*_test.go` | modified | PHP family language lists, `php-*` contracts, `source.php-input-v1` selection |
| `internal/guidelines/php.md` (+ per-family `*_php.md` sections) | new | versioned PHP Analysis Guidelines consumed by `FamilyBody` |
| `cmd/scan/main.go` | modified | `--entry` help text covers PHP |
| `internal/analysis/`, `internal/report/`, `internal/judge/` | modified only if necessary | language-neutral reuse; no report forks |
| `docs/analysis/` family guides | modified | document the PHP bindings and bounds for the bound families |
| `.zazz/specifications/php-support.md`, `.zazz/specifications/README.md` | new/modified | this contract and index entry |
| `.zazz/project/implementation-plan.md`, `.zazz/project/vulnerable-sample-apps.md` | modified | PHP status; DVWA catalog row with pin and detection-guide link |
| `.zazz/evaluation/php-support-results.md`, `.zazz/evaluation/dvwa-detection-guide.md` | new | durable acceptance evidence and source-reviewed expectations |
| `docs/php-support.md`, `docs/samples/dvwa/**`, `docs/samples/README.md`, `README.md` | new/modified | user-facing coverage doc; published DVWA reports at paid closeout |
| `.zazz/ephemeral/php-support-run-log.md` | ignored | append-only execution record |

Paths reflect [architecture phase 3A](architecture-phase-3-php-package.md): the adapter moved from
`internal/parse/php_*.go` to `internal/langphp` (prefix dropped) and uses `parse`'s language core API.

Out of scope: Drupal, Symfony, Laravel, Twig or any framework adapter; composer/vendor dependency
resolution; NoSQL; SSRF/outbound and logging families for PHP; client/DOM XSS inside PHP-emitted
inline scripts (`xss_d` stays Not covered); PHP 8-only attribute/enum semantics; whole-program
class-hierarchy analysis; deployment/runtime claims; edits to other worktrees.

## 5. Decisions

### D-1 — Tree-sitter PHP grammar

Pin `github.com/tree-sitter/tree-sitter-php` from the v0.23.x generation and load it via its
`bindings/go` through the existing `openParser` helper, exactly like the Python grammar.
**Why:** keeps one parser stack (cgo tree-sitter) ABI-compatible with `go-tree-sitter v0.24.0`;
a separate PHP parser library would fork the parsing architecture. If no compatible tagged Go
binding exists, halt and surface the version evidence rather than vendoring C sources by hand.

### D-2 — Server-mapped file entries

Every `.php` file under the scan root is a potential HTTP entry with the normalized repository
path as HTTP path metadata and no method restriction; `include`/`require` never creates an entry.
**Why:** plain PHP has no router — web servers map URLs to files, and direct access to included
files is a real exposure; DVWA's `view_help.php`/`source/*.php` are directly requestable.
**Rejected:** treating only `index.php` files as entries — silently drops most DVWA surfaces.

### D-3 — Include composition with conditional dispatch alternatives

Static `include`/`require`(_once) of a literal path joins the included file's top-level scope
into the includer's flow as bounded inlined analysis. A variable path whose assignments are
constrained to a finite literal set (DVWA's security-level `switch`) resolves to dispatch
alternatives — one invocation context per candidate file, each carrying its selecting condition
(`dvwaSecurityLevelGet() == 'low'` etc.) as an invocation control. Unresolvable dynamic includes
record a `php_dynamic_include` gap and no edge.
**Why:** DVWA's taint and sinks are split across `index.php` + `source/{low,…}.php` files joined
by a switch-constrained `require_once`; the common dispatch-alternative model keeps impossible-level
controls from protecting low-level siblings. **Rejected:** analyzing `source/*.php` only as
standalone entries — loses the cross-file `$file`/`$html` flows that carry the vulnerability.

### D-4 — Superglobal acquisition facts (`source.php-input-v1`)

`$_GET`→`http.query`, `$_POST`→`http.form`, `$_REQUEST`→`http.query_or_form`,
`$_COOKIE`→`http.cookie`, `$_FILES`→`http.upload`, selected `$_SERVER` keys→header/host facts,
`file_get_contents('php://input')`→`http.body`. `$_SESSION` is a storage container keyed
`php-session:<key>` that links prior writes as transfers, not an untrusted origin — preserving
DVWA's `session-input.php` → `sqli/source/high.php` flow without overclaiming trust.
**Why:** mirrors `source.python-input-v1`'s origin vocabulary so family selection and the judge
reuse the same interpretation boundary. **Rejected:** treating `$_SESSION` as a request origin —
it would mark server-side values attacker-controlled with no evidence.

### D-5 — SQL contracts per engine

`php-mysqli-v1` (procedural `mysqli_query`/`mysqli_real_escape_string` and OO `->query`, with the
`$GLOBALS["___mysqli_ston"]` converter idiom normalized to the verified connection handle),
`php-pdo-v1` (`query`/`exec`/`prepare`+`bindParam` as the binding control), `php-sqlite3-v1`
(`SQLite3::query/exec`). `mysqli_real_escape_string`, `intval`, `is_numeric` are recorded value
transforms/guards, never protection verdicts. Fake/shadowed functions (a locally defined
`mysqli_query`) do not become sinks.
**Why:** per-engine contracts mirror `python-<driver>-dbapi-v1` because prepared-statement
semantics differ between mysqli and PDO. **Rejected:** one generic `php-sql-v1` — would lose the
engine-specific binding evidence the SQL claim needs.

### D-6 — Command family

One `php-program-execution-v1` contract covering `system`, `exec`, `shell_exec`, `passthru`,
`popen`, `proc_open` and the backtick operator, with shell-string semantics (as `os.system`);
`escapeshellarg`/`escapeshellcmd` are argument-quoting controls. DVWA `exec` module is the witness.
**Why:** these built-ins share one claim shape (a shell command string operand); **rejected:**
per-function contracts that add no claim-level distinction.

### D-7 — XSS rendering model

PHP output is modeled as HTML string values: interpolations/concatenations accumulating into
HTML-valued variables (`$html`, `$page['body']`, `$html .= …`) ending in a terminal `echo`/`print`;
`htmlspecialchars` (with its actual flags recorded) is the escape transform; unescaped
request-derived HTML values produce reflected claims. Stored claims link SQL reads to writes via
`php-sql:<table>.<field>` storage keys (guestbook `INSERT` → `SELECT` → output).
**Why:** DVWA renders by string concatenation with no template engine; this is the PHP equivalent
of the Jinja/Flask rendering model. **Rejected:** waiting for a template-engine adapter — no DVWA
evidence would exist.

### D-8 — Include as a path-family operand

`include`/`require` with a request-derived operand is a `path_traversal_candidate` under
`php-include-v1`, with a `file_inclusion` execution-context fact and scheme classification on the
path facts (local vs remote destination); `move_uploaded_file` is `php-upload-move-v1` (DVWA
`upload`), and `fopen`/`file_get_contents`/`readfile`/`file`/`file_put_contents`/`unlink` are
`php-filesystem-v1` (witnesses: `view_help.php`, `view_source.php`, `instructions.php` whitelist
control). `basename`/`realpath`/`is_uploaded_file` are component transforms/guards.
**Why:** the claim is control of a file-path operand — the existing path family's question — and
CWE-98 attribution stays on the path record's facts. **Rejected:** modeling include as a
code-family claim — the `code` family's contract is interpreter string operands (`eval`), and the
destination is a path, not source text.

### D-9 — Redirect via `header()`

`header('Location: <dest>')` selects `php-header-redirect-v1`; PHP's documented behavior makes a
Location header an implied 302 redirect, so no separate status statement is required. Only the
destination operand is the claim; fixed literals and query-only changes produce no claim.
**Why:** requiring explicit `http_response_code` evidence would miss the canonical PHP redirect.
**Rejected:** modeling bare `header()` calls generally — non-Location headers are not redirects.

### D-10 — Code injection

`php-eval-v1` covers `eval` (DVWA `view_help.php`), string-form `assert` (PHP<8 semantics recorded
as a fact), and `create_function` (removed in PHP 8; poor practice when bound).
**Why:** these are the PHP interpreter-string operands matching the existing `code` family;
module-loading is deliberately excluded (D-8 owns the file-operand claim).

### D-11 — Guidelines and catalog identities

Add versioned `php.md` plus per-family PHP sections so `FamilyBody` resolves; component identities
follow the existing scheme (`language.php`, `language.<family>.php`, `source.php-input-v1`,
`api.<php-contract>`); families register PHP in `Languages` with an HTTP-entry restriction
mirroring `PythonHTTPOnly`.
**Why:** the catalog derives identities uniformly; inventing a PHP-specific scheme would fork
selection and provenance.

### D-12 — Mixed repositories

Whole-repository scans merge PHP entries/uses with existing JS/TS results; DVWA's standalone
`.js` files keep their current browser treatment unchanged.
**Why:** PHP apps are commonly mixed; the merge seam already exists for Python.

## 6. Agent implementation rules

Work from the checkout containing `go.mod` on `php-dvwa`; verify path/branch/status and the
`stage` diff before edits. Use the declared native Go toolchain with `GOTOOLCHAIN=local`, a C
compiler for cgo, and an isolated writable `GOCACHE` under `.zazz/ephemeral/`. Downloads are
authorized only for the pinned PHP grammar and its dependencies. Format only changed Go files.
Follow `spec-driven` during execution and `doc-check` for modified documents. Preserve unrelated
user changes; never touch sibling worktrees. Commit coherent green work after verifying zazzcode
identity/authentication; push the feature branch at completion and open one draft PR into `stage`.
Keep the append-only run log. Stop and surface when: the same test fails 3 iterations; the diff
leaves §4 scope; the grammar is ABI-incompatible (D-1); DVWA is dirty at a non-`a1978a2` revision;
provider/account exhaustion or destructive recovery looms; or implementation surfaces a contract
change (update this spec in place and record it in §13 first).

## 7. Acceptance criteria

1. `.php`/`.phtml` are detected as PHP; `--list` reports PHP counts; mixed JS/TS+PHP fixtures
   inventory both. Verified by `internal/lang`/`internal/walk` table tests and `TestPHPCLI`.
2. Server-mapped HTTP entries exist for every fixture `.php` file with deterministic identity and
   normalized path metadata; `--routes` lists PHP entries. Verified by `TestPHPRoutes` golden.
3. Switch-constrained `require_once` resolves to conditional dispatch alternatives; cross-file
   taint reaches includer sinks; unresolvable dynamic includes yield `php_dynamic_include` gaps
   and no invented edges; impossible-alternative controls never protect low alternatives.
   Verified by `TestPHPIncludeDispatch`.
4. Superglobal origins, `$_SESSION` write→read transfers and `php://input` body origins validate
   as `InputFacts`; `source.php-input-v1` is selected for HTTP-acquired candidates. Verified by
   `TestPHPInputFacts` and analysispacks selection tests.
5. SQL candidates bind `php-mysqli-v1`/`php-pdo-v1`/`php-sqlite3-v1` with verified handle
   provenance (including the `$GLOBALS` converter idiom), operand roles and completeness;
   prepare+bind paths carry binding controls; shadowed SQL functions stay negative.
   Verified by `TestSQLPHPContracts`.
6. Command candidates cover the D-6 table with shell-operand facts; `escapeshellarg` is a
   control. Verified by `TestCommandPHPOperands`.
7. Reflected XSS candidates arise from request-derived HTML values; stored claims link
   `php-sql:` keys; `htmlspecialchars` transforms are recorded; escaped outputs are not red.
   Verified by `TestPHPXSSReflected`, `TestPHPXSSStored`.
8. Path candidates cover D-8 operations with `PathFacts`; `basename`/whitelist controls behave
   as controls, not sink removals. Verified by `TestPathPHPOperands`.
9. `eval` produces a `code` candidate with whole-program operand facts; `header('Location: …')`
   produces a redirect candidate with destination facts. Verified by `TestCodePHPEval`,
   `TestCodeRedirectPHP`.
10. Every PHP candidate selects the expected component closure (`language.php`, family pack,
    contract, `source.php-input-v1`) with provenance; NoSQL/SSRF/logging never select for PHP.
    Verified by analysispacks closure tests.
11. Existing JS/TS/Python fixtures keep byte-identical reports and request digests. Verified by
    the existing full suite plus predecessor baselines.
12. Offline DVWA structural gate (`ZAZZLES_DVWA`): module entries present; required candidate
    kinds exist for `sqli`, `sqli_blind`, `brute`, `captcha`, `csrf`, `exec`, `xss_r`, `xss_s`,
    `upload`, `fi`, `open_redirect` and `view_help.php` eval; impossible-level variants carry
    their controls; the sample tree is clean before/after. Verified by `TestDVWASourceKey`.
13. `go test ./... -count=1`, `go test -race ./... -count=1`, `go vet ./...`, `go build ./...`,
    changed-file `gofmt`, `git diff --check` and scoped doc checks pass.
14. After offline gates pass and the user re-confirms: one paid `gpt-6-luna` DVWA pass within the
    300-request cap where every cataloged required positive is Confirmed, no impossible-level
    control is red, and every completed assessment replays exactly offline. Verified by
    `TestReplaySavedRun` on the retained run directory; results recorded in
    `.zazz/evaluation/php-support-results.md`.

## 8. Test strategy

Synthetic fixtures under `internal/parse/testdata/php/` (routes, includes, sql, command, xss,
path/upload, code/redirect, inputs) each pair vulnerable/protected/unknown siblings per
[testing.md](../standards/testing.md#2-test-kinds): conditional `htmlspecialchars`,
`prepare`+`bindParam`, `escapeshellarg`, `basename`/whitelist paths, shadowed sink names,
`$_SESSION` transfer, switch-literal includes, a locally defined `mysqli_query` negative, and a
trimmed DVWA-shaped module (`index.php` + `source/low.php` + `source/impossible.php`). Golden
route inventory mirrors `python/routes/routes.json`. The DVWA gate reuses the
`ZAZZLES_VULN_NEXTJS` env-gated pattern with a source-reviewed key in
`.zazz/evaluation/dvwa-detection-guide.md`; expected labels never enter model input. Judgment and
policy behavior is exercised with local stub answers; no live calls in unit tests. Existing
JS/TS/Python suites are the regression layer — no duplicated coverage.

## 9. TDD entry point and execution sequence

First failing test: `TestPHPRoutes` over a minimal `testdata/php/routes` fixture asserting
`.php` detection and one server-mapped entry.

1. Pin grammar; add `lang.PHP` + extensions; prove `TestPHPRoutes` green with a routes golden.
2. `php_modules.go`/`php_entries.go`: module loading, literal include composition, entry
   assembly, `AnalyzeWithOptions` dispatch and merge; extend `TestPHPIncludeDispatch`.
3. `php_flow.go`: assignments, interpolation/concatenation, superglobal sources, HTML-value
   tracking, function calls and returns with the Python helper bounds; `php_input_facts.go` +
   analysispacks selection (`source.php-input-v1`, PHP family languages).
4. SQL models and storage keys; then command; then XSS reflected/stored; then path/upload/include;
   then code/redirect — each phase lands its family tests with paired controls.
5. `internal/guidelines/php.md` + family sections; CLI/error-string updates; `TestPHPCLI` mixed
   repo.
6. DVWA offline scan: author the detection guide from source review, add the gated
   `TestDVWASourceKey`, iterate bounded gaps, and record limits honestly.
7. Full contributor checks; update the spec index, implementation plan, sample catalog row,
   family-guide PHP sections and `docs/php-support.md`; commit, push, draft PR into `stage`.
8. Paid closeout (AC14): capped DVWA run, exact replay, results document, published sample
   reports under `docs/samples/dvwa/`.

Skeletons (load-bearing on shape only):

```go
type phpModule struct {
    file, src, hash string
    tree            *sitter.Tree
    funcs, classes  map[string]*sitter.Node
}
type phpSet struct {
    root    string
    parser  *sitter.Parser
    modules map[string]*phpModule // repo-relative path → module
    files   []analysis.File
    gaps    []analysis.Gap
}
func newPHPSet(root string) (*phpSet, error)
func (s *phpSet) report(entry string, checks []analysis.Check) (*analysis.AnalysisReport, error)

type phpFlow struct {
    set     *phpSet
    module  *phpModule
    entry   *analysis.EntryPoint
    context string
    values  map[string]phpValue // variable → value (deps, literal, html, callable)
    html    *phpValue           // accumulated HTML output value
}
func (f *phpFlow) addUse(kind string, n *sitter.Node, v phpValue) *analysis.CandidateUse
```

Include resolution: `includeTargets(n) []phpIncludeTarget` returns literal targets or
condition-tagged alternatives from finite switch/if assignment sets; everything else is a
`php_dynamic_include` gap.

## 10. Definition of done

- [x] All §2 required reading consumed; standards-index verification performed.
- [x] All §7 ACs verified with cited evidence; offline ACs 1–13 green before any paid request.
- [x] DVWA clean at `a1978a2` before/after every scan; no artifacts inside the sample.
- [x] Full offline contributor checks pass; changed docs pass `doc-check`.
- [x] Working tree contains only §4 changes; run log current through the final phase.
- [x] Draft PR into `stage` links this contract and lists each AC's verification.
- [x] Paid closeout (AC14) either completed with exact replay or explicitly deferred by the user.

## 11. Open questions

None block implementation. Resolved by the owner on 2026-11-16 and recorded here: core family
scope (D-5–D-10; SSRF/logging deferred); offline-first with one ≤300-request `gpt-6-luna` pass
re-confirmed before execution (AC14); DVWA pinned `a1978a2`.

## 12. Run log protocol

Append authorization, standards verification, phase completions with commands/outcomes,
deviations, DVWA integrity checks, manual evidence paths, QA/rework, issues/recoveries and
cumulative paid usage to `.zazz/ephemeral/php-support-run-log.md`. Raw artifacts live under
`_test-findings/dvwa/`. Durable conclusions promote to `.zazz/evaluation/` and the family docs;
the run log is never committed.

## 13. Agent implementation prompt

Resume in the `php-dvwa` worktree. Read [AGENTS.md](../../AGENTS.md), the
[orientation](../docs/zazzles-agent-orientation.md), this contract and the entire local run log;
verify worktree path, branch `php-dvwa`, status and the `stage` diff; verify DVWA is clean at
`a1978a2`. Work alone in this checkout. Resolve no open questions (none are open). Execute §9 in
order with TDD discipline, honoring §3 invariants and §6 rules, including halt conditions. Run
each §7 acceptance check as its phase completes and append evidence to the run log. Do not make
paid requests until ACs 1–13 pass and the user re-confirms the capped run; then execute AC14,
retain traces, and verify exact replay. Update the spec in place with owner-approved changes and
record them in §14. Commit coherent green work with the zazzcode identity, push only this feature
branch, and prepare one draft PR into `stage` linking this contract. Do not merge; do not touch
sibling worktrees or the samples.

## 14. Implementation and review change log

### 2026-11-16 — Initial contract

**Source.** User request to add PHP support in the `php-dvwa` worktree, tested against
zazzcode/DVWA, following the established TypeScript/Node and Python adapter patterns; Drupal is a
separate future deliverable.

**Summary.** Owner resolved family scope (core), live-call policy (offline first, one ≤300-request
capped pass re-confirmed before execution) and the DVWA pin (`a1978a2`). Contract drafted from the
Python adapter precedent, the analysis-pack ownership model, and a direct source review of the
pinned DVWA checkout.

**Verification impact.** None yet; implementation evidence accrues in the run log and
`.zazz/evaluation/php-support-results.md`.

### 2026-11-17 — Offline implementation complete (ACs 1–13)

**Source.** §9 execution sequence completed in the `php-dvwa` worktree per §13.

**Summary.** Adapter, families, contracts, guidelines, CLI and fixtures implemented and green
(milestone `b825f5b`); full-tree DVWA offline scan closed two structural gaps (numeric
`fetch_row` storage columns; `file_get_contents` dependency propagation into `eval`) in
`6b60ced`; detection guide and `TestDVWASourceKey` gate added in `b921976`. Offline results and
bounded gaps are recorded in `.zazz/evaluation/php-support-results.md`.

**Deviations approved as implemented.** Helper work budget is 96 per entry (Python uses 24 per
route; DVWA page assembly chains more helpers) with depth 3 unchanged; gap/evidence merges dedupe
by content because branch clones inherit parent state and plain append doubles per conditional;
conditional joins use a dirty-set so only changed variables rejoin. All three are visible as
documented bounds in `docs/php-support.md` and the results document.

**Verification impact.** ACs 1–13 verified with cited evidence; AC14 (paid capped pass) pending
user confirmation, 0 requests spent.

### 2026-11-17 — Paid closeout (AC14) complete

**Source.** User re-confirmed the capped paid pass ("you can make paid runs against luna"; quota
reset twice after provider-side interruptions).

**Summary.** Final run `run-1226915911` at `1deee35`: 292/296 assessed within the 300-request
cap, every cataloged required positive Confirmed (after the honest guide re-scopes of AUTH-002
captcha and UPLD-001 upload recorded in the detection guide), no exclusively-impossible-sourced
record red, 292/292 exact offline replay. Sample published under `docs/samples/dvwa/`. Diagnostic
runs exposed and fixed generic adapter defects: claim-kind/evidence-role mismatches against the
shared judge policies, flow-wide gap blockers vetoing raw witnesses (now value-scoped, matching
the command policy's raw-witness principle), invalid PathFacts slots/roles, unmodeled
`!in_array` membership guards (with terminating-rejection semantics via exit/die), positional
array-literal elements, and branch-merge dirty-marking for protection-only changes. Cumulative
paid usage 1,336 requests, per-run caps honored.

**Verification impact.** All §7 ACs verified; results and provenance in
`.zazz/evaluation/php-support-results.md` and the sample metadata.

### 2026-11-17 — Independent review and rebase onto stage

**Source.** Owner-assigned independent review of the implemented MVP before merge, with paid
passes on DVWA and php-goof authorized by the owner during the review.

**Summary.** Rebased onto `stage` `86efc7e` without conflicts. Fixed defects found by direct
PHP-semantics review and by the two samples: merge dirty propagation; guard polarity; if/elseif/
else chains, braceless and colon bodies; loop termination; `die()` statements; foreach and
whole-superglobal sources; builtin shadowing by variables; include cycles and depth; zero-argument
calls; literal double-quoted SQL; D-3 selector narrowing with exact-constant condition folding and
sibling-alternative gap isolation; inline-HTML output context and `<?=`; interpolated SELECT rows;
INSERT/UPDATE write attribution across joins; session writer linking across entries; raw-witness
XSS typing; `urlencode` as a scoped XSS control; shell deny-lists; `explode` and element type
guards; flow-scoped `define()`, entry-relative includes, `__DIR__`; `=&` assignment; guarded
command/code/redirect facts valid under the shared contracts; stored-only injection claims kept in
Review; server-determined `$_SERVER` keys. Adapter reorganized into values/control/guards/
includes/input-facts files. Bounds as implemented: helper depth 4, 256 calls per entry, include
nesting 8. PHP guideline version 2 (inline-HTML output context).

**Verification impact.** Offline suites, `-race`, vet and the DVWA source-key gate green.
Evaluation of record and sample analysis in `.zazz/evaluation/php-support-results.md` and
`.zazz/evaluation/php-sample-analysis.md`; 721 review requests. The published
`docs/samples/dvwa/` reports remain pinned to scanner `1deee35` by their metadata.

### 2026-11-18 — Adapter moved to `internal/langphp` (architecture phase 3A)

**Source.** [Architecture phase 3A](architecture-phase-3-php-package.md), `arch-multi-lang-packaging`.

**Summary.** §4 paths updated: PHP sources, tests and fixtures now live in `internal/langphp`
(`langphp.Run`, `langphp.Routes`), route-inventory orchestration in `pipeline.Routes`. Behavior and
bounds are unchanged; other sections keep their original file names as history.

**Verification impact.** None to PHP output. The architecture golden's PHP report hashes changed only
for the embedded fixture root path; request and SARIF digests are unchanged.
