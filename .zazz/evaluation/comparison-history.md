# Scanner comparison history

The comparison results of 2026-10-31 (Bearer) and 2026-11-01 (Semgrep CE), moved here unchanged
on 2026-11-24 when the comparison was rerun on four samples. They describe the scanner as it was
then: SQL, NoSQL and XSS analysis on three JavaScript samples. Current results are in the
[Semgrep](semgrep-results.md), [Bearer](bearer-results.md) and [zizmor](zizmor-results.md)
detail documents. Headings are one level deeper than in the original documents.

## Semgrep CE baseline and XSS comparison

**2026-11-01.** First Semgrep Community Edition baseline on the three pinned sample apps, compared with
Zazzles (hardening 10, commit `83aa7bd`) and the existing [Bearer results](bearer-results.md) on the
source-reviewed XSS answer keys. How to repeat it: [Semgrep CE cheat sheet](../../docs/semgrep-ce-cheat-sheet.md).

### Run

Semgrep 1.183.0, `--metrics=off`, offline against a rule snapshot downloaded once from the registry:
`p/javascript`, `p/typescript`, `p/xss` and `p/owasp-top-ten` (563 rules after merging, all valid).
Exclusions match the Zazzles source scope (`node_modules`, `.github`, Goof `exploits/` and
`public/js/bundle.js`, Juice Shop `three.js`, build output). Targets were unchanged before and after
(`git status --porcelain --ignored` empty).

| Target | Revision | Files | Results | Errors | Baseline |
|---|---|---:|---:|---:|---|
| Node.js Goof | `add14ba` | 30 | 6 | 0 | [JSON/SARIF/text](../../docs/samples/nodejs-goof/semgrep/20261101-baseline-01/metadata.json) |
| Vulnerable TypeScript app | `7f8b240` | 7 | 7 | 0 | [JSON/SARIF/text](../../docs/samples/vulnerable-typescript-app/semgrep/20261101-baseline-01/metadata.json) |
| OWASP Juice Shop | `f189f52` | 1,168 | 30 | 32 | [JSON/SARIF/text](../../docs/samples/juice-shop/semgrep/20261101-baseline-01/metadata.json) |

Juice Shop's 32 errors are syntax/partial-parse warnings in `data/static/codefixes/*` challenge snippets,
which are not complete TypeScript files. Curated copies make target paths relative and drop the local
rules-directory prefix from rule IDs; raw outputs remain under `_test-findings/<app>/semgrep-20261101-1/`.

### XSS answer-key comparison

Positive = expected vulnerable flow found as a finding. "Review" = Zazzles kept a record with a named
blocker instead of claiming a finding. Bearer columns use the saved Goof baseline and the earlier
TypeScript comparison. Bearer has not yet been run on Juice Shop for XSS.

| Case | Expected | Zazzles | Semgrep CE | Bearer |
|---|---|---|---|---|
| `GOOF-XSS-01` reflected login (EJS raw attribute) | positive | finding (red, replayed judgment) | missed | missed |
| `GOOF-XSS-02` stored Markdown, create | positive | finding, separate supported path | missed | missed |
| `GOOF-XSS-03` stored Markdown, update | positive | finding, separate supported path | missed | missed |
| `GOOF-XSS-N01`/`N02` escaped edit outputs | protected | Protected | no result | no result |
| `GOOF-XSS-N03` render options | Review | Review | no result | no result |
| `GOOF-XSS-N04` fixed analytics script | no finding | no finding | no finding | **false positive** (`dangerous_insert_html`) |
| `TS-XSS-01` reflected search | positive | finding | found (`direct-response-write`, `raw-html-format`) | found |
| `TS-XSS-N01` JSON output | no finding | no finding | no finding | — |
| `JS-XSS-01` DOM search trust bypass | positive | finding | missed | not run |
| `JS-XSS-02` track order (cross-tier) | positive | finding, branch paths | missed | not run |
| `JS-XSS-03` saved login IP via JWT | positive | Review (token origin) | missed | not run |
| `JS-XSS-04` admin email | positive | Review (stored origin) | missed | not run |
| `JS-XSS-05` feedback | positive | Review | missed | not run |
| `JS-XSS-06` product description dialog | positive | Review (dialog sink unlinked) | missed | not run |
| `JS-XSS-07` profile template construction | positive | Review (stored origin) | missed | not run |
| `JS-XSS-08` subtitles | Review | Review | no result | not run |
| `JS-XSS-N04` CAPTCHA trust bypass | no finding | Review, no finding | no finding | not run |

Totals over expected positives: Zazzles **6 of 11** found, with the other 5 kept as Review;
Semgrep CE **1 of 11**; Bearer **1 of 4** run (with one Goof false positive).

Semgrep's Angular `bypassSecurityTrust*` rule is taint-mode with intra-file sources, so it does not reach
Juice Shop's route-parameter, API-response or stored sources. CE has no cross-file or stored-flow
tracking (that is Semgrep Pro), and the snapshot packs have no rule for raw EJS `<%-` output or `marked`.
That is a capability difference on these labeled cases, not a general accuracy claim.

### Other Semgrep results (not XSS)

- **Goof:** cookie-session options and a hard-coded session secret (`app.js:42-43`), Dockerfile user.
- **TypeScript:** hard-coded session and JWT secrets, path traversal `:103`, string-built code `:137`,
  open redirect `:239`. Zazzles has no rule for secrets, path traversal or open redirect; these are
  candidate capability gaps, not verified cases.
- **Juice Shop:** six Sequelize injection results, `res.sendFile`, directory listing, a JWT secret,
  an open redirect, and Terraform/npm configuration rules.

Next: run Bearer on Juice Shop with the pinned rules; write answer-key cases for the non-XSS Semgrep
results before counting them; repeat with each Zazzles hardening increment against the same rule snapshot.

## Pinned Bearer CLI comparison

**2026-10-31; development evaluation, not held-out accuracy or product parity.**
Source inspection supplied provisional labels; independent human label review, Findings Review and
runtime confirmation remain pending. Bearer is a comparator, not ground truth.

### Tool and source identity

| Component | Revision / configuration |
|---|---|
| Bearer CLI source | `e3753de6347988bed15bdba80b9ff731bf028c80`; locally built with Go 1.27.3, darwin/arm64, default CGO; reports `dev`, `devSHA` |
| Bearer rules | `82c335f781a61a6d8b052394f84fd1d93edec467`; upstream bearer-rules snapshot loaded through external-rule-dir |
| Scan implementation | `d0c6fcf2dbb0c86030822ea5047016cf35f8fd2c`; no scanner implementation changes in this experiment |
| Juice Shop | `f189f521266f42c6bd05884468292000cee852ed`, v20.3.0 |
| Second TypeScript sample | `7f8b240a2f02beba099da3632d1ba679ff8bc32f` |

The Bearer build used `-mod=readonly`, with caches and binary in scratch locations; its checkout
remains unchanged. No generation, tidy, target installation, target execution or SCA audit ran.
Rules were downloaded separately; scans disabled default/built-in rules, version checks and domain
resolution. The configured upstream external snapshot supplied the security rules. This is a pinned
external-rule run, not a claim that current hosted defaults or Pro behave identically.

The child environment contains only PATH and TMPDIR. Empty explicit configuration and JSON ignore
files prevent local overrides. Bearer uses filesystem discovery (`--ignore-git`), includes tests,
forces uncached detection, runs two workers and emits debug logs plus JSON. Supported output formats
were inspected in help/source; JSON was exercised here. SARIF consumer behavior was not tested.
Source inspection found version/rule-service requests; disabling version checks alone does not
disable the rules metadata request. No hosted report output was selected. No packet-level network
audit or comprehensive telemetry audit was performed.

### Scope and execution validity

Original and added controls use the same case roots for both tools. Labels remain in manifests
outside each scanned root. Requirements contain questions, not expected answers. The six added
[transfer controls](transfer-corpus/README.md) were created before their first runs, but are authored
development controls rather than independently labeled held-out cases.

The sample runs use matching copies of tracked JS/JSX/TS/TSX/JSON files, excluding scanner-default
dependency/build directories and the exact bundled asset `frontend/src/assets/private/three.js`.
Juice Shop contains 757 copied files; the second sample contains four. Scope manifests record the
original revision, exclusions and every copied file hash. Bearer examines these copies broadly;
scan restricts entry registration to `server.ts` or `src/server.ts` and follows its bounded imports.
This matches available source, not equivalent semantic coverage: broad finding totals cannot be
compared to route-selected candidate counts. Training snippets and tests are retained and identified.

The original whole-tree Juice Shop attempt exceeded Bearer's file deadline on bundled three.js;
its partial output is excluded from conclusions. An earlier snapshot attempt found no files because
Bearer Git discovery omitted ignored scratch files despite `--skip-git-ignore`; those empty reports
are also excluded. The sandbox initially blocked loopback workers while Bearer exited 0. The
[runner](run-bearer-comparison.py) rejects worker errors, empty scans, malformed JSON and invalid
exit statuses, and records elapsed time and execution status. Local worker sockets required an
approved execution outside the sandbox. Findings exit 1 is preserved as a successful execution.

### Original controls: equivalent claims only

Scan columns below are **saved historical Luna judgments**, not reassessments of rebuilt evidence.
Case02 uses the explicitly separate changed-evidence recheck; its initial abstention remains recorded
in [original results](corpus/README.md). Bearer columns are the new pinned offline runs. Every case
also produced two Express configuration findings, excluded from the query/field comparison.

| Case / inspected property | Saved scan validation / protection; status | Bearer equivalent finding | Disposition |
|---|---|---|---|
| case01, interpolated SQL | insufficient / insufficient; supported_potential | SQL injection, server.ts:5 | Both flag query structure |
| case02, bound SQL parameter | insufficient / sufficient; protected_for_claim | No SQL finding | Consistent with binding; no Bearer safety assertion |
| case03, enforced custom allow-list | sufficient / sufficient; protected_for_claim | SQL injection, server.ts:6 | False SQL concern for this exact guard and quoted use |
| case04, length-only SQL guard | insufficient / insufficient; supported_potential | SQL injection, server.ts:6 | Both flag query structure |
| case05, optional confirmation bypass | insufficient / insufficient; supported_potential | No equivalent finding | Business-policy question; do not count as a SQL-rule miss |
| case06, enforced normalized nonempty field | sufficient / sufficient; protected_for_claim | No equivalent finding | No Bearer validation assessment |
| case07, unknown applicable middleware | uncertain / uncertain; needs_evidence | No equivalent finding | Scan abstains; Bearer absence does not resolve middleware |

Case03's ASCII lowercase/digit allow-list returns false for values outside its allowed alphabet;
the rejecting branch returns before the quoted SQL use. The comparison does not generalize that
sanitizer to other SQL contexts. Bound parameters remain the preferred general protection.

### Additional controls: offline structural comparison

All new scan assessments are `not_run`; none inherits a saved Luna answer. No new false-safe rate or
semantic-judge recognition rate can be computed from these offline reports.

| Case / inspected property | Scan evidence | Bearer result | Disposition / missing facts |
|---|---|---|---|
| case08, imported enforced custom validator | SQL candidate server.ts:9; guard.ts body attached; unknown_control_effect blocker | SQL injection server.ts:9 | False SQL concern under source label; scan still needs control evidence and a fresh judgment |
| case09, same-file query helper | One route, zero uses | SQL injection server.ts:5 | Scan misses helper sink; argument-to-parameter flow needed |
| case10, imported query helper | One route, zero uses | SQL injection store.ts:3 | Scan misses helper sink; module/call witness needed |
| case11, validated local replaced by alternate | SQL candidate server.ts:9, alternate dependency, no checked blockers | SQL injection server.ts:9 | Both retain dangerous use; scan has no semantic judgment |
| case12, imported helper binds parameter | One route, zero uses | No SQL finding | Neither absence proves protection; scan must discover the use before assessing binding |
| case13, request URL reaches Axios | outbound candidate server.ts:4 | SSRF plus HTTP URL rule at server.ts:4 | One destination concern, two Bearer rules; no scan destination judgment |

Bearer detects a query in the imported helper, so a blanket claim that its TypeScript CLI cannot
detect anything across file boundaries is incorrect. This result alone does **not** establish
route-to-sink interprocedural flow: the pinned rule's shared dynamic-input model also matches
function parameters directly. Inspecting that rule explains why a helper can be flagged without a
proven caller relationship. CLI/Pro general interprocedural/control-flow parity remains unverified.

Across the **nine SQL controls only**, provisional source labels contain five vulnerable and four
protected uses. Bearer flags all five vulnerable uses and two protected custom-validator uses;
binding cases have no SQL finding. These are small, deliberately constructed development cases,
not population precision/recall estimates. Field-policy and outbound cases are excluded from that
denominator. No Bearer absent finding is counted as an explicit protected claim.

### Sample repositories and source-inspected disagreements

| Target / claim | Scan | Bearer | Assessment boundary |
|---|---|---|---|
| Juice Shop login email SQL | Saved Luna insufficient / insufficient, supported_potential; fresh checked evidence at routes/login.ts:34 | SQL injection at same sink | SQL structure concern agrees; saved judgment predates refinements |
| Juice Shop registration required fields | Saved Luna insufficient / insufficient, supported_potential; generated create context server.ts:528 | No equivalent field-policy finding | Conditional middleware server.ts:436–450; generated persistence and model rules remain necessary |
| Juice Shop search SQL | Fresh unchecked SQL candidate routes/search.ts:23 | SQL injection at same sink | Structural overlap only; no fresh semantic assessment |
| Juice Shop profile image URL | Fresh unchecked outbound candidate routes/profileImageUrlUpload.ts:24 | SSRF and HTTP URL rules at same sink | Destination concern; no new judge claim |
| Second sample login SQL-looking log | No SQL candidate | No SQL finding | src/server.ts:74 logs text; no executed database sink |
| Second sample proxy URL | outbound candidate src/server.ts:125 | No equivalent SSRF/HTTP URL finding | `axios.default.get(url)` uses request query value without a local destination guard; source-level Bearer miss |
| Second sample exec / file / reflected HTML | Outside current scan sink catalog | Command injection :90; path traversal :103; XSS :117 | Concrete Bearer coverage absent from scan; no runtime exploit claim |

Bearer emits **671 findings / 29 rule IDs** on the scoped Juice Shop copy and **28 / 21** on the
second sample. Eleven Juice Shop SQL findings include nine `data/static/codefixes` training snippets
and the login/search sinks. Those totals include additional privacy/configuration/secret findings
and have not all been adjudicated; they are not confirmed-vulnerability counts. Two rules at one
source/sink are not two independently confirmed vulnerabilities.

### Timing, usage and reproduction

Final local elapsed times, including CLI startup, with the build/dependency download excluded:

| Scope | Bearer | Scan offline |
|---|---:|---:|
| Thirteen controls, summed | 14.300 s | 0.130 s |
| Scoped Juice Shop | 16.322 s | 0.293 s checked; 0.316 s unchecked discovery |
| Scoped second sample | 1.249 s | 0.010 s |

These are single local runs, different analysis coverage, warm OS/build state, not a speed benchmark.
There were **zero new model requests and zero new model tokens**. Historical usage remains
68,934 input tokens across 13 Luna Decisions requests. No runtime target requests were made.

```bash
python3 .zazz/evaluation/test_bearer_comparison.py
python3 .zazz/evaluation/run-bearer-comparison.py \
  --bearer .zazz/ephemeral/bearer --bearer-source <DEV_ROOT>/bearer \
  --rules .zazz/ephemeral/bearer-rules --scan .zazz/ephemeral/scan-eval \
  --output <DEV_ROOT>/zazzcode/zazzles/_test-findings/bearer-comparison/<run-id> \
  --juice-shop <DEV_ROOT>/juice-shop --second-target <DEV_ROOT>/vulnerable-typescript-app \
  --snapshot-samples --sample-exclude frontend/src/assets/private/three.js
```

Use an unused output directory; pin/reverify both tool and rules revisions before interpreting a new
run. The binary SHA256, commands, raw JSON, debug logs, timings and scope hashes for this experiment
remain ignored under `.zazz/ephemeral/bearer-comparison/final`. Earlier failed/partial attempts remain
separate. The runner now additionally saves control hashes and unchecked discovery alongside checked
reports; those bookkeeping additions do not change the evaluated scanner or Bearer analysis.

### Next bounded implementation

Helper-call SQL discovery is now implemented. Parse tests on case09/10 produce SQL candidates whose
dependencies run from `req.body.handle` through `parameter_binding`, and case12 reaches Sequelize
binding evidence instead of an empty use list. A declared SQL check with no candidate records
`sql_sink_missing`. The comparison table above is the pre-change run and has not been repeated.

Next, preserve case08's real guard body and distinguish a branch that cannot mutate the queried local
from an unknown mutation (case11). Then run fresh capped Luna assessments on the changed bundles.
Do not reuse saved judgments on new evidence. Broader rule families, languages, baseline/CI and Pro
capabilities remain separate items in the [versioned inventory](bearer-capabilities.md).
