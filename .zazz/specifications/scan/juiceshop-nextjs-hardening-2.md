# Juice Shop and Next.js hardening 2 — scanner comparison on four samples

- **Lane rules** [Branch 1 §0](juiceshop-nextjs-hardening-1.md#0-lane-model). They apply here and
  are not repeated.
- **Branch** `juiceshop-nextjs-hardening-2`, stacked on `juiceshop-nextjs-hardening-1`.
- **Depends on** Branch 1 §3 (the Juice Shop answer key) and its judged acceptance run. Part A
  below does not depend on branch 1 and may run first.
- **Owner request** 2026-11-24: bring the comparison with other scanners up to date with what
  Code Scan does now, reorganize the comparison documents around one summary, add zizmor, cover
  four samples, and link the result prominently from the project README.
- **Review artifact** One draft PR. Its base is branch 1 until that PR merges, then `stage`.

## 1. Capability

The comparison record is two documents from 2026-10-31 and 2026-11-01:
[bearer-results.md](../../evaluation/bearer-results.md) and
[semgrep-results.md](../../evaluation/semgrep-results.md). They compare a scanner that had SQL,
NoSQL and XSS analysis on three JavaScript samples. Code Scan now has 21 vulnerability classes
in three languages, and neither document covers a PHP sample. The capability inventory
(`.zazz/evaluation/bearer-capabilities.md`, since removed) states "mostly outside sink
catalog" for families that are delivered.

This branch reruns Semgrep CE and Bearer, adds zizmor, and publishes one summary a reader can
reach from the README.

**Samples.** The four the owner named, at the pins of the
[sample catalog](../../project/vulnerable-sample-apps.md#applications):

| Sample | Language | Pin | Answer key |
|---|---|---|---|
| OWASP Juice Shop | TypeScript (Express, Sequelize, Angular) | `f189f52` | `.zazz/evaluation/juice-shop-detection-guide.md` (branch 1) and the [XSS key](../../../docs/samples/juice-shop/xss-answer-key.md) |
| vuln-nextjs | JavaScript (Next.js) | `f5d47de` (branch 1 AC12) | The lab's `tests/expected-scanner-findings.json` |
| DVWA | PHP | `a1978a2` | [DVWA detection guide](../../evaluation/dvwa-detection-guide.md) |
| vuln-symfony | PHP (Symfony) | `086f81f` | [Symfony detection guide](../../evaluation/vuln-symfony-detection-guide.md) |

## 2. Decisions

**D-1. Document layout.**

| Document | Role | Audience |
|---|---|---|
| `docs/scan/scanner-comparison.md` (new) | The summary: one table per sample of keyed cases found by each tool, one table of vulnerability classes by tool, the workflow-analysis table, and how to read them. Linked from the README | Users |
| `.zazz/evaluation/comparison-results.md` (new) | The run record: tool versions, rule snapshots, commands, scope, counting rules, the capability inventory, links to the detail documents | Contributors |
| `.zazz/evaluation/semgrep-results.md` | Rewritten as the Semgrep detail for the four samples | Contributors |
| `.zazz/evaluation/bearer-results.md` | Rewritten as the Bearer detail for the four samples | Contributors |
| `.zazz/evaluation/zizmor-results.md` (new) | The zizmor detail | Contributors |
| `.zazz/evaluation/comparison-history.md` (new) | The 2026-10-31 and 2026-11-01 results, moved unchanged from the two detail documents, with the controls corpus comparison | Contributors |
| `.zazz/evaluation/bearer-comparison.md` | Kept as the repeat protocol. Its "Capability-parity inventory" section points to `comparison-results.md` | Contributors |
| `.zazz/evaluation/bearer-capabilities.md` | Removed. Its table moves into `comparison-results.md` with the "Scan state" column rewritten from [detection capabilities](../../../docs/scan/detection-capabilities.md) | — |

*Why the summary is under `docs/`:* the README links only to user documentation, and `.zazz/`
is internal. *Why one summary and one run record:* the numbers appear once, in the summary; the
run record explains how they were produced and never restates them. *Why history is moved, not
deleted:* the old tables are cited by [Juice Shop evaluation](../../evaluation/juice-shop/README.md)
and the Goof results. Every inbound link to a moved or removed section is updated; find them
with `grep -rn 'bearer-results\|semgrep-results\|bearer-capabilities' --include='*.md' .`.

**D-2. The comparison counts keyed cases only.** A tool's result is matched to a keyed case
when it is in the case's sink file, within three lines of the keyed line, and its rule's CWE or
class is the case's class. Each case gets one cell per tool: `found`, `missed`, or for a
control `flagged` or `not flagged`. Zazzles cells use its statuses: `Confirmed`, `Review`,
`Protected`, `no record`. A tool's total result count is shown beside the table and is never
used as a score. *Why:* a result count rewards noise, and the samples hold many results nobody
has reviewed. *Why three lines:* tools anchor one statement differently (the call, the
argument, the template literal).

A result outside every key is not a false positive and is not counted as one. The detail
document lists such results by rule with their count, and marks those in test files and
training snippets.

**D-3. Zazzles columns come from recorded judged runs.**

| Sample | Run |
|---|---|
| Juice Shop, vuln-nextjs | The branch 1 acceptance runs |
| DVWA | `run-4266343441` ([DVWA results](../../evaluation/dvwa-results.md#judged-run-after-the-pr-47-review)) |
| vuln-symfony | `b4-review-accept` ([Symfony results](../../evaluation/symfony-results.md)) |

No paid run is made in this branch. The PHP runs stay valid because branch 1 changes no PHP
request (its AC11). Each table names the scanner commit of its Zazzles column.

**D-4. Tools.** Each is run offline against a snapshot recorded by revision, with the sample
unchanged before and after.

| Tool | Version | Rules | Notes |
|---|---|---|---|
| Semgrep CE | The installed `semgrep --version` | A snapshot of `p/javascript`, `p/typescript`, `p/php`, `p/xss` and `p/owasp-top-ten`, downloaded once, `--metrics=off` | Follow the [Semgrep CE cheat sheet](../../../docs/scan/semgrep-ce-cheat-sheet.md). CE has no cross-file analysis; say so where a miss follows from it |
| Bearer CLI | Built from `<DEV_ROOT>/scanners/bearer` at its checked-out revision | A pinned `bearer-rules` snapshot loaded as an external rule directory, default rules disabled | Follow the [protocol](../../evaluation/bearer-comparison.md#procedure). Run on the source tree with the exclusions of the Zazzles source scope |
| zizmor | The installed release, recorded with `zizmor --version` | Built-in audits, `--offline` | D-5 |

Exclusions for Semgrep and Bearer match the Zazzles source scope for each sample
(`node_modules`, `vendor`, build output, the bundled `three.js`). No tool's process receives a
model provider key.

**D-5. zizmor is reported on its own surface.** zizmor audits GitHub Actions workflows. Code
Scan reads application source and excludes `.github/`. The two do not overlap, so zizmor has
its own table (workflow files, findings by audit and severity) and no column in the
vulnerability-class table. Juice Shop has 15 workflow files, DVWA 5 and vuln-nextjs 1.
vuln-symfony has none and is reported as "no workflow files". The summary states that this is
coverage Code Scan does not have.

**D-6. Raw output and curated copies.** Raw JSON and SARIF go to
`<DEV_ROOT>/zazzcode/zazzles/_test-findings/<sample>/<tool>-<date>-<n>/`. Curated copies with
relative paths go to `docs/samples/<sample>/<tool>/<run-id>/` with a `metadata.json`, as
`docs/samples/juice-shop/semgrep/20261101-baseline-01/` does. A sample with no `docs/samples`
folder gets none; its detail table is the record.

**D-7. README.** [README.md](../../../README.md) gains "Scanner comparison" in its top link row and
a section of at most ten lines after "Current coverage": one sentence on what was compared, the
per-sample totals table (keyed cases found by each tool), and the link. It states that the
samples are development references and the result is not a general accuracy claim.

## 3. Parts

**Part A — tool runs and detail documents.** Independent of branch 1. Run the three tools on
the four samples (D-4 to D-6) and write the three detail documents from what the tools report:
run identity, results by rule, results in test and training files, errors, timing.

**Part B — matching and summary.** After the branch 1 acceptance run. Match each tool's results
to the keys (D-2), write the summary, the run record and the README section, move the history
(D-1) and run `doc-check`.

## 4. Acceptance criteria

1. **AC1.** Each tool ran on each sample it applies to, with exit status and error count
   recorded. `git status --porcelain --ignored` is empty in each sample before and after.
   Verified by the `metadata.json` of each run.
2. **AC2.** `.zazz/evaluation/match-scanner-results.py` reads a tool's SARIF or JSON and the
   keyed cases and prints the D-2 cells. `python3 .zazz/evaluation/test_match_scanner_results.py`
   covers: a result on the keyed line, three lines away, four lines away (missed), the right
   line with another class (missed), a control (flagged), and a result outside every key (listed,
   not counted).
3. **AC3.** Every cell of the summary tables is reproduced by running AC2's script on the saved
   outputs. The run record gives the command for each table.
4. **AC4.** The layout of D-1 exists. `grep -rn 'bearer-capabilities' --include='*.md' .`
   returns nothing outside `comparison-history.md` and this specification. No link in `docs/`,
   `.zazz/` or `README.md` is broken; verified by the `doc-check` skill's link check.
5. **AC5.** The capability inventory in the run record has one row per class of
   [detection capabilities](../../../docs/scan/detection-capabilities.md) and states for each tool
   whether a keyed case exercised it. No row claims a capability that no run exercised.
6. **AC6.** The README section of D-7 is present and its totals equal the summary's.
7. **AC7.** The summary names, for each sample, the Zazzles scanner commit and run, each tool's
   version and rule revision, and the date.
8. **AC8.** The branch changes no file under `scan/` or `cmd/`.

## 5. Scope

| Path | Change |
|---|---|
| `docs/scan/scanner-comparison.md`, `docs/scan/README.md`, `docs/README.md`, `README.md` | New and modified |
| `.zazz/evaluation/` documents of D-1, `match-scanner-results.py` and its test | New, modified, one removed |
| `docs/samples/<sample>/{semgrep,bearer,zizmor}/` | New curated outputs |
| `.zazz/project/implementation-plan.md`, specification indexes | Modified |

**Out of scope.** Scanner code. New paid model calls. Semgrep Pro, Bearer Pro and CodeQL.
`nestjs-security-scan`. Samples other than the four. Runtime confirmation of any finding.
Adjudicating results that match no keyed case.

## 6. Halt conditions

1. A tool cannot run offline against a pinned snapshot.
2. A sample changes during a run.
3. A keyed case's label looks wrong when a tool's result is read against it. Bring the source
   evidence; do not relabel.
4. Part B is reached before the branch 1 acceptance run exists.

## 7. Open questions for the owner

| ID | Question | Recommended, and assumed unless the owner says otherwise |
|---|---|---|
| OQ-1 | Installing zizmor and downloading rule snapshots | Homebrew `zizmor`; Semgrep packs from its registry; `bearer-rules` from its GitHub repository at a recorded commit. **Each download needs the owner's word** |
| OQ-2 | Semgrep rule packs for PHP | `p/php` only. Add `p/symfony` if the registry has it at snapshot time |
| OQ-3 | The older samples (Goof, TypeScript app) | Stay in `comparison-history.md`; not rerun |

## 8. Definition of done

- [ ] Every criterion of §4 is met with its command output in the run log.
- [ ] `doc-check` passes on every changed document.
- [ ] The draft PR is open, based on branch 1, with the per-sample totals table in its body.

## 9. Change log

### 2026-11-24 — Drafted

Written from the two existing result documents, the capability inventory and the scanner
checkouts under `<DEV_ROOT>/scanners`. The owner then proposed running the three tools in the
authoring session; Part A was separated from Part B so that it does not wait for branch 1.

### 2026-11-24 — zizmor removed

Owner decision. zizmor audits GitHub Actions workflow files and does not read application
code, so it does not belong in a comparison scored against application vulnerabilities. D-5,
the zizmor row of D-4, its detail document and its curated copies are withdrawn. The run is
noted in the [run record](../../evaluation/comparison-results.md). The text above is kept as the
contract that was written.

### 2026-11-24 — Part B delivered

The summary, the run record, the matcher with its test and the README section are written. The
owner set the table shape: rows are every known vulnerability of an application, a miss is
shown for every scanner including Code Scan, and each false positive is its own row. Changes to
the decisions above that follow from it:

- **D-2.** False positives are rows of a second table per application, not cell values, and
  are counted by location. Results on application code in a class Code Scan covers were
  source-reviewed for Juice Shop; eight documented vulnerabilities that the key lacked became
  rows. The DVWA and vuln-symfony tables were not widened; their unreviewed results are counted.
- **D-3.** The Juice Shop run is `r10-acceptance-juice-shop`, the full scan made after the lead
  review of branch 1, not the session's first acceptance run.
- **AC2.** The script reads each tool's JSON, not SARIF. Bearer SARIF was not produced.
- **Not done.** The curated copies of D-6 under `docs/samples/`, and `doc-check` as a skill run;
  links were checked by script.

### 2026-11-24 — Part A run

The three tools ran on the four samples and the detail documents were written:
[Semgrep](../../evaluation/semgrep-results.md), [Bearer](../../evaluation/bearer-results.md) and
zizmor (`.zazz/evaluation/zizmor-results.md`, since removed). The earlier results moved to
[comparison-history.md](../../evaluation/comparison-history.md). Still open from Part A: the
curated copies of D-6 under `docs/samples/`, and Bearer SARIF output. The registry has no
`p/symfony` pack (OQ-2). The owner stated that the Zazzles columns of Part B come from paid
judged runs, which D-3 already requires.
