# Architecture phase 0 — Compatibility baseline

**Worktree / branch:** `arch-review-clean-up` (owner decision 2026-11-17; phases 0–3 share it)
**Plan:** [architecture update plan](architecture-update-plan.md), phase 0. Objective: maintainability (refactor guard)
**Depends on:** the revised plan committed on `arch-review-clean-up`
**Delivery topology:** one deliverable; its commits join the phases 0–3 milestone draft PR into `stage`
**Coordination:** Lead Agent alone, local run log
**Run log:** `.zazz/ephemeral/architecture-phase-0-compatibility-baseline-run-log.md`
**Drafted:** 2026-11-17

## 1. Capability

Add one golden test that every later architecture phase runs. For every fixture repository
it pins what a refactor must not change:

- candidate IDs, in report order;
- the offline judge request digest and equivalence signature of each candidate;
- normalized report JSON and SARIF hashes;
- entry/registration/dispatch/callable/invocation/use/gap counts.

It adds one three-language fixture that pins the JS/TS → Python → PHP merge order. It also records
offline "before" wall clock and peak memory on pinned samples, so phases 1–3 can report measured
changes. Scanner behavior does not change.

## 2. Required reading

- Plan [shared rules](architecture-update-plan.md#shared-rules-for-every-phase) and
  [common rules](architecture-update-plan.md#common-agent-implementation-rules).
- [Testing: golden files](../standards/testing.md#4-golden-files), [concurrency](../standards/testing.md#6-concurrency).
- Precedent: `internal/parse/python_input_baseline_test.go` (report-hash golden with `-update`),
  `internal/judge/python_input_compat_test.go` (offline client `judge.New("openai", "fixture-model", "never-persist-test-key")` and `Preview`).
- `cmd/scan/analysis.go` `runAnalysisConfigured`: the order is analyze, select, record checks,
  judge, then `reportpkg.Enrich`.
- [Orientation: samples](../docs/zazzles-agent-orientation.md#available-vulnerable-sample-apps).

## 3. Invariants

- The test is offline. It makes no network calls and reads no credentials. The fake key never
  leaves the process.
- The production code diff is empty, apart from test-only helpers in `_test.go` files.
- Golden output is deterministic. Two consecutive runs produce identical bytes.
- Request digests come from the same `Preview` path that `AssessTrace` sends, not from a re-implementation.

## 4. Scope and review shape

| Path | New / modified | Purpose |
|---|---|---|
| `cmd/scan/architecture_baseline_test.go` | new | `TestArchitectureBaseline` and `-update-architecture-baseline` flag |
| `cmd/scan/testdata/architecture-baseline.json` | new | Golden (generated, never hand-edited) |
| `internal/parse/testdata/mixed/three-language/` | new | `server.js` (Express GET with SQL concatenation), `app.py` (Flask GET with SQL concatenation), `index.php` (`mysqli_query` with `$_GET` concatenation) |
| `.zazz/evaluation/architecture-baseline.md` | new | Before measurements and how to rerun them |
| `.zazz/specifications/README.md`, this spec | modified | Index entry, change log |

Out of scope: any production code change, any golden update for existing tests, and paid calls.
Review shape: one PR.

## 5. Decisions

- **D-1 Location: `cmd/scan`.** It is the only package that already depends on `parse`, `judge`,
  and `report` together, and it mirrors the CLI order. It would be wrong in `parse` because
  that package cannot import `judge`. A new package is rejected because there is no production consumer.
- **D-2 Fixture set: every repository directory under `internal/parse/testdata/{javascript,typescript,python,php,mixed}/*`,
  plus `express-login` and `string-flow`.** The list is computed from the directory tree and sorted,
  so a new fixture is pinned automatically on its next `-update`. A hand-kept list was rejected
  because it goes stale silently.
- **D-3 Per-fixture record shape.** The golden stores digests, not full reports. Full reports would
  make 30+ fixtures unreviewable, while a digest mismatch plus the per-use table is enough to
  localize a change. Each use row is `{id, kind, request_sha256 | preview_error, signature_sha256}`.
- **D-4 One provider (`openai`).** Request structure is shared across providers; the other
  providers' wire differences already have their own tests. One provider keeps the golden small.
- **D-5 Hashes taken after `report.Enrich`.** That is the normalized report users receive.
  Request digests are taken before `Enrich`, matching the CLI order.
- **D-6 Separate update flag.** Use `-update-architecture-baseline` rather than the `parse`
  package's `-update`. A broad `-update` run then cannot silently rebaseline the architecture guard.

## 6. Agent implementation rules

Follow the plan's [common rules](architecture-update-plan.md#common-agent-implementation-rules).
Additional halts:

- A fixture produces nondeterministic output across two runs. Record it and ask; do not mask it in the harness.
- `Preview` panics or needs a network or credential for any fixture.
- A pinned sample is missing or at a different HEAD. Record it, skip that sample's measurement, and continue.

## 7. Acceptance criteria

1. **AC1.** `go test ./cmd/scan -run TestArchitectureBaseline -count=1` passes on a clean
   checkout. With `-update-architecture-baseline`, it rewrites `cmd/scan/testdata/architecture-baseline.json`.
2. **AC2.** The golden has one entry per fixture from D-2, keyed by repository-relative path.
   Each entry holds: ordered use rows (D-3); `report_sha256`; `sarif_sha256`; and counts for
   entries, registrations, dispatch bindings, callables, invocation contexts, uses, and gaps.
3. **AC3.** For `mixed/three-language`, the use rows list the JS/TS candidates first, then Python,
   then PHP. This matches the current merge order, and each language has at least one SQL candidate.
4. **AC4.** The test runs analysis twice per fixture and fails if the two results differ.
5. **AC5.** A deliberate one-byte change to any fixture's handler source fails the test with a
   message naming the fixture and the first differing use ID. This is checked once manually and
   recorded in the run log, not committed.
6. **AC6.** `.zazz/evaluation/architecture-baseline.md` records, for juice-shop, vulnpy, and
   DVWA at their catalog pins:
   - offline full-scan wall clock as the median of 3 runs with `/usr/bin/time -l`;
   - maximum resident set size;
   - entries and candidate count;
   - the command used.
   The scans run with no judge and write to `_test-findings/<app>/run-arch-baseline/`.
7. **AC7.** The contributor gate passes with no production diff.

## 8. Test strategy

`TestArchitectureBaseline` is the single new test. It covers AC1–AC4. AC5 is a one-time manual
mutation check. AC6 is a measurement record, not a test. No unit tests are added for the helper
functions; the golden itself is the signal. Reference data is the current `stage` output, which
is authoritative by definition for a compatibility baseline.

## 9. TDD entry point and execution sequence

1. Add the mixed fixture. Write the test with an empty golden and confirm it fails with "golden missing".
2. Implement the harness:

```go
// cmd/scan/architecture_baseline_test.go (shape; helper names adaptive)
var updateArchitectureBaseline = flag.Bool("update-architecture-baseline", false, "rewrite the architecture compatibility golden")

type baselineUse struct {
	ID, Kind        string
	RequestSHA256   string `json:",omitempty"`
	PreviewError    string `json:",omitempty"`
	SignatureSHA256 string `json:",omitempty"`
}
type baselineFixture struct {
	Uses                                   []baselineUse
	ReportSHA256, SARIFSHA256              string
	Entries, Registrations, Dispatch       int
	Callables, Invocations, UsesCount, Gaps int
}

func TestArchitectureBaseline(t *testing.T) {
	// fixtures(): walk ../../internal/parse/testdata per D-2, sorted
	// per fixture: snapshot(root) twice, compare, then compare with golden
}

func snapshot(t *testing.T, root string) baselineFixture {
	// report := parse.AnalyzeWithOptions(root, "", nil, parse.Options{})
	// report.SelectedScope = &analysis.EntrySelection{}; report.RecordCheckMatches(nil)
	// client := judge.New("openai", "fixture-model", "never-persist-test-key")
	// per use in report order: client.Preview(u) -> sha256(trace.Request) or error text;
	//   client.EquivalenceSignature(u) -> sha256
	// reportpkg.Enrich(report); sha256(json.Marshal(report)), sha256(json.Marshal(reportpkg.SARIF(report)))
}
```

3. Run with `-update-architecture-baseline` and review the golden. Confirm that AC3's order holds.
4. Do the AC5 mutation check, then revert it.
5. Measure the samples for AC6 and write the evaluation record.
6. Run the contributor gate and update the README index. Commit and push.

## 10. Definition of done

- [ ] Required reading done; standards lookup recorded.
- [ ] AC1–AC7 verified, with the evidence for each AC cited in the run log.
- [ ] `git diff <phase start HEAD> --stat` matches §4.
- [ ] The run log's PR summary lists each AC and states that there is no production diff.

## 11. Open questions

None.

## 12. Run log protocol

Use the path in the header, with the sections from the plan's common rules. Sample HEADs and
`git status` before and after go under Manual Evidence Locations.

## 13. Agent implementation prompt

> Work in the `arch-review-clean-up` worktree (`<DEV_ROOT>/zazzcode/zazzles/arch-review-clean-up`).
> Record the starting HEAD. Read AGENTS.md, the orientation contents, the
> [plan](architecture-update-plan.md), and this spec. Follow the plan's session start and common
> rules. Implement §9 in order and keep the production diff empty. Stop on any §6 halt. Finish with
> the contributor gate, commit, and push the branch, with AC1–AC7 evidence in the run log; the phase 3
> session opens the milestone draft PR. Verifier: have a
> fresh-context subagent run `go test ./cmd/scan -run TestArchitectureBaseline -count=2`. It should
> confirm the golden covers every directory D-2 selects and that the diff touches only §4 paths,
> then report PASS or FAIL.

## 14. Implementation and review change log

### 2026-11-17 — Owner topology decision

Source: owner, in the planning session. Runs in the `arch-review-clean-up` worktree as one fresh
session, after the previous phase's commits, with no new worktree. Changed: header, §10 scope diff
base, §13 prompt. Verification impact: the scope diff is taken from this phase's recorded starting
HEAD, not `origin/stage`. The PR is the shared milestone draft PR into `stage`.

### 2026-11-17 — Implementation

Source: implementation session. Changed: no contract sections. Recorded adaptations within §9's
adaptive helper names:

- Each use row also carries `signature_error` when `EquivalenceSignature` fails. This happens
  in the same cases as `preview_error`, so the golden records the failure instead of an empty digest.
- The mixed fixture's JS handler uses a verified `sequelize` client. With an unbound `db` receiver,
  `Preview` reported unverified SQL component selection, so no request bytes would have been pinned
  for that language.
- An Express GET with `db.query` and Flask's `sqlite3` cursor match the §4 fixture description.

Verification impact: none. AC1–AC7 evidence is in the run log.
