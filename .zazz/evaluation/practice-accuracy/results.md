# Practice accuracy and evaluation results

**Branch:** `accuracy-false-positive-eval`, based on merged PR #20 at `cb40f3705949`.
**Date:** 2026-11-16. **Contract:**
[practice accuracy and false-positive evaluation](../../specifications/practice-accuracy-and-false-positive-evaluation.md).

## Delivered corrections

The eight practice checks now have 51 source scenarios, including the seven unchanged research
probes. The seven-probe diagnostic set improves from **0/7 correct expectations to 7/7**:
two false observations are removed and five missed observations are restored. Its observation
precision changes from **0/2 to 5/5**, and recall from **0/5 to 5/5**. This deliberately selected
regression set does not estimate accuracy over all real applications.

| Boundary | Result |
|---|---|
| Cookie options, NX-BP-11 | Immutable local aliases and ordered spreads resolve; later overrides win. Mutation, deletion, escaped objects and unknown options retain uncertainty |
| Cache identity, NX-BP-15 | Identity follows the actual cached value/key. Different-cookie and whole-jar keys cannot suppress Review; unrelated public fetches stay separate |
| Message origin, NX-BP-21 | Exact-origin checks must enforce before data use in the same callback; unused, late, nested and mutated-event checks cannot suppress Review |
| Client/server authorization, NX-BP-22 | Only the gated request/method/route is checked. Known server-session identity plus a rejecting admin-role check must precede operations; unknown auth and fake/successful rejection responses remain Review |
| Action validation, NX-BP-09 | Validation applies to every request-derived value, including sibling fields. An ignored parse result or authorization context cannot validate another value |
| Configuration, NX-BP-13/14 | Unknown composition and later unknown spreads remain Review; restrictive earlier literals cannot supply overwritten policy |
| Sensitive projections, NX-BP-18 | Whole/nested rows, action returns and client props remain covered; explicit public projections remain unflagged |

All observations remain model-free and separate from vulnerability findings. Bounded local
resolvers stop conservatively; no new cross-request store tracking, analyzer or general auth engine
was introduced. Detailed source expectations and primary-source references are in the
[research record](research.md); exact regression sources are in
`internal/parse/next_practice_accuracy_test.go`.
An independent read-only review reproduced two further authorization regressions: session alias
mutation and direct ternary client gates. Both are corrected and pass the reviewer's targeted
reproduction, as well as the regression race tests. The evaluator also tests pending-case recall
and strict report identity validation rather than accepting use IDs alone.

## Eight-target before/after comparison

All target revisions and source hashes match the [research pins](research.md#pinned-corpus).
No target source, dependency, checkout or application was modified/executed. Offline reports are
retained outside the checkout under `<container>/_test-findings/practice-accuracy/{baseline,after}/`.
Every non-practice report field compares structurally equal, including all **3,880 security
records**. These practice-only corrections do not change security evidence or verdicts.

| Target | Entries | Security records before → after | Practice observations before → after |
|---|---:|---:|---:|
| Next.js lab | 37 | 54 → 54 | 5 → 5 |
| OopsSec | 131 | 125 → 125 | 48 → 48 |
| Commerce | 16 | 23 → 23 | 2 → 2 |
| vuln-demo-app | 14 | 19 → 19 | 0 → 0 |
| vulnerable-typescript-app | 19 | 26 → 26 | 0 → 0 |
| nodejs-goof | 19 | 32 → 32 | 0 → 0 |
| Juice Shop | 175 | 251 → 251 | 0 → 0 |
| VulnPy | 2,214 | 3,350 → 3,350 | 0 → 0 |

The four Express comparisons have no changed security records. The real pinned apps do not exercise
the demonstrated practice errors: their unchanged totals are reported without claiming a reduction
in real-app Review burden.

## Commerce interpretation

All **23/23** security records remain unjudged Review: 21 standalone validation records and two
HTML records. Each is individually source-reviewed in the [Commerce audit](research.md#commerce-record-audit).
Repeated cart-cookie reads remain distinct contexts. Unused `prevState` arguments are explicit
workload, not inferred vulnerabilities. Finite sort selection and GraphQL variable transport do
not establish every business validation constraint.

CMS/editorial HTML trust remains unresolved. JSON-LD has no `<` escaping, while attacker control
of its product fields is also unresolved. Neither is relabeled Protected. Commerce has zero
Confirmed records offline; its semantic false-positive rate is **unmeasured**, not zero.

## Evaluation and retained judgments

The [case matrix](cases.json) reconciles all 135 predecessor rows exactly once, with explicit
selected/carry dispositions and original provenance. The [machine results](results.json) publish
family/context/defect breakdowns, denominators, assessment coverage, missing candidates and
unresolved trust. Carried rows without fresh source adjudication stay outside selected metrics;
unavailable carried hashes are explicit nulls, not invented evidence.

The final matrix contains 166 rows: 53 selected contexts, two justified safe exclusions and 111
carried rows. Selection includes the [source-audited prior Protected controls](protected-controls.json).
All 55 selected/excluded case source hashes were independently checked against current pinned
files. Both before/after report mappings validate sink, byte span, hash, operand, entry and family.

| Selected security measurement | Before → after | Interpretation |
|---|---|---|
| Known-positive recall | 4/7 → 4/7 | Same for source-defect and context counts; three retained Review cases remain |
| Protected recognition | 6/16 → 6/16 | Five deterministic offline protections and one retained judged protection |
| Representative safe-defect recognition | 5/15 → 5/15 | One recognized context counts a representative; context coverage remains separate |
| Justified safe exclusions | 2/18 → 2/18 | React text controls have no raw HTML sink |
| False Confirmed | 0/2 → 0/2 | Only two safe contexts have completed retained semantic assessments; all-safe assessed coverage is 2/18 |
| False Protected | 0/7 → 0/7 | Completed retained semantic coverage is 7/7 selected positives |
| Missing candidates | 0/7 positives; 0/16 safe candidates | These denominators apply only to selected cases, not all carried inventory |
| Review burden | 36/46 → 36/46 | Includes 23 Commerce records; four are judged unresolved |
| Unjudged workload | 37/46 → 37/46 | Includes deterministic protections without a completed model assessment |

The 21 unjudged Commerce validation records and two unresolved-trust HTML records stay distinct.
The limited assessed-safe population does not support a broad false-positive-rate claim.

The latest nine predecessor assessments exact-replay from fresh source. Of 51 older phase-2
assessments, 42 match current requests and nine are stale: five candidate IDs are absent and four
requests no longer match. Baseline raw reports and a `cb40f` source overlay reproduce those stale
boundaries, so they are not attributed to this change. Originals remain immutable; stale judgments
are excluded rather than copied onto different evidence. The
[replay registry](replay-results.json) preserves exact IDs, outcomes, digests and verification logs.

No new paid requests were necessary: practice corrections use none, security evidence is unchanged,
and a model cannot supply the missing Commerce source/API trust contract. The
[session ledger](paid-ledger.json) records **0/300 requests sent**, with no fallback and no allowance
carried to a later session.

## Verification and remaining limits

Verification commands and final outcomes are recorded in the local run log and the contract's
acceptance checklist. Tests use offline fixtures/local stubs and real pinned answer keys. The
research runner also requires all seven original probes to pass in `--expect improved` mode;
its baseline mode verifies the original failure set without installing red tests in the suite.

| Check | Final result |
|---|---|
| `TestPracticeAccuracy*` plus existing practice tests, under race detector | pass; 51 source scenarios |
| `TestNextJSVulnLab`, `TestNextJSOopsStoreAnswerKey` | pass at pins, no skips; 29 supported lab rows |
| `go test -race ./... -count=1 -timeout=15m` | pass, all nine packages on final source |
| `go vet ./...`, `go build ./...`, changed-file `gofmt -l` | pass / clean |
| `python3 -m unittest discover -s .zazz/evaluation/practice-accuracy -p 'test_*.py'` | pass; 18 evaluator tests |
| Matrix/report/source validation | 135 predecessor IDs; 55 selected/excluded hashes; both report stages verified |
| Exact replay | 51 retained assessments pass; zero mismatches/missing traces |
| Target integrity and eight-target comparison | pass; [counts and hashes](comparison.json) |
| Documentation | relative links/anchors, whitespace, final newlines, private paths and conflict markers checked |

The two real sample environment variables were set for the answer-key and full-race runs.
`evaluate.py --validate cases.json` alone labels its result `structural_only`; supplying the
baseline/after reports named in the machine results enables strict report-backed validation.
No report identity is inferred from a candidate ID alone. Local execution logs are under
`.zazz/ephemeral/accuracy-*.log`; full raw artifacts remain outside the checkout.

Cross-request writers through server-held stores remain out of scope and unresolved. The seven
known security positives selected for retained semantic evaluation include three still at Review:
the redirect bypass, Juice stored-code path and Juice SSRF path. These recall limits are not fixed
or relabeled by practice changes. Human review determines acceptance and integration.
