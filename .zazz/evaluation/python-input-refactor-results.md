# Shared Python input acquisition: verification

[Implementation contract](../specifications/scan/python-input-refactor.md) ·
[Node acquisition design](../specifications/scan/node-http-input-refactor.md)

The existing Python HTTP adapters now supply optional `InputFacts` version 1, using the
same acquisition/value schema as Node. Parameter and ambient-context binding live in
`python_input_adapters.go`; shared Python flow and existing operation contracts retain
their behavior. `source.python-input-v1` owns the separately versioned interpretation.
Existing Node component material and requests are unchanged.

## Delivered boundary and limits

Acquisition is indexed by originating invocation and exact source evidence, then attached
after storage linking and claim/check construction. Each fact repeats the exact final
source and transfer chain for its dependency. Framework registration, origin, supplied
context and existing gaps stay separate from sink semantics and security judgments.
Query, form, JSON/body, path, headers, cookies, combined query/form, uploads, sessions,
stored values and external responses retain distinct origins. Verified upload projections
can distinguish filenames and content. Legacy binding bytes remain unchanged even when
the new metadata distinguishes a route capture from the legacy query label.

Initial and sink runtime types deliberately remain `unknown`. This migration introduces
no new type-based protection, annotation trust, validator inference or gap removal.
Legacy protection projections and existing source-present controls continue to feed the
same operation-specific questions and policy. Missing or unsupported lifecycle ordering,
dependency bodies and continuations retain the existing conservative behavior.

This implements the proposal's shared acquisition migration for existing coverage. New
hook/dependency resolution, expanded framework APIs, standalone Starlette registration,
Python model-assisted registration discovery, Python NoSQL and general Python-to-browser
linkage remain deferred features. Existing FastAPI/Starlette upload/file-response support
is preserved; this is not a claim of complete framework coverage.

## Compatibility evidence

`TestPythonInputPredecessorBaseline` freezes the complete reports of five retained fixture
repositories: routes, dynamic VulnPy, command injection, path traversal and outbound.
Hashes were recorded before product changes. Projecting out only new input facts and
reattaching predecessor components reproduces those hashes. Existing SQL discovery and
predecessor effective-request digests remain unchanged; their expected hashes were not
replaced to accommodate this refactor.

`TestPythonInputRequestCompatibility` checks all assessable candidates in those five
fixtures. It verifies unchanged operation contracts/questions, every registered answer
choice under identical deterministic response sets, identical resulting assessments,
valid fresh offline replay and rejection of historical requests against changed facts.
The 184 fixture candidates preserve their classifications across these response sets.
The tests do not claim that stub answers establish source-level accuracy.

New requests intentionally include `input_facts` and `source.python-input-v1` provenance.
They cannot reuse historical exact-request traces. Saved reports without these optional
facts retain their old component selection; no report schema or retained raw answer was
rewritten. Existing Python SQL local-server tests and command/path/SSRF policies continue
to verify vulnerable, protected and unresolved outcomes and JSON/HTML/SARIF parity.

`TestPythonInputFacts`, `TestPythonInputOrigins`,
`TestPythonInputAnnotationAndPathFacts`, `TestPythonInputConditionalInvocations` and
`TestPythonInputSelection` and `TestPythonInputSourceModuleIsolation` verify source/transfer
consistency, invocation-local bindings,
origin distinctions, absence of invented type guarantees, preserved gaps and rejection
of malformed provenance or unsupported language/family combinations.

## Full Python source comparison

The refactor and an independently built archive of unmodified baseline `4d05198` analyzed
all four available Python samples offline. After projecting out the acquisition extension,
the entire serialized predecessor report matched byte-for-byte for every sample, including
registration/dispatch identities, sources, transfers, gaps, API models and component selection.

| Sample | Revision | Entries | Candidate uses | Result |
| --- | --- | ---: | ---: | --- |
| VulnPy | `b81885e58283a3449b578d20c20557aff637e5ea` | 2,214 | 3,260 | Exact predecessor match |
| ThreatByte | `ede28f27e7e5061866a67b19b6088df4dd11c569` | 24 | 62 | Exact predecessor match |
| python-insecure-app | `b188493768ca2c1ef003e08148fb2e4577219c36` | 1 | 2 | Exact predecessor match |
| vulnerable-flask-app | `a67cbe590698dc4a0422f28e2495a40af559e257` | 19 | 30 | Exact predecessor match |

The 3,354 candidate uses preserve their prior evidence. Of these, 3,353 HTTP uses receive
shared acquisition facts; the remaining browser use retains its existing representation.
VulnPy retains 61 command contexts across the existing eleven-adapter corpus, including
Django sync/ASGI and Falcon sync/ASGI variants. Existing full-suite source acceptance tests
check the pinned independent command matrix, including upload/thread and Erlik controls.
Unique sinks and registration-specific contexts retain their separate existing identities;
these counts are candidate coverage, not fresh model-confirmed findings.

All four checkouts were clean including ignored files before and after comparison, at
identical revisions. Targets were read only: no execution, dependency installation or edits.
Local hashes, per-family counts and audit output are retained in the ignored execution
record under `.zazz/ephemeral/` rather than embedded source-containing reports.

## Verification commands

- `go test ./... -count=1` — passed, including pinned source acceptance where available.
- `go test -race ./... -count=1` — passed (parser source acceptance: 492.458 seconds).
  The final same-file provenance guard and its regression also passed the scoped race suite.
- `go vet ./...` — passed.
- `go build ./...` — passed with a clean final build log.
- `gofmt -l cmd internal` and `git diff --check` — passed.
- Changed-document relative links, whitespace, conflict markers and final newlines are checked
  manually with a scoped script; this repository declares no Markdown formatter.

Verification uses Go 1.27.3 and Apple clang on macOS arm64, satisfying the declared Go 1.27.2
minimum. Local HTTP stubs require localhost access. The offline evidence above makes no model-accuracy claim. The user subsequently authorized
full paid Python validation with `gpt-6-luna`, across all existing families, including
VulnPy input validation. The user explicitly approved transmitting source-derived evidence from the four sample
checkouts to OpenAI Decisions. The complete all-family pass finished with **3,354/3,354
completed assessments**, all HTTP 200, no failed/unassessed contexts, and no provider fallback
or automatic retries. Every decision replayed against fresh source: **3,354/3,354**, zero
mismatches and zero missing traces. All four JSON/HTML/SARIF views preserve canonical findings,
raw assessments and input facts. Target revisions and clean status remained unchanged.

| Python app | Requests / exact replays | Input tokens | Canonical report outcomes |
| --- | ---: | ---: | --- |
| vulnpy | 3,260 / 3,260 | 16,014,526 | 346 confirmed_vulnerability, 2,899 needs_evidence, 15 poor_practice |
| ThreatByte | 62 / 62 | 302,537 | 6 confirmed_vulnerability, 20 needs_evidence, 3 poor_practice, 33 protected_for_claim |
| python-insecure-app | 2 / 2 | 7,067 | 1 confirmed_vulnerability, 1 needs_evidence |
| vulnerable-flask-app | 30 / 30 | 98,624 | 8 confirmed_vulnerability, 22 needs_evidence |

Total provider-reported input tokens: **16,422,754**. All 2,830 VulnPy standalone
input-validation contexts were included and remain Review without an established policy.
The complete published VulnPy HTML is about 93 MiB; complete gzip JSON/SARIF are about
14/23 MiB. All are below GitHub's per-file cap and retain every assessed record.

Fresh ThreatByte source controls preserve protected bound SQL for `/profile` and the
three `/signup` statements, vulnerable dashboard SQL and its raw template output, and
the stored profile-country `safe` bypass. Autoescaped profile fields retain their
existing stored-origin Review limitation; encoding uncertainty is not fabricated.


## Review corrections and full-report publication

Independent Standards and Spec reviews found the acquisition migration aligned with
its bounded contract. The Standards review caught unresolved FastAPI dependency values
being labeled query/path inputs; recognized `Depends`/`Security` defaults and `Annotated`
metadata now retain unknown origin without changing legacy flow. Direct, aliased,
qualified and path-match cases pass normal and race checks. None of the four target
snapshots uses those bindings, so existing paid requests remain valid.

The complete post-review race suite passed again (parser 486.145 seconds), followed by
scoped acquisition race checks for the final annotation correction. The offline exporter
now accepts saved reports up to 512 MiB: the former 64 MiB bound rejected the scanner's
own full 206 MiB VulnPy JSON. The CLI race suite passed after this limit-only change.

Full-sized publication trials retained all 3,260 JSON/SARIF records. Plain HTML is about
88 MiB; complete JSON/SARIF are losslessly compressed to fit GitHub's documented 100 MiB
per-file bound. The preview gzip files were about 12 and 21 MiB. Small-report compressed
round trips preserve canonical equality and exact SARIF bytes; repeated refresh hashes
are stable. No records or model answers are dropped for publication.

The three smaller fresh reports pass their source case checks: FastAPI 3/3, Flask 8/8,
ThreatByte 18/18. ThreatByte's older inventory kind for the payload-controlled picture
fetch was reconciled from outbound observation to the already implemented SSRF contract,
with direct source rationale. Its historical published snapshot had that same outdated
kind plus excluded validation cases; this was not a new refactor regression.

The older VulnPy evaluator initially returned 5/10 because its Jinja selector still
pointed at the render call and four controls demanded warnings for finite registrations
that the existing adapters now resolve. Direct source review corrected the Jinja anchor
to the actual template output (`apps/templates/jinja/xss.html:30`) and retained its former
call location as provenance. The positive remains raw-output XSS, already recognized in
the preceding published report. Four coverage controls now require either source-backed
resolved registration/dispatch/invocation evidence or their explicit warning; missing
both fails. No positive was dropped or relabeled safe. All ten source/coverage checks now
pass, with historical anchors and expectations retained as correction metadata.

The user requested committing/pushing refreshed Python reports and implementation on
the feature branch, with a draft PR into stage and human-owned merge. Node/TypeScript
paid scans and their sample artifact files are outside this publication update.
Future routine Python comparisons skip standalone input validation; this complete run
includes it. With this unchanged source corpus, skipping validation reduces the four-app
assessment count from 3,354 to 496. Old/new equivalence-signature audits have identical
counts, so the refactor did not increase the number of distinct requests.


Final independent source-case checks pass **39/39**: VulnPy 10/10, ThreatByte 18/18,
FastAPI 3/3 and Flask 8/8. Jinja's corrected sink anchor and all four resolved-registration
controls are source-backed; missing both registration evidence and a warning fails the
negative control. Node/TypeScript sample files are unchanged. The implementation plan's
delivery list and vulnerable-app metrics catalog now include this completed Python work.
