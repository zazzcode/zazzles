# Python adapter implementation and evaluation

[Contract](../specifications/python-support.md) · [User guide](../../docs/scan/python-support.md) ·
[Sample reports](../../docs/samples/README.md) ·
[ThreatByte detection checklist](threatbyte-detection-guide.md) ·
[FastAPI answer guide](python-insecure-app-detection-guide.md)

## Delivered behavior

The Python adapter uses Tree-sitter Python v0.23.6 and supplies the existing graph, versioned decision
protocols and JSON/HTML/SARIF pipeline. It discovers Flask/Blueprint, RESTX Resource and FastAPI routes,
tracks a bounded value-flow subset, verifies DB-API/logging/HTTP bindings and models Flask/Jinja and
explicit FastAPI HTML. Inline template scripts reuse the browser adapter, including verified jQuery
input-to-HTML flow. No application code, dependency installation, database query or outbound request
from the targets was executed.

Input validation remains separate from SQL/XSS protection. Source-backed forms can establish policy
for the matching handler; client constraints do not establish server enforcement. For ThreatByte
signup, the form declares email syntax, while the backend shows presence/password-match checks.
The live assessment reports insufficient validation on the insert, independently of its sufficient
SQL parameter binding. Missing business requirements remain Review. Policy-backed standalone validation now reports that exact email-format defect independently,
while six required-only fields retain protected presence-enforcement claims. Query validation
facets are not additional independent defects.

## Pinned corpus and final results

| Target | Revision | Route/method entries | Browser entries | Records / assessed | Static SQL/XSS findings | Other outcomes |
| --- | --- | --- | --- | --- | --- | --- |
| ThreatByte | `ede28f2` | 23 | 1 | 56 / 56 | 4 | 41 protected, 8 needs-evidence, 1 construction-practice, 1 validation-practice, 1 destination-review |
| python-insecure-app | `b188493` | 1 | 0 | 2 / 2 | 1 | 1 validation-review |
| vulnerable-flask-app | `a67cbe5` | 19 | 0 | 24 / 24 | 4 | 20 needs-evidence |

The nine static findings match source-reviewed positive discovery cases: two SQL injection cases,
ThreatByte reflected/stored/DOM XSS, FastAPI HTML/template-source XSS, and three Erlik raw-response
paths. One additional source-backed email-format practice defect is assessed separately.
All [29 scoped case checks](../../docs/samples/evaluate-python.py) pass. This is case discovery
and classification evidence, not exhaustive recall, zero false positives on every operation, runtime
exploitation, or independent human findings review. The same agent reviewed source and implemented
the adapter; expected labels were kept separate from detector code and model evidence.

## Accuracy iterations

- Initial source review corrected the handoff: Erlik `/welcome` returns JSON and is an XSS negative;
  `/welcome2` returns raw HTML text. The initial implementation found seven of the final nine
  reviewed SQL/XSS cases.
- The first sample loop exposed a missing exception-body grammar shape. Prefix environments and
  exception preconditions now preserve input assigned before a failing operation, recovering
  Erlik's exception-return case.
- Source review found ThreatByte's inline jQuery comment append, absent from Python-only and saved
  comparator results. Snapshot-preserving script extraction and the existing browser flow adapter
  recover this ninth case. Native DOM append(string), fake bindings and escaped siblings are controls.
- Added method feasibility so POST-only bodies are not assigned to GET entries. Deduplicated value
  evidence and bounded helper/path expansion. Relevant unknown pre-use calls block claims without
  blocking a query on an unrelated field.
- Paired tests cover escaped versus raw/unknown branches, script/URL contexts, Markup/safe versus
  actual escaping/forceescape, imports and keyword helpers, stored-field origins, literal versus
  parameterized SQL, logger bindings, password/email content versus derived facts and outbound slots.
- Source-backed form policy supplies concrete validation questions without treating HTML required/type
  attributes as backend enforcement. Standalone fields with unknown policy stay Review.

## Live calibration and disagreement

The user authorized `gpt-6-luna` only and ultimately removed the request-count cap. There were **184
live requests**, all HTTP 200, totaling **833,272 reported input/total tokens** and zero reported
output tokens for this Decisions endpoint. Every current record has a completed assessment. The original pass used 78 calls; shared trace hardening and scoped validation calibration added 106. Exact request/response traces and the
append-only attempt ledger are local; reports retain answers, probabilities/confidence and usage.
Confidence never establishes a verdict. Unchanged requests were replayed only after exact payload,
model and question-version matching; changed evidence received a fresh assessment.

Two model overclaims were caught by structural policy:

- ThreatByte's dynamic update columns are assembled from explicit key allow-lists while values are
  bound. The model answered vulnerable, but unsupported comprehension/key reasoning remains a
  blocker. A construction concern is retained; no confirmed injection claim is emitted. Precise
  allow-list/comprehension modeling remains a follow-up.
- Erlik logs a literal internal role mailbox. The model called it personal data; email syntax alone
  does not establish privacy or a person-identifying value. A generic sensitivity blocker, tested
  against overconfident responses, keeps that candidate Review. Database-result and whole-session
  logging also remain Review. Request password/email/header content controls are tested separately.

Some escaped stored fields received model answers inconsistent with static facts or lacked complete
origins. They remain needs-evidence. Unknown subprocess return content is not converted into XSS
confirmation. Lack of model agreement does not erase an established construction-practice concern.

## Shared trace hardening and validation correction

The [implemented design](../architecture/trace-judgment.md) now supplies an explicit static trace,
SQL operand roles, storage keys and a supplied/missing role ledger for all language adapters.
Focused surrounding template markup is available for Python and JS/TS; it resolved the two
previous unknown attribute contexts in ThreatByte. A richer bundle cannot close a canonical blocker.

The first validation calibration overclaimed five required-only fields despite actual rejecting
presence guards. That iteration remains in raw logs. `validation-use-v2` supplies the complete
named-field constraint list, excludes unrelated field policies and rejects invented stronger
requirements. Fresh answers now match seven independent source controls: one unmet email-format
policy and six enforced required-only policies. This correction improves precision; extra findings
are not treated as success. All original nine SQL/XSS positives remain supported.

Additional generic controls cover nested dictionary alternatives, unresolved values, relative
package helpers, request aliases, unsupported variadic parameters, real/shadowed PostgreSQL/MySQL
bindings, SQL text/parameter roles and constant Jinja templates with autoescape on/off/unknown.
Alternative bindings cannot borrow a sibling driver contract or escaping setting. These are scanner
fixtures, not edits to benchmark apps. The report guardrails prevent inconclusive/blocked claims
from retaining green styling or a protection title. Scoped guidance is shared by HTML/JSON/SARIF.

The [documentation inventory](../../docs/samples/python-documented-claims.md) maps every advertised
README family, additional local test/Swagger material and author articles to supported or unsupported
scope. It does not imply all advertised vulnerabilities are implemented or precisely located.

## Comparator observations

| Target | Semgrep CE 1.183.0, snapshot 20261101 | Bearer e3753de, rules 82c335f | Source-backed differences |
| --- | --- | --- | --- |
| ThreatByte | 7 results | 6 results | Semgrep reports two locations for the dashboard SQL case; neither saved baseline reports the three reviewed XSS cases or outbound URL. Other findings include MD5, traversal, debug and IaC. |
| python-insecure-app | 0 | 0 | Source review and Zazzles identify the HTML/template-source flow. README SSTI/SCA/secret claims are separate families. |
| vulnerable-flask-app | 17 results | 2 results | Both report SQL; Semgrep also covers raw responses and several out-of-scope families. Neither saved baseline reports render_template_string at line 51 or the logging cases. |

Normalized baselines and upstream attribution are under each sample directory. A comparator's result
count spans its own rules and can contain multiple locations for one issue; these totals are not
precision/recall scores. No additional rule-pack downloads were made.

## Verification and provenance

Native Go 1.27.3 darwin/arm64, with `GOTOOLCHAIN=local`, `GOPROXY=off` and a local ignored GOCACHE:

- `go test ./internal/... ./cmd/...` and `go test -race ./...` pass, including existing JS/TS tests.
- `go vet ./...` and `go build ./...` pass; changed Go files are gofmt-clean.
- Python route golden, mixed-language CLI/bundle test, deterministic evidence, paired precision
  controls and a local HTTP-stub Python evidence→decision→report test pass.
- All 29 case checks pass on curated reports. Source excerpt byte ranges and hashes were checked;
  canonical JSON/SARIF parse, every record has an assessment, and public roots contain no local paths.
- ThreatByte and Erlik remained clean at their pins. Finder metadata appeared in the original FastAPI
  checkout during final verification; it was preserved. Final analysis used a fresh clean upstream
  clone at the same pin with identical source hashes and two exact decision replays, no extra calls.

Raw runs remain under `_test-findings/<app>/run-<id>/`; the local results report names exact runs and
records source checks. The source clones were not remediated or dependency-modified. At the original evaluation closeout, work was committed
and pushed on `python-support-base` without PR publication, integration push or merge.
The user subsequently authorized the terminology closeout and draft PR publication into `stage`;
merge remains human-operated.

## Remaining boundaries

No selected app uses a MongoDB driver, so Python NoSQL is unimplemented/out of corpus. Dynamic
registration, custom decorators, arbitrary helper/control/heap semantics, loops/comprehensions,
full template inheritance/macros, exact stored-row identity and deployed schema verification remain
incomplete. Outbound destinations are review candidates, not a new SSRF verdict engine. New
vulnerability families, SCA and other languages remain separate work. General novel-repository
coverage and independent accuracy measurements still require more labeled controls and review.

## Added VulnPy corpus and living answer guides

The living [ThreatByte guide](threatbyte-detection-guide.md) independently verifies profile/signup
SQL binding and dashboard SQL injection, with detailed current-family and future-branch checklists.
The [FastAPI answer guide](python-insecure-app-detection-guide.md) distinguishes its two XSS source
witnesses from SSTI and other planned families; the author article does not establish a SQL sink.

[VulnPy](vulnpy-detection-guide.md) is an additional coverage corpus, not part of the original 29-case
success claim. Its generated registrations/trigger dispatch hide three SQL variants and generated
Flask/FastAPI XSS from the current route subset. The separate Jinja Environment path remains an
unresolved candidate. Six source-positive cases remain known misses; four checks require explicit
coverage warnings. Offline results: 11 static entries, six unassessed records, no model calls.
Semgrep CE reports eight findings and Bearer 21 with pinned local rules; neither reports the three
SQL variants. The initial sandbox-failed Bearer worker run was rejected and rerun successfully.
Full details and provenance live with the sample; new framework/family work remains future branches.

## Architecture and terminology closeout verification

The naming migration and [implemented architecture](../architecture/README.md) now distinguish Analysis
Guidelines, candidate uses, route inventories, evidence trace graphs and the planned repository graph.
The [technical approach](../../docs/technical-approach.md) records design strengths, primary SAST/prior-art
references and evaluation limits. Dynamic route/GraphQL entry-model pressure points are documented
as future design work, not implemented coverage.

Verified with native Go 1.27.3, `GOTOOLCHAIN=local`, `GOPROXY=off` and the local ignored Go cache:

- `go test -race ./...`, `go vet ./...`, `go build ./...` and
  `go build -o bin/scan ./cmd/scan` passed. The sandbox initially blocked loopback listeners;
  the complete race suite passed with local HTTP-stub access. No tests were skipped.
- `gofmt -l cmd internal` and `git diff --check` are clean. Changed Markdown relative links
  and all incoming main-architecture anchor references resolve. No repository doc linter is configured.
- The built CLI scanned TypeScript and a source-only Python fixture, generated schema-2 bundles
  with guideline metadata and unassessed model statuses, and exported both to HTML/SARIF.
  `--analyze` and compatibility alias `--strings` produced byte-identical JSON.
- All seven historical sample reports exported to HTML and SARIF without modifying saved JSON.
  The original 29 saved-report case checks still pass (18 ThreatByte, 3 FastAPI, 8 Erlik).
  These checks validate historical evidence, not new live judgments.
- Four golden fixtures preserve exactly the previous entries, evidence, dependencies and gaps;
  analysis goldens change only schema and renamed/versioned guideline metadata. Route JSON stays schema 1.
- Tests cover schema-1/schema-2 export, legacy metadata decoding, both provider guideline envelopes
  and rejection of saved decisions after guideline text/key changes, even with unchanged source.

No paid model calls or target application execution occurred. Historical source-containing artifacts,
answers and provenance remain unchanged. Fresh model inputs use renamed/versioned guidelines;
existing answers cannot serve as calibration of those changed requests. The known VulnPy misses
and remaining dynamic-registration limits are unchanged.
