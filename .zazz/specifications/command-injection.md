# Command Injection Analyzer: request-to-process analysis

## 1. Capability and delivery boundary

Implement a bounded **Command Injection Analyzer** for JavaScript, TypeScript and Python on the existing shared analysis
engine and embedded analysis-pack architecture. Trace request values into verified process operands, distinguish shell
syntax from executable/argument control, and produce source-backed findings, Protected and Review records in JSON, HTML
and SARIF.

The implementation includes **creating every missing command analysis-pack component**, not just wiring a detector to
existing packs. TypeScript `/api/ping`, Erlik and portable controls establish the first slice. Final acceptance is an
iterative full, live judged scan of **Juice Shop, VulnPy, nodejs-goof and vulnerable-typescript-app**, detecting every
independently documented command-injection positive and producing three-format reports for human review. §8 defines the
independent references and §9 the fix loop.

This session prepares documentation; implementation starts when the user instructs a new session to implement this
contract. One deliverable uses the existing `command-injection` worktree/branch; one future draft PR targets `stage`,
with human-owned integration. The user separately authorized committing/pushing the documentation checkpoint. No extra
worktree or split/stack is required.

**Terminology:** an Analyzer is the capability spanning extraction, interpretation, judgment and reporting; an analysis
pack supplies versioned knowledge composed of reusable analysis components. The shared analysis engine supplies common
infrastructure. Follow the [canonical vocabulary](../architecture.md#analyzer-terminology). `command` remains the
internal family key and `pack.command` the pack ID. Existing IDs and locked specifications are unchanged.

## 2. Focused required reading

Read this contract end to end. It contains the language, scope and acceptance requirements; the implementation plan and
backlog are **not implementation prerequisites**.

| When | Read | Implementation purpose |
| --- | --- | --- |
| Session start | [AGENTS.md](../../AGENTS.md), [orientation](../docs/zazzles-agent-orientation.md#task-reading-paths), repository `.agents/skills/spec-driven/SKILL.md` | Local authorization, shared worktree state and execution discipline; old session checkpoints do not override this contract's later user instructions |
| Before catalog work | [Pack ownership](../architecture/analysis-packs.md#boundary-and-ownership), [selection](../architecture/analysis-packs.md#descriptor-and-selection-contract), [bounds](../architecture/analysis-packs.md#bounds-and-compatibility) | Same runtime integration and provenance as other analyzers; dated verification ledgers need not be read in full |
| Before evidence/policy work | [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes), [trace gates](../architecture/trace-judgment.md#separate-judgments-and-gates), [input-validation rules](../../docs/analysis/input-validation.md) | Value/control evidence, claim-specific blockers and independent field policy |
| Before source evaluation | App references in §8; [sample policy](../../docs/samples/reference-policy.md) | Independent labels, pins, target integrity and separation from model inputs |
| Before final sample/doc delivery | [Sample and implemented-state delivery](../evaluation/command-injection-sample-delivery.md) | Twelve final reports, curated GitHub samples, README links and delivered analyzer documentation |
| Before verification/live calls | [Contributor checks](../../docs/contributing.md#contributing), [decision-model guide](../../docs/decision-models.md), [toolchain guidance](../docs/worktree-setup.md#linked-computer-agent-toolchain) only when applicable to the execution host | Correct CLI, credentials, explicit provider/caps and native versus linked Go setup |
| Before changing files | [Standards index](../standards/index.yaml); matched [code structure](../standards/code-structure.md), [testing](../standards/testing.md), [docs hygiene](../standards/docs-hygiene.md) | Load only matched standards; use `doc-check` for documentation and `spec-hygiene` when revising this contract |

Read these code patterns when touching the corresponding stage, rather than entire packages:

- Catalog: `internal/analysispacks/{families,descriptors,select,material}.go`; mirror the XSS/SQL
  family integrations and `internal/analysispacks/{xss,xss_selection}.go` where appropriate.
- Extraction/assembly: `internal/parse/{flow,python_calls,analysis,python_modules,xss_claims}.go`;
  inspect existing binding/helper/control helpers only as required by the selected witness.
- Judgment: `internal/judge/{injection,client,policy,bundle,xss,answer_details}.go` and `trace.go`.
- Presentation: `internal/report/{findings,finding_types,scoped_guidance}.go` and `bundle.go`.

Operation contracts MUST cite applicable official semantics: [Node
child_process](https://nodejs.org/api/child_process.html), [Python
subprocess](https://docs.python.org/3/library/subprocess.html#popen-constructor), [Python
os](https://docs.python.org/3/library/os.html#os.system), and [OWASP
defenses](https://cheatsheetseries.owasp.org/cheatsheets/OS_Command_Injection_Defense_Cheat_Sheet.html). These were
reviewed on 2026-11-07. Verify the target-relevant runtime/platform behavior; the scanner host and moving documentation
versions are not evidence of the target's deployed environment.

## 3. Invariants

- Static adapters establish actual import bindings, operand roles, source hashes and value/control
  transfers. Components cannot invent an edge, entry or trusted API binding.
- The existing catalog owns selected operation contracts, guidance, questions and obligations.
  Mandatory Go completeness/consistency gates cannot be removed by model answers or pack content.
- Shell syntax, executable choice, argument interpretation and field-policy enforcement are separate
  claims. Shell-disabled argument arrays alone cannot establish overall protection.
- Preserve invocation/field/operand/branch identity. Unknown relevant guards/transfers remain blockers;
  a supported unsafe path can establish a scoped finding while unresolved siblings remain visible.
- Only final `protected_for_claim` is green. Preserve raw answers; confidence never closes a blocker.
  A source-confirmed vulnerability does not claim runtime exploitation or independent Findings Review.
- Preserve existing candidates' IDs, evidence, effective request bytes and historical answers except
  explicitly recorded command-acceptance prerequisites. New entry coverage may add new candidates;
  it is not permission to change unrelated analyzer judgments or silently rewrite old baselines.
- Targets remain read-only: no application execution, unsafe commands, installs, dependency caches,
  source remediation or checkout changes inside them. Live calls are only the §9 authorized scans.

## 4. Implementation scope

The allowed roots are `internal/`, `cmd/scan/`, `docs/`, `.zazz/architecture/`, `.zazz/project/`, `.zazz/evaluation/`
and this specification/index. Preserve the documentation already changed in this worktree; record the starting diff and
source hashes before implementation. Locked predecessor specifications MUST NOT be edited. File lists below are bounded
file groups, not a general rewrite.

| Paths / file groups | Change | Responsibility |
| --- | --- | --- |
| `internal/analysis/{analysis,command}.go` and compatibility tests | Modified / new | Optional command facts, serialized operands/paths and schema1–4 compatibility |
| `internal/analysispacks/command*.go` | New | Contracts, descriptors, selected questions/choices and tests |
| `internal/analysispacks/{families,descriptors,catalog,select,material,contracts}.go` and tests | Modified as needed | All family dispatch, descriptor/material validation and provenance hooks |
| `internal/guidelines/command*.go`, `command_javascript.md`, `command_python.md`; `guidelines.go`, `families.go` and tests | New / modified | Independently versioned command guidance; existing family material unchanged |
| `internal/parse/command*.go`, `python_command*.go`, testdata `{javascript,typescript,python}/command-injection/` | New | Recognition, operands, completeness assembly and portable fixtures/goldens |
| `internal/parse/{flow,python_calls,python_flow,analysis,python_modules}.go` and tests | Modified | Execution hooks and final claim assembly before catalog attachment |
| Existing `internal/parse/` binding, helper, control, regex-projection, entry/dispatch files; new `python_command_entries*.go` if needed | Modified / new, only for §8 witnesses | Source-backed prerequisites for generated routes, named frameworks, loops, uploads and thread dispatch; add generalizable fixtures, never target-name exceptions |
| `internal/judge/command*.go`; `{injection,client,policy,bundle,evidence_trace,evidence_coverage,trace}.go` and tests | New / modified | Questions/choices dispatch, wire facts, policy, replay and parity |
| `internal/report/command*.go`; `{findings,finding_types,guidance,scoped_guidance,sarif}.go` and tests | New / modified | Command classification, scoped guidance, CWE and three-format parity |
| `cmd/scan/*command*test.go`, CLI scheduling helpers only if required | New / modified | Full-scan eligibility, limits, incompleteness and bundle verification |
| `docs/analysis/command-injection.md`, `docs/analysis/README.md` | New / modified | Public implemented rules and guidance |
| `docs/samples/{juice-shop,vulnpy,nodejs-goof,vulnerable-typescript-app}/`, sample README/index and refresh tooling only as needed | Modified / new artifacts | Final canonical samples, metadata, attribution and links |
| `.zazz/evaluation/{command-injection-sample-delivery.md,vulnerable-typescript-app-detection-guide.md,command-injection-results.md,vulnpy-detection-guide.md,vulnpy-command-injection-sources.json,nodejs-goof-capabilities.md,juice-shop/}` plus command case/evaluator files | New / modified | Independent reference matrix, reproducible comparisons and acceptance evidence |
| `.zazz/project.md`, `.zazz/architecture.md`, `.zazz/architecture/{analysis-packs,evidence-and-claims,trace-judgment}.md`, `.zazz/project/{implementation-plan,01-functionality}.md`, README/index | Modified as needed | Synchronize delivered capability/limits after verification; not extra required reading for code work |

Identify exact prerequisite files and tests in the run log before editing. The user's full-corpus acceptance instruction
includes bounded command-relevant entry/dispatch/flow repairs necessary for all §8 positives. It supersedes the earlier
permission to leave VulnPy command misses unresolved. Do not expand unrelated vulnerability classes, perform general
dynamic-route/report redesign, reimplement XSS, migrate logging, add SCA/secrets, build public plugins, or introduce an
arbitrary whole-program/heap interpreter. Material changes beyond these command prerequisites need steering; never
declare final acceptance complete by narrowing the expected corpus.

## 5. Decisions and concrete implementation contract

### 5.1 Required analysis-pack structure

Create family registration for `command_execution_candidate` with `RequiresAPI=true`, protocol `command-components-v1`,
HTTP for JS/TS/Python and existing JS/TS GraphQL/unary gRPC entries. Browser-only entries cannot select a Node process
contract. All new Python framework coverage is bounded HTTP/request entry modeling, retaining the shared entry/context
records.

The deliverable MUST create/version/register all of the following components:

| Component | Required content / behavior |
| --- | --- |
| `pack.command` | Versioned family root and pinned dependencies |
| `claim.command` | Exact ordered questions/choices from §5.4, with interpretation material |
| `evidence.command` | Mandatory evidence obligations, unioned with Go policy roles |
| `flow.command` | Compiled adapter owner references and explicit supported transfer/coverage limits |
| `language.command.javascript`, `language.command.python` | Selected versioned JS/TS or Python command guidance |
| `api.node-child-process-shell-v1`, `api.node-child-process-argv-v1`, `api.python-os-shell-v1`, `api.python-subprocess-v1` | Catalog-owned operation contracts selected only after verified binding |
| Existing applicable `entry.http`, `entry.graphql`, `entry.grpc` | Reused entry descriptors; new compiled prerequisites must be described honestly |

Extend explicit switches in `Families`, `familyProtocol`, `familyContract`, `contractIDs`, `flowID`, `descriptors`,
selection/applicability and material validation. Do not let command dispatch fall through to NoSQL contracts or generic
legacy questions. Parse attaches the same catalog selection that judge revalidates with `ForUse`; JSON preserves
versions/digests and effective obligations. Malformed catalog fails before transport; missing/unverified API retains
Review and zero model calls.

Why: every analyzer must use the accepted source-facts → catalog selection → selected material → Go policy path. No
parallel command-only catalog, hardcoded provider prompt or legacy fallback is permitted. Selected closures retain 32
components / 16 KiB material / 64 KiB final request bounds, with explicit failures, lossless existing compaction and no
dropped source/controls to fit a body.

Create separately embedded `command_javascript.md` and `command_python.md` guidance, each version 1, with distinct IDs
`zazzles.command.javascript` and `zazzles.command.python`. Load via a command-only family path; do not add them to
default language selection or change existing guidance bytes/versions. This avoids changing every existing analyzer's
request merely to add a new family. Validate missing or duplicate required sections; include actual selected guideline
identity in command provenance.

### 5.2 Supported APIs, configuration and discovery

| Verified operations | Required effective operand mapping |
| --- | --- |
| Node `exec`, `execSync` | Shell command; custom `shell` selects interpreter. Invalid/non-string disabling options cannot turn this into a verified safe argv API |
| Node `execFile`, `execFileSync`, `spawn`, `spawnSync` | Executable and argument array; default/false shell-disabled versus true/string shell-enabled; handle omitted argv/options and callback overloads |
| Python `os.system`, `os.popen` | Shell-command operand, distinct from output mode/handling |
| Python `subprocess.run`, `Popen`, `call`, `check_call`, `check_output` | Positional/keyword args, shell and executable override; default shell=False; string and literal list/tuple forms |

Support direct ESM named/namespace bindings, bare/core `node:child_process`, CommonJS direct member and destructuring
requires, Python module/from imports and immutable local callable aliases. Fake objects, shadowed require/import
symbols, reassignment, local Python module shadowing and source-visible monkey-patches cannot acquire a verified
contract. Dynamic shell/options, spreads, duplicate/computed properties, unmodeled mutations and *args/**kwargs retain
relevant gaps.

With Python shell=True on POSIX, a sequence's first item is shell command text; remaining items are shell arguments, not
strings concatenated into that command. With shell=False, a command string is not automatically shell-split. Node
shell-enabled argv calls are not ordinary separated-data execution. Test these boundaries against the cited operation
contract. Track executable overrides, request-controlled shell/configuration, cwd and env separately;
input/stdout/stderr/timeout alone are not command text. Do not manufacture command dependencies from callback output
parameters.

Record POSIX as a declared analysis assumption, never inferred from the scanner host. Explicit Windows/batch or
conflicting runtime semantics remain Review. An API-shell-disabled call to a literal POSIX `sh`/`bash` with `-c` still
has an interpreter command operand: retain API shell mode separately from effective shell interpretation. Model that
literal slot; cmd /c, PowerShell and unknown/custom interpreter semantics remain blocked in this slice. A bare fixed
program name has unresolved PATH selection unless justified; protection controls use a fixed absolute executable and no
dynamic env.

Emit a candidate when request data reaches command text, executable, argv, executable override or shell configuration.
Exclude constant-only calls and data-only stdin/output controls. Ambiguous plausible process calls retain Review/binding
gaps; a demonstrated fake is a negative. Preserve upstream source through Goof's regex capture, supported
helpers/branches and the §8 Python adapters.

### 5.3 Shared evidence and claim assembly

Add optional `Command *CommandFacts` as `command,omitempty`; preserve schema 4 additive compatibility. Use
`Completeness.ClaimKind="command_execution"`. Facts carry operation, contract ID, platform assumptions, API shell mode
and effective shell mode (`enabled`, `disabled`, `unknown`), interpreter, ordered operands and path-specific
protection/uncertainty. Operand slots are `shell_command`, `executable`, `argument:<index>`, `shell_option`,
`executable_override`; unknown argv shape is explicit. Each operand refers to dependency indices and constant/config
evidence in the candidate Context; each path refers to its dependency/control evidence and facet facts. Validate every
index/reference. Do not invent a second source store; wire facts refer to the existing deduplicated eN evidence table.

Required roles are `input_source`, `sink_binding`, `invoked_callable`, `control_flow`, `command_operands`,
`execution_configuration`; enforcing protection adds guard/constraint evidence. Union catalog obligations with Go
mandatory roles. Preserve exact source/span/hash and invocation identity. Evidence-role presence alone does not prove
adequacy. Unknown relevant pre-sink helpers, mutable operands, dispatch or guards block the affected witness; unrelated
response/output gaps do not. A raw branch and constrained/unknown sibling retain separate facts; no global safe bit is
allowed.

Create `assembleCommandClaims` and invoke it for JS/TS and Python after entry/flow extraction and before
`analysispacks.Attach` in the common AnalyzeWithChecks completion path. This MUST run with and without explicit check
files; input-validation/query builders must not erase the command claim. Reuse actual invoked callable and
middleware/control evidence, not blanket deletion of generic gaps. All-context protection requires complete relevant
coverage; an unsafe witness only requires its own source-to-sink path complete. Retain unresolved sibling coverage
without pretending it was analyzed.

Include command facts in `wireBundle`, compact representation and digest/replay. Existing evidence wire version 6
remains for unchanged candidates; command facts are additive under the new protocol. Advance presentation version 6 to 7
when the new family is delivered; preserve old raw answers.

### 5.4 Questions, answers and Go policy

The catalog owns these exact ordered names/choices; implement `CommandQuestions`/`CommandChoices` and wire
`questionsFor`, `questionChoices`, protocol dispatch, provider encoding/decoding and replay. Dispatch
`applyCommandPolicy` before generic injection policy. Both provider transports use the same selected material and
existing response envelope. `AnswerDetail` currently contains choice/confidence/probabilities, **not citations**; reuse
that contract. Source references come from scanner facts and policy reasoning, not invented required citation fields in
provider answers.

| Question | Choices | Facet |
| --- | --- | --- |
| `shell_syntax_protection` | `vulnerable`, `protected`, `not_applicable`, `unknown` | Can supported external text alter effective shell syntax? |
| `executable_control` | `unsafe`, `constrained`, `not_applicable`, `unknown` | Is executable/interpreter selection fixed or source-constrained? |
| `argument_control` | `unsafe`, `constrained`, `not_applicable`, `unknown` | Do supplied semantics establish dangerous option/interpreter control or enforced data-only constraints? |
| `protection_coverage` | `complete`, `incomplete`, `unknown` | Are relevant operand/path protection obligations established? |

| Condition after canonical evidence/consistency gates | Final assessment / presentation |
| --- | --- |
| Consistent unsafe facet plus an independently supported violating source path | `completed`, `confirmed_vulnerability`, protection `insufficient`; name that facet and any conditional execution assumptions |
| Every applicable facet protected/constrained, coverage complete, no blockers | `completed`, `protected_for_claim`, protection `sufficient` |
| Unknown/contradictory answer or missing role/binding/configuration/affected path | `needs_evidence`, protection `uncertain`; raw answers retained |
| Structural-only mode | `not_run`; Review, no green and no model-confirmed finding |
| Catalog/selection/decoding failure or oversized request | Existing failed/not_run convention with explicit reason; Review and zero calls for pre-transport failures |

Do not add an optional structural poor-practice route in this deliverable; deterministic source facts remain visible,
but final positive acceptance requires a completed source-consistent model judgment. Shell-disabled API plus data
operands gives shell facet `not_applicable` (unless explicit interpreter command); it does not prove executable/argument
protection. All-not-applicable is not green. A shell vulnerability answer against verified effective shell-disabled data
is contradictory. An unknown utility's options are Review, not a fabricated CWE-88 positive. Unknown siblings can
coexist with a complete unsafe witness; incomplete coverage can never support aggregate protection.

Protection fixtures use fixed absolute executables and source-backed finite allowed operand values, with rejecting
branches that terminate before use. Supply ordinary permitted literals that cannot be option/command syntax;
model-consistency gates reject optimistic claims on unguarded siblings. No universal utility allowlist is invented. TS
casts/annotations, Python annotations, length limits, blacklist replacement, exception handling and unrelated hashing
cannot establish protection. General quoting/`shlex.quote` adequacy remains Review unless an independently supported
constraint already establishes the exact facet. Field policy remains a separate existing validation claim.

### 5.5 Reporting and remediation

Register finding type `command-injection`, label **Command Injection**, and one record per process use/invocation with
separate facets. CWE-78 applies to supported shell-command defects; CWE-88 only to demonstrated option/delimiter
injection. Arbitrary executable selection must name that actual risk without fabricating a shell-syntax witness. Update
the command-specific branch in generic report status handling so a gated command `confirmed_vulnerability` becomes a
finding, not the fallback Review. Preserve source/entry/context, conditions, raw answers, blockers and provenance.

Protected guidance states what to preserve; Review names missing facts; findings identify the operand/control to repair.
Prefer eliminating process execution, otherwise a fixed trusted executable, separate arguments and actual
utility-specific constraints. `--` is not a universal utility contract. Do not recommend stripping arbitrary
punctuation, label every array call safe, or export verified fixes. JSON/HTML/SARIF must agree on unique record counts
and statuses. Distinguish five VulnPy sink source locations from repeated framework/method witnesses and separate
validation records.

## 6. Agent execution rules

One Contributor Agent works autonomously in the assigned worktree; no delegation is required. Use ignored
`.zazz/ephemeral/command-injection-run-log.md` for append-only evidence. Record starting branch/diff, uncommitted
checkpoint state, source baseline and commands. Missing log on the first implementation session means create it, not
stop. Preserve existing user work.

Use declared Go toolchain (go.mod currently 1.27.2), cgo, native/shared cached dependencies and ignored local GOCACHE.
Ordinary tests use only fixtures/local HTTP stubs. The user's 2026-11-07 direction explicitly authorizes the final full
source-transmitting OpenAI Decisions gpt-6-luna evaluations on all four pinned targets and necessary corrected rescans
during implementation; it does not authorize live calls during this documentation checkpoint, provider/model fallback or
target execution. Pass only the selected provider key to scanner children; never print keys or .env content.

For a real blocker (missing target pin, inaccessible provider, funding/transport failure), record unfinished acceptance
and continue independent work. Three identical failing attempts require root cause review and a changed strategy; they
do not permit weakening expectations or a success claim. If no authorized meaningful progress is possible, report the
exact blocker. Do not repeatedly pay for unchanged requests to seek a favorable answer. Human merge and final review
remain human actions.

## 7. Acceptance criteria

- **AC1 — JS/TS operands:** `/api/ping` and Goof-shaped fixtures retain input → cast/assignment or
  regex-capture → shell-command transfer, actual binding and hashes. `TestCommandJSOperands`.
- **AC2 — Python operands:** core system/Popen/check_output wrappers and positional/keyword/sequence
  forms retain actual request/operand/configuration evidence; constant/stdio siblings are negative.
  `TestCommandPythonOperands`.
- **AC3 — Policy matrix:** raw, protected finite-allowlist, untrusted executable, unknown utility,
  explicit interpreter, reject-without-return, mixed branches/invocations and conditional paths behave
  exactly as §5.4 in all three languages. `TestCommandPolicyMatrix`.
- **AC4 — Binding/configuration:** every listed operation and import shape has coverage; fake/shadowed/
  reassigned bindings, spreads/kwargs, shell options and unsupported platform facts cannot fabricate
  a verified protected call. `TestCommandBindingsAndOptions`.
- **AC5 — Complete pack:** every §5.1 component is created/registered/selected with valid versions,
  dependencies, roles, owner/limits and required guidance. Deterministic closure, applicability errors,
  malformed/missing material and bounds are tested with zero HTTP calls on failures.
  `TestCommandComponentSelection`, `TestCommandComponentFailures`.
- **AC6 — Judgment/replay:** both local provider transports receive only selected command material
  and exact source facts, dispatch all four questions/choices and enforce mandatory gates. Changed
  facts/source/roles/material/model/protocol reject replay; failures stay explicit.
  `TestCommandPayloadAndReplay`, `TestCommandPolicyMatrix`.
- **AC7 — Pipeline/report parity:** actual parsed HTTP fixtures in JS/TS/Python and existing JS/TS
  GraphQL/gRPC contexts preserve statuses, IDs, zero-use coverage, per-context isolation, separate
  validation and scoped guidance across JSON/HTML/SARIF. Browser entries gain no Node contract.
  `TestCommandPipelineParity`, `TestCommandCLI`.
- **AC8 — Compatibility/regression:** frozen existing candidates retain effective request bytes and
  facts; schema1–4 exports preserve old raw answers without invented command facts. New shared-entry
  prerequisites have documented expected deltas, preserving unrelated analyzer semantics.
  `TestCommandPredecessorRequests`, `TestCommandReportHistory`, existing family/replay suites.
- **AC9 — Portable source acceptance:** TypeScript ping, Erlik's two unsafe plus constant control,
  Goof capture and every required VulnPy sink/adapter/app path have independent expected traces,
  hashes and fixture/evaluator evidence. Known misses remain failing positives, not allowed Review.
  `TestCommandSourceCases` plus the §8 machine-readable source-case evaluator.
- **AC10 — Engineering checks:** scoped tests, `go test -race ./...`, `go vet ./...`, `go build ./...`,
  changed-Go formatting, scoped doc/link checks and `git diff --check` pass with the declared toolchain;
  source/target-integrity and scope checks pass. Public docs describe actual implemented limits.
- **AC11 — Final full judged scans and fix loop:** execute §9 on all four full pinned checkouts,
  compare independently documented expected command vulnerabilities and controls, and iterate fixes
  until all required positives have completed gated command findings and controls are correct.
  Deliver findings.html, findings.json and findings.sarif per app plus comparison/usage evidence and
  clickable final artifact links. Refresh GitHub samples/README links and final implemented-state docs
  per the delivery guide; Review/unassessed/binding warnings do not pass a known positive.

## 8. Test strategy and independent references

Table-driven parser tests assert evidence before model interpretation; parsed pipeline tests exercise selection,
encoding, decoding, Go policy and exports with optimistic and contradictory stub answers. Reuse existing
transport/compatibility tests. Add focused fixtures for each source-path prerequisite including framework registration,
loop/upload/thread transfer and Goof regex capture. No unit test imports or runs target code. Test
labels/comparators/reference documents never enter model bundles.

Resolve `<DEV_ROOT>` using the [workspace
convention](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root). The current local checkouts are
`<DEV_ROOT>/juice-shop`, `<DEV_ROOT>/vulnpy`, `<DEV_ROOT>/nodejs-goof` and `<DEV_ROOT>/vulnerable-typescript-app`; on
the current workstation DEV_ROOT is the user's `Dev` directory.

| Acceptance target / pin | Known-vulnerability analysis documents and source basis |
| --- | --- |
| Juice Shop `f189f521266f42c6bd05884468292000cee852ed` | [Command classification reference](../evaluation/juice-shop/command-injection-review.md), [evaluation index](../evaluation/juice-shop/README.md), [documented challenge registry](../evaluation/juice-shop/expected-challenges.jsonl), [review decisions](../evaluation/juice-shop/review-decisions.json), [sample provenance](../../docs/samples/juice-shop/README.md); check actual challenge source/tests before defining expected command findings |
| VulnPy `b81885e58283a3449b578d20c20557aff637e5ea` | [Command-injection source review](../evaluation/vulnpy-detection-guide.md#command-injection-source-reviewed-acceptance-cases), [review hashes](../evaluation/vulnpy-command-injection-sources.json), [existing source reference](../../docs/samples/vulnpy/reference.md) |
| nodejs-goof `add14ba59e98240d9e00a235dd7d42cd61ae9912` | [Command-injection case](../evaluation/nodejs-goof-capabilities.md#command-injection-source-reviewed-acceptance-case), [earlier results](../evaluation/nodejs-goof-results.md), [sample provenance](../../docs/samples/nodejs-goof/README.md); POST /create → routes/index.js:174 exec |
| vulnerable-typescript-app `7f8b240a2f02beba099da3632d1ba679ff8bc32f` | [Expected vulnerabilities with exact file/line references](../evaluation/vulnerable-typescript-app-detection-guide.md), [sample provenance](../../docs/samples/vulnerable-typescript-app/README.md); mandatory TS-CMDI-01 at src/server.ts:90 |
| Initial Erlik fixtures | [Source reference](../../docs/samples/vulnerable-flask-app/reference.md), pin `a67cbe590698dc4a0422f28e2495a40af559e257`; vulnerable-flask-app.py:53–58 /114–119 unsafe and64–68 constant control |

VulnPy's reference covers both cmdi.py core sinks, generated request paths through Flask, FastAPI, Quart, Django
sync/ASGI, Falcon sync/ASGI, Bottle, Pyramid, aiohttp and WSGI, plus direct loop, upload and conditional thread
witnesses. **All are final acceptance obligations**, including source-backed conditional contexts. Existing SQL/XSS
cases.json is historical and must not be rewritten. Goof's full checkout is required; its historical 22-file comparator
snapshot is insufficient.

Juice Shop's challenge registry is not an adjudicated command-injection answer key. Before judging, review relevant
source and documentation, distinguish direct command execution from code-injection/ SSTI payloads and
dependency/runtime-only demonstrations, and record each disposition. Do not invent a command vulnerability solely
because a test string mentions child_process. A zero expected-positive count is acceptable only with explicit
source-reviewed reasoning and a mandatory no-false-positive control; it cannot be assumed from a scanner's zero
findings.

Create a machine-readable independent matrix under `.zazz/evaluation/command-injection/` before observing new judged
results. Each case records target pin/file hashes, source/sink, entry/method/ mount context, path conditions, expected
positive/protected/negative and rationale. Include all reviewed exposures rather than only supported frameworks. Keep
unknown documentation leads separate until adjudicated; unresolved command leads cannot silently disappear at
completion. Evaluate unique sink coverage and per-context coverage separately. Update expectations only for
independently verified source mistakes, with the old label, rationale and evidence retained; never to fit output.

## 9. TDD execution, live evaluation and iterative fix loop

Integration skeleton (private signatures may adapt; stage responsibilities MUST remain):

```go
// internal/analysispacks/command.go: catalog-owned operations, descriptors and questions.
func CommandContract(id string) *analysis.APIModel { /* verify supported contract ID */ }
func CommandQuestions() []Question { /* exact ordered protocol questions */ }
func CommandChoices(name string) []map[string]string { /* selected question choices */ }
// internal/parse/command_claims.go: run before the common catalog-attachment hook.
func assembleCommandClaims(r *analysis.AnalysisReport) { /* roles, facts, witness blockers */ }
// internal/judge/command.go: called before generic injection policy.
func applyCommandPolicy(u analysis.CandidateUse, a *analysis.Assessment) { /* gated facet policy */ }
```

Start `TestCommandJSOperands` failing on a real Express ping fixture: one request-dependent command candidate, verified
import/contract, enabled effective shell, command operand and snapshot references.

1. Record the actual starting source manifest and dirty-document baseline; freeze effective requests
   of existing families using current parsed fixtures and local stubs. Do not assume HEAD contains
   every checkpoint change. Review/pin §8 sources and construct the independent expected matrix.
2. Create shared facts and every §5.1 pack component. Implement extraction and claim assembly,
   including required source-path prerequisites. Run AC1–AC5/AC9 and review generated golden diffs.
3. Implement both provider paths/questions and Go policy, then findings/guidance/CLI exports. Run
   AC6–AC8 plus prerequisite regressions. Use stubs before paid requests. Synchronize implemented docs.
4. Complete AC10 and a full offline inventory for each of the four targets. Check all required
   command contexts are present and request construction fits limits before source transmission.
5. Execute the full live judged scans below, compare every expected case and repair misses/false
   positives or wrong protection in the scanner. Add a failing regression before each fix; rerun
   scoped tests, affected regressions and AC10 as appropriate before another paid pass.
6. Repeat corrected scans until AC11 passes on all four apps. The final retained judged reports
   MUST use the final scanner revision/source digest, not a mixture of earlier implementations.
   Finish replay/parity, curate all four GitHub samples and final implemented-state docs per the
   delivery guide, preserve all runs, and deliver the review package.

The loop uses **OpenAI Decisions, gpt-6-luna only**, no fallback or automatic retry. Before each pass, record a finite
request cap sufficient for the full current inventory (candidate-position scheduling can include ineligible
observations), intended eligible count and reason for the rerun in the ledger. Use all normal scan registrations and
source files, with **no entry/route/family filter or sampled scope**. Record the default manifest/exclusions. A source
app's documentation/tests provide expected labels outside the scanner input; do not inject the answer key into code or
prompts.

Build the scanner using the declared toolchain. Run this pattern once per verified target, substituting actual quoted
paths and the recorded cap; the provider key must enter through its existing env setup:

```bash
<SCAN_BINARY> --analyze --json --judge openai --judge-model gpt-6-luna \
  --judge-limit <FULL_INVENTORY_CAP> --output-dir <EXTERNAL_FINDINGS_ROOT> <PINNED_TARGET_ROOT>
```

Use `<DEV_ROOT>/zazzcode/zazzles/_test-findings/command-injection/<pass>/` as the external findings root.
`report.WriteBundle` creates per-app fresh run folders containing findings.json, findings.html and findings.sarif.
Record actual paths, scanner/source digest, target hash manifest, flags, model, request cap,
attempted/completed/failed/not_run counts, provider-reported usage and raw request/response traces (via existing
decision trace APIs or a same-pipeline evaluation harness). Never print credentials. No unbounded spend or repeated
unchanged resampling is authorized by the fix loop.

A full scan may retain unrelated existing observation-only not_run/Review records and exit 1 under current incompleteness
rules. Explain that result; it cannot excuse an unassessed **required command case**, transport/selection failure for
one, or hiding an unrelated regression. Assess all eligible families, compare non-command results against the
predecessor with source review of material changes, and keep unrelated coverage limits explicit. Saved historical
answers are not fresh paid assessment. Exact-request replay verifies final responses offline without additional calls.

Final review package: twelve report artifacts (three formats × four apps), expected/actual mapping, zero unresolved
command positives, conditions/coverage notes, ledger/trace locations, integrity and replay/parity checks. Validate HTML
rendering, JSON and SARIF mappings. Complete the linked [sample and implemented-state delivery
gate](../evaluation/command-injection-sample-delivery.md) and link final artifacts/GitHub sample files in the reply. No
integration merge or runtime-exploit claim is implied.

## 10. Definition of done

- [x] Required reading, matched standards and start-state manifest recorded; log created/resumed.
- [x] All command pack components and stage hooks exist and AC1–AC10 have reproducible evidence.
- [x] Every supported language has positive/protected/unknown controls; existing requests/history pass.
- [x] Independent expected matrix covers all reviewed command witnesses, including conditional paths.
- [x] AC11 live fix loop passed on all four complete pinned checkouts using the final scanner source (VulnPy with the user-directed input-validation skip, recorded as a departure).
- [x] Twelve final HTML/JSON/SARIF files plus comparison, usage, integrity/replay evidence are linked.
- [x] Final GitHub samples/README links and implemented-state docs pass the linked delivery guide.
- [x] Scope/docs and the append-only run log match actual implementation; human review is pending.

## 11. Open questions and autonomy

### Accepted follow-up: Express path IDs and Mongoose findById

User steering on 2026-11-07 authorizes bounded NoSQL evidence hardening in this worktree: identify an
unmodified direct Express named path parameter as a primitive string, and select a separate catalog-owned
Mongoose 4.2.4 `findById` contract only for a verified model with the default ObjectId `_id` schema.
Changes are limited to the relevant `internal/parse`, `internal/analysispacks`, `internal/judge` and `internal/report` code/tests,
public database analysis guide and Goof evaluation/sample artifacts. Unknown middleware, request mutation,
custom IDs/schema behavior, unpinned dependencies and object-valued inputs cannot inherit this evidence.
The existing semantic judgment and completeness gates decide protection; evidence extraction never
rewrites an old answer or declares application-wide safety. Tests must exercise source facts, protected
and unsafe controls, contradictory answers, replay invalidation and JSON/HTML/SARIF status parity.
The user authorized at most two fresh OpenAI Decisions `gpt-6-luna` calls, after offline checks, for
Goof `/update/:id` and `/destroy/:id` only. Preserve prior scans and record new request/response traces.

No open product decision requires an intake interview before implementation. POSIX assumptions, conservative unmodeled
semantics, pack integration, four-target live evaluation and report delivery are selected above. The broader acceptance
requires command-specific discovery prerequisites; leaving those known positives as Review is not an approved scope
shortcut. Missing external resources or provider access are execution blockers, not permission to self-mark acceptance
complete.

A later explicit “implement this spec” instruction is sufficient to start autonomously. Routine private helper/file
choices within §4 do not require repeated approval. Update this contract in place for material accepted steering,
preserve the change log and respect any later user restriction.

## 12. Run log protocol

Use ignored `.zazz/ephemeral/command-injection-run-log.md`. Append standards verification, source/expected-matrix
provenance, phase completions, commands/outcomes, prerequisite file scope, user steering, deviations, regression/fix
iterations, failures/recoveries, live request/usage counts and artifact locations. At session start read this contract,
the existing log if present and current Git state. Resume from recorded evidence. Never commit secrets/raw execution
scratch or rewrite history.

## 13. Unattended implementation prompt for a new session

```text
Implement .zazz/specifications/command-injection.md in the existing command-injection worktree/branch.
This user instruction authorizes autonomous implementation of the entire contract; do not stop after
planning or fixtures. Read AGENTS.md, agent orientation, the full spec and its focused required reading.
Load spec-driven, matched standards and doc-check when applicable. Implementation plan/backlog is not
required reading. Read .zazz/ephemeral/command-injection-run-log.md if present, otherwise create it.
Record current branch, source manifest, existing dirty changes and target pins. Preserve user work.
Work as one Contributor Agent. Create all required analysis-pack components, use the shared catalog
selection/material/provenance path, and wire extraction, claim assembly, questions/choices, policy,
replay and reporting. Follow the first failing test and phases; fix command-specific entry/flow gaps
needed for every independent positive. Do not edit locked specs, targets, or unrelated analyzers.
The spec records the user's authorization for full source-transmitting judged scans and necessary
corrected rescans of Juice Shop, VulnPy, nodejs-goof and vulnerable-typescript-app, using OpenAI Decisions gpt-6-luna only.
Freeze independent expectations before new model results; run scoped/full offline checks first.
Use explicit per-pass caps and a request/usage ledger, no fallback, no target execution and no repeated
unchanged paid resampling. Iterate scanner fixes/regressions/full final scans until all required
command positives and controls pass. Known misses, warnings or Review do not satisfy final acceptance.
Complete AC1–AC11. Deliver HTML, JSON and SARIF for each app (twelve files), expected/actual mapping,
usage/trace, integrity/replay and validation evidence, with clickable final report links. Follow the
linked sample-delivery guide: curate all four GitHub samples and update README/project/architecture
docs to implemented Command Injection support and next-task XSS hardening before declaring ready.
Keep working without routine confirmation; if access/funding or a material out-of-scope need blocks
progress, record unfinished ACs and explain the exact blocker. Never weaken expected labels to finish.
The user authorized updated GitHub sample findings as part of implementation: commit/push the
feature branch artifacts under the linked delivery guide. Never merge or push to stage/main.
```

## 14. Implementation and review change log

### 2026-11-07 — Source-backed findById protection follow-up

User requested implementing the distinction between an Express URL ID and object-valued NoSQL selectors.
Section 11 records the bounded follow-up and two-call limit. Verification must establish scalar provenance,
default ObjectId casting, conservative exclusions and unchanged unrelated requests; saved judgments require
fresh exact evidence before the Goof sample can be refreshed.

### 2026-11-07 — Consistent analyzer vocabulary

User steering renamed the capability in the title/§1 and distinguished analyzers, supporting packs and shared engine.
Existing IDs/protocols and locked predecessor specifications were preserved.

### 2026-11-07 — Executable handoff and full judged acceptance

User requested focused reading, a fresh-session gap review, all required pack components, independent app-vulnerability
references, VulnPy source review, nodejs-goof as the third target, iterative full judged scans and three-format
human-review artifacts. Sections 1–13 now specify the concrete catalog/assembly/question hooks, new guidance ownership,
actual provider envelope, deterministic statuses, command-only prerequisite scope, references, full-scan fix loop and
unattended prompt. The earlier permission to leave VulnPy command misses unresolved and blanket live-call prohibition
are superseded by this recorded direction. Verification now requires AC11 and the complete nine-artifact package; no
implementation or paid scan has been performed by this documentation revision.



### 2026-11-07 — Fourth target, GitHub samples and final documentation

User added vulnerable-typescript-app to full final judged evaluation, requested its independent
expected-vulnerability/file/line inventory, VulnPy in the README samples, refreshed GitHub sample artifacts, and
documentation reflecting implemented Command Injection when merged. Sections1/2/4/ 6–13 now require four targets, twelve
reports and the linked sample-delivery gate. Its instructions supersede earlier three-target/nine-artifact checkpoint
requirements. All current-state README, architecture, project and orientation status text must be reconciled after
actual implementation; this source-review checkpoint does not claim the analyzer or refreshed judged reports exist yet.

### 2026-11-07 — Implementation, scope direction and results

Implemented per this contract; see the [acceptance results](../evaluation/command-injection-results.md). Accepted steering
and deviations: (1) on explicit user direction VulnPy's final judged scan used `--skip-family input-validation` (a new
standard option, with report callouts) instead of the contract's no-family-filter rule, because newly covered
frameworks made a full pass about 3,000 requests; Juice Shop, goof and the TypeScript app ran unfiltered. (2) `--trace-dir`
was added to retain exact request/response traces for offline replay. (3) The published VulnPy sample omits the
unjudged records and their entries because the full report exceeds GitHub's file-size limit; the full report is retained.
(4) Predecessor effects: command candidates and entry coverage are additive; the outbound golden hashes changed only by the
new registry entry and presentation version 7.
