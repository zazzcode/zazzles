# 05 — Prior art, Bearer study, and feasibility assessment

**Reviewed 2026-10-19.** Concept-stage research, not an implementation spec or a benchmark result.
The chosen roles remain [Jev Assessment → Findings Review](../architecture.md). This note records
originality/feasibility judgments and a focused read-only study of the supplied Bearer checkout.

## Opinion

The approach is technically credible for a bounded set of source-code vulnerability families. Its
practical value will come from accurate evidence, useful custom-validator assessment, review quality,
and manageable cost. Broad multi-language OWASP coverage remains a substantial engineering program.

The broad architecture is established, not a new invention: syntax/flow analysis plus semantic
assessment and model-assisted findings review have prior art. The particular division between Jev
Assessment and an independent LLM Findings Reviewer may be a useful product differentiator, but no
novelty claim is established by this limited survey. This is not an exhaustive originality search.

## Relevant prior art

| Source | Relevant precedent | Limit of the comparison |
|---|---|---|
| [IRIS paper](https://arxiv.org/abs/2405.17238) and [authors' repository](https://github.com/iris-sast/iris) | Combines static analysis with LLM-inferred taint specifications and contextual review of candidate paths | Java/CodeQL research; does not establish zazzles's Jev or JS/TS performance |
| [Jev Security Scan](https://github.com/win4r/jev-security-scan/blob/main/README.en.md) | Static evidence plus Jev triage, a second localization/check pass, explicit coverage gaps | Agent Skill/MCP suspicious-behavior review; both passes use Jev, not zazzles's LLM Findings Reviewer |
| [Jev Security Sentinel](https://github.com/JevForge/jev-security-sentinel) | Jev-based policy over existing SAST/SCA/IaC and other findings | Findings triage/gating is different from building zazzles's source-to-sink analysis |
| [Bearer](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/README.md) | Go, Tree-sitter, language analyzers, dataflow relationships, declarative rules, reporting | Read source for design ideas; do not assume parity with advanced/commercial analysis |
| [Semgrep Community Edition](https://docs.semgrep.dev/getting-started/quickstart-ce) | Pattern and intraprocedural taint rules over many languages; local CLI with SARIF/JSON output | Local comparison scanner ([cheat sheet](../../docs/semgrep-ce-cheat-sheet.md)); CE taint is single-file, and registry rules are licensed separately and not copied into zazzles |
| [CodeQL libraries and queries](https://github.com/github/codeql) | Explicit source/sink models, taint steps, barriers, path queries, and regression cases | MIT repository; the CLI/engine is separately licensed and is not zazzles's planned runtime |
| [Joern Scan](https://docs.joern.io/scan/) and [Code Property Graph](https://docs.joern.io/code-property-graph/) (documentation reviewed 2026-11-04) | Common typed program representation, graph traversals and predefined security queries | Architecture inspiration only; no Joern execution, benchmark, integration or code reuse is claimed |

These sources show precedent and implementation choices, not verified comparative quality.
The [Jev capability note](04-jev-validation-research.md) owns sanitizer-specific published results and
the controlled evaluation protocol; those figures are not repeated here.

## What the related model-assisted tools actually do

**IRIS:** an LLM identifies candidate source/sink API annotations; CodeQL performs static taint analysis;
LLM contextual review examines candidate paths to reduce false positives. Its orchestration and
evaluation tooling use Python; CodeQL supplies the static-analysis engine. These source/sink annotations
are analyzer configuration, not Zazz deliverable specifications. The useful precedent is the separation
between repeatable program analysis and contextual judgment. Scan chooses Go analysis, Jev Assessment
of validation/sanitization, and an LLM Findings Reviewer; IRIS does not establish Jev's fitness.
Source: [authors' overview](https://github.com/iris-sast/iris#-overview).

IRIS is an architectural reference, not a dependency or implementation template. Zazzles's analysis,
model clients, orchestration, and evaluation harnesses are Go, as defined in the
[architecture](../architecture.md#1-architecture-premise). Studying IRIS does not introduce Python
or CodeQL into zazzles's planned runtime.

**Jev Security Scan:** a Python tool reviewing Agent Skills/MCP/source for suspicious behavior. It
collects text, applies local checks, asks Jev category questions across chunks, then uses a second Jev
pass with numbered source windows and active/example/unknown context options. Policy combines the
results and reports evidence/gaps. Both passes use Jev; the project explicitly does not call them
independent verification. This is related precedent for typed evidence-based assessment, not evidence
of a Go interprocedural OWASP scanner or a separate LLM Findings Reviewer.
Source: [documented pipeline](https://github.com/win4r/jev-security-scan/blob/main/README.en.md#how-it-works).

These tools demonstrate related building blocks. The limited survey does not establish a prior tool
with precisely zazzles's chosen division of roles, nor prove that division is unprecedented.

## CodeQL as an additional design reference

The [CodeQL repository](https://github.com/github/codeql#license) publishes libraries and queries under
MIT. Its README distinguishes that repository from the separately licensed CLI/analysis engine,
distributed through [codeql-cli-binaries](https://github.com/github/codeql-cli-binaries). Do not describe
the entire CodeQL toolchain as MIT/open source on the strength of the query repository's license.
This is a documentation/source reference; no CLI was installed or run for this review.

The supplied local clone was verified clean at `bc53c78af0de4ee7578850698f12ab5638bc1b6d` on
2026-10-19, with origin `https://github.com/github/codeql.git`. Its portable location lives in the
[orientation](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root). This records clone
provenance; a local implementation study has not yet been performed.

Start with the official [JS/TS dataflow guide](https://codeql.github.com/docs/codeql-language-guides/analyzing-data-flow-in-javascript-and-typescript/):
local versus global flow, value-preserving versus taint steps, explicit sources/sinks, additional flow
steps, and sanitizer guards/barriers. Study small relevant queries and their tests for the selected
SQL/command/path corpus instead of surveying the whole repository. Record the source revision for
any concrete implementation study or reused material in its owning spec.

Bearer informs Go/parser implementation patterns; CodeQL informs explicit semantic models, rule
preconditions, and negative/regression cases. Neither supplies zazzles's unbuilt engine by analogy.
Translate useful concepts into the chosen Go IR/flow contracts and test them; do not add a QL runtime,
database extractor, or CodeQL dependency to the plan. Any later reuse preserves the applicable notices.

## Bearer inspection provenance

The Project Owner supplied a clone at the portable reference location recorded in the
[orientation](../docs/zazzles-agent-orientation.md#portable-workspace-and-dev_root). Inspected commit:
`e3753de6347988bed15bdba80b9ff731bf028c80`. The checkout was clean at inspection. No dependencies were installed, code
executed, scanner run, or files modified in that clone. Findings below come from selected source,
fixtures, and documentation, not a full correctness audit.

The checkout's [module](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/go.mod) uses Go and `smacker/go-tree-sitter`. That supports the general
stack choice, not an instruction to select the same binding/version. The parser spec still decides
zazzles's binding and native/build requirements.

## Concrete ideas worth studying

| Area and pinned source | Observed mechanism | Lesson for zazzles |
|---|---|---|
| [Language contract](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/language/language.go) | Each language supplies parser grammar, analyzer, pattern behavior, detector hooks, and string-fragment types | A common parser does not remove language-specific semantics; make adapters own those explicitly |
| [JS/TS analyzer](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/languages/javascript/analyzer/analyzer.go) | Per-syntax handling of assignments, declarations, calls, imports, members, object spread, and ternaries | Build a tested transfer/capability matrix, not generic traversal that assumes all AST shapes mean the same thing |
| [Graph builder](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/ast/tree/builder.go) and [tree](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/ast/tree/tree.go) | Distinct syntax children, value-flow sources, aliases, and source positions | Separate syntactic containment, value dependency, identity, and location in the IR; preserve their provenance |
| [Scope table](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/language/scope.go) | Declaration/assignment lookup through parent scopes | Test shadowing and reassignment before making source-derived-value claims |
| [Rule compilation](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/detectors/customrule/customrule.go) | Compiles patterns/filters and evaluates them against captured variables | Keep pattern capture, filtering, security metadata, and semantic model questions separate |
| [Ruleset](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/ruleset/ruleset.go) and [sanitizer detection](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/scanner/detectorset/detectorset.go) | Rules explicitly reference sanitizer rules; sanitizer matching participates in detection | Deterministically model known protections with preconditions; investigate custom/unknown protections through Jev |
| [Sanitizer fixture](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/e2e/rules/testdata/rules/sanitizer.yml) and [paired cases](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/e2e/rules/testdata/data/sanitizer/sanitizer.rb) | Small cases distinguish raw, assigned, and transformed values | Test direct use and local-variable use of both unsafe and protected values. The fixture's `hash` is a synthetic example, not a universal sanitizer |
| [JS/TS tests](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/languages/javascript/javascript_test.go) | Separate snapshot groups for flow, imports, strings, object destructuring, pattern variables, and scope | Organize fixtures by semantic construct so errors are attributable before model integration |
| [SARIF emitter](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/report/output/sarif/sarif.go) and [security output](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/pkg/report/output/security/security.go) | Rule/location/severity output, fingerprints, baseline/ignore integration | Learn report packaging, but specify/test zazzles's identity and grouping instead of assuming copied fingerprints are stable enough |
| [Dataflow guide](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/docs/guides/dataflow.md) | Uses Juice Shop to demonstrate report structure | Useful reference for mapping our selected Juice Shop source cases and comparing report evidence |

The inspected analyzer provides evidence of local value/alias modeling. It is not proof of complete
path-sensitive CFG analysis, all-files interprocedural propagation, or framework correctness. The
README distinguishes advanced cross-file analysis under the commercial offering; do not assume those
capabilities are present in the inspected CLI merely because the product description mentions them.

The checkout uses [Elastic License 2.0](https://github.com/Bearer/bearer/blob/e3753de6347988bed15bdba80b9ff731bf028c80/LICENSE.txt). This study records ideas and observations;
no Bearer source or rules have been copied into zazzles. Any later code/rule reuse is a separate design
and licensing decision, not an assumption of MIT/Apache-style terms.

## Where I expect the design to work

- Bounded JS/TS cases with a resolved source/value/sink relationship and a complete helper definition.
- Distinguishing named field validation from context-specific sanitization/encoding, using narrowly
  scoped Jev questions and explicit sink requirements.
- Improving review usefulness when the LLM Findings Reviewer catches unsupported claims or identifies
  a guard/bypass that the initial assessment missed, with both results preserved.
- Repeatable rule/flow output and cached model assessments where versioned dependencies are complete.

These are engineering expectations, not measured outcomes. The experiment must determine whether
Jev actually adds accuracy or lowers review cost on the selected cases.

## Main ways it can fail

**Candidate discovery dominates recall.** If resolution/flow/filtering omits a real issue, neither Jev
nor review of identified issues sees it. Score discovery separately and audit Jev-protected/dropped
cases; improving classification precision does not repair missing candidates.

**Sanitization is contextual.** A check can validate one value, use the wrong encoding context, ignore
a return, or leave an unchecked branch. Do not collapse these into a global “string is safe” bit.

**Two models can share an error.** Independent first-pass Findings Review reduces anchoring, but both
models can be wrong because of the same missing snippet or library assumption. Measure against human
labels, including incorrect agreement, rather than treating agreement as confirmation.

**The static frontend is a large investment.** Parsing is relatively straightforward; resolution,
branch/value semantics, summaries, framework models, and invalidation dominate complexity. Go and
Tree-sitter make that work practical, not automatic.

**Review cost can dominate.** Every identified issue enters Findings Review. Measure candidate volume,
deduplication, cache effectiveness, review time, and total cost, not only Jev request latency.

## Recommended next evidence

Use Phase 1's human-reviewed paired fixtures and selected pinned Juice Shop cases to test Jev
Assessment and the LLM Findings Reviewer on hand-prepared evidence before investing in the full
frontend. This isolates the semantic experiment without changing the chosen architecture.

Use Bearer as a comparator, with its revision/rule/configuration pinned. Its output is not ground
truth or a complete candidate source: include manually labeled cases it does not flag, and review
both tools' disagreements. A temporary experiment harness can ingest prepared/Bearer evidence without
committing zazzles to reusing Bearer internals.

Then build one complete source-to-sink slice in zazzles, extend to the agreed initial rule families, and
measure discovery separately from Jev classification and Findings Review. Expand languages only after
the selected slice meets its agreed evidence bar. The existing
[ordered backlog](implementation-plan.md#ordered-specification-backlog) remains the execution plan;
these observations inform its future specs rather than authorizing code now.

Success means useful evidence-backed findings with a measured precision/recall/review-cost tradeoff.
It does not require the combination to be unprecedented, and this note makes no prediction of full
OWASP coverage or production readiness.

## Joern Scan reference review — 2026-11-04

At the user's request, reviewed the official Joern Scan and Code Property Graph documentation as
additional architecture references alongside the earlier Bearer, Semgrep and CodeQL research.
Joern Scan documents generation of a CPG followed by execution of predefined security queries and
reporting of matches. Its common graph representation is relevant to separating Zazzles's language
adapters from shared semantic records. This is documentation research; no target or Joern scanner
was executed, no benchmark was added, and no engine/code/rules were adopted.

The [public technical comparison](../../docs/technical-approach.md#relationship-to-joern-scan)
explains the shared static-analysis principles and the differences: Zazzles's bounded Go evidence
assembly, explicit entry/invocation contexts, claim-specific decision-model assessment and evidence
validation. This is not a claim of equivalent trace coverage, novel algorithms or measured superiority.
