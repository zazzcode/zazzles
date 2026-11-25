# Specification index, in delivery order

This index lists every specification in this directory in the order the work was delivered or is
planned. The [README](README.md) owns the storage policy and a longer description of each
specification. The [implementation plan](../project/implementation-plan.md) owns the roadmap and
functionality status.

**How the order was set.** Delivered work is ordered by the pull request that merged it into
`stage`, as the implementation plan records, and by the date each specification was first
committed where no pull request number is recorded. Planned work follows the plan's "Next up"
order. **Reconciled 2026-11-22** against `stage` at `af5dbc1`.

"State" is the state the implementation plan or the specification header gives. A specification
with no merge recorded there reads "See specification".

## 1. Foundations (2026-10-11 to 2026-11-06)

| Order | Specification | First committed | State |
|---:|---|---|---|
| 1 | [Phase 0 skeleton](phase0-skeleton/README.md) | 2026-10-11 | Historical foundation |
| 2 | [Tree-sitter route identification MVP](tree-sitter-route-identification-mvp.md) | 2026-10-24 | Implemented |
| 3 | [Route string validation](route-string-validation.md) | 2026-10-31 | Implemented |
| 4 | [Sensitive-data logging](sensitive-data-logging.md) | 2026-11-01 | Implemented |
| 5 | [SQL and NoSQL judgment](sql-nosql-judgment.md) | 2026-11-01 | Implemented |
| 6 | [XSS response analysis](xss-response.md) | 2026-11-01 | Implemented |
| 7 | [Human-readable reports](human-readable-reports.md) | 2026-11-01 | Implemented |
| 8 | [Python support](python-support.md) | 2026-11-01 | Implemented |
| 9 | [Common entry and dispatch](common-entry-dispatch.md): [01 model](common-entry-dispatch-01-model.md), [02 consumers](common-entry-dispatch-02-consumers-compatibility.md), [03 reporting selectors](common-entry-dispatch-03-reporting-selectors.md), [04 browser events](common-entry-dispatch-04-browser-events.md), [05 dynamic HTTP](common-entry-dispatch-05-dynamic-http.md), [06 GraphQL](common-entry-dispatch-06-graphql.md), [07 gRPC](common-entry-dispatch-07-grpc.md), [08 acceptance](common-entry-dispatch-08-acceptance.md) | 2026-11-03 | Merged (PR #8) |
| 10 | [Analysis pack MVP](analysis-pack-mvp.md) | 2026-11-05 | Implemented |
| 11 | [Components 01: NoSQL and input validation](components-01-nosql-validation.md) | 2026-11-05 | Implemented |
| 12 | [Components 02: XSS](components-02-xss.md) | 2026-11-05 | Implemented |
| 13 | [Components 03: outbound observations](components-03-outbound.md) | 2026-11-05 | Implemented |

## 2. Analyzer families and hardening (2026-11-07 to 2026-11-16)

| Order | Specification | First committed | State |
|---:|---|---|---|
| 14 | [XSS hardening](xss-hardening.md) | 2026-11-07 | Implemented |
| 15 | [Node.js input and acquisition refactor](node-http-input-refactor.md) | 2026-11-07 | Implemented |
| 16 | [Command injection analyzer](command-injection.md) | 2026-11-07 | Implemented |
| 17 | [Shared Gemini Decisions provider](gemini-decisions.md) | 2026-11-14 | Implemented |
| 18 | [Decision-model limits](decision-model-limits.md) | 2026-11-14 | Implemented |
| 19 | [Path traversal analyzer](path-traversal.md) | 2026-11-14 | Implemented |
| 20 | [Path traversal tier-1 hardening](path-traversal-hardening.md) | 2026-11-14 | Implemented |
| 21 | [Cross-analyzer engine hardening (E1)](analyzer-engine-hardening.md) | 2026-11-14 | Implemented |
| 22 | [Shared guard and workspace manifest engine (E2)](shared-guard-and-manifest-engine.md) | 2026-11-14 | Implemented |
| 23 | [Analyzer assessment coverage](analyzer-assessment-coverage.md) | 2026-11-15 | Merged (PR #14) |
| 24 | [Wire bundle v7 (E3)](wire-bundle-v7.md) | 2026-11-15 | Merged (PR #14) |
| 25 | [Shared Node inputs and file APIs (E4)](shared-node-inputs-and-file-apis.md) | 2026-11-15 | Merged (PR #15) |
| 26 | [Shared Python input acquisition](python-input-refactor.md) | 2026-11-15 | Merged (PR #17) |
| 27 | [JavaScript conditional flow](javascript-if-flow.md) | 2026-11-15 | See specification |
| 28 | [Data-path slicing](data-path-slicing.md) | 2026-11-15 | See specification |
| 29 | [Evidence relevance tier](evidence-relevance-tier.md) | 2026-11-15 | See specification |
| 30 | [Next.js support](nextjs-support.md) | 2026-11-16 | Merged (PR #18) |
| 31 | [Next.js phase 2 and code/redirect](nextjs-phase-2-and-code-redirect.md) | 2026-11-16 | Merged (PR #19) |
| 32 | [Practice accuracy and false-positive evaluation](practice-accuracy-and-false-positive-evaluation.md) | 2026-11-16 | Merged (PR #20, PR #21) |
| 33 | [Analyzer protection and flow coverage](analyzer-protection-and-flow-coverage.md) | 2026-11-16 | See specification |
| 34 | [PHP support (DVWA MVP)](php-support.md) | 2026-11-16 | Merged (PR #23) |

## 3. Architecture update and accuracy (2026-11-17 to 2026-11-21)

| Order | Specification | First committed | State |
|---:|---|---|---|
| 35 | [Architecture update plan](architecture-update-plan.md) | 2026-11-17 | Plan for phases 0 to 9 |
| 36 | [Phase 0: compatibility baseline](architecture-phase-0-compatibility-baseline.md) | 2026-11-17 | Merged |
| 37 | [Phase 1: registration graph](architecture-phase-1-registration-graph.md) | 2026-11-17 | Superseded by the source index |
| 38 | [Phase 1: source index](architecture-phase-1-source-index.md), [summary completion](architecture-phase-1-summary-completion.md) | 2026-11-17 | Merged (PR #24) |
| 39 | [Phase 2: pipeline and concurrent runners](architecture-phase-2-pipeline-runners.md) | 2026-11-17 | Merged (PR #25) |
| 40 | [Phase 3A: PHP package](architecture-phase-3-php-package.md), [Phase 3B: JS/TS and Python packages](architecture-phase-3-js-ts-python-package.md) | 2026-11-17 | Merged (PR #26) |
| 41 | [Phase 4: parallel judge](architecture-phase-4-parallel-judge.md) | 2026-11-17 | Merged (PR #27) |
| 42 | [Judge scan resume](judge-scan-resume.md) | 2026-11-18 | See specification |
| 43 | [Judge transient retry and token estimate](judge-transient-retry-and-token-estimate.md) | 2026-11-18 | See specification |
| 44 | [Phase 5: measured recall gaps](architecture-phase-5-accuracy-gaps.md) | 2026-11-17 | See specification |
| 45 | [False positives and Review noise](accuracy-false-positive-noise.md) | 2026-11-19 | Merged (PR #29) |
| 46 | [Model-assisted evidence resolution](model-assisted-evidence-resolution.md) | 2026-11-19 | Merged (PR #30) |
| 47 | [Close findings gaps](close-findings-gaps.md) | 2026-11-19 | Merged (PR #31) |
| 48 | [Judge request size reduction](judge-request-size-reduction.md), [Judge evidence quality](judge-evidence-quality.md) | 2026-11-19 | Merged (PR #33) |
| 49 | [Command bypass support](command-bypass-support.md) | 2026-11-20 | Merged (PR #34) |
| 50 | [Prototype pollution analyzer](prototype-pollution.md), [write shapes](pollution-write-shapes.md) | 2026-11-20 | Stage 1 merged (PR #35). Library stage planned |
| 51 | [Prototype pollution walk start](pollution-walk-start.md) | 2026-11-21 | Merged (PR #36) |
| 52 | [Scan, Fix and Probe repository layout](scan-fix-probe-repository-layout.md) | 2026-11-21 | Merged (PR #37) |
| 53 | [Unsafe deserialization analyzer](unsafe-deserialization.md) | 2026-11-19 | Merged (PR #38). Lab scenarios and live evaluation open |

## 4. PHP frameworks: Symfony (2026-11-17 to now)

| Order | Specification | First committed | State |
|---:|---|---|---|
| 54 | [Phase 6: Symfony registration resolver](architecture-phase-6-symfony.md) | 2026-11-17 | Superseded by PHP Symfony support |
| 55 | [PHP Symfony support](php-symfony-support.md) | 2026-11-19 | Merged (PR #39) |
| 56 | [Symfony application-security analyzers: lane contract](symfony-more-analyzers.md) | 2026-11-23 | Branches 1 to 4 merged. Branch 5 in review (PR #47) |
| 56.1 | [Branch 1: information exposure, mass assignment, security-field census](symfony-more-analyzers-1.md) | 2026-11-22 | Merged (PR #42) |
| 56.2 | [Branch 2: entry access rules and authorization](symfony-more-analyzers-2.md) | 2026-11-22 | Merged (PR #43) |
| 56.3 | [Branch 3: account enumeration, recovery-secret delivery, weak password hashing](symfony-more-analyzers-3.md) | 2026-11-22 | Merged (PR #45) |
| 56.4 | [Branch 4: configuration, SSRF through a shell URL client, lane closure](symfony-more-analyzers-4.md) | 2026-11-22 | Merged (PR #46) |
| 56.5 | [Branch 5: plain-PHP recall on the PHP sample](symfony-more-analyzers-5.md) | 2026-11-23 | In review (PR #47) |
| 57.1 | [Juice Shop and Next.js hardening, branch 1: existing analyzers on JavaScript and TypeScript](juiceshop-nextjs-hardening-1.md) | 2026-11-24 | Specified. Branch 1 of a two-branch stack |
| 57.2 | [Branch 2: scanner comparison on four samples](juiceshop-nextjs-hardening-2.md) | 2026-11-24 | Implemented on its branch; curated sample copies open |
| 57.3 | [Branch 3: misses, blocked records, reads and false positives](juiceshop-nextjs-hardening-3.md) | 2026-11-24 | Implemented; judged acceptance not met, six rows open ([results](../evaluation/juiceshop-hardening-results.md#open-rows)) |

## 5. Planned, in the plan's order

| Order | Specification | First committed | State |
|---:|---|---|---|
| 58 | [Phase 7: npm corpus and direct-model baseline](architecture-phase-7-npm-corpus.md) | 2026-11-17 | Ready to assign (waypoint W2) |
| 59 | [Phase 8: npm library mode](architecture-phase-8-npm-library-mode.md) | 2026-11-17 | Starts after phase 7 (waypoint W4) |
| 60 | [Phase 9: Drupal](architecture-phase-9-drupal.md) | 2026-11-17 | Planned |
| 61 | [Detection generalization: series index](detection-generalization/README.md), with its [delivery plan](detection-generalization/delivery-plan.md) and specifications 00 to 11 | 2026-11-25 | Draft. Implementation starts on the owner's word |

## Maintaining this index

Add a row when a specification is created, and update its state when its pull request merges.
Keep the order by delivery. Do not copy acceptance evidence here: link the specification. A
stacked lane takes one order number with a decimal per branch.
