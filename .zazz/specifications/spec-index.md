# Specification index, by module

This index lists every specification in this directory, grouped by module, with what each one
delivers. Within a module, rows are in delivery order. The [README](README.md) owns the storage
policy and longer descriptions. The [implementation plan](../project/implementation-plan.md) owns the
roadmap and functionality status.

**How the order was set.** Delivered work is ordered by the pull request that merged it into
`stage`, as the implementation plan records, and by the date each specification was first
committed where no pull request number is recorded. Planned work follows the plan's "Next up"
order. **Reconciled 2026-11-28** against `stage` at `6cfb9b2`.

"State" is the state the implementation plan or the specification header gives. A specification
with no merge recorded there reads "See specification".

**Order** is one sequence across all modules, so the numbers show what was delivered or is planned
before what. Each module's specifications live in a folder named like its code directory: Dependency
Audit in [`audit/`](audit/README.md), Zazzles Agent in `agent/`, Endpoint Probe in `probe/`. Code
Scan's are in this directory's root for now.

## 1. Code Scan (`scan/`)

These specifications are in this directory's root.

### Delivered and in progress

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 1 | [Phase 0 skeleton](phase0-skeleton/README.md) | The first repository and CLI skeleton; kept as history | 2026-10-11 | Historical foundation |
| 2 | [Tree-sitter route identification MVP](tree-sitter-route-identification-mvp.md) | `scan --routes`: a JSON index of JS/TS routes and their handler chains | 2026-10-24 | Implemented |
| 3 | [Route string validation](route-string-validation.md) | Request fields traced from a route to string uses, with validation evidence | 2026-10-31 | Implemented |
| 4 | [Sensitive-data logging](sensitive-data-logging.md) | Findings for credentials and personal data written to logs | 2026-11-01 | Implemented |
| 5 | [SQL and NoSQL judgment](sql-nosql-judgment.md) | Decision-model judgment of SQL and NoSQL injection, measured on Juice Shop | 2026-11-01 | Implemented |
| 6 | [XSS response analysis](xss-response.md) | Reflected, template, stored and browser XSS, one type at a time | 2026-11-01 | Implemented |
| 7 | [Human-readable reports](human-readable-reports.md) | The standalone expandable HTML report generated from saved JSON | 2026-11-01 | Implemented |
| 8 | [Python support](python-support.md) | Python routes, requests, value flow and sinks through the shared engine | 2026-11-01 | Implemented |
| 9 | [Common entry and dispatch](common-entry-dispatch.md): [01 model](common-entry-dispatch-01-model.md), [02 consumers](common-entry-dispatch-02-consumers-compatibility.md), [03 reporting selectors](common-entry-dispatch-03-reporting-selectors.md), [04 browser events](common-entry-dispatch-04-browser-events.md), [05 dynamic HTTP](common-entry-dispatch-05-dynamic-http.md), [06 GraphQL](common-entry-dispatch-06-graphql.md), [07 gRPC](common-entry-dispatch-07-grpc.md), [08 acceptance](common-entry-dispatch-08-acceptance.md) | One entry and dispatch model for HTTP, browser events, GraphQL and gRPC | 2026-11-03 | Merged (PR #8) |
| 10 | [Analysis pack MVP](analysis-pack-mvp.md) | The embedded, versioned analysis-pack catalog, with SQL as its first user | 2026-11-05 | Implemented |
| 11 | [Components 01: NoSQL and input validation](components-01-nosql-validation.md) | NoSQL and input validation moved into the component catalog | 2026-11-05 | Implemented |
| 12 | [Components 02: XSS](components-02-xss.md) | XSS interpretation moved into the component catalog | 2026-11-05 | Implemented |
| 13 | [Components 03: outbound observations](components-03-outbound.md) | Outbound destination observations moved into the component catalog | 2026-11-05 | Implemented |
| 14 | [XSS hardening](xss-hardening.md) | Every documented XSS in five samples Confirmed, negatives held | 2026-11-07 | Implemented |
| 15 | [Node.js input and acquisition refactor](node-http-input-refactor.md) | Transport-neutral request facts for Express, Fastify and Hapi | 2026-11-07 | Implemented |
| 16 | [Command injection analyzer](command-injection.md) | Command injection for JS, TS and Python process and shell calls | 2026-11-07 | Implemented |
| 17 | [Shared Gemini Decisions provider](gemini-decisions.md) | Google Gemini as a second decision-model provider | 2026-11-14 | Implemented |
| 18 | [Decision-model limits](decision-model-limits.md) | A per-run request cap and RPM/TPM pacing | 2026-11-14 | Implemented |
| 19 | [Path traversal analyzer](path-traversal.md) | Path traversal and Zip Slip for JS, TS and Python file operations | 2026-11-14 | Implemented |
| 20 | [Path traversal tier-1 hardening](path-traversal-hardening.md) | Fixes for path-traversal false positives, false protection and nondeterminism | 2026-11-14 | Implemented |
| 21 | [Cross-analyzer engine hardening (E1)](analyzer-engine-hardening.md) | Family selection flags, judge-limit priority and context deduplication | 2026-11-14 | Implemented |
| 22 | [Shared guard and workspace manifest engine (E2)](shared-guard-and-manifest-engine.md) | One guard engine for command and path, and workspace-aware package versions | 2026-11-14 | Implemented |
| 23 | [Analyzer assessment coverage](analyzer-assessment-coverage.md) | Fewer unjudged records, each with an honest reason, and the first SSRF family | 2026-11-15 | Merged (PR #14) |
| 24 | [Wire bundle v7 (E3)](wire-bundle-v7.md) | A compact evidence format for decision requests | 2026-11-15 | Merged (PR #14) |
| 25 | [Shared Node inputs and file APIs (E4)](shared-node-inputs-and-file-apis.md) | Express middleware entries, URL and upload facts, Node `http` SSRF | 2026-11-15 | Merged (PR #15) |
| 26 | [Shared Python input acquisition](python-input-refactor.md) | Python HTTP adapters on the shared request-fact schema | 2026-11-15 | Merged (PR #17) |
| 27 | [JavaScript conditional flow](javascript-if-flow.md) | Branch-aware JS value flow through `if` statements | 2026-11-15 | See specification |
| 28 | [Data-path slicing](data-path-slicing.md) | Evidence cut to the data path of each claim | 2026-11-15 | See specification |
| 29 | [Evidence relevance tier](evidence-relevance-tier.md) | Helper and model relevance filtering and claim-relevant coverage gaps | 2026-11-15 | See specification |
| 30 | [Next.js support](nextjs-support.md) | Next.js App and Pages Router entries, Server Actions and library contracts | 2026-11-16 | Merged (PR #18) |
| 31 | [Next.js phase 2 and code/redirect](nextjs-phase-2-and-code-redirect.md) | Code injection and open redirect families, more Next.js practice checks | 2026-11-16 | Merged (PR #19) |
| 32 | [Practice accuracy and false-positive evaluation](practice-accuracy-and-false-positive-evaluation.md) | Measured Next.js practice checks and an accuracy baseline | 2026-11-16 | Merged (PR #20, PR #21) |
| 33 | [Analyzer protection and flow coverage](analyzer-protection-and-flow-coverage.md) | Guard protection to the final operand and stored-path flows | 2026-11-16 | See specification |
| 34 | [PHP support (DVWA MVP)](php-support.md) | PHP as a scanned language, measured on DVWA | 2026-11-16 | Merged (PR #23) |
| 35 | [Architecture update plan](architecture-update-plan.md) | The ordered plan for architecture phases 0 to 9 | 2026-11-17 | Plan for phases 0 to 9 |
| 36 | [Phase 0: compatibility baseline](architecture-phase-0-compatibility-baseline.md) | A golden test every later refactor must keep passing | 2026-11-17 | Merged |
| 37 | [Phase 1: registration graph](architecture-phase-1-registration-graph.md) | An indexed store of the entry catalog | 2026-11-17 | Superseded by the source index |
| 38 | [Phase 1: source index](architecture-phase-1-source-index.md), [summary completion](architecture-phase-1-summary-completion.md) | A layered source index and per-callable summaries | 2026-11-17 | Merged (PR #24) |
| 39 | [Phase 2: pipeline and concurrent runners](architecture-phase-2-pipeline-runners.md) | One directory walk and concurrent language runners | 2026-11-17 | Merged (PR #25) |
| 40 | [Phase 3A: PHP package](architecture-phase-3-php-package.md), [Phase 3B: JS/TS and Python packages](architecture-phase-3-js-ts-python-package.md) | One package per language adapter | 2026-11-17 | Merged (PR #26) |
| 41 | [Phase 4: parallel judge](architecture-phase-4-parallel-judge.md) | Concurrent decision-model requests with a cap | 2026-11-17 | Merged (PR #27) |
| 42 | [Judge scan resume](judge-scan-resume.md) | Resuming a judged scan that stopped part-way | 2026-11-18 | See specification |
| 43 | [Judge transient retry and token estimate](judge-transient-retry-and-token-estimate.md) | Retries on transient provider failures and a better token estimate | 2026-11-18 | See specification |
| 44 | [Phase 5: measured recall gaps](architecture-phase-5-accuracy-gaps.md) | An offline inventory of known positives and one closed structural miss | 2026-11-17 | See specification |
| 45 | [False positives and Review noise](accuracy-false-positive-noise.md) | Fewer false findings and less low-value Review, with recall measured | 2026-11-19 | Merged (PR #29) |
| 46 | [Model-assisted evidence resolution](model-assisted-evidence-resolution.md) | The decision model resolves scanner blockers through cited evidence | 2026-11-19 | Merged (PR #30) |
| 47 | [Close findings gaps](close-findings-gaps.md) | The remaining Review and missed rows on three samples | 2026-11-19 | Merged (PR #31) |
| 48 | [Judge request size reduction](judge-request-size-reduction.md), [Judge evidence quality](judge-evidence-quality.md) | Smaller decision requests, and the facts the model lacked on unsure records | 2026-11-19 | Merged (PR #33) |
| 49 | [Command bypass support](command-bypass-support.md) | Guard-bypass judgment on guarded command paths | 2026-11-20 | Merged (PR #34) |
| 50 | [Prototype pollution analyzer](prototype-pollution.md), [write shapes](pollution-write-shapes.md) | The `pollution` family for JS and TS and more source-visible write shapes | 2026-11-20 | Stage 1 merged (PR #35). Library stage planned |
| 51 | [Prototype pollution walk start](pollution-walk-start.md) | Pollution walks that start from module, local and property values | 2026-11-21 | Merged (PR #36) |
| 53 | [Unsafe deserialization analyzer](unsafe-deserialization.md) | The `deserialization` family for Python, JS, TS and PHP | 2026-11-19 | Merged (PR #38). Lab scenarios and live evaluation open |
| 54 | [Phase 6: Symfony registration resolver](architecture-phase-6-symfony.md) | Symfony routes as PHP entries | 2026-11-17 | Superseded by PHP Symfony support |
| 55 | [PHP Symfony support](php-symfony-support.md) | Symfony websites across every supported analyzer family | 2026-11-19 | Merged (PR #39) |
| 56 | [Symfony application-security analyzers: lane contract](symfony-more-analyzers.md) | Five stacked branches of application-security analyzers for PHP | 2026-11-23 | Branches 1 to 4 merged. Branch 5 in review (PR #47) |
| 56.1 | [Branch 1: information exposure, mass assignment, security-field census](symfony-more-analyzers-1.md) | `exposure` and `mass-assignment` families | 2026-11-22 | Merged (PR #42) |
| 56.2 | [Branch 2: entry access rules and authorization](symfony-more-analyzers-2.md) | Entry access requirements and the `authorization` family | 2026-11-22 | Merged (PR #43) |
| 56.3 | [Branch 3: account enumeration, recovery-secret delivery, weak password hashing](symfony-more-analyzers-3.md) | The `account` family | 2026-11-22 | Merged (PR #45) |
| 56.4 | [Branch 4: configuration, SSRF through a shell URL client, lane closure](symfony-more-analyzers-4.md) | The `configuration` family and `curl`/`wget` SSRF | 2026-11-22 | Merged (PR #46) |
| 56.5 | [Branch 5: plain-PHP recall on the PHP sample](symfony-more-analyzers-5.md) | Two DVWA misses closed and two more configuration settings | 2026-11-23 | In review (PR #47) |
| 57.1 | [Juice Shop and Next.js hardening, branch 1: existing analyzers on JavaScript and TypeScript](juiceshop-nextjs-hardening-1.md) | Application-security families on Express apps, and the upload gap closed | 2026-11-24 | Specified. Branch 1 of a two-branch stack |
| 57.2 | [Branch 2: scanner comparison on four samples](juiceshop-nextjs-hardening-2.md) | Semgrep CE and Bearer rerun on four samples, with one comparison summary | 2026-11-24 | Implemented on its branch; curated sample copies open |
| 57.3 | [Branch 3: misses, blocked records, reads and false positives](juiceshop-nextjs-hardening-3.md) | The comparison's Juice Shop misses and false positives | 2026-11-24 | Implemented; judged acceptance not met, six rows open ([results](../evaluation/juiceshop-hardening-results.md#open-rows)) |
| 59 | [Detection generalization: series index](detection-generalization/README.md), with its [delivery plan](detection-generalization/delivery-plan.md) and specifications 00 to 23 | Detection by what an operation does, judged by the model, instead of per-library rules | 2026-11-25 | 17, 19 and 21 merged (PRs #52, #54, #56); 20 closed unmerged; 22 and 23 implemented, unmerged; the rest draft |

### Planned

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 63 | [Phase 7: npm corpus and direct-model baseline](architecture-phase-7-npm-corpus.md) | A pinned npm library corpus, answer keys and a direct-model baseline | 2026-11-17 | Plan order 4 (waypoint W2) |
| 64 | [Phase 8: npm library mode](architecture-phase-8-npm-library-mode.md) | Library-mode scanning on the existing analyzers | 2026-11-17 | Starts after phase 7 (waypoint W4) |
| 65 | [Phase 9: Drupal](architecture-phase-9-drupal.md) | Drupal module routes as PHP entries | 2026-11-17 | Planned |

## 2. Dependency Audit (`audit/`)

Specifications live in [`audit/`](audit/README.md).

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 60 | [Dependency Audit: series index](audit/README.md): [01 npm and pnpm](audit/01-node.md); 02 Python and PHP, 03 advisory enrichment and 04 documentation not written | The `audit` command, the `zazzles.audit/v1` findings file and an HTML report | 2026-11-28 | Plan order 2. 01 drafted, for owner review |

## 3. Zazzles Agent (`agent/`)

Specifications will live in `agent/`.

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 62 | Zazzles Agent (`agent/`) | Installed skills that remediate from Audit findings through reviewed PRs | Not written | Plan order 3, after Dependency Audit 01 merges |

## 4. Endpoint Probe (`probe/`)

Specifications will live in `probe/`.

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 66 | Endpoint Probe (`probe/`) | Authorized read-only endpoint checks, starting with TLS and certificates | Not written | Plan order 5 |

## 5. Repository and release

Layout, tooling and release work that spans modules. These specifications stay in this directory's root.

| Order | Specification | Delivers | First committed | State |
|---:|---|---|---|---|
| 52 | [Scan, Fix and Probe repository layout](scan-fix-probe-repository-layout.md) | Top-level module directories and per-module user docs | 2026-11-21 | Merged (PR #37) |
| 58 | [Markdown diff linting](markdown-diff-linting.md) | CI lint of added Markdown for prompt injection and hidden text | 2026-11-25 | Merged (PR #53) |
| 61 | First release of `scan` and `audit` (`first-release.md`) | Release workflow, macOS and Linux binaries, a GitHub Action, promotion to `main` | Not written | After Dependency Audit 04. Own worktree; the owner merges to `main` and tags |

## Maintaining this index

Add a row to the module's section when a specification is created, and update its state when its
pull request merges. Give a new specification the next order number. Do not copy acceptance
evidence here: link the specification. A stacked lane takes one order number with a decimal per
branch. Keep **Delivers** to one short line about the outcome; the specification owns the detail. A
planned module row with no specification yet names the module directory and is replaced by a link
when the first specification is written.
