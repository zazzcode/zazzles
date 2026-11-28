# Specifications

Deliverable specifications — the bounded execution contracts that agent sessions implement.

- authored with the `spec-builder` skill (see `.agents/skills/spec-builder/`)
- quality bar: `../standards/spec-hygiene.md`
- explicit user implementation requests authorize work; use `.agents/skills/spec-driven/` for evidence
  and review discipline, with the local authorization rules taking precedence

## Storage policy

Specifications are **tracked in Git** in this repo (Git-native audit trail). They are committed to the
deliverable's branch and reviewed through the same PR flow as code.

Working notes, run logs, QA findings, and handoffs do **not** live here — they go to
`.zazz/ephemeral/` (gitignored) or a worktree-local location.

## Folders by module

Each module's specifications live in a folder named like the code directory they change:
[`scan/`](scan/) for Code Scan, [`audit/`](audit/README.md) for Dependency Audit, and, when their
first specifications are written, `agent/` for Zazzles Agent and `probe/` for Endpoint Probe.
Repository-wide specifications (layout, tooling, release) stay in this directory's root. A series of
specifications gets its own folder inside its module's folder, with a `README.md` index.

## Specification index

The [index](spec-index.md) lists every specification grouped by module, in delivery order, with a
one-line description of what each delivers. The entries below describe each one.

- [Markdown diff linting](markdown-diff-linting.md) covers agent-facing text checks in CI.

- [Dependency Audit](audit/README.md) — series of five specifications for the `audit` command under `audit/`, which runs the target's own package-manager audit and writes the `zazzles.audit/v1` findings file Zazzles Agent reads and an HTML report. [01 npm and pnpm](audit/01-node.md), [02 advisory enrichment](audit/02-enrichment.md) (OSV, NIST NVD, CISA KEV, EPSS), [03 Python](audit/03-python.md) and [04 PHP](audit/04-php.md) are drafted; 05 documentation follows. A separate first-release specification then publishes `scan` and `audit` binaries and promotes to `main`.

- [Detection generalization](scan/detection-generalization/README.md) — draft series of fourteen specifications, ordered by expected general value after precision, with a shared [contract](scan/detection-generalization/contract.md) and a [delivery plan](scan/detection-generalization/delivery-plan.md). Not approved or implemented.

- [Juice Shop and Next.js hardening](scan/juiceshop-nextjs-hardening-1.md) — specified as two stacked branches in the `juiceshop-nextjs-hardening` worktree. [Branch 1](scan/juiceshop-nextjs-hardening-1.md) extends the `exposure`, `mass-assignment`, `authorization`, `account` and `configuration` families to Express applications in JavaScript and TypeScript and closes the upload gap, with OWASP Juice Shop and vuln-nextjs as the measure; it adds no analyzer. [Branch 2](scan/juiceshop-nextjs-hardening-2.md) reruns Semgrep CE and Bearer on four samples and reorganizes the comparison documents around one summary linked from the project README. [Branch 3](scan/juiceshop-nextjs-hardening-3.md) is specified: it closes the three Juice Shop misses the comparison found, reports reads of a record another user owns, removes three false positives, and lists the follow-on work.

- [Symfony application-security analyzers](scan/symfony-more-analyzers.md) — implemented as a stacked lane of five PRs in the `symfony-more-analyzers` worktree. Branches 1 to 4 are merged (PRs #42, #43, #45 and #46); branch 4 delivered configuration, SSRF through a shell URL client and lane closure: [1](scan/symfony-more-analyzers-1.md), [2](scan/symfony-more-analyzers-2.md), [3](scan/symfony-more-analyzers-3.md), [4](scan/symfony-more-analyzers-4.md). Branch 5 is in review (PR #47) and closes the four PHP-sample gaps an existing analyzer can cover: a SQL statement held in a variable, a request-selected row, remote include and session cookie flags set in code: [5](scan/symfony-more-analyzers-5.md). Paid judged runs are recorded in [symfony-results.md](../evaluation/symfony-results.md) and [dvwa-results.md](../evaluation/dvwa-results.md).

- [Scan, Fix, and Probe repository layout](scan-fix-probe-repository-layout.md) — proposed module migration, CLI and report compatibility, and a full documentation audit.

- [Architecture update plan](scan/architecture-update-plan.md) — foundation first (accuracy, performance, maintainability), then features. Capability matrix and one spec per phase, run in series:
  [0 compatibility baseline](scan/architecture-phase-0-compatibility-baseline.md) (implemented:
  `TestArchitectureBaseline`, [before measurements](../evaluation/architecture-baseline.md)),
  [1 source index and callable summaries](scan/architecture-phase-1-source-index.md) (replaces the superseded
  [registration graph](scan/architecture-phase-1-registration-graph.md)),
  [2 pipeline and concurrent runners](scan/architecture-phase-2-pipeline-runners.md),
  [3A PHP package](scan/architecture-phase-3-php-package.md),
  [3B JS/TS and Python packages](scan/architecture-phase-3-js-ts-python-package.md),
  [4 parallel judge](scan/architecture-phase-4-parallel-judge.md),
  [5 measured recall gaps](scan/architecture-phase-5-accuracy-gaps.md),
  [6 Symfony](scan/architecture-phase-6-symfony.md),
  [7 npm corpus and baseline](scan/architecture-phase-7-npm-corpus.md),
  [8 npm library mode](scan/architecture-phase-8-npm-library-mode.md),
  [9 Drupal](scan/architecture-phase-9-drupal.md). Each unimplemented phase starts on owner assignment.
- [Shared Gemini Decisions provider](scan/gemini-decisions.md) — interactive shared-provider integration and bounded live smoke before analyzer work.
- [Path Traversal Analyzer](scan/path-traversal.md) — JS/TS/Python filesystem, Zip Slip (`adm-zip`/`unzipper`) and `hbs` layout containment analysis; implemented and live-verified across all eight sample apps.
- [Path Traversal Tier-1 Hardening](scan/path-traversal-hardening.md) — AST branch-polarity/conjunction soundness, normalization-sensitive substring policy, false-protection closures, guarded constant/import excerpt injection, determinism and file-size split; implemented and live-verified.
- [Cross-Analyzer Engine Hardening](scan/analyzer-engine-hardening.md) — milestone specification index (`E1`–`E4`) and executable Slice `E1` contract (`--only-family`/`--skip-family`, `--judge-limit` XSS/Logging priority & zero-call observation handling, and default-on context deduplication) for execution after `path-traversal` merges to `stage`.
- [Shared Guard & Workspace Manifest Engine](scan/shared-guard-and-manifest-engine.md) — Slice `E2` contract: one lexical guard engine (polarity, terminators, derived values, reassignment, helper call sites) for Command and Path, allow-list definition evidence, and nearest-workspace manifest/lockfile version resolution for Path, XSS and NoSQL; implemented and verified in the `analyzer-engine-hardening` worktree.

- [Analyzer assessment coverage](scan/analyzer-assessment-coverage.md) — MarsDB named-import binding, request budget with explicit omissions and `evidence_too_large` floor, outbound destination origin/grouping and the first SSRF family, Sequelize finder contract; implemented and merged via PR #14.
- [Wire bundle v7](scan/wire-bundle-v7.md) — compact evidence wire, logging catalog sync, wrappers/middleware summaries, JS conditionals; merged via PR #14.
- [Shared Node inputs and file APIs (E4)](scan/shared-node-inputs-and-file-apis.md) — Express middleware-chain entries, `source.node-input-v2` URL/upload facts, phase-2 Node/Python file APIs, Node `http`/`https` SSRF; merged via [PR #15](https://github.com/zazzcode/zazzles/pull/15).
- [Next.js phase 2 and code/redirect](scan/nextjs-phase-2-and-code-redirect.md) — two analyzer families, remaining practice checks, flow/entry coverage and non-vulnerable-app measurement; [results](../evaluation/nextjs-phase-2-results.md).
- [Analyzer protection and flow coverage](scan/analyzer-protection-and-flow-coverage.md) — proposal 1: guard/validator protection to the final operand, redirect normalization semantics, inventory-selected flow gaps, stored-path writes/reads and Review explanations on the PR #19 analyzers; in progress.
- [Practice accuracy and false-positive evaluation](scan/practice-accuracy-and-false-positive-evaluation.md) — proposal 2 implementation contract, reproduced practice defects, pinned Commerce record audit, explicit accuracy metrics and bounded evaluation plan on the merged PR #20 baseline.
- [False positives and Review noise](scan/accuracy-false-positive-noise.md) — proposal: precision denominators, source-less finding demotion, undecidable-validation gate, sink grouping, origin evidence and model-judged guard adequacy.
- [Model-assisted evidence resolution](scan/model-assisted-evidence-resolution.md) — proposal, follows the false-positive contract: the decision model resolves scanner blockers through verified citations.
- [Close findings gaps](scan/close-findings-gaps.md) — proposal: the Review and missed rows on Node.js Goof, DVWA and Python insecure app. Single-path bypass citation, regex capture facts, PHP class and method binding, over-limit path-group requests, upload and template-injection claims, key corrections.
- [Judge request size reduction](scan/judge-request-size-reduction.md) — implemented, in review ([results](../evaluation/judge-request-size-reduction-results.md)): smaller decision requests with no source or fact removed. Request-local identity aliases, structural repetition stated once, count-based size notices and short XSS choice labels under one protocol bump, with offline size criteria and a paired live accuracy check on DVWA and Juice Shop.
- [Judge evidence quality](scan/judge-evidence-quality.md) — implemented, in review (same PR): prepared-statement provenance, per-path PHP XSS output context, one transfer per concatenation site, a cookie-source XSS rule and allow-listed request-element state, measured by live verdict confidence on DVWA.
- [Command bypass support](scan/command-bypass-support.md) — implemented, in review: a guard bypass on a fully guarded shell path is Confirmed only when the path's scanner-listed characters can carry command text; a PHP numeric path cites its check, and the bypass question asks for command text of the request's choosing (`command-components-v5`). Protected control PC-CMD-02 is Protected on the paid DVWA run ([results](../evaluation/command-bypass-support-results.md)).
- [Prototype pollution analyzer](scan/prototype-pollution.md) — proposal: new `pollution` family (CWE-1321) for JS/TS. Lodash merge and set-by-path by version, source-visible recursive merge, path walk and nested computed write, with the scanner listing what a key deny-list blocks. Node.js Goof and the Vulnerable TypeScript app are the application samples; the library write claim follows npm phases 7 and 8. Own branch and worktree.
- [Prototype pollution walk start](scan/pollution-walk-start.md) — implemented in the feature branch with offline verification. Stable module, local and property starts and inline handler walks close `PP-N01` and `PP-N02`. The six pinned JS/TS samples gained no new write sites. [Results](../evaluation/pollution-walk-start-results.md).
- [Prototype pollution write shapes](scan/pollution-write-shapes.md) — implemented and verified offline, uncommitted and pending owner review: seven source-visible write shapes the stage 1 analyzer missed (other key enumerators, alias recursion, array and regular-expression paths, unflatten, `reduce` walks) and four exploration shapes, taken from the NDSS 2026 Bullseye paper and confirmed with probe fixtures. Static only. [Results](../evaluation/pollution-write-shapes-results.md).
- [PHP Symfony support](scan/php-symfony-support.md) — implemented on the feature branch and in draft review, supersedes phase 6: Symfony websites as scan targets across every supported analyzer family (routes, argument binding, `Request` sources, services, Doctrine, Twig, upload, URL-open SSRF, PSR-3 logging), 112 defined fixture cases, and the `vuln-symfony` answer key of 14 required findings. Its prerequisites are merged.
- [Unsafe deserialization analyzer](scan/unsafe-deserialization.md) — implemented in the feature worktree for Python, JavaScript, TypeScript, and PHP. [Offline verification](../evaluation/deserialization-results.md) records the fixture and sample results, with lab scenarios and live evaluation open.
- [Next.js support](scan/nextjs-support.md) — App Router/Server Action/page entries, `web-request-v1` origins, Prisma/better-sqlite3/pino/zod contracts, client and server rendering, practice tier; draft [PR #18](https://github.com/zazzcode/zazzles/pull/18).
- [PHP support (DVWA MVP)](scan/php-support.md) — plain-PHP adapter (server-mapped entries, include dispatch alternatives, `source.php-input-v1`), core family contracts (`php-mysqli/pdo/sqlite3-v1`, `php-program-execution-v1`, filesystem/upload/include, `php-eval-v1`, `php-header-redirect-v1`) evaluated against DVWA `a1978a2`; implemented on `php-dvwa`, offline ACs 1–13 green ([results](../evaluation/php-support-results.md)), paid AC14 pending.

- [XSS hardening](scan/xss-hardening.md) — every known XSS across five sample apps confirmed, with source-reviewed negatives held

- [Node.js input/acquisition refactor](scan/node-http-input-refactor.md) — transport-neutral value facts, bounded Express/Fastify/Hapi adapters, shared sink contracts and opt-in provisional model discovery; follow-up Python migration has its own [contract](scan/python-input-refactor.md).
- [Shared Python input acquisition](scan/python-input-refactor.md) — existing Python HTTP adapters emit shared origin/type/transfer facts with separate versioned interpretation; behavior and replay compatibility verified independently of new framework coverage.

- [Command Injection Analyzer](scan/command-injection.md) — JS/TS/Python process and shell analysis using the shared analysis-pack structure; full judged Juice Shop, VulnPy, nodejs-goof and vulnerable-typescript-app acceptance with refreshed GitHub HTML/JSON/SARIF samples; implemented and source-reviewed, with later bounded follow-ups recorded in evaluation docs.

Use the assigned feature worktree for related contract, design, implementation and tests. Explicit
user implementation requests authorize work under [AGENTS.md](../../AGENTS.md#authorization-and-delivery).
Independent future deliverables may use separate feature worktrees/PRs targeting `stage`.

- [Phase 0 skeleton](scan/phase0-skeleton/README.md) — historical foundation contract, retained for context.
  The revised [Phase 0 plan](../project/implementation-plan.md#phase-0--foundation-audit-and-tooling-decision)
  audits existing artifacts before further work.
- [Tree-sitter route identification MVP](scan/tree-sitter-route-identification-mvp.md) — greenlit
  2026-10-24 and implemented; syntax inventory only. Reverified on Juice Shop in the
  [route assessment](../project/06-route-validation-assessment.md#route-verification).
- [Route string validation](scan/route-string-validation.md) — implementation explicitly authorized by
  the user on 2026-10-31 in the assigned feature worktree.
  Start from the [near-term sequence](../project/implementation-plan.md#route-string-validation-delivery-sequence).
- [Sensitive-data logging](scan/sensitive-data-logging.md) — requested by the user on 2026-11-01 in the
  `logger-leak` worktree; increment 1 (explicit logger calls) in progress.
- [XSS response analysis](scan/xss-response.md) — authorized sequential implementation on 2026-11-01;
  backend responses/templates/storage first, browser results separately, Python adapter boundary preserved.
- [Common entry and dispatch](scan/common-entry-dispatch.md) — architecture and eight phased
  deliverable contracts requested 2026-11-03 in `common-entry-and-dispatch`; deliverables1–7
  implemented, accepted and merged through PR #8 on 2026-11-05. See
  [acceptance results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05). Includes HTTP/browser preservation, browser events, bounded
  dynamic HTTP, Node.js GraphQL/gRPC, entry-specific reports and saved-report compatibility.
- [Analysis pack MVP](scan/analysis-pack-mvp.md) — SQL-first embedded component migration; implemented
  and offline-verified 2026-11-05 in `analysis-pack-mvp` on the merged common-entry/dispatch
  foundation. Includes applicability, provenance and offline SQL acceptance.
- [Components 01: NoSQL + input validation](scan/components-01-nosql-validation.md) — implemented and
  offline-verified 2026-11-05; SQL-only assumptions generalized, NoSQL and standalone validation
  migrated with independent claim protocols.
- [Components 02: all XSS types and browser](scan/components-02-xss.md) — implemented and offline-verified
  2026-11-05; selected rendering/stored/browser/cross-tier material, independent context/origin/path
  gates and isolated literal/default/unknown fetch-method attribution.
- [Components 03: outbound observations](scan/components-03-outbound.md) — implemented and offline-verified
  2026-11-06; scoped observation selections, zero-call `not_run`, browser/server isolation and
  saved-report parity. Complete SSRF judgment remains separate.
- Other planned specs are not authored yet. Their proposed slices live in the
  [implementation plan](../project/implementation-plan.md); each needs a bounded contract and user authorization.

See [repository state](../project.md#concept-stage-repository-state) for the current concept stage and
[specification-driven delivery](../docs/zazz-methodology.md#specification-driven-delivery-cycle) for
ownership, approval, execution, and review requirements. Earlier LLM-era phase numbering is superseded
by the current plan.

The [decision-model limits contract](scan/decision-model-limits.md) records owner-authorized shared rate and
spending controls implemented and verified under the full race suite.

## Wire bundle v7

[Wire bundle v7 and catalog synchronization](scan/wire-bundle-v7.md) implements the coordinated E3 protocol upgrade in the assessment-coverage branch.
