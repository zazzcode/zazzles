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

## Specification index

- [Architecture update plan](architecture-update-plan.md) — foundation first (accuracy, performance, maintainability), then features. Capability matrix and one spec per phase, run in series:
  [0 compatibility baseline](architecture-phase-0-compatibility-baseline.md) (implemented:
  `TestArchitectureBaseline`, [before measurements](../evaluation/architecture-baseline.md)),
  [1 source index and callable summaries](architecture-phase-1-source-index.md) (replaces the superseded
  [registration graph](architecture-phase-1-registration-graph.md)),
  [2 pipeline and concurrent runners](architecture-phase-2-pipeline-runners.md),
  [3A PHP package](architecture-phase-3-php-package.md),
  [3B JS/TS and Python packages](architecture-phase-3-js-ts-python-package.md),
  [4 parallel judge](architecture-phase-4-parallel-judge.md),
  [5 measured recall gaps](architecture-phase-5-accuracy-gaps.md),
  [6 Symfony](architecture-phase-6-symfony.md),
  [7 npm corpus and baseline](architecture-phase-7-npm-corpus.md),
  [8 npm library mode](architecture-phase-8-npm-library-mode.md),
  [9 Drupal](architecture-phase-9-drupal.md). Each unimplemented phase starts on owner assignment.
- [Shared Gemini Decisions provider](gemini-decisions.md) — interactive shared-provider integration and bounded live smoke before analyzer work.
- [Path Traversal Analyzer](path-traversal.md) — JS/TS/Python filesystem, Zip Slip (`adm-zip`/`unzipper`) and `hbs` layout containment analysis; implemented and live-verified across all eight sample apps.
- [Path Traversal Tier-1 Hardening](path-traversal-hardening.md) — AST branch-polarity/conjunction soundness, normalization-sensitive substring policy, false-protection closures, guarded constant/import excerpt injection, determinism and file-size split; implemented and live-verified.
- [Cross-Analyzer Engine Hardening](analyzer-engine-hardening.md) — milestone specification index (`E1`–`E4`) and executable Slice `E1` contract (`--only-family`/`--skip-family`, `--judge-limit` XSS/Logging priority & zero-call observation handling, and default-on context deduplication) for execution after `path-traversal` merges to `stage`.
- [Shared Guard & Workspace Manifest Engine](shared-guard-and-manifest-engine.md) — Slice `E2` contract: one lexical guard engine (polarity, terminators, derived values, reassignment, helper call sites) for Command and Path, allow-list definition evidence, and nearest-workspace manifest/lockfile version resolution for Path, XSS and NoSQL; implemented and verified in the `analyzer-engine-hardening` worktree.

- [Analyzer assessment coverage](analyzer-assessment-coverage.md) — MarsDB named-import binding, request budget with explicit omissions and `evidence_too_large` floor, outbound destination origin/grouping and the first SSRF family, Sequelize finder contract; implemented and merged via PR #14.
- [Wire bundle v7](wire-bundle-v7.md) — compact evidence wire, logging catalog sync, wrappers/middleware summaries, JS conditionals; merged via PR #14.
- [Shared Node inputs and file APIs (E4)](shared-node-inputs-and-file-apis.md) — Express middleware-chain entries, `source.node-input-v2` URL/upload facts, phase-2 Node/Python file APIs, Node `http`/`https` SSRF; merged via [PR #15](https://github.com/zazzcode/zazzles/pull/15).
- [Next.js phase 2 and code/redirect](nextjs-phase-2-and-code-redirect.md) — two analyzer families, remaining practice checks, flow/entry coverage and non-vulnerable-app measurement; [results](../evaluation/nextjs-phase-2-results.md).
- [Analyzer protection and flow coverage](analyzer-protection-and-flow-coverage.md) — proposal 1: guard/validator protection to the final operand, redirect normalization semantics, inventory-selected flow gaps, stored-path writes/reads and Review explanations on the PR #19 analyzers; in progress.
- [Practice accuracy and false-positive evaluation](practice-accuracy-and-false-positive-evaluation.md) — proposal 2 implementation contract, reproduced practice defects, pinned Commerce record audit, explicit accuracy metrics and bounded evaluation plan on the merged PR #20 baseline.
- [Next.js support](nextjs-support.md) — App Router/Server Action/page entries, `web-request-v1` origins, Prisma/better-sqlite3/pino/zod contracts, client and server rendering, practice tier; draft [PR #18](https://github.com/zazzcode/zazzles/pull/18).
- [PHP support (DVWA MVP)](php-support.md) — plain-PHP adapter (server-mapped entries, include dispatch alternatives, `source.php-input-v1`), core family contracts (`php-mysqli/pdo/sqlite3-v1`, `php-program-execution-v1`, filesystem/upload/include, `php-eval-v1`, `php-header-redirect-v1`) evaluated against DVWA `a1978a2`; implemented on `php-dvwa`, offline ACs 1–13 green ([results](../evaluation/php-support-results.md)), paid AC14 pending.

- [XSS hardening](xss-hardening.md) — every known XSS across five sample apps confirmed, with source-reviewed negatives held

- [Node.js input/acquisition refactor](node-http-input-refactor.md) — transport-neutral value facts, bounded Express/Fastify/Hapi adapters, shared sink contracts and opt-in provisional model discovery; follow-up Python migration has its own [contract](python-input-refactor.md).
- [Shared Python input acquisition](python-input-refactor.md) — existing Python HTTP adapters emit shared origin/type/transfer facts with separate versioned interpretation; behavior and replay compatibility verified independently of new framework coverage.

- [Command Injection Analyzer](command-injection.md) — JS/TS/Python process and shell analysis using the shared analysis-pack structure; full judged Juice Shop, VulnPy, nodejs-goof and vulnerable-typescript-app acceptance with refreshed GitHub HTML/JSON/SARIF samples; implemented and source-reviewed, with later bounded follow-ups recorded in evaluation docs.

Use the assigned feature worktree for related contract, design, implementation and tests. Explicit
user implementation requests authorize work under [AGENTS.md](../../AGENTS.md#authorization-and-delivery).
Independent future deliverables may use separate feature worktrees/PRs targeting `stage`.

- [Phase 0 skeleton](phase0-skeleton/README.md) — historical foundation contract, retained for context.
  The revised [Phase 0 plan](../project/implementation-plan.md#phase-0--foundation-audit-and-tooling-decision)
  audits existing artifacts before further work.
- [Tree-sitter route identification MVP](tree-sitter-route-identification-mvp.md) — greenlit
  2026-10-24 and implemented; syntax inventory only. Reverified on Juice Shop in the
  [route assessment](../project/06-route-validation-assessment.md#route-verification).
- [Route string validation](route-string-validation.md) — implementation explicitly authorized by
  the user on 2026-10-31 in the assigned feature worktree.
  Start from the [near-term sequence](../project/implementation-plan.md#route-string-validation-delivery-sequence).
- [Sensitive-data logging](sensitive-data-logging.md) — requested by the user on 2026-11-01 in the
  `logger-leak` worktree; increment 1 (explicit logger calls) in progress.
- [XSS response analysis](xss-response.md) — authorized sequential implementation on 2026-11-01;
  backend responses/templates/storage first, browser results separately, Python adapter boundary preserved.
- [Common entry and dispatch](common-entry-dispatch.md) — architecture and eight phased
  deliverable contracts requested 2026-11-03 in `common-entry-and-dispatch`; deliverables1–7
  implemented, accepted and merged through PR #8 on 2026-11-05. See
  [acceptance results](../evaluation/common-entry-dispatch-results.md#cross-entry-acceptance-2026-11-05). Includes HTTP/browser preservation, browser events, bounded
  dynamic HTTP, Node.js GraphQL/gRPC, entry-specific reports and saved-report compatibility.
- [Analysis pack MVP](analysis-pack-mvp.md) — SQL-first embedded component migration; implemented
  and offline-verified 2026-11-05 in `analysis-pack-mvp` on the merged common-entry/dispatch
  foundation. Includes applicability, provenance and offline SQL acceptance.
- [Components 01: NoSQL + input validation](components-01-nosql-validation.md) — implemented and
  offline-verified 2026-11-05; SQL-only assumptions generalized, NoSQL and standalone validation
  migrated with independent claim protocols.
- [Components 02: all XSS types and browser](components-02-xss.md) — implemented and offline-verified
  2026-11-05; selected rendering/stored/browser/cross-tier material, independent context/origin/path
  gates and isolated literal/default/unknown fetch-method attribution.
- [Components 03: outbound observations](components-03-outbound.md) — implemented and offline-verified
  2026-11-06; scoped observation selections, zero-call `not_run`, browser/server isolation and
  saved-report parity. Complete SSRF judgment remains separate.
- Other planned specs are not authored yet. Their proposed slices live in the
  [implementation plan](../project/implementation-plan.md); each needs a bounded contract and user authorization.

See [repository state](../project.md#concept-stage-repository-state) for the current concept stage and
[specification-driven delivery](../docs/zazz-methodology.md#specification-driven-delivery-cycle) for
ownership, approval, execution, and review requirements. Earlier LLM-era phase numbering is superseded
by the current plan.

The [decision-model limits contract](decision-model-limits.md) records owner-authorized shared rate and
spending controls implemented and verified under the full race suite.

## Wire bundle v7

[Wire bundle v7 and catalog synchronization](wire-bundle-v7.md) implements the coordinated E3 protocol upgrade in the assessment-coverage branch.
