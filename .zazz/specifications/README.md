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

- [XSS hardening](xss-hardening.md) — every known XSS across five sample apps confirmed, with source-reviewed negatives held

- [Node.js input/acquisition refactor](node-http-input-refactor.md) — transport-neutral value facts, bounded Express/Fastify/Hapi adapters, shared sink contracts and opt-in provisional model discovery; Python migration proposed separately at project root.

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
