# The Zazz Methodology

**Scan authorization override, 2026-10-31:** an explicit user implementation request is sufficient
approval in the assigned isolated worktree. No separate Deliverable Owner greenlight ceremony is
required. Related documentation, design, implementation and tests may share that worktree. See
[AGENTS.md](../../AGENTS.md#authorization-and-delivery), which takes precedence over the historical
lifecycle/topology wording below. Human review and merge authority remain unchanged.

Zazz is an operating model for the agentic software delivery lifecycle. It helps teams use agents to move faster while keeping product direction, engineering quality, review discipline, and merge authority in human hands.

This document is the methodology entry point and executive overview. Scan vendors the entry-point guide and selected workflow skills; the [section guide](#section-guide)
routes to references available in this repository. Upstream focused section documents are not all vendored here.

## Scan applicability during project definition

This guide describes the shared delivery process as adapted for zazzles. Repository status is recorded in
the [project overview](../project.md#concept-stage-repository-state); the documentation-only `stage/`
exception is declared in [AGENTS.md](../../AGENTS.md#branch-model). Workspace/session guidance and
methodology refinement live in the [orientation](zazzles-agent-orientation.md).

The [project plan](../project/implementation-plan.md) groups future specs into phases. Those groupings
are neither execution approval nor scheduled milestones. Explicit user implementation requests
supply authorization; related contract, design and implementation stay in the assigned feature
worktree under [AGENTS.md](../../AGENTS.md#authorization-and-delivery). The evidence and human review
lifecycle below still applies with that local override.

## Executive Overview

AI agents can produce code quickly. The hard part is making sure the team is building the right thing, the implementation is reviewable, the evidence is credible, and the knowledge survives after merge.

Zazz gives teams a repeatable path from product intent to a human-reviewed, merged software change:

- Durable docs explain the product, architecture, decisions, features, and standards.
- Deliverable specifications turn intent into bounded implementation contracts with acceptance criteria, test strategies, standards, and halt conditions.
- Spec-driven development keeps approved specifications, implementation evidence, Deliverable Owner steering, QA feedback, and PR review aligned through a controlled lifecycle.
- Deterministic quality gates turn enforceable code, documentation, accessibility, type-safety, and formatting rules into repeatable checks before probabilistic agent or human review.
- Standards conformance work keeps legacy and existing code moving toward adopted standards through small, reviewable,
  evidence-backed maintenance PRs.
- Agents execute inside approved contracts, isolated worktrees, and repo standards.
- Validation, pull request packaging, and automated self-review happen before human review and merge.
- Durable docs are updated when shipped work changes the product, architecture, or standards.

The result is faster agent-assisted delivery with clearer scope, stronger review signal, less rework, and durable knowledge that stays useful after the PR is merged.

## Roles

Zazz reserves ownership for human accountability and names AI participation explicitly:

- A **Project Owner** is the human accountable for project direction and durable product context.
- A **Deliverable Owner** is the human accountable for a deliverable's intent, scope decisions, acceptance, and review or merge readiness. A Project Owner may also be a Deliverable Owner.
- A **Contributor** is a human engineer contributing to a deliverable. A Contributor may also be its Deliverable Owner.
- A **Contributor Agent** is an AI agent assigned explicitly to bounded implementation, testing, documentation, or investigation work.
- A **Lead Agent** is a designated Contributor Agent that coordinates execution. It may delegate work to other Contributor Agents and Verifier Agents, but remains responsible for integrating agent-produced work and evidence.
- A **Verifier Agent** or **QA Agent** is an AI agent performing independent verification. It does not modify implementation unless explicitly assigned that work.

The Deliverable Owner retains authority for contract changes, acceptance, and review or merge readiness. A Lead Agent coordinates execution; it does not gain Deliverable Owner authority.

## Progression

Zazz moves from durable context to executable work, then back into durable knowledge after the work ships.

```text
project.md
  -> architecture.md
  -> proposals/
  -> features/ for capability context
  -> project milestones / roadmap for timeline planning
  -> specifications/
  -> spec-driven development
  -> deterministic quality gates
  -> standards conformance maintenance
  -> code generation
  -> testing and validation
  -> PR packaging and automated review
  -> human review and merge
  -> durable docs updated
```

Not every step is needed for every change. Small fixes may start at a specification. Uncertain product or technical direction should start with a proposal. Long-lived capabilities should have feature and architecture context before deliverables are sliced.

## Specification-Driven Delivery Cycle

Specification-driven delivery is the core execution segment of the SDLC, not the
entire SDLC. It begins when a Deliverable Owner greenlights a bounded deliverable
specification and ends when that deliverable is human-reviewed, merged, and its durable
knowledge is updated. It connects pre-delivery product planning to post-delivery
operational oversight.

```text
Project Owner establishes project direction and project milestones
  -> proposals resolve uncertainty when needed
  -> features and architecture establish durable capability context
  -> deliverables are assigned to project milestone time boxes
  -> Deliverable Owner greenlights a deliverable specification
  -> Lead Agent coordinates Contributor Agents and Verifier Agents
  -> implementation, evidence, QA, and draft-PR feedback refine the current contract
  -> human review, approval, and merge
  -> deployment, operational review, maintenance, and durable-doc updates
```

Within this cycle, a Lead Agent may implement directly or delegate bounded work to
Contributor Agents. The Lead Agent integrates agent-produced work and evidence; the
Deliverable Owner remains the human authority for scope changes, acceptance, and review
or merge readiness. QA and Verifier Agents provide independent evidence but do not
change implementation unless explicitly reassigned.

The cycle does not replace the work before a specification exists—project direction,
proposals, features, architecture, and milestone planning—nor the work after merge:
deployment, monitoring, support, maintenance, and subsequent planning. Those stages
inform the next deliverables and may reopen proposals, feature documents, architecture,
or standards when the product or operating environment changes.

## Project Milestones And Deliverables

Project milestones are project-owned time boxes for communicating planned delivery.
They belong to the project plan, not to an individual feature. A milestone can contain
deliverables from multiple features, as well as bug fixes, chores, or technical
investments. A deliverable may contribute to a feature for capability context while also
being assigned to a project milestone for timeline and stakeholder planning.

Every deliverable should record its Project Owner, Deliverable Owner, feature context
when applicable, and assigned project milestone or an explicit `N/A`. The milestone is
the time box; the deliverable is the bounded, reviewable execution unit inside it.

Use incremental discovery: read the entry point to choose the current stage, then load only its
relevant local guide or skill. Do not assume upstream section documents exist in this checkout.

## Section Guide

These are available local routes for the lifecycle stages. Product/architecture documents describe
zazzles's current proposals; workflow skills and standards describe how approved work is handled.

| Stage / local reference | Local role |
| ------- | ------- |
| [Project Document](../project.md) | Zazzles's top-level product orientation. |
| [Document Storage](../../AGENTS.md#document-model) | Defines where durable docs, active implementation scratch, completed specs, project plans, roadmaps, and milestones live. |
| [Architecture](../architecture/README.md) | Zazzles's proposed technical shape. |
| [Proposals](../project/03-jev-design-proposal.md) | Current proposal, rationale, research inputs, and open decisions. |
| [Features and Project Milestones](../project/implementation-plan.md) | Proposed phases/spec slices; milestones and owners remain to be assigned. |
| [Specifications](../../.agents/skills/spec-builder/SKILL.md) | Defines deliverable specifications as bounded execution contracts. |
| [Spec-Driven Development](../../.agents/skills/spec-driven/SKILL.md) | Defines the post-greenlight lifecycle for implementation, steering, contract updates, QA, PR feedback, and signoff. |
| [Deterministic Quality Gates](../standards/testing.md) | Defines linters, formatters, type checks, accessibility checks, doc checks, CI gates, and ongoing standards conformance as deterministic controls. |
| [Code Generation](agent-execution-discipline.md) | Defines agent implementation workflow, worktree discipline, and halt conditions. |
| [Testing and Validation](../standards/testing.md) | Defines acceptance verification, test quality, QA loops, and evidence. |
| [PR Creation](../../.agents/skills/pr-builder/SKILL.md) | Defines draft-first PR packaging and stacked PR usage. |
| [Self-Review](../../.agents/skills/pr-review/SKILL.md) | Defines author-side automated review before human review. |
| [Human Review and Merge](human-in-loop-pr-review-strategy.md) | Defines review tiers, human approval, merge expectations, and post-merge learning. |

## Core Model

Zazz uses a project-first document model:

- `project.md` explains the product's purpose, users, major capabilities, and durable operating assumptions.
- `architecture.md` or `architecture/` explains intended technical shape and important system decisions.
  Scan uses `.zazz/architecture/README.md`.
- `proposals/` or a declared project-doc location records decisions when the path is uncertain.
  Scan currently keeps its proposal/research docs in `.zazz/project/`.
- `features/` or a declared project-doc location describes long-lived capabilities and roadmap increments.
  Scan currently keeps capability context and the phase plan in `.zazz/project/`.
- `specifications/` contains deliverable specifications authored by spec-builder and executed by Contributor Agents inside the worktree. The repo decides whether this directory is tracked, ignored, mirrored, or promoted elsewhere.
- `ephemeral/` contains active implementation scratch: run logs, QA findings, handoff notes, recovery notes, evidence, and other records that normally stay out of Git. Ephemeral means uncommitted and non-durable, not necessarily memory-only; these files may persist locally until the worktree is removed.
- `standards/` defines how the software should be built.

Repos declare the docs root in `AGENTS.md`, commonly `docs/` or `.zazz/`. The value must be repo-relative.
Repos also declare their documentation operating model. That model decides whether
`specifications/` is tracked, ignored, mirrored, or promoted, and whether final specs,
project plans, roadmap, project milestones, or other durable docs are promoted to
GitHub Wiki, Confluence, or another system.

```text
<DOCS_ROOT>/
├── project.md
├── architecture/
├── proposals/
├── features/
├── specifications/
├── ephemeral/
└── standards/
```

## Operating Principles

1. Durable product and architecture knowledge lives in durable docs, not chats or transient task notes.
2. Deliverable specifications are the execution contracts for bounded work.
3. Approved specifications stay current through spec-driven development: implementation feedback updates the spec body in place and records an audit trail.
4. Deterministic tools enforce every quality rule they can express reliably.
5. Existing code is kept aligned through focused, agent-prepared conformance PRs against named standards and bounded
   repo areas.
6. Acceptance criteria and test evidence are required for convergence.
7. Agents may operate autonomously inside approved contracts, but humans retain scope, approval, signoff, and merge authority.
8. Active implementation happens in isolated worktrees or approved stacked lanes, with one Lead Agent coordinating file-conflict serialization. A gh-stack lane is one dedicated worktree containing every stacked branch; each branch and PR represents one dependent deliverable.
9. Draft PRs are the normal packaging surface for agent-generated work.
10. Automated self-review runs before a PR is marked ready for human review.
11. Active implementation artifacts live in `<DOCS_ROOT>/ephemeral/` or a declared tracker/service, and only durable knowledge is promoted into the repo, wiki, Confluence, or another declared knowledge base.
12. Durable docs are updated when implementation changes the product, architecture, feature capability, roadmap, project milestone state, or standards.

## Skills

The shared skills under [`.agents/skills/`](../../.agents/skills/) implement the methodology's common workflows:

| Workflow | Skill |
| -------- | ----- |
| Proposal exploration | `proposal-builder` |
| GitHub Wiki durable docs | `gh-wiki` |
| Confluence-backed durable docs | `confluence` |
| Feature requirements | `feature-doc-builder` |
| Architecture docs | `architecture-doc-builder` |
| Deliverable specifications | `spec-builder` |
| Spec-driven implementation lifecycle | `spec-driven` |
| Implementation verification | `qa-testing` |
| PR packaging | `pr-builder` |
| Automated self-review | `pr-review` |
| Stacked PR workflow | `gh-stack` |
| Worktree setup | `worktree` |
| Temporary handoff notes | `handoff` |
| Standard creation | `standard-builder` |
| Standards conformance | `conformance` |
| Documentation checks | `doc-check` |

Companion utility skills such as `gh-issue`, `handoff`, `zazz-board`, `jira`, `psql`, and `sqlcmd` provide repo-specific or tool-specific support when a project uses those systems.

Shared skills follow the Agent Skills format. Use [Agent Skills](../standards/agent-skills.md) for authoring rules,
portable front matter, metadata placement, and validation.

## Authority Gates

Agents can draft docs, implement code, run tests, prepare pull requests, and perform self-review when the governing contract is approved.

Humans control:

- approving proposals, feature direction, architecture direction, and deliverable specifications
- resolving product or technical ambiguity
- accepting subjective UX or product behavior
- requesting human review when repo policy requires it
- approving and merging PRs

## Storage Modes

Zazz is Git-native by default, but not every durable document has to live as a committed Markdown file in the application repository. Repos declare a documentation storage mode in `AGENTS.md` so agents know where to read and update project knowledge.

Supported durable storage modes include:

- repo-committed Markdown reviewed through normal branches and PRs
- GitHub Wiki, GitLab Wiki, Bitbucket Wiki, or another Git-backed repository wiki
- Confluence or a similar knowledge-base system
- tracker-backed records for issue-specific context

`project.md`, architecture, feature requirements, project plans, roadmaps, project milestones, and final implemented specifications may live in the declared durable storage surface. Local specification working files live under `<DOCS_ROOT>/specifications/`; RUN_LOG files and other active execution records live in `<DOCS_ROOT>/ephemeral/` or the declared tracker/service while work is underway. After implementation lands, the final current specification may be promoted to a wiki, Confluence, Jira, Zazz Board, or another durable location if the repo policy calls for it.

When an external document is the source of truth, keep a stable pointer in `AGENTS.md`, an index page, or a repo-tracked pointer file with title, responsible human, status, and link. See [Document Storage](../../AGENTS.md#document-model).

## Reference Implementation

Scan vendors selected methodology guidance and skills from
[zazz-skills](https://github.com/zazzcode/zazz-skills). Local adaptations are recorded here; candidate
shared-methodology improvements can be proposed upstream separately.

[zazz-board](https://github.com/zazzcode/zazz-board) is the reference implementation and uses the methodology.
