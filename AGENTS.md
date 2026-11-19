# AGENTS.md — zazzles

## Start here

This file owns agent startup and context-loading policy.

At session start, agents MUST read this file, then open the
[agent orientation introduction and contents](.zazz/docs/zazzles-agent-orientation.md#contents).
Agents MUST use that table of contents to select and read the sections relevant to the current task.
Reading every orientation section is not required. Agents MUST load additional sections when the task
expands into those topics.

Links are references, not automatic includes. Agents MUST NOT recursively load every linked guide,
skill, standard or evaluation record. Use the task table below and the orientation's topic maps to
load only the relevant sections before acting. In particular, load the worktree setup guide for
worktree operations and the Worktrunk cheat sheet only when using `wt` or configuring its hooks;
routine edits or builds in an already verified checkout do not require either guide. Mandatory rules
in this file apply regardless of which reference sections are loaded.

The [README](README.md) introduces the project; root [user documentation](docs/README.md) owns
philosophy, user setup, CLI usage, result interpretation, and contributor guides.
Product analysis rules and guidelines belong in root [docs/analysis](docs/analysis/README.md), not
`.zazz/`. Agents MUST load the matching analysis guide when changing scanner evidence or judgment.
Current assignments, progress, evaluation results, and session restrictions belong in the project
docs or local handoff, not this file. Agents MUST verify the actual worktree path, branch, and changes
before editing and MUST preserve unrelated user changes.

## Load context by task

| Task | Load |
|---|---|
| Run zazzles or configure a decision provider | [README](README.md), then [decision-model user guide](docs/decision-models.md) when needed |
| Product, scope, or architecture decisions | Orientation's [documentation map](.zazz/docs/zazzles-agent-orientation.md#documentation-map); select the document that owns the topic |
| Graph structure or outbound service paths | [Repository graph design](.zazz/architecture/repository-graph.md), then relevant architecture sections |
| Author or refine a spec | Relevant [plan](.zazz/project/implementation-plan.md) and contract, `spec-builder`, and [spec hygiene](.zazz/standards/spec-hygiene.md) |
| Implement, test, resume, or verify work | Assigned contract and local run log, [execution discipline](.zazz/docs/agent-execution-discipline.md), `spec-driven`, and matched [standards](.zazz/standards/index.yaml) |
| Create or manage a worktree | [Worktree setup](.zazz/docs/worktree-setup.md); [Worktrunk cheat sheet](.zazz/docs/wt-cheat-sheet.md) only when using Worktrunk |
| Refine SDLC or ownership/process rules | [Zazz methodology](.zazz/docs/zazz-methodology.md) |
| Edit documentation or standards | Matched [standards](.zazz/standards/index.yaml) and `doc-check` |
| Prepare or review a PR | [PR process](.zazz/standards/pr-process.md) and matching `pr-builder`/`pr-review` skill; [human-review guide](.zazz/docs/human-in-loop-pr-review-strategy.md) only for review policy |

Skills live in `.agents/skills/`; agents MUST load only the matching skill. Procedures belong in their
owning guides so this entry point stays small and stable.

## Authorization and delivery

An explicit user request to implement authorizes the requested work in the assigned isolated feature
worktree. Agents MUST NOT require a separate Deliverable Owner ceremony or repeated confirmation.
Agents MUST record bounded implementation scope and acceptance evidence in a tracked implementation
contract and refine it as the user steers the work. A backlog entry alone is not an implementation request.
The human user owns scope and review decisions; this is the meaning of Deliverable Owner in older guides.

Agents MUST use the assigned worktree for related architecture, documentation, implementation, and tests.
Independent future deliverables MAY be split when useful; agents MUST NOT create extra worktrees or PRs
merely for steps of the active task. These authorization rules take precedence over stricter
greenlight/topology wording in the methodology, execution discipline, and skills.

## Worktree location

This repository uses one bare Git directory, `<container>/.bare/`, with sibling worktrees such as
`<container>/stage/` and `<container>/nextjs-support-mvp/`. Agents MUST view, edit, build and test in
the user-assigned sibling worktree. The container and `.bare/` are not source checkouts.

Agents MUST NOT create or use worktrees outside this structure, including `.claude/worktrees/`,
other tool-specific nested checkouts, temporary clones or alternate repository copies. Any authorized
new worktree MUST be registered with the existing `.bare/` repository and placed directly under the
same container. Reuse the assigned checkout for the current deliverable.

Before editing, agents MUST verify `pwd`, `git branch --show-current`, `git status --short --branch`
and `git worktree list`. The active user's assigned path takes precedence over paths in older
handoffs. If a handoff points at another checkout, resolve it against the assigned worktree before
continuing; do not silently switch to the handoff's path. See [worktree setup](.zazz/docs/worktree-setup.md).

## Claude Code

These rules apply to Claude Code desktop sessions and the agents they start:

- Start desktop sessions on the assigned sibling worktree folder with the app's worktree option off.
- Never use app-created `.claude/worktrees/` checkouts or `claude/*` branches. A session that finds
  itself in one MUST stop and ask the owner instead of working around the edit guard.
- Subagents never use worktree isolation. They share the assigned checkout and own disjoint files.
- `start_session` uses `cwd` set to the assigned worktree and `use_worktree: false`.
- Sonnet subagents are acceptable for scoped implementation. The lead reviews their diffs and runs
  the gates.

## Branch model

`stage` integrates reviewed work; `main` receives human-operated release promotion and version tags.
All fixes flow through `stage`. Agents MUST NOT merge PRs, merge locally into integration, tag releases,
or push directly to integration. Only explicitly assigned concept, architecture, or methodology
documentation may be edited in `stage/`; this does not permit spec work or feature implementation there.
Detailed layout and operations live in [worktree setup](.zazz/docs/worktree-setup.md).

Before committing or pushing, agents MUST verify path/branch, `git config user.name` (**zazzcode**),
and the zazzcode Git/`gh` authentication profile. Feature/deliverable PRs MUST start as drafts and target `stage`.

## Document model

**Internal DOCS_ROOT: `.zazz/`**. User-facing documentation belongs in root `docs/`. Specs are Git-tracked in `.zazz/specifications/`; execution scratch belongs in
gitignored `.zazz/ephemeral/` and MUST NOT be committed. Zazz Board is not used. See the
[documentation map](.zazz/docs/zazzles-agent-orientation.md#documentation-map) for durable document owners.

## Credentials and live model calls

Agents MUST NOT print `.env` contents or credentials, include secrets in tracked files, or pass keys
in command arguments. Agents MUST pass only the selected provider's key to the scanner child process.
Offline checks need no key. An existing local key is configuration, not authorization for paid calls.
The owner's typical live check is standing-authorized: when the owner asks for a live check of a
sample, run one judged scan with `--judge openai --judge-model gpt-6-luna`, the default judge limit
(every candidate; about 157 requests for Juice Shop), `JUDGE_RPM=4500` and `JUDGE_TPM=1800000`,
without asking for a cap. Anything larger or another provider/model still needs the owner's word.
Agents MUST follow the user's active provider/model restrictions, keep live request counts small and
explicit, and MUST NOT use automatic provider/model fallback. Judge transport retries only
transient failures (HTTP 408/429/500/502/503/504/529, timeouts, dropped connections; up to 3 times)
and stops a scan only for an account failure or an unresponsive model; agents MUST NOT add other
retries or stop conditions without an owner-approved spec. Funding context is not authorization to
exhaust a balance. Alternative adapters MAY be tested with local HTTP stubs.

## Verification

Agents MUST run the assigned contract's scoped checks using the worktree's declared Go toolchain.
The [contributor guide](docs/contributing.md) owns build, test, vet, and format commands;
[evidence conventions](.zazz/standards/testing.md) define the required validation record.
Agents MUST format only changed Go files and keep documentation changes within the requested scope.
A linked-computer session runs checks with the shared `.tools/` toolchain described in
[worktree setup](.zazz/docs/worktree-setup.md#linked-computer-agent-toolchain).
