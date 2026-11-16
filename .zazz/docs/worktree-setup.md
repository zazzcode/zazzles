# Zazzles worktree setup

This guide owns contributor and agent operations in the maintained workspace. Read
[AGENTS.md](../../AGENTS.md#worktree-location) for mandatory location and authorization rules;
[agent orientation](zazzles-agent-orientation.md#branches-and-worktrees) is the entry point.
`stage` integrates reviewed work; `main` receives human-operated release promotion.

Native `git worktree` is fully supported. Worktrunk is **optional but recommended**, especially for
its configured copy hook that carries `.env` and other needed gitignored local files into new
worktrees. Its commands and hooks are in the [cheat sheet](wt-cheat-sheet.md). Both tools MUST use the same existing `.bare/`
repository and direct sibling checkout paths. Tool defaults do not override this layout.

## Required Model

The preferred workflow for **all contributors** is a bare-repo container with sibling worktrees,
following the maintainer's setup for consistency. Contributors can use another local layout and submit feature-branch PRs; this convention is not a PR acceptance requirement.
They are responsible for adapting their setup, paths and commands. Agents in the maintained
workspace MUST use the assigned sibling worktree managed by its existing `.bare/` repository.

Zazzles's container layout (resolve the development root using the
[orientation](zazzles-agent-orientation.md#portable-workspace-and-dev_root)):

```text
zazzles/                         # container; not a development checkout
├── .bare/                    # shared Git directory
├── stage/                    # integration and current definition worktree
├── feature-<spec>/           # one dedicated worktree per spec, created as needed
└── main/                     # optional release worktree; need not exist now
```

Required conventions within the maintained workspace:

- the container directory is not itself the active development checkout
- `.bare/` is the shared Git directory
- each active worktree MUST be a direct sibling of `.bare/` under the container
- nested tool directories such as `.claude/worktrees/` and external/temporary scanner checkouts MUST NOT be used
- reuse the assigned checkout for the current deliverable; a new session is not a new deliverable
- one active deliverable or document effort maps to one worktree in the normal case
- each spec has its own branch and worktree; generic stacked-lane examples do not override this policy
- do not use `/` in branch names
- use flat branch names so the branch name can map directly to a sibling worktree directory
- merges happen through PRs, not by locally merging feature branches into the integration worktree

Related specs, implementation, documentation and tests stay in the assigned feature worktree and
its draft PR into `stage`. Follow [authorization](../../AGENTS.md#authorization-and-delivery): an
explicit implementation request authorizes the assigned work; no additional ceremony is needed.
Independent deliverables may have separate sibling worktrees when assigned. A stale handoff or a
tool-created checkout MUST NOT override the user's current worktree assignment.

### Start or resume in an existing worktree

Run these read-only checks from the assigned checkout before editing:

```bash
pwd
git branch --show-current
git status --short --branch
git rev-parse --path-format=absolute --git-common-dir
git worktree list
```

The directory MUST be `<repo-container>/<assigned-worktree>` and the common Git directory MUST
resolve to `<repo-container>/.bare`. Confirm the expected branch and preserve local/ignored files.
If an old handoff names another checkout, use the current user assignment and recover the needed
committed state or records into that checkout. Inspect divergence before changing branches or history.
Do not create another worktree merely to resume a session.

Example: a contributor assigned `<repo-container>/nextjs-support-mvp` works there. A handoff naming
`<repo-container>/.claude/worktrees/...` does not authorize using that nested checkout.

## Why This Pattern

This pattern gives the methodology three important properties:

- isolation: each active effort has its own checkout and branch
- recoverability: a failed line of work can be abandoned cleanly
- consistency: builders and AI agents can use the same branch/worktree mental model

It also pairs well with the methodology's document model:

- durable docs stay in Git
- durable specs stay tracked; transient execution artifacts stay local under the declared document model
- worktrees keep those transient artifacts scoped to one effort at a time

## Integration Worktree

Keep one integration worktree for the repo's declared integration branch — in scan, `stage/`.

Its role is:

- represent the integration target branch
- stay clean and reviewable
- receive changes through PR merge

Do not use the integration worktree as the normal place for day-to-day feature implementation.

Zazzles's current concept/architecture-definition documentation work is explicitly assigned to `stage/`
by the Project Owner. Assigned methodology refinement may also happen there. This narrow exception is
declared in [AGENTS.md](../../AGENTS.md) and the [orientation](zazzles-agent-orientation.md); it does not
permit feature implementation, direct pushes, local merges, or releases. Later approved deliverables
use sibling worktrees.

## New Setup Paths

The maintained workspace already has `.bare/`; contributors and agents MUST NOT rerun conversion
or create another clone there. These examples are for an explicitly requested initial workspace
setup. Conversion requires a full clone whose `.git` is a directory, not a linked worktree's `.git`
file. Preserve existing work and configuration before conversion.

### Option A: Convert an existing clone

If you already have a normal clone and want to convert it into the bare + sibling-worktree layout:

1. Make sure your current checkout is clean or intentionally stashed/committed.
2. Rename `.git` to `.bare`.
3. Mark `.bare` as a bare repository.
4. Create the integration worktree from the repo's declared integration branch.

Example:

```bash
cd <repo-container>
git status

mv .git .bare
git --git-dir=.bare config --bool core.bare true

git --git-dir=.bare worktree add stage -b stage origin/stage
# or, if that branch does not exist yet:
git --git-dir=.bare worktree add stage -b stage origin/main
```

### Option B: Fresh setup

If you are starting from scratch:

```bash
mkdir -p <repo-container>
cd <repo-container>
git clone --bare <repo-url> .bare
git --git-dir=.bare worktree add stage -b stage origin/stage
# or, if that branch does not exist yet:
git --git-dir=.bare worktree add stage -b stage origin/main
```

## Verification Checklist

After setup, verify:

- `.bare/` exists and is the shared Git directory
- the integration worktree exists
- `git --git-dir=.bare rev-parse --is-bare-repository` returns `true`
- `git --git-dir=.bare worktree list` shows the expected worktrees
- the integration worktree is on the expected base branch

Useful commands:

```bash
git --git-dir=.bare rev-parse --is-bare-repository
git --git-dir=.bare worktree list
git -C stage branch -vv
```

## Reference application checkout

Juice Shop is a separate clone, not a branch or worktree of scan. Its portable lookup convention is
recorded in the [orientation](zazzles-agent-orientation.md#portable-workspace-and-dev_root). Identify a
fixture by upstream repository URL plus an agreed commit, independently of its local location.
Future fixture configuration must allow a per-machine root override; no flag/environment contract
is implemented now. Do not modify, install, or run the reference app merely for source inspection.
The [acceptance-target plan](../project/implementation-plan.md#acceptance-targets) owns revision and
challenge mapping, inclusion/exclusion, and fixture evaluation scope.

## Linked-computer agent toolchain

A cloud agent session linked to the user's computer runs shell commands in a Linux arm64 VM. That
VM has a C compiler but no Go toolchain and no network, so it cannot download Go or modules. A shared,
untracked `.tools/` directory in the container root (beside `.bare/`, outside every worktree) supplies
both. Human contributors on macOS do not need it; see [contributing](../../docs/contributing.md).

One-time setup on the user's computer, from the container root (repeat the last line after `go.mod`
changes; use the Go version that `go.mod` declares):

```bash
mkdir -p .tools && cd .tools
curl -LO https://go.dev/dl/go1.27.2.linux-arm64.tar.gz
tar -xzf go1.27.2.linux-arm64.tar.gz && rm go1.27.2.linux-arm64.tar.gz
cd ../<worktree> && GOMODCACHE="$(cd .. && pwd)/.tools/gomod" go mod download
```

Agent environment for each VM command (the container is mounted at `$HOME/mnt/<container>`):

```bash
T=$HOME/mnt/zazzles/.tools
export GOROOT=$T/go PATH=$T/go/bin:$PATH GOMODCACHE=$T/gomod GOCACHE=$HOME/.cache/zazzles-go \
  GOTOOLCHAIN=local GOPROXY=off GOFLAGS='-mod=readonly -buildvcs=false' CGO_ENABLED=1
```

The worktree's `.git` file names a macOS path the VM cannot see; set
`GIT_DIR=$HOME/mnt/zazzles/.bare/worktrees/<worktree>` and `GIT_WORK_TREE=<worktree path>` for Git.
VM results are Linux results, matching CI; a macOS run before a PR remains worthwhile.

## Branch Naming Rules

Because the methodology expects sibling worktree directories, branch names should also be worktree-safe directory names.

Recommended guidance:

- do not use `/` in branch names
- use flat branch names with hyphens
- prefer names that describe the feature, deliverable, or document effort
- keep the branch name and worktree directory the same whenever practical

If the repo adopts the recommended sibling-worktree model:

- `feature/rbac` is wrong for Zazz worktrees
- `docs/reorg-mw1` is wrong for Zazz worktrees
- `feature-rbac` and `docs-reorg-mw1` are correct

Preferred examples:

- `feature-rbac`
- `deliverable-zazz-142-role-management-ui`
- `proposal-role-management-options`
- `docs-reorg-mw1`

Avoid:

- `feature/rbac`
- `docs/reorg-mw1`
- `deliverable/ZAZZ-142-role-management-ui`

Git allows `/` in branch names, but that creates awkward nested directory paths if the same string is used for a sibling worktree directory. Zazz avoids that mismatch by standardizing on flat branch names when using sibling worktrees.

## Creating Feature, Deliverable, or Proposal Worktrees

First list existing worktrees and reuse the assigned checkout if it exists. For an authorized new
independent deliverable, run from the container and name an explicit direct sibling destination:

```bash
git --git-dir=.bare worktree list
git --git-dir=.bare fetch origin stage:refs/remotes/origin/stage
git --git-dir=.bare worktree add feature-rbac -b feature-rbac origin/stage
```

Then `cd <repo-container>/feature-rbac` and run the start/resume checks above. Do not use a nested
or external destination. Native Git does not copy ignored `.env`, local tool configuration or
handoffs: inspect and copy only the required files deliberately, preserving credentials and existing
content. Worktrunk users can follow the [optional hook setup](wt-cheat-sheet.md#local-files-and-hooks).

## Deliverables Directory Policy

Scan uses Git-tracked deliverable specs under `.zazz/specifications/`. Author the spec and its
implementation in that spec's feature worktree and review both through its PR into `stage`.
Do not ignore the specification directory or store contracts only in local scratch.

Run logs, QA evidence, recovery notes, and handoffs belong in gitignored `.zazz/ephemeral/`, as declared
in [AGENTS.md](../../AGENTS.md#document-model). Machine-local files may use local exclude rules;
never add secrets or transient execution records to the PR. Load
[execution discipline](agent-execution-discipline.md#execution-records) for record/handoff procedures.

## Daily Operations

### List worktrees

```bash
git --git-dir=.bare worktree list
git --git-dir=.bare worktree list --verbose
```

### Keep a branch current

```bash
cd <repo-container>/feature-rbac
git fetch origin
git rebase origin/stage
```

### Commit and push

```bash
cd <repo-container>/feature-rbac
git add <changed-paths>
git commit -m "[DOC] Describe the change"
git push origin feature-rbac
```

### Remove a worktree

Before removal, verify the exact path, branch, uncommitted changes and ignored files. Preserve
handoffs and replay evidence outside the checkout if needed after cleanup. Remove only the assigned
finished/redundant checkout; removing a worktree and deleting its branch are separate decisions.

```bash
git -C <repo-container>/feature-rbac status --short --ignored
cd <repo-container>
git --git-dir=.bare worktree remove feature-rbac
git --git-dir=.bare worktree prune --dry-run
```

Use forced removal only after intentionally preserving or discarding the local files it would
remove. Prune stale registrations after reviewing the dry run; pruning does not remove live checkouts.

## Worktrunk Usage

Worktrunk is optional but recommended for local-file setup: its configured `copy-ignored` hook can
carry `.env` and other needed gitignored files into a new sibling checkout. Native Git above supports
the complete workflow; copy the needed local files deliberately when using it.
If using `wt`, first inspect existing worktrees and configuration:

```bash
wt -C <repo-container>/.bare list
wt -C <repo-container>/.bare config show
```

A Worktrunk switch can create a checkout when none exists. For authorized creation, explicitly set a
direct sibling path and base; verify the resulting checkout before editing. The
[cheat sheet](wt-cheat-sheet.md) owns commands, local file copying, approval handling and cleanup flags.
Agents MUST NOT use `wt merge` or `wt step push` to integrate into `stage`/`main`; human-reviewed PRs
are the integration path. Ordinary remote publication uses `git push` from the feature checkout.

## Review and PR Flow

When pushing a branch for review:

- target the repo's declared integration branch
- avoid merging feature branches locally into the integration worktree
- prefer PR review as the integration path

If the repo has a fixed integration branch such as `stage`, keep that policy explicit in `AGENTS.md` or repo docs.

## Recovery Model

One of the reasons the methodology requires worktrees is recovery.

If a session of work:

- goes down the wrong path
- fails owner review
- reveals that the proposal, feature requirements document, or deliverable specification is wrong

first repair the assigned checkout when safe. If replacement is explicitly warranted, preserve its
work and execution records, revise the governing contract, and use a direct sibling registered with
the same `.bare/`. Do not create a tool-specific or external fallback checkout.

Useful commands:

```bash
git --git-dir=.bare worktree remove my-failed-branch
git --git-dir=.bare worktree prune
```

## Operational Rules

1. Do implementation work only inside feature, deliverable, proposal, or docs worktrees.
2. Keep the integration worktree clean.
3. Open PRs from non-integration worktrees into the integration branch.
4. Do not let agents merge PRs.
5. Require a human reviewer to approve and merge.

## Relationship to the Methodology

This document is the operational companion to [zazz-methodology.md](zazz-methodology.md).

The methodology defines:

- why worktrees are required
- where human gates remain
- how worktrees support isolation and recovery

This document defines:

- the required bare-repo + sibling-worktree layout
- setup and conversion paths
- worktree-local exclusion guidance
- daily operations with `git worktree`
- optional Worktrunk use without changing location or review rules
