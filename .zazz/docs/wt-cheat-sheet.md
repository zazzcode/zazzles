# Zazzles Worktrunk cheat sheet

Worktrunk is optional. The [worktree setup guide](worktree-setup.md#worktrunk-usage) owns the
recommendation, local-file rationale and expected `.bare/` sibling layout. Native Git is fully
supported there. Contributors choosing another local setup can still submit feature-branch PRs;
agents in the maintained workspace MUST follow [AGENTS.md](../../AGENTS.md#worktree-location).

This reference covers the optional CLI, not a different repository layout. Resolve `<repo-container>`
to the existing container; use an absolute path when substituting it below. Commands were checked
against installed `wt v0.81.0` and the official [switch](https://worktrunk.dev/switch/),
[remove](https://worktrunk.dev/remove/) and [configuration](https://worktrunk.dev/config/) references.
Check your installed `wt <command> --help` before using version-dependent flags.

## Inspect and reuse first

From the container:

```bash
wt -C .bare list
wt -C .bare config show
```

From a sibling checkout, use `wt -C ../.bare ...`. Inspect configuration locally; do not publish
credential-bearing hook commands. The assigned path takes precedence over an old handoff.

If the assigned worktree already exists, enter it directly and verify it:

```bash
cd <repo-container>/nextjs-support-mvp
pwd
git branch --show-current
git status --short --branch
git rev-parse --path-format=absolute --git-common-dir
git worktree list
```

The common directory must resolve to `<repo-container>/.bare`. A new session or a new step in the
same deliverable does not require another checkout. `wt switch` can create a checkout even without
`--create` when a branch has no worktree, so inspect the list and destination before switching.
Shell directory switching requires Worktrunk shell integration; verify `pwd` rather than assuming
that a command changed the calling shell's directory.

## Create an authorized independent worktree

First update the remote base, then give Worktrunk an explicit direct sibling destination. `--path`
is available in the checked CLI version; use the native Git procedure if yours lacks that option.

```bash
cd <repo-container>
git --git-dir=.bare fetch origin stage:refs/remotes/origin/stage
wt -C .bare switch --create my-feature --base origin/stage --path "<repo-container>/my-feature"
cd <repo-container>/my-feature
```

Run the verification commands above. Configured path templates, hooks and tool defaults MUST NOT
place a checkout outside the required sibling layout. Use flat branch names for new branches.
Preserve existing local changes and never use `--clobber` to resolve a path collision blindly.

## Review an existing PR

Reuse its assigned local worktree when one exists. If an independent review checkout is needed,
inspect the PR branch and existing checkouts before creating a direct sibling review directory:

```bash
wt -C <repo-container>/.bare switch pr:123 --path "<repo-container>/review-123"
```

The PR shortcut may fetch a branch and create a checkout; it is not merely a read-only view.
Verify the actual path and branch before reviewing. PRs target `stage`; humans approve and merge.
Agents MUST NOT use `wt merge` or `wt step push` to integrate into `stage` or `main`. Publish feature
commits using ordinary `git push` from the assigned checkout.

## Local files and hooks

Native Git does not copy ignored files. Worktrunk can copy them with an optional `copy-ignored` hook,
configured in the machine-local `.config/wt.toml`. Inspect the source checkout and selected files;
copy only task-required configuration, never overwrite a contributor's existing `.env`, and never
print credentials. Later edits are not synchronized between worktrees.

A local hook may also copy `.zazz/ephemeral/`; copied handoffs are historical context and MUST NOT
change the active assignment. Preserve useful records and start the current task's own run log.
Generated binaries, installed dependencies and stale analysis output should be rebuilt or kept out
of the copy. Inspect hook templates before running them; hook setup is not required to contribute.

Some existing bare-workspace configurations use worktree-specific `core.bare=false` and
`core.worktree` overrides with `extensions.worktreeConfig=true`. If Git reports that the command
must run in a worktree, inspect this configuration and the common Git directory before changing it.
Do not turn the shared `.bare/` into a non-bare repository to work around a checkout error.

### Hook approvals

Inspect approval state without modifying it:

```bash
wt -C <repo-container>/.bare config approvals list
```

A contributor may review and approve the declared commands through Worktrunk's normal interactive
flow. For an agent, existing session authorization still governs each hook's actions. Do not silently
rewrite the approval file or approve unrelated commands to get past a prompt. Native Git remains
available when optional hooks are not configured or approved.

## Cleanup

The [setup guide](worktree-setup.md#remove-a-worktree) owns preservation and removal checks. Verify
the exact checkout, uncommitted/ignored files and whether its branch is still needed. Save handoffs
and replay evidence before removing a finished checkout. To remove the checkout while retaining its
branch and wait for completion:

```bash
wt -C <repo-container>/.bare remove my-feature --no-delete-branch --foreground
```

The flags have different scopes:

| Flag | Effect |
|---|---|
| `--force` / `-f` | Removes a dirty checkout, including uncommitted and untracked files |
| `--force-delete` / `-D` | Allows deletion of an unmerged branch |
| `--no-delete-branch` | Keeps the branch when removing the checkout |
| `--foreground` | Waits for removal to finish |

Force flags are deliberate cleanup choices, not routine fixes for a failing command. Do not remove
unrelated active worktrees. Use `git worktree list` to verify the result; review a prune dry run before
removing stale registrations.

## Local excludes and advanced workflows

Keep machine-local configuration out of tracked `.gitignore` changes. Shared local exclusions live
in `<repo-container>/.bare/info/exclude`; inspect a specific rule with `git check-ignore -v <path>`.

Dependent PR stacks are a separate, explicitly scoped workflow: see
[using gh-stack](using-gh-stack.md). A stack does not authorize extra checkouts for steps of one
active deliverable, and any worktree it uses still follows the same sibling layout.
