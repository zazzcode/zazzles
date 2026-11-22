---
name: gh-stack
description: "Plan, implement, verify, or maintain dependent pull requests in one Zazzles worktree when a specification explicitly calls for a stack or multiple PRs per slice."
---

# GitHub stacked pull requests

Read the [Zazzles gh-stack guide](../../../.zazz/docs/using-gh-stack.md) for setup,
command details, and recovery examples. Follow the single branch and draft PR
workflow when the assignment specifies a single review unit.

## Establish the lane

- From the assigned worktree, verify the physical path, branch, worktree list,
  clean state, GitHub identity, and installed `gh stack` command help. Confirm
  that the specification assigns the stack and names its review layers.
- Keep all stack branches in that one worktree. Follow the repository's worktree
  setup guide if the assignment requires provisioning the lane.
- Use `stage` as the stack base. The bottom PR targets `stage`, and each higher
  PR targets its immediate parent branch. Each layer contains only its own
  slice commits and records its acceptance evidence.

## Deliver the layers

1. Initialize or adopt the bottom branch with the installed `gh stack init`
   syntax and an explicit `--base stage`. Add each higher branch from the tip of
   its parent in the same lane.
2. Before switching layers or placing a commit, verify branch ownership and
   inspect the staged diff. After changing a lower branch, rebase the affected
   upper layers and rerun their gates.
3. Before publishing, check the stack and every consecutive parent-to-child diff.
   When publication is authorized, submit the stack as drafts. Verify the actual
   remote base of every PR and record a compact stack map and slice evidence.
4. Verify `sync` effects before running it on shared state. It can rebase and push
   stack branches. Surface unexpected remote divergence or a scope change without
   discarding work. The owner controls review readiness and merges.

If the extension or GitHub support is unavailable, follow the guide's explicit
base-branch workflow with the same draft dependency chain.
