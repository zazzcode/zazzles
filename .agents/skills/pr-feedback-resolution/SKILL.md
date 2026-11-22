---
name: pr-feedback-resolution
description: "Resolve review feedback on a pull request: verify each finding against the code, implement the ones that hold with failing-first evidence, challenge or defer the rest with a stated rationale, then commit, push and reply on the PR; use when asked to address, implement, triage, accept or challenge PR review comments, including feedback from a pr-review pass or another agent."
---

# PR feedback resolution

## Purpose

Turn a set of review findings into a resolved PR. Every finding is either **fixed** or
**challenged**. Deferring a finding is a kind of challenge: it accepts the finding but argues
against fixing it in this PR. Each disposition carries evidence, and the PR records which and why. This skill follows the
`pr-review` skill: `pr-review` produces findings, this skill resolves them. The human owner still
decides scope and approval.

A finding is a claim, not an instruction. Read it the way you would read a bug report: reproduce
it, then decide.

## Core rules

- **Verify before acting.** Confirm each finding against the current code, the specification and
  the standards it cites. A reviewer's patch, prototype or "verified" note is input. It is not
  evidence. Apply it only after its tests pass on the branch, and fix it when they do not.
- **Work on the PR's head branch only.** Resolve the head branch from the PR, not from the
  current checkout. Never commit to another branch. In a stacked lane, never commit to the parent
  or child branch, and never switch a checkout that another session is using.
- **Failing first.** For a behavior finding, add the reviewer's case, or your own, as a test.
  See it fail, then fix the code. A fix with no test that would have caught the finding is not
  done.
- **Keep the spec and docs in step.** When a fix changes what the code does, update the
  specification's test table and change log, and every user and architecture document that
  describes the behavior, in the same change.
- **Re-check evidence that depends on behavior.** A fix after recorded acceptance evidence, such
  as a sample scan or a judged run, can invalidate that evidence. Re-run the offline check and
  compare. Re-run a paid or live check only under the repository's standing authorization, or
  with the owner's word.
- **Challenge with reasons, never by silence.** Every finding gets a disposition.

## Dispositions

| Disposition | When | Record |
|---|---|---|
| Fixed | The finding holds and the fix belongs in this PR | What changed, the test or check that proves it, the commit |
| Fixed differently | The finding holds, but the proposed fix is wrong or incomplete | The fix made and why the proposal was not used as is |
| Challenged: deferred | The finding holds, but fixing it now costs more than it saves (for example, churn on files a stacked branch is editing) | Where and when it will be done, and who owns it |
| Challenged: rejected | The finding is wrong, out of scope, or conflicts with the spec, an owner decision or a standard | The evidence: a file and line, a spec clause, a test result, an owner decision |

Severity guides urgency, not disposition. A `[rock]` or `[boulder]` that is challenged needs the
owner's agreement before the PR is approvable. A `[pebble]` or `[sand]` may be deferred or
challenged on the agent's judgment.

## Where to work

**An ordinary PR (the usual case).** Work in the assigned worktree that has the PR's head branch
checked out. No extra worktree and no cleanup step are needed. Skip the rest of this section.

**A stacked PR where nothing else is running.** Switch the lane's one worktree to the head branch,
resolve the feedback, then rebase the upper branches and rerun their gates, as the `gh-stack` skill
describes.

**A stacked PR where another agent is working on a higher branch.** Read this only when it
applies. A stacked lane normally keeps all its branches in one worktree. When another agent is
working on a higher branch there, the PR's head branch is not checked out, and switching branches
would break that agent's work. In that case:

1. **Do not switch, stash or reset the shared worktree.** Leave its branch, index and files as
   they are.
2. **Create a temporary sibling worktree for the head branch.** Register it with the repository's
   shared Git directory, and place it directly in the container that holds the other worktrees, as
   `AGENTS.md` and the worktree setup guide require. Never place it in a tool-specific or nested
   location. Name it after the branch, then run the startup checks there before editing. If the
   repository keeps per-worktree Git configuration, give the new worktree the same settings the
   other worktrees have.
3. **Do all of the resolution work there:** edit, test, commit and push the head branch only.
4. **Tell the owner what the upper branch must now rebase onto.** Name the files the fixes touched
   that the upper branch also edits. Do not rebase or push the upper branch yourself while its
   agent is active.
5. **Remove the temporary worktree after the push succeeds.** Use the repository's normal
   worktree removal, not a raw directory delete, and confirm the worktree list no longer shows it.
   Before removing it, check for uncommitted or ignored files you need. Gitignored execution
   scratch, such as `.zazz/ephemeral/` run logs and handoffs, exists only in that worktree and is
   lost when it is removed. Copy anything worth keeping into the shared worktree's ephemeral
   directory, or into a tracked document, first.

Prefer deferring a finding whose fix would rewrite large parts of files the upper branch is
editing, such as a comment sweep or a file split. Record that in the challenge comment, so it is
done once at the end of the lane instead of in every rebase.

## Workflow

1. **Collect.** Read every review comment, inline comment and review summary on the PR. Number
   each finding and note its severity, its location and the fix it proposes.
2. **Locate.** Verify the PR's head branch, the base branch and the checkout you will edit, using
   the startup checks of `AGENTS.md`. Choose the checkout as "Where to work" describes. For a
   stack, list which branches sit above the head. Note what files they touch, so you know what a
   change here will cost them when they rebase.
3. **Triage.** For each finding, reproduce it and assign a disposition. When a finding has a
   reasonable reading and the cited rule supports it, implement it. Challenge it only with
   evidence.
4. **Implement.** One logical change per commit, following the commit labels of the PR process
   standard. Tests and goldens go in the commit of the code they cover. Format only the files you
   changed.
5. **Verify.** Run the gate that the assigned contract and the contributor guide name. Re-check
   any acceptance evidence the fix may affect. Confirm that only the intended golden rows changed.
6. **Escalate.** Before publishing, ask the owner (the person who committed or assigned the PR)
   about every open question and decision, in one message, each with your recommended answer. A
   question can be a challenged `[rock]` or `[boulder]`, a deferral that needs an owner and a date,
   a finding whose fix would change spec scope or an owner decision, a reviewer's ambiguous intent,
   or a change to the PR title, body or shared evidence. Fix what needs no decision first, so the
   owner answers once. Do not publish a disposition that depends on an unanswered question. If the
   owner is unavailable, publish the fixes and list the open questions in the challenge comment as
   awaiting the owner.
7. **Publish.** Re-verify the branch, the Git identity and authentication. Then push the head
   branch only. Edit the PR title or body when a finding is about them.
8. **Reply on the PR.** Post one comment that lists the fixed findings, each with its commit and
   evidence. When any finding is challenged, whether deferred or rejected, post a second, separate
   comment that lists those findings and the rationale for each, so the owner can decide on them
   apart from the fixes.
9. **Clean up.** Remove any temporary worktree you created, as described in "Where to work".
   An ordinary PR has nothing to clean up.
10. **Hand over.** Tell the owner what is ready for review, what still needs their decision, and what an
   upper stacked branch must now rebase onto.

## Output

The two PR comments are the durable record. Each one names the finding by its original label,
severity and location, so a reader can match it to the review without re-reading the review.

## Halt conditions

These need an answer before the affected work goes on. Raise them as soon as they appear, not
only at the escalation step. Stop and ask the owner when:

- the fix needs a paid or live run that no standing authorization covers;
- a challenged finding is a `[rock]` or `[boulder]`, and the PR cannot proceed without a decision;
- the only way to do the work is to switch a checkout another session is using;
- implementing a finding would change scope that the specification or an owner decision fixed;
- the feedback and the specification, or two findings, contradict each other.
