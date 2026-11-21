# Scan methodology guides

Supporting methodology guides and workflow cheat sheets, vendored from the upstream
[zazz-skills](https://github.com/zazzcode/zazz-skills) `docs/` directory and **adapted for zazzles**.

Local deviations from upstream are deliberate. Known adaptations:

- the integration branch is **`stage`** (upstream examples use `dev`); `main` is release-only
- the doc model consolidates product orientation under `.zazz/project/` (see
  [zazz-methodology.md](zazz-methodology.md) § Core Model)
- zazz-board is not used in this project
- current concept/architecture definition and assigned methodology refinement explicitly use `stage/`;
  each spec is authored, refined, and implemented in its own sibling feature worktree and PR into `stage`

Feature documents, deliverable specifications, project/architecture docs, and ephemeral working
notes do not live under this directory — they live under `.zazz/project/`,
`.zazz/specifications/`, and `.zazz/ephemeral/` respectively.

## Guides

Load these on demand using [AGENTS.md](../../AGENTS.md#load-context-by-task); this directory is not an
automatic context bundle. Orientation is the session entry point, execution discipline governs active
work, and worktree setup owns layout/operations. The cheat sheet is for Worktrunk commands only.

- [zazzles-agent-orientation.md](zazzles-agent-orientation.md) — **first-read** agent orientation: repo layout, branch model, routing (repo-specific)
- [openai-decisions-setup.md](openai-decisions-setup.md) — current GPT decision API key and Go setup
- [gopls-setup.md](gopls-setup.md) — gopls benefits and setup for Claude Code and Codex (repo-specific)
- [agent-execution-discipline.md](agent-execution-discipline.md) — agent execution discipline (vendored)
- [worktree-setup.md](worktree-setup.md) — worktree operating model setup (adapted: stage integration branch)
- [wt-cheat-sheet.md](wt-cheat-sheet.md) — Worktrunk cheat sheet (adapted for this container)
- [using-gh-stack.md](using-gh-stack.md) — stacked PR lanes with `gh-stack`
- [human-in-loop-pr-review-strategy.md](human-in-loop-pr-review-strategy.md) — human-in-the-loop PR review strategy
- [zazz-methodology.md](zazz-methodology.md) — methodology entry point (adapted: project-folder doc model)

## Sync discipline

These guides started from upstream `zazz-skills/docs/` (top-level `.md` files only) and have been
adapted. When refreshing from upstream, review the diff against the local deviations listed above
before accepting it — do not blind-copy over local adaptations:

```bash
# re-sync upstream top-level guides (review the diff before committing)
SRC=/path/to/zazz-skills/docs
DST=.zazz/docs
for f in "$SRC"/*.md; do cmp -s "$f" "$DST/$(basename "$f")" || echo "differs: $(basename "$f")"; done
```
