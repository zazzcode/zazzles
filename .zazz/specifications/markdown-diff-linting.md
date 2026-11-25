# Markdown diff linting

Add a repository CI check for common prompt injection indicators and text defects in Markdown
and agent rule files. Follow the [contributor guide](../../docs/contributing.md#verification)
for Go checks. Keep the tool independent of the product code and model providers.

## Acceptance criteria

- `TestLintDiff` verifies that the CLI reports findings on added or replaced lines at their head
  commit line numbers. It skips deletions and unchanged findings, covers agent rule paths,
  treats rename targets as new files, handles paths with spaces, and fails on an invalid base.
- `TestLintLines` verifies hidden Unicode, raw HTML comments, common prompt injection patterns,
  merge conflict markers, malformed text, and missing final newlines. Normal Markdown and
  ordinary Unicode pass.
- The CI workflow runs the checker after checkout and Go setup and before the existing Go
  checks. The pull request path compares the base and test merge commits. Pushes compare the
  previous tip and new commit.
- The [Markdown lint guide](../../docs/markdown-linting.md) documents the commands, rules, and
  detection limits and is linked from contributor documentation.

Review the workflow configuration and run the package tests, the repository verification
commands, and the CLI against the deliverable diff. This change leaves repository history and
existing Markdown content outside the compared lines out of the lint gate.
