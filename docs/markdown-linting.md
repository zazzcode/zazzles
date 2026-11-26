# Markdown linting

CI checks added and replaced lines in tracked Markdown and agent rule files before the Go
format, vet, build, and test steps. The checker uses the Go standard library and Git.

From the repository root, check your committed changes against the point where you branched
from `stage`:

```sh
go run ./tools/mdlint -base "$(git merge-base stage HEAD)"
```

Use `origin/stage` if that is your integration ref. To compare two specific commits, pass
`-base <commit> -head <commit>`. On pull requests CI compares the base commit with GitHub's
test merge commit. On pushes CI compares the previous tip with the pushed commit. Both
commits must be available. Commit your changes before running the check locally.

## Checks

- Case-insensitive `.md`, `.markdown`, `.mdx`, and `.mdc` files, plus `.cursorrules`, at any depth.
  This includes agent instructions such as `AGENTS.md` and `CLAUDE.md`.
- Unicode default-ignorable characters, including tags, zero-width characters, bidirectional
  controls, and variation selectors. The check also catches Braille Pattern Blank, control
  characters such as backspace, and invisible characters written as HTML entities.
  Emoji that use variation selectors or zero-width joiners can also trigger this check.
- Raw HTML comments and edited lines inside them. Raw source is visible to agents even
  when the rendered document hides it. The check also applies inside code blocks.
- Common instruction overrides, requests to disclose model instructions or secrets, role
  control markers, and remote downloads piped into a shell. Prompt checks account for
  HTML entities, Unicode spaces, fullwidth ASCII, simple Markdown formatting, and line wrapping
  within a paragraph. An adjacent unchanged line can supply context for a changed line.
- Invalid UTF-8, NUL bytes, merge conflict markers, and missing final newlines. New files,
  including rename destinations, are checked in full. Symlinks and Git submodules at
  covered paths are rejected when changed.

Findings identify the path, line, and rule. Keep documentation examples descriptive and
put literal detector fixtures in Go tests. Pattern matching can flag legitimate examples
and can miss reworded instructions or techniques outside its normalization rules. Review
changes to the checker or its workflow as code.
