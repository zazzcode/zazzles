id: zazzles.path.python
version: 1
languages: python

# Python path-traversal guidelines

These guidelines interpret one builtin `open`, `io.open` or `pathlib.Path` read or write at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed path traversal separately from field validation. A request value that reaches the file operand of a verified `open`, `io.open` or `pathlib` operation is the claim; exploitability is a static judgment, not runtime confirmation. Prefer selecting a file by a trusted identifier over accepting a path.

## Operations

For `open` and `io.open` the first positional argument or the `file` keyword is the path; the mode decides read or write and is not a path. Text or bytes written through the returned object or `write_text` and `write_bytes` are not a path: request data written to a file is not a traversal by itself. `os.path.join` returns an absolute later segment alone, so a request value can replace a trusted base, and `..` segments remain until normalization; `pathlib` `/` behaves the same. `os.path.normpath` and `abspath` are lexical. None of them checks containment, and a verified join of a request value with a fixed directory does not establish a trusted root.

## Containment

Containment requires an enforced check on the same value that rejects before the file operation: a finite allow-list of trusted constant identities, or a comparison of the resolved target with the trusted root at a path-component boundary (`startswith(root + os.sep)`, `os.path.commonpath([root, target]) == root`, `Path.is_relative_to`). A prefix comparison without a separator is not a boundary: a sibling directory that shares the prefix satisfies it. A `..` substring blacklist, normalization alone, `basename` of an unreviewed value, casts, length limits, `try`/`except` and an error response after the open are not containment. A check followed by `unquote`, a reassignment or a different value inspected the wrong text.

## Symbolic links and platform

`os.path.abspath` and `normpath` are lexical; `os.path.realpath` and `Path.resolve` resolve symbolic links. A lexical boundary check says nothing about a symbolic link or a race created after it; record that as an assumption and do not call it resolved containment. A claim of resolved containment needs the realpath or resolve result in the supplied source as the compared value. Windows drive, UNC and backslash behavior is not modeled; do not infer the deployed platform from this analysis.

## Protection coverage

Protection must cover every request-derived path to the file operand and every feasible branch. A raw branch and a constrained sibling are separate facts; a control on one value, branch or invocation never protects another. A guard in a sibling branch does not protect this call. Incomplete coverage cannot support aggregate protection. Unknown helpers, reassignments and decodes after the check stay unknown. A function, import or assignment named `open` that shadows the builtin carries no contract.

## Do not claim

Do not claim runtime exploitation, symbolic-link safety, Windows behavior or independent findings review. Do not infer safety from a function name, a comment or an error response. Do not invent missing bindings, guards or operands; unknown source facts remain blockers.
