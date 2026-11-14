id: zazzles.path.javascript
version: 1
languages: javascript, typescript

# JavaScript and TypeScript path-traversal guidelines

TypeScript types, casts and annotations are not runtime validation. The same rules apply to `.js`, `.jsx`, `.ts` and `.tsx`. These guidelines interpret one Node `fs` read or write at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed path traversal separately from field validation. A request value that reaches the file-path argument of a verified `fs` operation is the claim; exploitability is a static judgment, not runtime confirmation. Prefer selecting a file by a trusted identifier over accepting a path.

## Operations

For `readFile`, `readFileSync`, `writeFile`, `writeFileSync` and their `fs/promises` forms the first argument is the path. Write data, encoding, mode, flag and callback arguments are not a path: request data written to a file is not a traversal by itself. `path.join` concatenates and normalizes, so `..` segments still climb while an absolute later segment is appended; `path.resolve` replaces everything before an absolute segment; `path.normalize` is lexical. None of them checks containment, and a verified join or resolve of a request value with a fixed directory does not establish a trusted root.

## Containment

Containment requires an enforced check on the same value that rejects before the file operation: a finite allow-list of trusted constant identities, or a comparison of the resolved target with the trusted root at a path-component boundary (a prefix that ends with the separator, a `path.relative` result that neither starts with `..` nor is absolute). A prefix comparison without a separator is not a boundary: a sibling directory that shares the prefix satisfies it. A `..` substring blacklist, normalization alone, type casts, length limits, exception handling and an error response after the read are not containment. A check followed by `decodeURIComponent`, a reassignment or a different value inspected the wrong text.

## Symbolic links and platform

`path.resolve` and `path.normalize` are lexical; only `fs.realpath` resolves symbolic links. A lexical boundary check says nothing about a symbolic link or a race created after it; record that as an assumption and do not call it resolved containment. A claim of resolved containment needs the realpath result in the supplied source as the compared value. Windows drive, UNC and backslash behavior is not modeled; do not infer the deployed platform from this analysis.

## Protection coverage

Protection must cover every request-derived path to the path operand and every feasible branch. A raw branch and a constrained sibling are separate facts; a control on one value, branch or invocation never protects another. A guard in a sibling branch does not protect this call. Incomplete coverage cannot support aggregate protection. Unknown helpers, reassignments and decodes after the check stay unknown.

## Do not claim

Do not claim runtime exploitation, symbolic-link safety, Windows behavior or independent findings review. Do not infer safety from a function name, a comment, a type annotation or an error response. Do not invent missing bindings, guards or operands; unknown source facts remain blockers.
