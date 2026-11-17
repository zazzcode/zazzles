id: zazzles.path.php
version: 1
languages: php

# PHP path-traversal guidelines

These guidelines interpret one verified filesystem operation or include at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed path traversal separately from field validation. A request value that reaches the file-path operand of a verified `fopen`, `file_get_contents`, `readfile`, `file`, `file_put_contents`, `unlink`, `move_uploaded_file` destination or `include`/`require` operand is the claim; exploitability is a static judgment, not runtime confirmation. Prefer selecting a file by a trusted identifier over accepting a path.

## Operations

For the filesystem functions the first argument is the path; `file_put_contents`' second argument is written data, never a path source; `fopen`'s mode selects read/write and is not a path; `readfile` streams the selected file to the response. `include`/`require` execute the resolved path: the operand is a path with a file-inclusion execution context, not an interpreter string operand. `move_uploaded_file`'s first argument is the server-managed `$_FILES` temporary name and not a request path; its destination is the path operand, and a destination built from `$_FILES[...]['name']` carries the client-supplied original name with separators intact. String concatenation and interpolation join segments without containment; `dirname`/`__DIR__` prefixes are bases, not boundaries. A relative path resolves against the including file's directory or the process working directory.

## Containment

Containment requires an enforced check on the same value that rejects before the operation: a finite allow-list of trusted constant identities (page names), or a comparison of the resolved target with the trusted root at a path-component boundary. `basename` reduces a value to a single component, which cannot climb a directory; a `basename` result joined to a fixed directory is component-sanitized. `realpath` resolves links and normalizes lexically but is not itself containment; a boundary check must compare the realpath result. A prefix comparison without a separator, a `..` substring blacklist, normalization alone, type casts, length limits, `try`/`catch` and an error response after the operation are not containment.

## Symbolic links and platform

`realpath` resolves symbolic links; lexical checks say nothing about a link or race created after them; record that as an assumption and do not call it resolved containment. Windows drive, UNC and backslash behavior is not modeled; do not infer the deployed platform. Remote include destinations are governed by `allow_url_include`; scheme classification on the path facts records the destination kind without asserting configuration.

## Protection coverage

Protection must cover every request-derived path to the file operand and every feasible branch. A raw branch and a constrained sibling are separate facts; a control on one value, branch or invocation never protects another. A guard in a sibling security-level alternative does not protect this call. Reassignment and decoding after the check stay unknown. A function defined locally with a filesystem function's name carries no contract.

## Do not claim

Do not invent an allow-list, a boundary check or a sanitizer that the evidence does not show. Do not treat normalization, concatenation with a fixed directory, or upload source checks as containment. Do not infer the deployed platform or filesystem state.
