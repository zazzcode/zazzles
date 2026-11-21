id: zazzles.command.python
version: 1
languages: python

# Python command-execution guidelines

Annotations are not runtime validation. These guidelines interpret one `os` or `subprocess` process use at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed command injection and weak process-execution practice separately from field validation. A request value that reaches shell command text, an executable, an argument or shell configuration is the claim; exploitability is a static judgment, not runtime confirmation. Prefer eliminating process execution.

## Shell syntax

`os.system` and `os.popen` pass one string to the shell. With `subprocess` and `shell=True`, a string is shell text; for a sequence on POSIX only the first item is shell command text and the remaining items are arguments to the shell itself, not concatenated into that command. With `shell=False` (the default) a string is not automatically shell-split and a list is an executable plus separate arguments. A literal `sh` or `bash` executable with `-c` still has a shell command operand even when the API shell option is false. Verified shell-disabled data operands have no shell-syntax question; answer not_applicable unless a literal interpreter is explicit. Do not answer vulnerable for a verified shell-disabled data operand.

## Executable

A request value in the executable position or the `executable` override selects the program and is unsafe unless a source-backed finite allow-list or constant constrains it before use. A fixed bare program name depends on PATH resolution; a fixed absolute path does not. A fixed executable is not protection for its arguments.

## Arguments

Separate arguments avoid shell parsing but do not prove that a value cannot be an option. A request value that becomes a utility option is an argument-control claim, not shell injection; unknown utility options stay unknown rather than a fabricated positive. `--` is not a universal utility contract. Protection requires an enforced, source-backed constraint such as a finite set of permitted literals that cannot be option syntax, with the rejecting branch terminating before use. Type annotations, length limits, blacklist replacement, exception handling, `str()` or `bytes` conversion and unrelated hashing are not protection. `shlex.quote` and similar quoting remain unproven unless an independently supported constraint establishes the exact facet.

## Protection coverage

Protection must cover every relevant operand and every feasible source-to-operand path. A raw branch and a constrained sibling are separate facts; a constraint on one operand, branch or invocation never protects another. Incomplete coverage cannot support aggregate protection. Constant-only operands and stdin, stdout, stderr, timeout, cwd and env options are not command text; track executable overrides, shell configuration, cwd and env separately.

## Do not claim

Do not claim runtime exploitation, a Windows or batch behavior, or independent findings review. Do not infer safety from a function name, a comment or an argument list alone. Do not invent missing bindings, guards or operands; unknown source facts remain blockers.
