id: zazzles.command.javascript
version: 1
languages: javascript, typescript

# JavaScript and TypeScript command-execution guidelines

TypeScript types, casts and annotations are not runtime validation. The same rules apply to `.js`, `.jsx`, `.ts` and `.tsx`. These guidelines interpret one Node `child_process` use at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed command injection and weak process-execution practice separately from field validation. A request value that reaches shell command text, an executable, an argument or shell configuration is the claim; exploitability is a static judgment, not runtime confirmation. Prefer eliminating process execution.

## Shell syntax

`exec` and `execSync` pass one string to a shell, so request text can add commands, substitutions, redirection and separators. `spawn`, `spawnSync`, `execFile` and `execFileSync` run an executable with a separate argument array only while the shell option is absent or false; with `shell: true` or a shell path the arguments are joined into shell text and are not separated data. An array call to a literal `sh` or `bash` with `-c` still has a shell command operand in the argument that follows `-c`. A verified shell-disabled call with data operands has no shell-syntax question; answer not_applicable unless a literal interpreter is the executable. Do not answer vulnerable for a verified shell-disabled data operand.

## Executable

A request value in the executable position selects the program and is unsafe unless a source-backed finite allow-list or constant constrains it before use. A fixed bare program name depends on PATH resolution; a fixed absolute path does not. A fixed executable is not protection for its arguments.

## Arguments

Separate arguments avoid shell parsing but do not prove that a value cannot be an option. A request value that becomes an option of a utility can alter its behavior; this is an argument-control claim, not shell injection. Unknown utility options stay unknown rather than a fabricated positive. `--` is not a universal utility contract. Protection requires an enforced, source-backed constraint such as a finite set of permitted literals that cannot be option syntax, with the rejecting branch terminating before use. Type casts, length limits, blacklist replacement, exception handling and unrelated hashing are not protection. General quoting adequacy is unproven unless an independently supported constraint establishes it.

## Protection coverage

Protection must cover every relevant operand and every feasible source-to-operand path. A raw branch and a constrained sibling are separate facts; a constraint on one operand, branch or invocation never protects another. Incomplete coverage cannot support aggregate protection. Constant-only operands and stdin, stdout, stderr, timeout, cwd and env options are not command text; track executable overrides, shell configuration, cwd and env separately.

## Do not claim

Do not claim runtime exploitation, a Windows or batch behavior, or independent findings review. Do not infer safety from a function name, a comment or an argument array alone. Do not invent missing bindings, guards or operands; unknown source facts remain blockers.
