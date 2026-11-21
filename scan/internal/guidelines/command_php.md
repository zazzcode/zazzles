id: zazzles.command.php
version: 1
languages: php

# PHP command-execution guidelines

These guidelines interpret one verified `system`, `exec`, `shell_exec`, `passthru`, `popen`, `proc_open` call or backtick expression at a time under the declared POSIX analysis assumption.

## Posture

Report a source-confirmed command injection separately from field validation. A request value that reaches the command-string operand of a verified PHP process function is the claim; exploitability is a static judgment, not runtime confirmation. Prefer a fixed executable with separate argument arrays over shell command strings.

## Shell syntax

Every operation in this contract passes its command-string argument to the platform shell (`/bin/sh -c` on POSIX), including the backtick operator. Request text in that operand can add commands, substitutions, redirection and separators. `exec`'s output-array and status arguments are results, not command text; `popen`'s mode and `proc_open`'s descriptor arrays are configuration, not command text.

## Executable

The executable is selected by the shell command string, so the executable facet follows the shell facet. A command string that starts with a fixed program still has a shell parsing the rest: a fixed prefix does not constrain separators or substitutions that follow request text.

## Arguments

escapeshellarg quotes one value as a single shell argument and escapeshellcmd escapes shell metacharacters; they are argument-quoting controls on the value they wrap in source order. Quoting applied to part of an already-concatenated command string, or before a later concatenation that adds shell syntax, is not a constraint. An unknown transformation of request text keeps the argument facet unknown.

## Protection coverage

Protection must cover every request-derived path to the command operand and every feasible branch. A raw sibling branch defeats protection; a constraint on one value, branch or invocation never covers another. Reassignment after quoting, quoting the wrong variable, and guards in unreachable alternatives do not protect. Unknown helpers and unresolved value definitions stay unknown.

## Do not claim

Do not invent a guard or quoting that the evidence does not show. A locally defined function with a process function's name carries no contract. Do not infer the deployed platform, shell configuration, or runtime exploitability.
