# Command injection analysis

[Analysis index](README.md) · [Database injection](database-injection.md) · [Input validation](input-validation.md) · [Command injection coverage](../detection-capabilities/command-injection.md) · [Argument injection coverage](../detection-capabilities/argument-injection.md)

The Command Injection Analyzer traces request values into verified operating-system process calls
in JavaScript, TypeScript and Python and separates three claims that people often merge: whether
text can change **shell syntax**, whether a request value selects the **executable**, and whether a
separate **argument** can act as an option or interpreter control. Field validation is a different
claim and keeps its own record. Reports state a static source judgment under a declared POSIX
assumption; they never claim runtime exploitation or independent Findings Review.

## What is verified

| Language | Verified operations (actual import/require binding required) | Contract |
|---|---|---|
| JS/TS | `exec`, `execSync` | shell command text |
| JS/TS | `execFile`, `execFileSync`, `spawn`, `spawnSync` | executable + argument array; `shell` option decides whether arguments are joined into shell text |
| Python | `os.system`, `os.popen` | shell command text |
| Python | `subprocess.run/Popen/call/check_call/check_output` | executable/arguments; `shell=True` makes a string (or a sequence's first item) shell text |

Bindings come from ESM named/namespace imports, `child_process` / `node:child_process`, CommonJS
members and destructuring, Python module/from imports and immutable local aliases. A fake object,
a shadowed symbol, a reassigned binding, a local module that shadows `os`/`subprocess`, or a
source-visible monkey-patch earns no verified contract. Spreads, `*args`/`**kwargs`, dynamic shell
options and unknown argument-vector shapes stay visible blockers. Windows, `cmd`, PowerShell and
unknown interpreters are Review. POSIX is an analysis assumption, never inferred from the scanner host.

A call with only constant operands, or request data only in `stdin`/`input`/output handling, is not
a command candidate. Callback output parameters never become command dependencies.

## Facets and outcomes

Each process use is one record. A model decision answers five questions (shell syntax, executable
control, argument control, guard bypass, protection coverage; protocol `command-components-v5`);
evidence validation checks those answers against the source facts before classification:

- A shell answer of vulnerable needs a request-derived value in an effective shell-command operand.
  A shell-disabled call with data operands has no shell question, so claiming one is contradictory.
- Protection (protected or constrained) needs a dominating or enclosing control that mentions the
  operand on **every** request-derived path: an enforced, rejecting branch that terminates before use
  or an enclosing allow-list test. A rejecting branch with no `return`/`throw` does not count; a
  type test, cast, annotation, length limit, blacklist replacement, exception handling or unrelated
  hashing never counts. Presence-only tests (`is not None`, truthiness, method/version checks) are
  not guards. Fixed absolute executables avoid PATH selection; a bare name stays unresolved.
- Guards are collected by one shared lexical engine for JavaScript, TypeScript and Python. A
  condition counts for the operand it mentions (or a value computed from it) only in the polarity the
  code gives it: an `if` whose body always ends the request (`return`, `throw`, `process.exit`, a
  verified `abort()`/`sys.exit()`) guards later code; a test whose body contains the call is enforced
  when true; a test on the `else` side is recorded as a false-branch fact (`branch_false_precondition`),
  never as an enforced control. A reassignment of the operand between the guard and the call
  invalidates the guard. A guard in the single caller of a local helper applies; with several callers
  only guards every caller shares apply. The contents of a module-level allow-list that a guard tests
  are supplied as evidence so the model can judge the guard.
- Guard adequacy is the model's call. For each recognised guard on a guarded path (`is_numeric`,
  `ctype_digit`, integer casts, anchored and unanchored regular expressions, allow-list membership)
  the request carries a short source-backed contract of the values the guard accepts, with its edge
  cases (for example PHP 8 `is_numeric` accepts trailing whitespace; PCRE `$` matches before a final
  newline). The guard-bypass question asks whether a value passes every guard and still adds command
  text of the request's choosing: `bypass_identified`, `no_bypass`, `guard_semantics_unknown` or `not_applicable`. Policy
  checks only self-consistency: a vulnerable or unsafe answer on a facet whose every path is guarded
  stands only with `bypass_identified`; with `no_bypass` it is `command_answers_inconsistent`; with
  `guard_semantics_unknown`, or a guard that has no contract, it stays Review
  (`command_guard_semantics_unknown`). A protected answer beside an identified bypass is also
  inconsistent. A raw path's witness is unaffected.
- A capture group of a literal regular expression is an exactly stated transform. When the operand
  is `s.match(re)[n]` or `re.exec(s)[n]` (JavaScript), `$m[n]` after `preg_match(re, $s, $m)` (PHP)
  or `m.group(n)` after `re.match`/`fullmatch`/`search` (Python), the dependency records a
  `regex_capture` transform with the pattern, flags, group and the group's own sub-pattern, classified
  as `admits_any` (the sub-pattern contains `.`, `\S`, `\W`, `\D`, or a negated class that excludes
  none of `;`, `|`, `&`, `$`, backtick, `(`, `)`, `<` and `>`), `explicit_alphabet` (only literals and positive classes; the accepted
  characters are listed, with Python's Unicode `\d`/`\w`/`\s` noted) or `unknown` (backreferences,
  lookaround, inline or verbose flags, other unsupported syntax). One deterministic rule applies, to
  the shell facet only: a path whose only controls are the match test of that expression (beside
  presence and runtime-type tests) and whose capture is `admits_any` is raw, with the capture kept as
  a transform, because the guard provably passes shell syntax. Any other control keeps the path
  guarded; `explicit_alphabet` and `unknown` captures stay guarded, and the guard contract states the
  classification so the model judges adequacy against the listed alphabet. Executable and argument
  facets, and the path and SQL families, do not apply the rule yet.
- A bypass must name the chain it bypasses. With two or more guarded paths the model cites one
  (`bypass-citation-v2`) and the scanner verifies the citation like any other chain. When the record
  has exactly one guarded path and that chain has no scanner gap, every verified citation would be
  that chain, so the question is not sent: the scanner binds the bypass answer to it and records
  `citation: implied_single_path` with `verifier: scanner`. A model citation that failed verification
  is never overridden. A follow-up request for a member that a supplied guard contract already
  describes (for example `item.match` under the regular-expression contract) has no body to fetch and
  is recorded as `answered_by_contract`.
- A bypass is command text of the request's choosing: a command, a substitution, a redirection or an
  option the executable acts on. A value that can only break a line or a word is not one, and the
  question says so. Binding a bypass to a path establishes where it is, not that the path's value
  can carry it. For the shell facet the scanner checks that too wherever it can list every character
  the guarded value can hold:
  - a PHP value that passed `is_numeric` (digits, a sign, a decimal point, an exponent marker and
    leading or trailing whitespace, including a line break), passed `ctype_digit` (digits only), or
    was converted with `intval`, `floatval` or a cast (the text of a number, no whitespace);
  - a capture classified `explicit_alphabet` with a complete listing.

  Such a PHP path cites the check itself as its control, and its reason states those characters and
  what they can do. A value carries command text when its characters include a redirection, or a
  separator (`;`, `&`, `|`, line break) or command substitution together with letters to name a
  command. When they do not, the bypass is not supported: the record stays Review
  (`command_bypass_unsupported`) and the reason names the guard and what its characters can still
  do. This applies to a path the scanner bound and to a path the model cited, so citing a limited
  sibling never confirms. It never creates protection, and guards the scanner cannot list (a hash,
  an allow-list, an opaque helper) stay the model's call.
- What a limited value can still do is stated, not dropped. A line break after `is_numeric` ends the
  command and starts a second one built from the same characters: `1⏎. 2.3.4` passes four
  `is_numeric` octets and runs the shell's `.` builtin on a file named `2.3.4` if one exists (checked
  with PHP 8.6 and `sh`). That needs a file the request did not write, so it is not a finding. A
  record that is Protected for the claim carries it as a `Hardening:` note in its reason.
- Unknown utility options are Review: no CWE-88 finding is made without established option or
  interpreter semantics (for example a literal `sh -c`).
- An unsafe witness needs only its own source-to-operand path; unresolved sibling paths remain
  visible blockers and never become protection. All-not-applicable is not green.

Status follows the shared vocabulary: `confirmed_vulnerability` (finding), `protected_for_claim`
(protection), or `needs_evidence` (Review). Only a final protected record is green. CWE-78 applies to
shell-command defects and arbitrary executable selection; CWE-88 only to demonstrated option or
interpreter injection.

## Entry coverage

Command analysis rides the shared entry model: HTTP routes in Express and, for Python, Flask, FastAPI,
Quart, Django (sync and ASGI), Falcon (sync and ASGI), Bottle, Pyramid, aiohttp and WSGI path
dispatch, plus the existing JS/TS GraphQL and unary gRPC contexts. Each framework context, method and
registration is its own candidate; repeated exposures of one source sink are not new defects.
Browser-only entries never select a Node process contract. Bounded models also cover generated
registrations, finite loops, upload reads, request-path registry dispatch and `threading.Thread`
hand-off. Test modules are not application registrations. Anything outside these shapes stays a gap.

For PHP, [server-mapped file entries](../php-support.md) cover `shell_exec`, `exec`, `system`,
`passthru`, `popen`, `proc_open` and backtick operators with `php-program-execution-v1`
shell-operand facts; concatenation into a fixed command prefix stays a raw operand.
`escapeshellarg` on the dynamic operand is a quoting control the judge weighs, not a sink removal;
a shadowed execution function stays negative.

## Skipping the input-validation analyzer

For very large targets, `--skip-family input-validation` leaves every input-validation record
unjudged (`not_run`, with the reason) so a scan can spend its request budget on injection, XSS and
command claims. The run states this in the JSON `skipped_families` field, the HTML scope section,
SARIF run properties and the limitations list. A skipped run says nothing about validation adequacy.

## Remediation guidance

Prefer eliminating process execution. Otherwise use a fixed trusted absolute executable, pass each
value as a separate argument with the shell disabled, and enforce utility-specific constraints such as a
finite set of permitted literals that cannot be option syntax. `--` is not a universal option
terminator, quoting is not protection without an enforced constraint, and stripping punctuation is not
a fix. Reports never export a verified patch.

## Limits

Static, bounded analysis: dynamic dispatch beyond the modeled registries, unmodeled middleware or
wrappers, mutation through unmodeled calls, whole-program flow and runtime/platform differences stay
Review. See the [command contract](../../../.zazz/specifications/scan/command-injection.md) and the
[acceptance results](../../../.zazz/evaluation/command-injection-results.md) for tested coverage.

## Symfony

Symfony Process::fromShellCommandline consumes shell text. A Process backed by an argument vector carries its executable and argument-slot facts. Resolved controller and service calls can reach the existing PHP shell sinks. FILTER_VALIDATE_URL records a format control and does not establish shell quoting.

[Symfony analysis coverage](../symfony-support.md)
