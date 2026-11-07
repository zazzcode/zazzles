# Command injection analysis

[Analysis index](README.md) · [Database injection](database-injection.md) · [Input validation](input-validation.md)

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

Each process use is one record. A model decision answers four questions (shell syntax, executable
control, argument control, protection coverage); the scanner's Go policy then gates them against the
source facts:

- A shell answer of vulnerable needs a request-derived value in an effective shell-command operand.
  A shell-disabled call with data operands has no shell question, so claiming one is contradictory.
- Protection (protected or constrained) needs a dominating or enclosing control that mentions the
  operand on **every** request-derived path: an enforced, rejecting branch that terminates before use
  or an enclosing allow-list test. A rejecting branch with no `return`/`throw` does not count; a
  type test, cast, annotation, length limit, blacklist replacement, exception handling or unrelated
  hashing never counts. Presence-only tests (`is not None`, truthiness, method/version checks) are
  not guards. Fixed absolute executables avoid PATH selection; a bare name stays unresolved.
- A path guarded by a control the scanner cannot judge can still be answered vulnerable; adequacy is
  the model's recorded decision, and the guard evidence is shown with the record.
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
Review. See the [command contract](../../.zazz/specifications/command-injection.md) and the
[acceptance results](../../.zazz/evaluation/command-injection-results.md) for tested coverage.
