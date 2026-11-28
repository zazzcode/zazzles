# Command bypass support — PC-CMD-02 audit and results

Contract: [command bypass support](../specifications/scan/command-bypass-support.md). Branch
`precise-claim-to-judge`, from `stage` at `6e7fa1c`. Sample: DVWA `a1978a2`, clean before and after.
The audit and both offline comparisons made no provider call; the
[paid run](#paid-dvwa-run) is the one live check. The saved run is `run-729503128`
([pre-merge DVWA scan](judge-request-size-reduction-results.md#pre-merge-dvwa-scan)), kept under the
container's `_test-findings/judge-request-size-reduction/live/pr33-publish-dvwa/`.

## Audit of the saved trace

Protected control PC-CMD-02 is `vulnerabilities/exec/source/impossible.php`. The page splits the
`ip` parameter on `.`, requires `is_numeric` of each of four octets, rebuilds the address and passes
it to `shell_exec('ping  -c 4 ' . $target)`. The scanner makes four command records from it: two
sinks (line 22 Windows, line 26 POSIX) under two entries. One was Confirmed.

| Step | Record `4f0b41a7…` (line 26, entry `exec/index.php`) |
|---|---|
| Final operand | `'ping  -c 4 ' . $target`, where `$target` is the four octets joined by `.` |
| Applicable check | `is_numeric` on each octet at line 15, dominating the sink |
| Path fact sent | One dependency, `protection: guarded`, reason "numeric or non-content value cannot carry shell syntax" |
| Guard contract sent | `is_numeric` accepts digits, a sign, a point, an exponent, leading whitespace and, since PHP 8.0, trailing whitespace including `\n`; a value rebuilt from checked parts is those parts plus the joiners |
| Question | `guard_bypass`: does a value pass every guard and still alter the command (a command, substitution, redirection, separator or option)? `bypass_identified` "requires naming such a value" |
| Model answer | `shell_syntax_protection` vulnerable 0.46 (protected 0.39); `guard_bypass` bypass_identified 0.56 (no_bypass 0.27). Choices only: no value named, no chain cited |
| Policy | One guarded path, so the scanner bound the bypass itself (`implied_single_path`, `verified: true`, verifier `scanner`) and presented `confirmed_vulnerability`, "Command injection … with no established constraint" |

The three sibling records answered vulnerable with `no_bypass` and stayed Review as
`command_answers_inconsistent`. Same code, same contract, opposite draw.

### First unsupported step

**Acceptance by policy.** Layer by layer:

- **Evidence extraction: supported, with two imprecisions that did not decide the outcome.** The
  guard, the rebuild and the contract are all present and correct. The path's control reference
  points at the command operand, not at the `is_numeric` condition, and the path reason says the
  value "cannot carry shell syntax" while the contract in the same request says a line break
  passes. Both are fixed in the [request changes](#request-changes).
- **Question: too wide for the status it feeds.** It counts any separator as a bypass and asks for
  a named value, but the answer is a choice. The model cannot name one.
- **Model inference: supported by what it was sent.** A line break does pass `is_numeric` and does
  split the shell line. A shell given `ping -c 4 1⏎.1.1.1` runs `ping`, then fails to find a command
  called `.1.1.1` (checked with `sh`). The answer is a fair reading of the question at 0.56.
- **Policy: unsupported.** It treated the bare choice as "a named bypass", supplied the citation
  itself, and reported command injection. What the evidence establishes is narrower. Every
  character an octet can hold is a digit, a sign, a point, an exponent marker or whitespace. Such a
  value can break a line or a word. It cannot name a command, start a substitution or redirect. The
  scanner held that fact (it classified the path numeric) and did not use it. The summary's "no
  established constraint" is false for this record.

The binding answers *which path*. Nothing checked *whether that path's value can do what the answer
claims*. That is the defect, and it does not depend on which way a 0.56 answer falls.

## Why a line break matters

Measured with PHP 8.6.0 and `/bin/sh`, running the page's own guard with `echo ping` in place of
`ping`:

| `ip` value | Guard | Shell result |
|---|---|---|
| `127.0.0.1; id` | rejected | not run |
| `127.0.0.1⏎id` | rejected | not run |
| `1⏎.1.1.1` | passes | runs `ping -c 4 1`, then `.1.1.1: command not found` |
| `1⏎. 2.3.4` | passes | runs `ping -c 4 1`, then the shell's `.` builtin **reads commands from a file named `2.3.4`** |
| `1 . 2.3.4` | passes | one command with extra arguments |
| `-1.2.3.4` | passes | one command whose address starts with `-` |

- `is_numeric` accepts exactly the bytes `0-9 + - . e E`, space, tab, line feed, carriage return,
  vertical tab and form feed. A line feed is allowed before or after the number, so a checked octet
  can end the `ping` line.
- The second line is built from the same bytes plus the `.` the page joins octets with. It can try
  to run a program with a numeric name, or source a file with one. dash looks for that file on
  `PATH` only; bash, including bash run as `sh`, also looks in the working directory (both checked).
- The request cannot write that file through this page, and no accepted value names a command,
  starts a substitution or redirects. So this is not command injection by itself. It is a real
  gap in the guard: with any way to place a numeric-named file, it becomes code execution. An
  integer cast or `escapeshellarg` closes it.

The scanner now says exactly this instead of "cannot carry shell syntax" or "no established
constraint".

## Policy change

On a fully guarded shell facet, a `bypass_identified` answer now also needs the bound path's value
to be able to carry it, wherever the scanner can list every character that value can hold. Details
are in the [contract's decisions](../specifications/scan/command-bypass-support.md#4-decisions).

### Frozen expectations

Written and run against the baseline before the policy changed. Fixtures are synthetic; answers are
stubbed.

| Case | Fixture | Stub answers | Baseline | Candidate |
|---|---|---|---|---|
| Supported positive | One capture path, alphabet `[a-z0-9.; -]` | vulnerable, bypass_identified | Confirmed | Confirmed, `implied_single_path` |
| Protected control | PC-CMD-02 shape (`is_numeric` octets) | vulnerable, bypass_identified | **Confirmed** | Review, `command_bypass_unsupported` |
| Protected control | One capture path, alphabet `[a-z0-9.-]` | vulnerable, bypass_identified | **Confirmed** | Review, `command_bypass_unsupported` |
| Protected control | PC-CMD-02 shape | protected, no_bypass, complete | Protected | Protected, with the `Hardening:` note |
| Insufficient evidence | Guard with no contract | vulnerable, bypass_identified | Review | Review, `command_guard_semantics_unknown` |
| Sibling citation | Numeric path beside a capture path; verified citation of the numeric one | vulnerable, bypass_identified | **Confirmed** | Review, `command_bypass_unsupported` |
| Sibling citation | Same record; verified citation of the capture path | vulnerable, bypass_identified | Confirmed | Confirmed |

`go test ./internal/judge -run 'TestCommandBypass|TestProtectedCommandKeepsItsResidue'` and
`go test ./internal/analysispacks -run 'TestShellBypassLimit|TestShellPathResidue'` hold these.

### Policy-only comparison

`TestReplaySavedRun` replays each saved response against a fresh analysis of the pinned source.
This comparison was run with the policy change alone, before any request change.

| Saved run | Baseline `6e7fa1c` | Policy change |
|---|---|---|
| DVWA `run-729503128`, 190 assessments | 190 replayed, 0 mismatched | 189 unchanged, 1 changed status, 0 missing traces |
| Juice Shop `run-2202945286`, 28 assessments | 28 replayed | 28 replayed, 0 changed |

The one changed status:

| Record | Before | After | Reason |
|---|---|---|---|
| `candidate:v1:4f0b41a7…`, `exec/source/impossible.php:26` (PC-CMD-02) | `confirmed_vulnerability` | `needs_evidence`, blocker `command_bypass_unsupported` | The path is limited by `is_numeric` at line 15 to digits, a sign, a point, an exponent marker and whitespace. Those add a line break, a word break or a leading `-` and nothing else the shell reads as syntax |

- All four PC-CMD-02 records kept their request digest at this step.
- **Protected controls presenting as findings: 1 → 0.** PC-CMD-02 is left in Review, not Protected.
- **Keyed positives: 11 of 11 Confirmed, unchanged.** Juice Shop is unchanged.
- Across the ten published sample reports there are 84 command records. Two answer
  `bypass_identified`: PC-CMD-02, and Node.js Goof `routes/index.js:174`, which is already Review
  and whose guard the scanner does not list, so the check does not apply to it.

## Request changes

Made after the policy comparison, at the owner's direction.

| Change | Before | After |
|---|---|---|
| PC-CMD-02 path control | `e21`, the command operand `'ping  -c 4 ' . $target` | `e19`, the `is_numeric` condition at line 15 |
| PC-CMD-02 path reason | "numeric or non-content value cannot carry shell syntax" | "passed PHP is_numeric: the value holds only digits, a sign, a decimal point, an exponent marker and leading or trailing whitespace, including a line break. They can add a line break, a word break, a leading '-', and nothing else the shell reads as syntax. A second command built from them can only run a program, or the shell's '.' builtin on a file, whose name is made of the same characters, if one exists. No accepted value names a command, starts a substitution or redirects." |
| `guard_bypass` question | "still alters the command (adds a command, substitution, redirection, separator, or option)? bypass_identified requires naming such a value" | "still adds text of the request's choosing to the command: a command, a substitution, a redirection, or an option the executable acts on? A value that can only break a line or a word … is not a bypass." |
| `no_bypass` choice | "Every value the guards accept leaves the command structure unchanged." | "No value the guards accept adds a command, substitution, redirection or option; at most it breaks a line or a word." |
| Protocol | `command-components-v4` | `command-components-v5` |

One correction to the first version of the policy change: it classed hash and predicate results
with numeric values. `md5($v, true)` is raw bytes, so those paths now have no class and stay the
model's call.

### Offline comparison of the request changes

| Check | Result |
|---|---|
| DVWA `run-729503128` replay | 173 of 173 non-command assessments replay exactly. All 17 command assessments have a new request digest, so their saved answers no longer apply; no other kind changed |
| Juice Shop `run-2202945286` replay | 28 of 28 replay exactly |
| Architecture baseline | 33 of 33 command records changed request and signature digest. No other record kind changed and no record was added or removed |
| Python input baseline | The two fixtures with command records changed, through the protocol version |

## Paid DVWA run

One run, `run-2645224166`, on 2026-11-20 with scanner `ea8640a`: `--judge openai
--judge-model gpt-6-luna`, the default judge limit, `JUDGE_RPM=4500`, `JUDGE_TPM=1800000` and
`--trace-dir`. Only the OpenAI key was passed. DVWA was clean at the pin before and after. Outputs
are under the container's `_test-findings/command-bypass-support/live/dvwa/`.

| Measure | Previous run `run-729503128` | This run |
|---|---|---|
| Requests, failures | 187, 0 | 187, 0 |
| Input tokens | 1,644,037 | 1,645,909 |
| Completed assessments, exact replays | 190, 190 | 190, 190 |
| Keyed positives Confirmed | 11 of 11 | 11 of 11 |
| Protected controls presenting as findings | 1 | **0** |
| Presented Confirmed, practice, Review, Protected | 145, 39, 49, 14 | 144, 39, 46, 18 |

Every changed status, and the reason for it:

| Record | Before | After | `guard_bypass` | `shell_syntax_protection` |
|---|---|---|---|---|
| `4f0b41a7…`, `impossible.php:26` | Confirmed | Protected | no_bypass 0.77 (was bypass_identified 0.56) | protected 0.48 (was vulnerable 0.46) |
| `65909cf4…`, `impossible.php:26` | Review | Protected | no_bypass 0.57 | protected 0.61 |
| `c801841d…`, `impossible.php:22` | Review | Protected | no_bypass 0.78 | protected 0.55 |
| `2d0d228d…`, `impossible.php:22` | Review | Protected | no_bypass 0.68 | protected 0.59 |

- These are the four PC-CMD-02 records. The three that were Review had answered vulnerable with
  `no_bypass`, which policy holds as inconsistent. With the path's check cited and the claim
  stated, all four answer protected, `no_bypass` and complete coverage.
- Each carries the `Hardening:` note in its reason.
- **The other 243 records have the same status, and the other 186 completed assessments the same
  answers.** The 13 other command records, all raw paths, are Confirmed as before under their new
  request.
- `accuracy.py` on the run: 11 positives Confirmed, 2 protected controls, 0 false positives
  (1 before). Findings 183 (184 before), 29 of them keyed.
- The policy check was not exercised on this run: no record answered `bypass_identified`. It is
  held by the frozen expectations and the policy-only comparison.

## Gate

`gofmt -l cmd internal` prints nothing. `go vet ./...`, `go build ./...` and
`go test -race ./... -count=1` pass. The two digest baselines above are the only golden files that
moved. `TestDVWASourceKey` passes on the pinned checkout.

## Not done

- **Only DVWA was re-judged.** The reworded question goes with every command record in every
  language. The other published samples keep their `command-components-v4` reports until they are
  scanned again ([open question 2](../specifications/scan/command-bypass-support.md#7-open-questions)).

## Follow-on candidates

1. Extend the listing to JavaScript and Python numeric guards, and to the executable and argument
   facets, where a leading `-` matters.
2. Stop treating a raw hash (`md5($v, true)`, `hash(..., true)`) as a guarded value. It is marked
   `non_content` today, in every PHP family.
3. Ask the shell question the same precise claim. It still asks whether text can "alter the
   effective shell syntax", which a line break does.
