# Command bypass support

- **Worktree and branch** `precise-claim-to-judge`, from `stage` at `6e7fa1c`.
- **Owner direction** On 2026-11-20 the owner asked for the PC-CMD-02 false positive called out in
  PR #33 to be fixed first, starting from an offline audit of the saved trace. After reviewing that
  result the same day the owner asked for three more things in this deliverable: harden the
  line-break case, fix the two request-side follow-ons now, and refresh the published DVWA sample
  with one paid run once the fix was verified offline.
- **Results** [Audit and results](../evaluation/command-bypass-support-results.md).

## 1. Capability

The decision model is asked a precise claim about a guarded command path, and its answer is
checked against the same path's facts.

- A bypass is command text of the request's choosing. A value that can only break a line or a word
  is not one, and the question says so.
- A PHP path guarded by a numeric check or conversion cites that check and states every character
  its value can hold.
- A record whose every shell path is guarded is Confirmed only when the `bypass_identified` answer
  is possible under those characters. Otherwise it stays in Review with a reason that names the
  guard and what its characters can still do.
- A record that is Protected for the claim still states what its guard lets through.

### Measured baseline

The final paid DVWA run for PR #33 Confirmed protected control PC-CMD-02
(`vulnerabilities/exec/source/impossible.php:26`). The
[audit](../evaluation/command-bypass-support-results.md#audit-of-the-saved-trace) places the first
unsupported step in policy: a choice answer at 0.56 was accepted as a named bypass, the scanner
supplied the citation itself, and nothing checked the claimed consequence against the `is_numeric`
guard the scanner had already recognised. Two request-side imprecisions fed the answer: the path
cited the command operand as its control, and the question counted any separator as a bypass
while asking for a named value that a choice answer cannot give.

## 2. Required reading

- [Command injection analysis](../../docs/analysis/command-injection.md), guard adequacy and
  bypass citation.
- [Close findings gaps](close-findings-gaps.md) D-1 and AC1 (single-path binding), which this
  contract narrows.
- [Protected controls](../evaluation/recall-gap-inventory/protected-controls.json), row PC-CMD-02.
- Code: `applyCommandPolicy` (`internal/judge/command.go`), `impliedBypassPath`
  (`internal/judge/resolution.go`), `GuardContracts` (`internal/analysispacks/guard_contracts.go`),
  `CommandQuestions` (`internal/analysispacks/command.go`), `commandUse`
  (`internal/langphp/command.go`).

## 3. Scope

| File | Change |
|---|---|
| `internal/analysis/command.go` | `CommandPath.Class`, extraction-only, and three value classes |
| `internal/langphp/` `values.go`, `guards.go`, `control.go`, `flow.go`, `calls.go`, `superglobal_state.go` | A numeric path remembers its check or conversion and the class of text it leaves |
| `internal/langphp/command.go` | A numeric path cites that check as its control and states its characters |
| `internal/analysispacks/guard_reach.go` (new), `regex_capture.go` | `ShellBypassLimit`, `ShellPathResidue`, `NumericPathReason`; the capture classifier returns its character set |
| `internal/analysispacks/command.go` | The bypass question and two choice descriptions; protocol `command-components-v5` |
| `internal/judge/command.go` | The support check, blocker `command_bypass_unsupported`, the `Hardening:` note |
| Tests beside each; two digest baselines | Frozen expectations, reach table, path facts; command request digests regenerated |
| `docs/analysis/command-injection.md`, `docs/decision-models.md`, `.zazz/architecture/analysis-packs.md` | The rule and the protocol version |
| `docs/samples/dvwa/`, `docs/samples/README.md` | The refreshed sample |

Out of scope: the other four command questions, the path, SQL, code and redirect families, the
executable and argument facets, JavaScript and Python numeric guards, the Protected rule, hash and
predicate results (`non_content`), and the other published samples.

## 4. Decisions

- **D-1 Policy first, then the request.** The false positive is fixed where the unsupported step
  is, in policy, and that fix is checked offline on the saved run with request bytes unchanged
  ([first comparison](../evaluation/command-bypass-support-results.md#policy-only-comparison)).
  The request-side changes came second, at the owner's direction, and are checked by the paid run.
- **D-2 A binding establishes the path, not the consequence.** The check runs after the bypass is
  bound to a guarded path of the shell facet, whether the scanner bound the single path or the
  model cited one of several. It reads only the bound path. A verified citation of a limited
  sibling does not confirm.
- **D-3 The scanner lists characters only where it holds them exactly.** Each listing was checked
  against PHP 8.6.
  - `numeric_string`: passed `is_numeric`. Digits, a sign, a point, an exponent marker and leading
    or trailing whitespace (space, tab, line feed, carriage return, vertical tab, form feed).
  - `digits`: passed `ctype_digit`. The digits 0-9.
  - `number`: converted by `intval`, `floatval`, `doubleval` or an int or float cast. The text of
    a number, or `INF` or `NAN`; no whitespace.
  - A regular-expression capture classified `explicit_alphabet` with a complete listing. Python
    patterns that also accept unlisted Unicode do not qualify.

  A path that joins differently checked values has no class. Hash and predicate results
  (`non_content`) have none either: `md5($v, true)` is raw bytes. Every unlisted guard stays the
  model's call as before.
- **D-4 What counts as carrying command text.** On an unquoted POSIX shell line: a redirection
  character, or a separator (`;`, `&`, `|`, line break) or command substitution together with
  letters to name a command. A numeric value has no name-forming letters. A separator alone starts
  a second command whose words come from the same characters, so the request picks among names
  that already exist and writes no text of its own. Measured on the PC-CMD-02 guard: `1⏎. 2.3.4`
  passes and runs the shell's `.` builtin on a file named `2.3.4`; `1⏎.1.1.1` passes and fails
  with "command not found".
- **D-5 Review, not Protected.** The limit withholds a finding. It never creates protection:
  Protected still needs the model's protected answers on a fully guarded facet with complete
  coverage. An unsupported bypass discharges nothing and records no scanner-bound citation.
- **D-6 The class is extraction-only.** `CommandPath.Class` is not serialised, like
  `ValueTransform.Regex`. The path reason words it for the model.
- **D-7 The path cites its check.** A PHP numeric path's control is the branch condition or the
  conversion, not the command operand, so the guard contract attaches to the evidence the path
  names and a conversion with no enclosing condition now gets its contract. Its reason replaces
  "cannot carry shell syntax", which contradicted the `is_numeric` contract about whitespace, with
  the class's characters and what they can do. Policy and the reason read one listing.
- **D-8 The question states the claim.** `guard_bypass` now asks whether an accepted value adds
  command text of the request's choosing, says a line or word break alone is not a bypass, and
  drops "requires naming such a value". The four choices keep their names, so answers, reports and
  policy vocabulary are unchanged. The protocol is `command-components-v5`. The other four
  questions are unchanged.
- **D-9 Protection keeps its residue.** When a record is Protected for the claim and a listed
  shell path can still break the command, the reason ends with a `Hardening:` note. The status is
  unchanged: the note needs a file the request did not write to matter.

  **Rejected.** A probability floor on the bypass answer: it would follow request wording, and a
  confident wrong answer would still confirm. A new choice for "only a break": it changes the
  answer vocabulary in every report for one case the reworded `no_bypass` already covers.
  Reporting the line break as a practice finding: a practice finding on a keyed protected control
  is a false positive against the key.

This narrows close-findings-gaps D-1 and AC1: a single guarded path still binds a bypass to itself,
and the record is Confirmed unless the path's listed characters cannot carry it.

## 5. Acceptance criteria

1. **AC1.** With stub answers `vulnerable` and `bypass_identified`, the PC-CMD-02 shape and a
   hostname-alphabet capture are `needs_evidence` with `command_bypass_unsupported`, no
   `implied_single_path` resolution and nothing model-resolved. A capture whose alphabet holds `;`
   and letters is Confirmed with the implied resolution. A guard with no contract stays
   `command_guard_semantics_unknown`.
2. **AC2.** On a record with a numeric path and a separator-capture path, a verified citation of
   the capture path is Confirmed, and a verified citation of the numeric path is Review.
3. **AC3.** The PC-CMD-02 shape with `protected`, `no_bypass` and `complete` is Protected, and its
   reason carries the `Hardening:` note. A `ctype_digit` path carries none.
4. **AC4.** With the policy change alone, `TestReplaySavedRun` on DVWA `run-729503128` changes
   exactly one status, the PC-CMD-02 record at line 26, to `needs_evidence`; every request digest
   matches. Juice Shop `run-2202945286` replays with no change.
5. **AC5.** An `is_numeric` condition, a rejecting `ctype_digit` branch and an `intval` conversion
   each give a path that cites that check once, with its class, reason and guard contract. A hash
   result has no class and is not limited.
6. **AC6.** With the request changes, the saved DVWA run's 173 non-command assessments and the
   saved Juice Shop run replay exactly. Only command records change request digest: 17 in the DVWA
   run and 33 of 33 in the architecture baseline, with no other kind.
7. **AC7.** One paid DVWA run at the pin: zero protected controls present as findings, all 11
   keyed positives are Confirmed, no provider failure, and every completed assessment replays
   exactly.
8. **AC8.** `gofmt -l cmd internal` prints nothing; `go vet ./...`, `go build ./...` and
   `go test -race ./... -count=1` pass.

## 6. Definition of done

- [x] AC1–AC6 and AC8 verified offline, with evidence in the
  [results](../evaluation/command-bypass-support-results.md).
- [x] AC7 verified on the paid run `run-2645224166` and the DVWA sample refreshed.
- [x] The analysis guide states the rule.
- [ ] Owner review.

## 7. Open questions

- **OQ-1.** Should a guard the scanner lists as limited also be required before a record is
  Protected? Today Protected rests on the model's answers plus the guarded-path facts. This
  contract leaves it unchanged.
- **OQ-2.** The reworded question is sent with every command record in every language, and only
  DVWA was re-judged. Is a live check of the JavaScript and Python samples with guarded command
  paths (Node.js Goof, vuln-nextjs) wanted before merge?
