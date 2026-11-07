# Juice Shop command-execution classification reference

Source-reviewed 2026-11-07 at pinned Juice Shop revision
`f189f521266f42c6bd05884468292000cee852ed` (v20.3.0). The original checkout remains read-only;
no target, test, exploit or scanner execution was performed for this review.

[Challenge inventory](README.md) · [Registry](expected-challenges.jsonl) ·
[Command analyzer contract](../../specifications/command-injection.md)

## Source-reviewed cases

| Case | Documentation and actual source | Expected command-analyzer treatment |
| --- | --- | --- |
| JS-CMDI-SSTI-BOUNDARY | `data/static/challenges.yml:1019–1033` documents SSTi with arbitrary command execution. `server.ts:694–695` registers GET/POST `/profile`. `routes/userProfile.ts:52–65` reads a stored username and evaluates extracted JavaScript on the enabled challenge branch; template assembly/compile/render continues at73–101. `test/cypress/e2e/profile.spec.ts:48–60` documents an injected child_process.exec call inside a payload string | Known code/template-injection concern with a command-execution consequence, not a fixed request-to-child_process command operand in the application's AST. Do not manufacture an imported process call from a test string or report the flow Protected. Separate code/SSTI coverage remains explicit |
| JS-CMDI-RCE-DOS-BOUNDARY | `rceChallenge` and `rceOccupyChallenge` describe JavaScript execution/DoS. `routes/b2bOrder.ts:16–31` supplies request body orderLinesData to notevil evaluation inside vm.runInContext, with timeout handling | A code-execution/sandbox concern, not an established shell-command construction. Names such as RCE or NoSQL command do not prove OS-command injection |
| JS-CMDI-PACKAGING-CONSTANT | `scripts/package.mjs:11–20` imports execSync and invokes a fixed `npm root -g` while packaging | No request-derived command-injection finding; this is a build-time constant command, not a request handler. Record normal scanner file-extension/default exclusions |

The review searched repository JS/TS/MJS/CJS source for core child_process bindings and common
process/shell-library spellings, and inspected the documented SSTi/RCE source/test paths above.
No direct request-to-process-API positive was independently established by that review. This is a
bounded source classification, not proof that all dynamic/dependency behavior is command-safe.
In particular, the profile code-execution concern MUST NOT be converted into a protected record or
removed from the comparison merely because direct command injection is this implementation's scope.

## Final full-scan comparison

The command analyzer's current direct positive set for this pin is empty, with the build-time
constant as a negative and the code/template-injection cases as explicit cross-class limitations.
The full judged scan is still mandatory: verify no unsupported command-injection positives are
invented, keep source/entry evidence and other analyzer findings visible, and report the profile/RCE
coverage boundary in the review summary. These independently reviewed dispositions are not based
on new scanner/model output and must not be silently changed to match it.

Before final evaluation, recheck the pin/hashes and review additional documented command-execution
leads. A newly established direct command positive expands the expected matrix and must be fixed;
it cannot be ignored to preserve a zero-positive target. Dependency/runtime exploitation and code/
template-injection support must remain accurately classified, without claiming they were detected
by the direct Command Injection Analyzer.

## Reviewed source hashes

| File | SHA-256 |
| --- | --- |
| `data/static/challenges.yml` | `a37357f5d4daa0981f87fa3af9817de140d87777732bb1bbbd0fbf8b5bf7d218` |
| `server.ts` | `1aef4d60cbdfb3458a25610d017a678ab4d69fc835bb8b592db9a13aceb20cb1` |
| `routes/userProfile.ts` | `07251f3d0dd9f4c530da60e3911091d8ff1bded650f72c31cbee499093979b39` |
| `routes/b2bOrder.ts` | `5e4affbd4072fae7d98737ef2b78cabcd039b157fec879d59308e5c0fde32f48` |
| `test/cypress/e2e/profile.spec.ts` | `de5a8399ce82ee380defcffaab6bfa18a1dff4c08a6e32e3f93fcfcd52cc6edd` |
| `scripts/package.mjs` | `f17e74f818a0498aac3bc6f36dbdec35401d36c4a8b743eb97e12def66ff1676` |
