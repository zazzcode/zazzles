# Experiment method

**Replay the saved answers through the scanner's own policy, offline.** Serve saved answers from a local stub keyed by the request
digest. On the four README applications it reproduces 387 of 403 ledger outcomes, and the other 16 are explained. So any arm is
scored by its policy outcome, free, after one paid answer per record. The [baseline ledger](../../specifications/detection-generalization/contract.md#7-detection-and-false-positive-accuracy-must-not-fall)
is the judge of true and false.

**Rules**

1. Write the criteria before the first request and do not change them. State what each result changes.
2. Ask with the exact count. One attempt, no retries, a hard stop, and prices in tokens.
3. Include a noise control: the same request with one neutral sentence. A difference smaller than that is not a result.
4. Report paired records, not only totals: lost in the arm and not in the control.
5. Pick development records by a rule, hold others back, and say which were sent before.
6. Identical requests answer identically (6 of 6), so repeats add nothing. New forms do.
7. Give each finding family and language its own row. A total hides a broken family.
8. Report what is not shown.

**Mistakes made, so they are not repeated**

- No noise control in rounds 3 and 4; round 4's "nothing is safe to drop" was noise.
- Re-encoding a request as a map moved sections, which changed arms C, V and X.
- An arm dropped evidence by a list of kinds. That list is the per-framework knowledge we want to avoid.
- Records called unused had been sent before.
- A rule on false positives had no false positive in its records, so it passed trivially. It was removed.
- The key was passed as a process argument in an early probe script; it is now in the environment.

Never use as evidence: forms the implementer wrote, or Juice Shop, vuln-nextjs, vuln-symfony and DVWA, whose records have all been
used. Held-out applications come from a separate key session ([contract §3](../../specifications/detection-generalization/contract.md#3-held-out-protocol)).
