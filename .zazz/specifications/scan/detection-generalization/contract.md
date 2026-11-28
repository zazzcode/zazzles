# Detection generalization — series contract

**Draft for owner review. Nothing here is approved or implemented.**

This document owns what the specifications of the series share: the rules, the gates, the held-out protocol
and the stop procedure. Each capability has its own specification, small enough to implement, test, review
and revert alone.

- **Why** [Research note](../../../evaluation/detection-generalization-research.md) and [strategy
  options](../../../evaluation/detection-generalization-strategy.md).
- **Feature** Detection generalization in Code Scan. **Milestone** N/A.
- **Deliverable Owner** the human user. **Integration branch** `stage`, PR review only.
- **Review shape** one branch and one PR per specification, except 02 (two). Two reusable lane worktrees, at
  the owner's direction. PRs start from `stage`; the only stack is 02.2 on 02.1. *Rejected:* one stack (a
  failed lower branch blocks the rest), one milestone PR (cannot be reverted by part), and a worktree per
  specification (most change the same authorization code).
- **Delivery plan** [Lanes, worktrees, branch names, order and checks](delivery-plan.md).
- **Run log** `.zazz/ephemeral/detection-generalization-run-log.md`, one per lane, one section per
  specification.
- **Drafted** 2026-11-25 from `021bad2`.

## 1. Shared invariants

1. No rule names an application's identifier, route, field, message or path. A library or framework name is
   allowed with its documentation cited.
2. The scanner records facts and the decision model judges. No scanner rule decides a verdict, and none
   suppresses a record on a guard.
3. A finding and a Protected outcome cite recorded source evidence. Missing evidence stays unknown.
4. Existing analyzers are extended. No specification adds an analyzer family.
5. Requests replay exactly. No provider or model fallback. Report fields are additive.
6. A request of a family or language the specification does not name stays byte-identical.
7. A protocol, question or instruction change is selected **per record** by its contract, never for a whole
   family. Families are shared by languages: authorization, account, SQL and configuration serve PHP too. If
   a change cannot be kept to its own records, halt.
8. **Precision before reach.** A specification that adds records to a family merges only after the evidence
   that lets the model clear correct code is in `stage` (02 and 04 for authorization).

## 2. Regression gates

Every specification meets these before its first paid checkpoint and again at the end. Base is the commit
the branch starts from. Samples are nine local ones of the
[catalog](../../../project/vulnerable-sample-apps.md#applications): Juice Shop, nodejs-goof, vuln-demo-app,
vulnerable-typescript-app, vuln-nextjs, DVWA, vuln-symfony, VulnPy and ThreatByte. Pins go in the results.

| Gate | Requirement |
|---|---|
| G1 | Every base record identifier is present in the offline scan of every sample. Added and changed records are listed with the reason |
| G2 | Request digests of untouched families and languages equal base, by `judge.Preview` on fixtures and samples |
| G3 | The recall-inventory checker floor holds; no keyed positive loses a candidate |
| G4 | Saved reports and traces of base load, export and replay |
| G5 | Offline scan time of Juice Shop within 10% of base on the same machine |
| G6 | `gofmt -l cmd scan` prints nothing; `go vet ./...`, `go build ./...`, `go test -race ./... -count=1` pass |
| G7 | Records added per sample are within the bound the specification states |

## 3. Held-out protocol

**Owner decision, 2026-11-27: held-out application runs are no longer required** ("remove the need for held out app
runs... we only have what we have"). The pool has no application beyond the reserved control. A specification is
accepted on its fixtures, the regression gates of §2, the reserved control's counts (§3.1, unchanged-control role) and
its acceptance runs on the development samples. Its results say plainly that accuracy on applications not used in
development is not measured. A held-out criterion in a specification of this series is replaced by the reserved-control
counts. The rest of this section stays as the protocol to use if the owner adds applications.

- A **pool** of applications no session has used for development. The owner is finding them. Needed: five
  that contain vulnerabilities and three ordinary ones, not all Express. Between them: Sequelize and
  Mongoose in CommonJS; checks inside handlers; the application's own access middleware; a SQL driver with
  no contract here; a raw call of an ORM; its own token cookie; a credentialed origin policy; a recovery
  flow.
- **Pool application 1: OWASP NodeGoat** (owner, 2026-11-25, `https://github.com/OWASP/NodeGoat`). Revision
  pinned by the key agent. No repository document used it before this series. It is public and well known,
  so the model and the author of this series may recall it from training; its results need the renamed copy
  beside them, and it does not stand alone as evidence. The author has not opened its source or scanned it.
- **Reserved control: oss-oopssec-store** (owner, 2026-11-25), under §3.1.
- A **key agent**, in its own session (owner, 2026-11-25), assigns applications to specifications, writes
  each key from source before any scan of it, and does not implement. A second agent checks the key without
  scanner output. The key is stored under `.zazz/evaluation/corpus/detection-generalization/` and changes
  only by owner decision.
- An implementer sees an application and its key only at the checkpoint that uses it. Reading one family's
  rows spends that application for that family only.
- Each key has positives, correct controls, and places not decidable from source.
- One run per series uses a **renamed copy** of a vulnerable sample (identifiers, routes, paths and messages
  changed, comments removed). Outcomes should not move. It tests name reliance and recall of a public sample
  by the model.
- Juice Shop rows are read last, as an acceptance check. They are not a design input and a specification
  that meets every other criterion is not failed by them.

### 3.1 The reserved control

`oss-oopssec-store` (Next.js, Prisma, `2d530ef`) is out of the development set from 2026-11-25. Agents that
design or implement do not open its source, its guide or its per-record results. A script runs the gates on
it and prints counts and pass or fail. The key agent writes the rows this series needs before any
checkpoint.

**What it can show.** It is held out by family, not as an application.

| Families | Status |
|---|---|
| SQL, path, SSRF, XSS, logging, Next.js entries | **Not held out.** A keyed development sample with its own adapter test |
| Authorization, mass assignment, account, configuration, exposure, upload | Never tuned for; zero records today |

**Roles.** *Unchanged control* for 01, 02, 04, 05, 06 and 10: their producers accept Express entries or
stores it does not use, so records and requests must not move. *False-positive control* for 03: its SQL
calls have contracts and must not change. *Held-out positives and controls* for 00, 07, 08, 09, 11, 12 and
13. An unchanged control shows no harm. It cannot show that a capability generalizes; 12 and 13 can.

**Already seen by the author of this series:** record counts per family, storage blocker counts, entry and
source sizes, counts of arms, awaits, creates and sends, package names, and lines 45 to 62 of one client
file. No keyed row was read for design. The counts were removed from the ranking evidence in the
[index](README.md#2-ranking); the totals in the two notes still include them.

## 4. Paid checkpoints

Each paid run needs the owner's word before it starts, whatever this series says. Provider, model, rates and
transport rules are those of [AGENTS.md](../../../../AGENTS.md#credentials-and-live-model-calls). An offline
plan states the exact request count first, and a plan over the stated cap halts. Arms compare the same
inputs before and after. Where an outcome is borderline, the specification states how many repeats. Results
record every request, token count, miss and disagreement.

**Judicious spending** (owner, 2026-11-25: caps may be high, and paid runs are to be chosen with care).

- A stated cap is a planning number. A plan may ask for up to twice it, with the reason, when held-out
  records or repeats need it. Cost alone does not remove a repeat that decides an outcome.
- A run names the question it answers and what each result would change. If no result would change a
  decision, it is not run.
- Offline first: facts, request previews and stubbed answers pass before any paid request.
- Send only records whose request changed, plus the named controls. Replay saved answers for the rest.
- Fixtures before samples. A failed step ends the sequence. (Held-out applications: §3, not required.)
- No rerun in search of a better answer. A repeat is planned before the first answer is seen.
- Full sample scans only at the end of a specification, at most two.

## 5. Stop procedure

Each specification has a stop rule with numbers. When it fires:

1. Stop. Do not tune the rule, the wording, a list or a threshold until the sample passes.
2. Record the result and the first stage at which the capability failed.
3. Propose to the owner: drop, or redesign with a new specification and fixtures not used before.
   One redesign at most.
4. Revert the code unless an intermediate part passes every gate alone and the owner keeps it.

A result that passes only on an application seen during development counted as a failure until the owner's decision of
2026-11-27 (§3). Development-sample results now count, labelled as such.

**A stop rule that fires only on false positives** blocks the merge and starts §7's fix first. Dropping
comes after that fix fails, or when it would cost a true finding.

## 6. Agent rules, standards and documents

- [AGENTS.md](../../../../AGENTS.md) and the [execution discipline](../../../docs/agent-execution-discipline.md)
  apply. One Lead Agent; a separate key agent and verifier. Two lane worktrees ([plan](delivery-plan.md)),
  created only when the owner asks. Commit and push only when the owner asks. Agents never merge.
- Standards for every specification: [code-structure.md](../../../standards/code-structure.md),
  [testing.md](../../../standards/testing.md), [pr-process.md](../../../standards/pr-process.md),
  [docs-hygiene.md](../../../standards/docs-hygiene.md), [spec-hygiene.md](../../../standards/spec-hygiene.md).
  Repeat the index lookup before code.
- Required reading for every specification: the two notes above, [evidence and
  claims](../../../architecture/evidence-and-claims.md), [calibration
  pairs](../../../../docs/scan/analysis/calibration.md#regression-pairs), and the analysis guide of the family.
- Documents every specification updates: the capability page and the analysis guide of each family it
  touches, the architecture document that owns the design, `.zazz/project/implementation-plan.md`, its file
  under `.zazz/evaluation/detection-generalization-results/`, `specifications/README.md` and
  `spec-index.md`. Verified by `doc-check`. Each specification names the pages.
- Scope is the paths a specification names, their tests and fixtures, and those documents. Anything else is
  a halt.

**Halt and ask** when an open question is unanswered; a gate fails for a reason not fixed in two tries; a
file outside scope is needed; a held-out key needs a change; a paid run is due; a stop rule fires; or the
same test fails three times for one cause.

**Definition of done.** Open questions answered and logged; gates G1 to G7 and every criterion verified with
evidence in the results; reserved-control counts reported, misses included; documents updated; verifier
PASS; draft PR to `stage` with the invariants and the stop-rule result in its body.

**Run log.** Append-only: standards lookup, answers, phase results, deviations, evidence locations,
findings, verifier report. Read it whole at session start.

**Implementation prompt.**

```text
Implement .zazz/specifications/scan/detection-generalization/<specification> in the assigned sibling worktree. Read AGENTS.md, the
series contract.md and delivery-plan.md beside it, the specification and the run log first. Resolve its open
questions with the owner before code. Start with its first failing test. Keep the semantics, scope,
criteria and stop rule as the contract; on any halt condition or stop rule, stop and report. Make no paid
call, commit or push without the owner's word. Do not look at a held-out application before the
checkpoint that uses it. Finish with a fresh verifier and a draft PR to stage; never merge.
```

## 7. Detection and false-positive accuracy must not fall

Owner, 2026-11-25: accuracy must not be lost; keep the rules strict; **minimize false positives, but not at
the expense of finding true positives.** These rules stand above each specification's own pass numbers.

**Priority when they pull apart:** (1) keep every true finding, (2) never mark a true one Protected, (3)
minimize false positives. A false positive is removed by better evidence that lets the model see the code is
safe. It is never removed by dropping a record, a threshold, an ignore list, a name, or moving a true
finding to Review.

**Base.** Before the first branch, an agent that did not write the first review checks every Confirmed
record and every known false positive of the judged samples, and reads a sample of Review records for true
findings left there. Then a ledger is frozen offline: every true finding (keyed or reviewed), control, known
false positive and Protected record, with request digest and outcome. State on 2026-11-25, before that
second review:

| Sample | Confirmed records | Reviewed false (records or locations) | Families with false ones |
|---|---:|---:|---|
| Juice Shop | 51 | 5 records, 4 locations | NoSQL 2 of 7, authorization 2 of 10, configuration 1 of 5 |
| vuln-nextjs | 13 | 0 | — |
| vuln-symfony | 55 | 0 | — |
| DVWA | in the ledger | 9 locations | SQL |

| Rule | Requirement |
|---|---|
| A1 True findings kept | No true finding in the ledger, keyed or not, stops being Confirmed on any sample or fixture. Review counts as lost |
| A2 Known-safe code | No control, known-safe location or Protected record becomes a finding. Known false positives may only go down |
| A3 False Protected | No true finding becomes Protected. Every new Protected record is read in source and has the same answer in three planned repeats. One false Protected stops the specification |
| A4 Changed requests | Ledger records and controls whose request changed, and every moved outcome: three planned answers before and after. Other changed requests: one. Unchanged requests are replayed, never resent |
| A5 New findings | Two agents that did not implement read every new Confirmed record. At least 95% true, and not below the family's base. Under twenty new records, at most one false |
| A6 Cumulative | The ledger is checked offline after each merge. Every two merged specifications close with one full judged scan of Juice Shop and one PHP sample |
| A7 Variance | Where repeats disagree, the worse outcome counts. Variance never excuses A1 or A3 |
| A8 Revert | Each PR reverts alone and restores the base requests, shown offline |
| A9 Review is not a place to hide | A true weakness recorded but left in Review counts as **not found**. Results list records moved into and out of Review, each with its reason |
| A10 Both sides, never averaged | Results state, per family and sample: true gained, true lost, false gained, false removed, left in Review. No single score |

**When a rule fails.** Do not merge.

- **A1 or A3:** stop. Restore the true finding, or revert.
- **A2 or A5, false positives:** first seek evidence that clears the code **in general** and loses no true
  finding. Measure the fix on code not used to design it. Do not drop a capability with true gains for a
  false positive before this is tried.
- If no such evidence is found, the owner decides with the numbers of A10. The default is not to merge.
- No rule, list, wording or threshold is added for the record that failed.
