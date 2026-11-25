# Detection generalization — series contract

**Draft for owner review. Nothing here is approved or implemented.**

This document owns what the specifications of the series share: the rules, the gates, the held-out protocol
and the stop procedure. Each capability has its own specification, small enough to implement, test, review
and revert alone.

- **Why** [Research note](../../evaluation/detection-generalization-research.md) and [strategy
  options](../../evaluation/detection-generalization-strategy.md).
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

## 2. Regression gates

Every specification meets these before its first paid checkpoint and again at the end. Base is the commit
the branch starts from. Samples are nine local ones of the
[catalog](../../project/vulnerable-sample-apps.md#applications): Juice Shop, nodejs-goof, vuln-demo-app,
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
calls have contracts and must not change. *Held-out positives and controls* for 00, 07, 08, 09 and 11, where
the rule is not tied to Express. An unchanged control shows no harm. It cannot show that a capability
generalizes.

**Already seen by the author of this series:** record counts per family, storage blocker counts, entry and
source sizes, counts of arms, awaits, creates and sends, package names, and lines 45 to 62 of one client
file. No keyed row was read for design. The counts were removed from the ranking evidence in the
[index](README.md#2-ranking); the totals in the two notes still include them.

## 4. Paid checkpoints

Each paid run needs the owner's word before it starts, whatever this series says. Provider, model, rates and
transport rules are those of [AGENTS.md](../../../AGENTS.md#credentials-and-live-model-calls). An offline
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
- Fixtures before samples, samples before held-out applications. A failed step ends the sequence.
- No rerun in search of a better answer. A repeat is planned before the first answer is seen.
- Full sample scans only at the end of a specification, at most two.

## 5. Stop procedure

Each specification has a stop rule with numbers. When it fires:

1. Stop. Do not tune the rule, the wording, a list or a threshold until the sample passes.
2. Record the result and the first stage at which the capability failed.
3. Propose to the owner: drop, or redesign with a new specification and **unused** held-out applications.
   One redesign at most.
4. Revert the code unless an intermediate part passes every gate alone and the owner keeps it.

A result that passes only on an application seen during development counts as a failure.

## 6. Agent rules, standards and documents

- [AGENTS.md](../../../AGENTS.md) and the [execution discipline](../../docs/agent-execution-discipline.md)
  apply. One Lead Agent; a separate key agent and verifier. Two lane worktrees ([plan](delivery-plan.md)),
  created only when the owner asks. Commit and push only when the owner asks. Agents never merge.
- Standards for every specification: [code-structure.md](../../standards/code-structure.md),
  [testing.md](../../standards/testing.md), [pr-process.md](../../standards/pr-process.md),
  [docs-hygiene.md](../../standards/docs-hygiene.md), [spec-hygiene.md](../../standards/spec-hygiene.md).
  Repeat the index lookup before code.
- Required reading for every specification: the two notes above, [evidence and
  claims](../../architecture/evidence-and-claims.md), [calibration
  pairs](../../../docs/scan/analysis/calibration.md#regression-pairs), and the analysis guide of the family.
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
evidence in the results; held-out results reported with counts, misses included; documents updated; verifier
PASS; draft PR to `stage` with the invariants and the stop-rule result in its body.

**Run log.** Append-only: standards lookup, answers, phase results, deviations, evidence locations,
findings, verifier report. Read it whole at session start.

**Implementation prompt.**

```text
Implement .zazz/specifications/detection-generalization/<specification> in the assigned sibling worktree. Read AGENTS.md, the
series contract.md and delivery-plan.md beside it, the specification and the run log first. Resolve its open
questions with the owner before code. Start with its first failing test. Keep the semantics, scope,
criteria and stop rule as the contract; on any halt condition or stop rule, stop and report. Make no paid
call, commit or push without the owner's word. Do not look at a held-out application before the
checkpoint that uses it. Finish with a fresh verifier and a draft PR to stage; never merge.
```
