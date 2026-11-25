# Detection generalization 14 — SQL calls without a contract, redesigned

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Stopped at its probe and dropped, 2026-11-25.**
- **Replaces** [03](03-sql-calls.md), stopped at checkpoint 1 and reverted
  ([results](../../evaluation/detection-generalization-results/03.md)). This is the one redesign that
  [contract §5](contract.md#5-stop-procedure) allows. If it stops, the capability is dropped.
- **Depends on** nothing. **Effort** small for the probe, medium if it passes. **Review artifact** one draft PR,
  with the probe result even when it stops.

## Capability

As 03: a string built from request data that reads as SQL and reaches a call on a package with no written
contract becomes a record, and the model says what the call does. Unchanged from 03: the candidate rule, the
citation check, no Protected and no dismissal, Review when unresolved. Changed: **how the model is asked**, and
that the asking is tested **before** any product code returns.

## Why 03 failed

Read in a full saved request, not only the added question. Five parts of the request forbid or contradict an
answer from package knowledge:

| # | Part of the request | Says |
|---:|---|---|
| 1 | Shared `resolve_*` instruction (`judge/client.go`) | "answer each from the supplied source alone" |
| 2 | Shared instruction | "Assess only the supplied source-backed use"; the API contract applies only with verified evidence |
| 3 | `injection_protection` question | Vulnerable needs a "verified library contract"; a missing API is `unknown` |
| 4 | JavaScript guidelines | Do not invent a binding |
| 5 | The record's own facts | The contract text says nothing is established, and a blocking gap says the binding is unverified |

Part 3 also explains why the two resolved calls still had `injection_protection` `unknown`: one request asks two
questions and the second could not rest on the first.

## Semantics

**S-1. Scope of package knowledge.** For this question only, and only on a record with the package contract, the
request says that the model may use what it knows of the **named package's published API**. Every other question
keeps the rule of the supplied source.

**S-2. Conditional injection.** On such a record, `injection_protection` is asked under a stated assumption: the
argument in slot `sql_text` runs as SQL text. Whether it does is the other question. The scanner joins the two:
a finding needs a verified `executes` or `prepares_then_executes` **and** `vulnerable`.

**S-3. Unknown packages.** The question says that a package the model does not know is `cannot_tell`, and that a
name, a method name or the look of the text is not knowledge.

**S-4. Per record.** The text of S-1 to S-3 is chosen by the record's contract, and only when the request asks the
package-call question. A request of such a record carries a variant of the shared instruction, of the
`injection_protection` question and of its choice texts. No instruction, family question or protocol of any other
record changes a byte (contract §1.6, §1.7).

Outcomes, citation and report text are those of 03. The "values argument" question of 03 is dropped: no outcome
uses it.

## Scope

| Phase | Path | Change |
|---|---|---|
| 0, probe | Test-only overlay in the scratch area | Built from the reverted 03 code with S-1 to S-4. Not merged |
| 1, only if 0 passes | The paths of 03, restored from `ed257a7` and `df02634`; `judge/client.go`, `judge/sql_call.go` | Restored, then S-1 to S-4 |

Out of scope: as 03; the guidelines; any change to the shared instruction or family questions **of another record**.

## Decisions

- **D-1. Probe before code.** *Why:* stubbed answers cannot show how a model reads a request.
- **D-2. Read the whole request.** A reviewer reads one complete request of each arm before it is sent and lists
  every sentence that bears on the question. *Why:* 03 tested its own question and missed the one around it.
- **D-3. Conditional question, not a second request.** *Why:* requests stay bounded. *Rejected:* a follow-up that
  asks injection after the call is resolved; it doubles the requests of every such record.
- **D-4. Made-up packages are controls.** *Why:* a model that answers `executes` for a package that does not exist
  is reading names. A name may not decide (contract §1.1).
- **D-5. New forms.** The 25 fixtures of 03 are spent and are not used as evidence.
- **D-6. No threshold on probabilities.** *Why:* confidence is not evidence.

- **D-7. Package knowledge is accepted for findings only** (owner, 2026-11-25). It never gives Protected or a dismissal,
  and the model-resolved mark stays visible in the report. This is a stated exception to contract §1.3 for this
  question on this contract: the citation proves which package it is, not that the knowledge is right, nor the version.
- **D-8. Safe construction is a control.** *Why:* S-2 could push safe code to `vulnerable` and no other group would show
  it. The safe forms are tricky on purpose.

## Probe forms

All are new and none was sent to a model. All 18 record offline with the overlay, each blocked only by
`sink_binding_unverified`. A driver of the probe is not an unseen driver at held-out.

| Group | Forms | Right answer |
|---|---|---|
| Drivers, 8 | mariadb, Neon, PlanetScale, Snowflake, BigQuery, pg-promise, ibm_db, Databricks | `executes` or `prepares_then_executes` |
| Lookalikes, 5 | SendGrid text, Slack message, node-sql-parser, highlight.js, ioredis value | Anything but those two |
| Made up, 2 | A neutral name and a database-like name | `cannot_tell` |
| Safe construction, 3 | A `Number` result (mariadb), an allow-list guard (pg-promise), a hex digest in quotes (Snowflake) | `injection_protection` not `vulnerable` |

`node-sql-parser` is the hard lookalike: it is a SQL package that parses and runs nothing.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | A reviewer's list of every bearing sentence in one full request of each arm, with no contradiction left | Results |
| AC2 | Probe passes | Results |
| AC3 | Restored offline tests of 03 pass, with S-2 in the policy matrix: call answer without `vulnerable`, and `vulnerable` without a verified call, are both Review | `go test ./scan/internal/langjs -run TestSQLUnknownCall`, `go test ./scan/internal/judge -run TestSQLCall` |
| AC4 | A request of any other record is byte-identical (G2), nine samples and the reserved control by script | Comparison |
| AC5 | Held-out passes | Results |
| AC6 | The documents 03 names | `doc-check` |
| AC7 | G1, G3 to G7 | Commands |

## Paid checkpoints

Each asks first (contract §4).

1. **Probe.** 18 forms, two repeats: 36 requests, hard stop 42. Pass, in **both** repeats: at least 7 of 8 drivers
   right with a verified citation and `vulnerable`; no lookalike and no made-up package answered `executes` or
   `prepares_then_executes`; no safe form answered `vulnerable`.
2. **Held-out**, only after phase 1. As 03: unused applications, cap 60, at least 80% of keyed positives Confirmed
   and none missed without its blocking fact; no keyed control Confirmed.

## Stop rule

Stop and drop the capability when, in either repeat, fewer than 6 of 8 drivers are right, or any lookalike or
made-up package is answered as running SQL, or the repeats disagree on more than two forms. Between 6 and 7 drivers
the owner decides. A safe form answered `vulnerable` fails the pass; when nothing else failed, contract §5's last
paragraph applies. The wording is not changed after the first probe request.

## Open questions, answered by the owner 2026-11-25

- **OQ-1. Branch.** `detgen-14-sql-calls-redesign` from `origin/stage`, started before 00 merges. It carries the two
  document commits of 03 and 14. 03 gets no PR of its own; its branch is kept.
- **OQ-2. Held-out applications.** Found and keyed by the key session only after the probe passes. The merge waits for
  them: a driver absent from all fixtures and forms, an ORM raw call, and one ordinary application. NodeGoat fits none.
- **OQ-3. Package knowledge as evidence.** Accepted as D-7.

## Loop

1. Commit a checkpoint. 2. Change. 3. Offline gates. 4. Read a full request. 5. Ask, then run the smallest paid
check that can decide. 6. Score against criteria written before the first request. 7. Keep, or `git revert` and
record.

## First step

AC1 on overlay requests, with no request sent.

## Implementation and review change log

### 2026-11-25 — Written after 03 stopped

The owner asked for the redesign. Nothing is approved.

### 2026-11-25 — Approved

The owner approved 14 with two changes: variants of the shared instruction and of `injection_protection` are allowed on
package records (S-4), and three safe construction forms join the probe (36 requests, hard stop 42). AC1 is in the
[results](../../evaluation/detection-generalization-results/14.md).

### 2026-11-25 — Stopped at the probe

4 of 8 drivers in repeat 1; repeat 2 not run. Dropped by the stop rule: 14 was the one redesign. No product code existed.
[Results](../../evaluation/detection-generalization-results/14.md).
