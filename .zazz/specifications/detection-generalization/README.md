# Detection generalization — series index

**Draft for owner review. Nothing here is approved or implemented.**

Ways to improve Code Scan's detection in general, one specification per capability, ordered by expected
value.

| Document | Owns |
|---|---|
| This index | Order, ranking, what has no specification, owner decisions, change log |
| [Contract](contract.md) | Invariants, gates, held-out protocol, paid runs, stop procedure, agent rules |
| [Delivery plan](delivery-plan.md) | Worktrees, branch names, start conditions, stack, checks |
| [Research](../../evaluation/detection-generalization-research.md), [strategy](../../evaluation/detection-generalization-strategy.md) | Evidence |

## 1. Index

Numbers are stable names. **The order is the first column.**

| Order | No. | Specification | Effort | Depends on | Expected effect |
|---:|---:|---|---|---|---|
| 0 | 00 | [Operation inventory experiment](00-operation-inventory.md) | S, offline | — | A decision: may replace producers in 06 to 10 |
| 1 | 02 | [Handler checks as evidence](02-handler-checks.md) | M | — | Correct in-handler checks become Protected, wrong ones stay findings |
| 2 | 04 | [Local middleware as evidence](04-middleware-checks.md) | S | 02 | An application's own access check can be judged |
| — | 03 | [SQL calls without a contract](03-sql-calls.md) | M to L | — | **Stopped and reverted** 2026-11-25, [results](../../evaluation/detection-generalization-results/03.md) |
| — | 14 | [SQL calls, redesigned](14-sql-calls-redesign.md) | S, then M | — | **Stopped at its probe and dropped** 2026-11-25, [results](../../evaluation/detection-generalization-results/14.md) |
| 4 | 01 | [Storage identity across module forms](01-storage-identity.md) | S to M | 02 and 04 to merge | Four families record on CommonJS, default-export and `define` projects |
| 5 | 12 | [Operation families on every HTTP entry](12-http-entries.md) | M to L | 02, 04 | Authorization, mass assignment and enumeration beyond Express |
| 6 | 13 | [Storage calls without a contract](13-storage-calls.md) | M to L | 02, 03, 04, 12 | State changes through any storage library |
| 7 | 05 | [Record selection through several steps](05-record-selection.md) | M | — | Writes on a record reached through more than one lookup |
| 8 | 06 | [Ownership on create](06-create-ownership.md) | M | 01, 02 | Records stored under an identity the request chose |
| 9 | 07 | [Response disclosure](07-response-disclosure.md) | M | 01 | Credential fields or request-chosen properties in a response |
| 10 | 08 | [Credential cookie settings](08-credential-cookies.md) | S | — | Script-readable or insecure session cookies outside session libraries |
| 11 | 09 | [Credentialed cross-origin reads](09-cross-origin.md) | S | — | Origin reflection with credentials, and script-readable responses |
| 12 | 10 | [Proof of a credential change](10-credential-change.md) | M | 05 | Password writes whose only proof is a reusable stored value |
| 13 | 11 | [Rejection that does not stop](11-rejection-without-stop.md) | S | 04 | A check that answers and lets the operation run |

## 2. Ranking

Value is P × gain. **P** is the probability that the capability generalizes beyond the samples. **Gain** is
1 to 5: how many applications and records it would improve. Both are **judgments**. Evidence is measured and
is in the linked notes.

The order is not value alone. **Precision before reach**
([contract](contract.md#7-detection-and-false-positive-accuracy-must-not-fall)): what lets the model clear
correct code (02, 04) comes before what adds records (01, 12, 13). Ties go to lower effort and lower
false-positive risk.

| No. | P | Gain | Value | False-positive risk | Evidence behind P | What P still assumes |
|---:|---:|---:|---:|---|---|---|
| 02 | 0.80 | 4 | 3.2 | Lowers it | 49 answering-and-exiting arms in four other development samples; 7 of 10 handler requests omit the handler; probe pairs recorded alike | The model uses the facts. Two earlier facts did not move answers |
| 04 | 0.65 | 3 | 2.0 | Lowers it | 21 Juice Shop and 3 nodejs-goof entries have access `unresolved`; the body is not sent | Other apps use local middleware as much |
| 03 | 0.60 | 5 | 3.0 | Medium | 16 of 19 driver forms unrecorded or unsendable | A model answers about a driver from the import and call; judged evidence is missing, and earlier model resolution moved few records |
| 01 | 0.90 | 4 | 3.6 | High without 02 and 04, medium after: it adds records on new projects | 8 of 12 ordinary definition forms unrecorded; nodejs-goof (CommonJS) has no such record | Real projects use these forms at similar rates |
| 12 | 0.80 | 4 | 3.2 | High without 02 and 04, medium after | The same update and create that record on Express record nothing on Next.js or Fastify (probe); Express-only tests in the producers; 150 Next.js route entries in two samples have no record of these families | Existing entry contexts hold what the producers need |
| 13 | 0.50 | 5 | 2.5 | Medium to high | Prisma update, create and delete, and a bound SQL update, record no authorization claim (probe) | 03's mechanism works on storage too. Earlier model resolution moved few records: 10 blockers on 64 sent |
| 05 | 0.60 | 3 | 1.8 | Low | Probe pair p5 and p5b | Multi-step selection is common |
| 06 | 0.60 | 3 | 1.8 | Medium to high | Two probe forms unrecorded; 2 create calls in one other development sample, so P is mostly judgment | Identity fields can be established without names |
| 07 | 0.50 | 3 | 1.5 | Medium | Probe p9 and p9b; 276 response sends in five development samples | A credential field can be linked to the response |
| 08 | 0.60 | 2 | 1.2 | Low | `res.cookie` in one of five development samples, a session library in two | The credential role of a cookie is provable |
| 09 | 0.50 | 2 | 1.0 | Medium | Origin policy in two of five development samples | Credential facts are joined correctly |
| 10 | 0.50 | 2 | 1.0 | Medium | One Juice Shop row, one probe | Recovery forms are similar across apps |
| 11 | 0.30 | 2 | 0.6 | Low | **None outside Juice Shop**: 0 in four other development samples | The defect occurs in real code. Known in general, not seen here |

## 3. No specification

| Gap | Reason |
|---|---|
| `UPLOAD-01` upload size | Not a defect as written: the server enforces a limit. Use it as a control |
| `UPLOAD-02` upload type | Nothing is stored. The general form is a client rule the server does not enforce |
| `VALID-01`, the repeat half of `VALID-02` | Business rules stated only in the client. Reading them needs client-to-server field links for each framework; low value, and client hints are not policy |
| `AUTHZ-10` transformed selector | Visible, rare. It needs a record per caller-scoped read |
| `XSS-09` and file keys | Three records in ten samples; Review is right until a writer is linked |
| "Guessable" in `RESET-01` | Not a source fact. Spec 10 states only that the proof is reusable |
| `CONF-05` as a vulnerability | Open origin without credentials is a choice. Spec 09 records the facts |
| Entry-level review by the model | Deferred: [option F](../../evaluation/detection-generalization-strategy.md#4-options). Needs a paid experiment |
| Upload bytes after memory storage | Low value until a follow-on store is common in samples |
| Entries beyond HTTP: queues, jobs, webhooks, events | In the owner's proposal. No local sample has one to measure. Needs a common entry model and an application that uses it; add a specification when the pool has one |
| In-memory collections and object spread into them | Seen in one demonstration application. Real applications store elsewhere; 13 covers those |
| Environment and deployment guards by enumeration | The known miss is fixed. Reading conditions as facts in other families follows if 02 passes |
| Python and PHP equivalents | The series is JavaScript first, where the gap is measured. 02.1's fields are for all three. Decide after 02 and 04 |
| Typed graph store; scanner rules that decide | Tried and removed; contrary to the design intent |
| The 17 rows with no analyzer (18 with the committed key) | Outside this brief: new analyzers |

## 4. Open questions for the owner

- **OQ-1** Answered by the owner, 2026-11-25: branches start from `stage` after PR 51 merges. No branch or
  worktree is created before that, and each is created only when the owner asks.
- **OQ-2** Partly answered, 2026-11-25: the owner finds the pool; a separate session writes the keys and
  another checks them ([contract §3](contract.md#3-held-out-protocol)). Open: the remaining applications.
  The key session starts on the owner's word, once the applications it keys are on disk.
- **OQ-3** Answered by the owner, 2026-11-25: spec 02 defines the shared check fields (condition, values
  read, write between check and use), independent of language. The injection false-positive work reuses
  them.
- **OQ-4** Answered by the owner, 2026-11-25: the caps are acceptable and may be high; spend judiciously
  ([contract §4](contract.md#4-paid-checkpoints)). Each run still asks first.
- **OQ-5** Owner, 2026-11-25: paid runs are kept for when they are needed. Read as: the entry-review
  experiment waits for spec 00 and runs only if 00 leaves its question open. It still asks first.
- **OQ-6** Answered by the owner, 2026-11-25: the seven rows are corrected in PR 51, by that session.
- **OQ-7** Answered by the owner, 2026-11-25 (correcting an earlier answer): make the accuracy rules
  stricter, and minimize false positives but not at the expense of true positives. [Contract
  §7](contract.md#7-detection-and-false-positive-accuracy-must-not-fall) is rewritten for that.

## 5. Implementation and review change log

### 2026-11-25 — 14 approved, then stopped

The owner approved 14 with two changes. Its probe gave 4 of 8 drivers and its stop rule fired. 13 starts only if 03
passed, which it did not; the owner decides what becomes of 13.
[Results](../../evaluation/detection-generalization-results/14.md).

### 2026-11-25 — 03 stopped, 14 written

The owner let 03 start before 00. It stopped at its first paid checkpoint and was reverted. 14 is its one redesign,
a draft.

### 2026-11-25 — Accuracy rules made stricter

The owner asked for stricter rules, with true positives first. Contract §7 is rewritten; spec 02's policy
item (6) is narrowed so that it cannot hold back a true finding. A change to §7 needs the owner.

### 2026-11-25 — Second pass

Reread against the owner's proposal. Added 12 and 13, and the accuracy rules of contract §7. Moved 01 behind
02 and 04. Replaced precision pass marks of 75 and 80 percent with contract §7. Shared protocols must be
selected per record.

### 2026-11-25 — Documents join PR 51

The owner put the series documents in PR 51. Implementation starts after it merges, from the two lane
worktrees.

### 2026-11-25 — OQ-6 answered, delivery map added

The key rows are corrected in PR 51. The owner asked for two reusable worktrees and named branches.

### 2026-11-25 — OQ-5 answered

The entry-review experiment waits for spec 00. Paid runs are frugal and used when needed.

### 2026-11-25 — OQ-4 answered

Caps accepted and may be high. The contract gains the spending rules.

### 2026-11-25 — OQ-2 partly answered

Keys are written by a separate session, and NodeGoat is the first pool application.

### 2026-11-25 — OQ-3 answered

Spec 02 defines the shared check fields, as its first pull request.

### 2026-11-25 — oss-oopssec-store reserved

The owner held it out as a control. It left the development samples and the ranking evidence. Ties go to
lower risk, so record selection and ownership on create changed places (05 and 06).

### 2026-11-25 — OQ-1 answered

The owner chose `stage` after PR 51 merges as the start of the series branches. Nothing else is approved.
