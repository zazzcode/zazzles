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

| Order | Specification | Effort | Depends on | Expected effect |
|---:|---|---|---|---|
| 00 | [Operation inventory experiment](00-operation-inventory.md) | S, offline | — | A decision: may replace producers in 06 to 10 |
| 01 | [Storage identity across module forms](01-storage-identity.md) | S to M | — | Four families record on CommonJS, default-export and `define` projects |
| 02 | [Handler checks as evidence](02-handler-checks.md) | M | — | Correct in-handler checks become Protected, wrong ones stay findings |
| 03 | [SQL calls without a contract](03-sql-calls.md) | M to L | — | SQL injection on drivers with no written contract |
| 04 | [Local middleware as evidence](04-middleware-checks.md) | S | 02 | An application's own access check can be judged |
| 05 | [Record selection through several steps](05-record-selection.md) | M | — | Writes on a record reached through more than one lookup |
| 06 | [Ownership on create](06-create-ownership.md) | M | 01, 02 | Records stored under an identity the request chose |
| 07 | [Response disclosure](07-response-disclosure.md) | M | 01 | Credential fields or request-chosen properties in a response |
| 08 | [Credential cookie settings](08-credential-cookies.md) | S | — | Script-readable or insecure session cookies outside session libraries |
| 09 | [Credentialed cross-origin reads](09-cross-origin.md) | S | — | Origin reflection with credentials, and script-readable responses |
| 10 | [Proof of a credential change](10-credential-change.md) | M | 05 | Password writes whose only proof is a reusable stored value |
| 11 | [Rejection that does not stop](11-rejection-without-stop.md) | S | 04 | A check that answers and lets the operation run |

## 2. Ranking

Value is P × gain. **P** is the probability that the capability generalizes beyond the samples. **Gain** is
1 to 5: how many applications and records it would improve. Both are **judgments**. Evidence is measured and
is in the linked notes. Ties go to lower effort, lower false-positive risk and independence.

| Order | P | Gain | Value | False-positive risk | Evidence behind P | What P still assumes |
|---:|---:|---:|---:|---|---|---|
| 01 | 0.90 | 4 | 3.6 | Low to medium: more correct candidates to judge | 8 of 12 ordinary definition forms unrecorded; nodejs-goof (CommonJS) has no such record | Real projects use these forms at similar rates |
| 02 | 0.80 | 4 | 3.2 | Lowers it | 49 answering-and-exiting arms in four other development samples; 7 of 10 handler requests omit the handler; probe pairs recorded alike | The model uses the facts. Two earlier facts did not move answers |
| 03 | 0.65 | 5 | 3.2 | Medium | 16 of 19 driver forms unrecorded or unsendable | A model answers about a driver from the import and call; judged evidence is missing |
| 04 | 0.65 | 3 | 2.0 | Lowers it | 21 Juice Shop and 3 nodejs-goof entries have access `unresolved`; the body is not sent | Other apps use local middleware as much |
| 05 | 0.60 | 3 | 1.8 | Low | Probe pair p5 and p5b | Multi-step selection is common |
| 06 | 0.60 | 3 | 1.8 | Medium to high | Two probe forms unrecorded; 2 create calls in one other development sample, so P is mostly judgment | Identity fields can be established without names |
| 07 | 0.50 | 3 | 1.5 | Medium | Probe p9 and p9b; 276 response sends in five development samples | A credential field can be linked to the response |
| 08 | 0.60 | 2 | 1.2 | Low | `res.cookie` in one of five development samples, a session library in two | The credential role of a cookie is provable |
| 09 | 0.50 | 2 | 1.0 | Medium | Origin policy in two of five development samples | Credential facts are joined correctly |
| 10 | 0.50 | 2 | 1.0 | Medium | One Juice Shop row, one probe | Recovery forms are similar across apps |
| 11 | 0.30 | 2 | 0.6 | Low | **None outside Juice Shop**: 0 in four other development samples | The defect occurs in real code. Known in general, not seen here |

01 precedes 02 and 03 because it needs no judged answer to show its effect. 03 is worth as much as 02 and
costs more. 00 is first because it is cheap and its result can change 06 to 10.

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

## 5. Implementation and review change log

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
