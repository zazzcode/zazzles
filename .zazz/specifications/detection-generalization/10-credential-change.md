# Detection generalization 10 — proof of a credential change

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** 10. **Depends on** 05. **Effort** medium. **Review artifact** one draft PR. If 00 passes, its
  update effect supplies the operation.

## Capability

A write to a credential field is recorded with what proves the caller: a session that owns the record, a
one-time secret, the current credential, or only a reusable stored value. Node has no recovery claim. PHP
covers token delivery.

## Required reading

`langjs/account.go`, `authorization.go`; [account
security](../../../docs/scan/analysis/account-security.md); `langphp/recovery_delivery.go`; specs 02 and 05;
CWE-640, CWE-620; NIST SP 800-63B, knowledge-based answers.

## Semantics

**Operation.** An update of a census credential field on a record the request selects.

**Proof facts**, from checks that stop (spec 02 when merged, otherwise the one enclosing or preceding
condition): the stored value compared, whether the same entry writes or clears it (`consumed`), whether it
is compared with a time (`expires`), whether a generator of the project writes it and its recorded strength,
whether a delivery of it exists, and the digest used in the comparison. `reusable` means: a stored value,
not consumed, no time comparison, and written by a client value somewhere in the project. `none` means no
such check.

The scanner states no guessability.

## Scope

New `langjs/credential_change.go`; account family kind for recovery with Node facts; questions and policy of
that kind for the Node contract; tests and fixtures. Out of scope: rate limits, password policy, delivery
recipients, SMS, MFA, PHP behavior.

## Decisions

- **D-1. Extend the account family's recovery claim.** *Why:* the same weakness. Node gets its own contract
  text and protocol; PHP bytes stay.
- **D-2. Lifecycle facts, not labels.** *Why:* "security question" is a name; "reusable stored value" is a
  program fact.
- **D-3. Deliberate anonymous recovery is the model's question.** The question names the proof facts. *Why:*
  recovery is anonymous by design.

## Fixtures

Positive: answer compared with a stored client-written value; no proof; constant proof. Negative: one-time
token consumed; token with expiry; current password verified; session-owned record; administrator entry;
registration (create, not update).

## Held-out

One application with a recovery flow and one ordinary application with token recovery.

## False-positive controls and G7 bound

Token recovery and change-password flows. At most two added records per sample.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestCredentialChange` |
| AC2 | PHP account requests byte-identical; G1 to G7 | Comparison |
| AC3 | Policy rows with adversarial answers | `go test ./scan/internal/judge -run TestCredentialChangePolicy` |
| AC4 | Paid checkpoint passes | Results |
| AC5 | Pages: weak password recovery; account guide; `application-security-analyzers.md` | `doc-check` |

## Paid checkpoints

Fixtures and held-out, two repeats. Cap 50. Pass: no token recovery Confirmed; at least two of three keyed
positives Confirmed in both repeats.

## Stop rule

Stop when lifecycle facts resolve on under half of held-out flows, a token flow is Confirmed, or fewer than
two pool applications outside Juice Shop have a flow to judge.

## Juice Shop check

`JS-X-RESET-01` should have a record that says the proof is reusable.

## First failing test and order

`TestCredentialChange/reusable_answer`. Then operation, lifecycle, policy, held-out.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
