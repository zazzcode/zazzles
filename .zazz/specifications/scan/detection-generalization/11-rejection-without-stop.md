# Detection generalization 11 — rejection that does not stop

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** last, see the [index](README.md#1-index). **Depends on** 04. **Effort** small. **Review
  artifact** one draft PR.

## Capability

A check that answers with a rejection and lets the operation run states a requirement the code does not
enforce. It becomes a decidable input-validation record. Authorization checks of this form are covered by 02
and 04.

## Why last

The evidence is thin. In five Node samples outside Juice Shop the shape occurs **zero** times; in Juice Shop
it was found in one middleware. The defect is well known in general. The pool decides whether it is worth
keeping.

## Required reading

Specs 02 and 04; [input validation](../../../../docs/scan/analysis/input-validation.md#establish-enforcement);
`judge/validation.go`, `langjs/query_shape.go`, `checks.go`; [false positives and Review
noise](../accuracy-false-positive-noise.md) (why undecidable validation records are not sent).

## Semantics

A test that reads a request field, or is enclosed by one that does, whose failing arm is
`responds_and_continues`, with a status of 4xx or an error argument, and a later stage or operation. It
fills that field's existing record: `input_source` the read, `field_policy` the condition and its arm,
`invoked_callable` the function, `control_flow` the test and the continuing statement. Existing questions,
protocol, policy and practice outcome apply. An arm that answers with success is not a rejection.

## Scope

`langjs/check_evidence.go`, `query_shape.go`, `checks.go`; tests and fixtures. Out of scope: field policies
from names or client code; other undecidable validation records.

## Decisions

- **D-1. The application's own rejection is the policy.** *Why:* nothing is inferred.
- **D-2. Practice finding only.** *Why:* impact depends on the later operation, which other families judge.
- **D-3. Existing records only.** *Why:* no new noise; G7 is zero added.

## Fixtures

Positive: middleware and handler; `status().send()`, `sendStatus`, `next(err)` without return; `else` arm.
Negative: `return`; throw; success answer; both arms return; a test on no request field; a streamed answer;
framework helper that throws.

## Held-out

Three unused applications, at least one ordinary, searched for every occurrence by the key agent.

## False-positive controls and G7 bound

Every occurrence in the pool is read. No record is added; sent records rise only by occurrences.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | Matrix | `go test ./scan/internal/langjs -run TestRejectionWithoutStop` |
| AC2 | No other validation record becomes sent | Sent-record lists compared |
| AC3 | G1 to G7 | Comparison |
| AC4 | Paid checkpoint passes | Results |
| AC5 | Pages: input validation; its guide | `doc-check` |

## Paid checkpoints

Fixtures and occurrences. Cap 30. Pass: no control a finding; every positive a practice finding.

## Stop rule

Stop **before** implementing when the key agent finds fewer than two true occurrences in three held-out
applications: the shape is then a sample's trait, and the specification is dropped. Stop after when a
control becomes a finding.

## Juice Shop check

`JS-X-VALID-02`, empty-field half only.

## First step

The occurrence count. Then `TestRejectionWithoutStop/middleware_sends_400_and_continues`.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
