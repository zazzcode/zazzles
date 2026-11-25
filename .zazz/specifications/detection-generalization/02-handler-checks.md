# Detection generalization 02 — handler checks as evidence

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and
  are not repeated. **Draft, not approved.**
- **Order** see the [index](README.md#1-index). **Depends on** nothing in code. **Effort** medium. **Review
  artifact** two draft PRs: 02.1 the shared check fields, 02.2 the rest. *Why two:* the injection
  false-positive work reuses 02.1 and must not wait for 02.2.

## Capability

For a protected operation in a JavaScript or TypeScript handler, the scanner records each check inside the
handler: its condition, the values it reads, how they relate to the operation, and what the failing side
does. It sends the handler source. The model judges whether a check protects the operation and cites it, and
the policy compares the citation with the facts. Today a Node write records no in-handler check, so correct
code can be Confirmed and a wrong check looks the same as a right one.

## Required reading

[Research §3.1 and
§3.2](../../evaluation/detection-generalization-research.md#31-what-an-authorization-request-contains);
[authorization](../../../docs/scan/analysis/authorization.md); [entry
access](../../architecture/entry-access-and-authorization.md#guards); [JavaScript conditional
flow](../../../docs/scan/analysis/README.md#javascript-conditional-flow); [hardening
3](../juiceshop-nextjs-hardening-3.md) D-7, D-8 and change log (two facts that did not move answers). Code:
`parse/guard_climb.go`, `langjs/guard_lang.go`, `authorization.go`, `authorization_reads.go`,
`judge/authorization.go`, `client.go`, `bundle.go`; pattern `langphp/authorization_guards.go`.

## Semantics

A check is one `if` or conditional test that precedes or encloses the operation in the same function.

| Field | Values |
|---|---|
| `position` | `precedes`, `encloses` |
| `failure_effect` | `stops`: the arm cannot fall through. `responds_and_continues`: the arm calls an ending method of the verified response parameter and can reach the operation. `unresolved`: callback, promise chain or loop |
| `reads[].origin` | `request_field`, `stored_record` with its selector, `verified_claim`, `application_call`, `constant`, `unknown` |
| `reads[].relation` | `same_subject`: the selecting value, or a member of the record it selected, unwritten since. `other_subject`: another resolved field, element or record. `caller_only`: no request-selected value and at least one claim or application call. `unknown` |
| `reassigned` | A value the test reads is written between the test and the operation |

A test with neither an ending nor an answering arm, outside an enclosing position, is not a check. Two
elements of one collection differ unless both indexes are the same constant. An `application_call` carries
the callee's body, one step, at most 40 lines; whether it yields the caller is the model's question.
Express: a sent response does not end a function
([guide](https://expressjs.com/en/guide/writing-middleware.html)).

### Shared check fields (02.1)

Owner decision: this specification defines them and the injection false-positive work reuses them. Three
fields, for any language: the **condition**; the **values it reads**, each tied by value identity to the
operand it is read for; and **`reassigned`**. They live in `scan/internal/analysis/check.go` with
validation, and the identity and write-between helpers in `scan/internal/parse` with an adapter per
language. `failure_effect` and `relation` are this specification's additions. What a check limits a value's
text to, and an operand's position in a statement, are the injection work's. 02.1 changes no record, request
or outcome. It ships with table tests on JavaScript, Python and PHP syntax, so that neither user has to
change the fields.

## Scope

New `scan/internal/analysis/check.go`, `langjs/check_evidence.go`, tests and `testdata/check-evidence/`.
Modified: `analysis/authorization.go`, `parse/guard_climb.go` (an optional `Rejects` hook, nil for other
adapters), `langjs/guard_lang.go`, `authorization.go`, `authorization_reads.go`, `analysispacks`
authorization material, `judge/authorization.go`, `client.go`, `bundle.go`,
`report/application_findings.go`. Out of scope: middleware (04), new operations (06), PHP and Python beyond
the adapters 02.1 needs (`langpy/guard_lang.go`, a new `langphp` one), SQL operand constraints, lists of
session helpers.

## Decisions

- **D-1. Facts, not kinds.** *Why:* `ownership_check` is a judgment; PHP takes it from framework contracts
  that Node does not have. *Rejected:* porting the PHP classifier with a list per library.
- **D-2. Handler source is sent**, 120 lines. A longer handler is cut to checks, operation and enclosing
  statements, with gap `handler_source_truncated`. *Why:* 7 of 10 requests carry at most two of its lines.
- **D-3. A Node protocol**, `authorization-checks-v1`, chosen by contract. PHP stays on v9 byte-identical.
  It adds `deciding_check`: one closed choice per check or guard, and `none`. *Why:* a citation can be
  compared.
- **D-4. Policy.** (1) `adequate` with no citation or an absent one is inconsistent. (2) `adequate` citing a
  check that does not stop, is reassigned, or relates only to another subject is inconsistent. (3)
  `adequate` citing a stopping check with a `same_subject` or `caller_only` read is Protected. (4) One whose
  reads are all `unknown` is Review. (5) A cited `query_scope` guard keeps today's outcome. (6) `none`
  contradicts a stopping check with a `same_subject` or `caller_only` read: Review. (7) Otherwise today's
  Confirmed rule, unless such a check is `unresolved`: Review. *Risk accepted:* (6) can hold a true finding
  in Review when a stopping check serves another purpose; `inadequate` still confirms.

## Fixtures

One table-driven matrix, names used by no sample. Effect: return after the answer / none; throw; `else` arm;
`else if`; both arms exiting. Position: before, enclosing, after (not recorded), sibling arm (not recorded).
Relation: same field; other field; first against last element; record found by another key; reassigned
variable; destructured parameter. Caller: claim; application call; constant. Unresolved: promise callback,
loop. Negative: a test that only logs; a check in a nested function; `Next.js` and `Fastify` handlers add no
record here.

## Held-out

One vulnerable application and one ordinary one, with every in-handler check keyed as stopping and right,
stopping and wrong, or not stopping.

## False-positive controls and G7 bound

Each keyed correct check is a control. No record is added (G7: zero).

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC0 | 02.1: the three fields are the same for equal JavaScript, Python and PHP cases; no request or report byte changes | `go test ./scan/internal/parse -run TestCheckFields`; G1, G2 |
| AC1 | The matrix records every expected field | `go test ./scan/internal/langjs -run TestCheckEvidence` |
| AC2 | Each policy row gives its outcome; adversarial citations are never Protected | `go test ./scan/internal/judge -run TestAuthorizationChecksPolicy` |
| AC3 | Every authorization request with a handler carries its body or the truncation gap | `TestCheckEvidenceRequestSource` |
| AC4 | G1, G2 (PHP, Python and other Node families), G3 to G7 | Comparison, commands |
| AC5 | Held-out facts: 90% of keyed checks have the right effect and relation, or `unresolved`; none has a wrong `stops` | Results, before any paid run |
| AC6 | Paid checkpoints pass | Results |
| AC7 | Pages: missing authorization; its guide; `entry-access-and-authorization.md`, `application-security-analyzers.md`, `evidence-and-claims.md` | `doc-check` |

## Paid checkpoints

1. Fixtures (about 24 records) and Juice Shop authorization (18), before and after arms. Cap 100. Pass: no
   fixture control Confirmed; every fixture positive Confirmed or in Review with the blocking fact, at most
   one by (6); no keyed finding lost; the three Protected Juice Shop records stay.
2. Held-out and the renamed copy, authorization only, before and after, twice for changed outcomes. Cap 160.
   Pass: no correct check Confirmed; contract §7 holds; no keyed positive Protected; renamed outcomes equal.

## Stop rule

Stop when, at checkpoint 1, answers do not follow the facts: fewer than 80% of the fixture pairs separate.
Do not add a rule that decides the check, and do not reword until they pass. Stop when AC5 finds a wrong
`stops`, or at checkpoint 2 a keyed positive becomes Protected, or a correct check is Confirmed.

## Juice Shop check

Keyed findings and the three Protected records unchanged. No row of the 13 is expected to change.

## First failing test and order

02.1: `TestCheckFields/same_condition_three_languages`, then merge review. 02.2:
`TestCheckEvidence/owner_check_stops_and_does_not_stop`. Then record, producer, source, protocol, policy,
checkpoint 1, held-out, documents.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents).

## Implementation and review change log

No changes recorded.
