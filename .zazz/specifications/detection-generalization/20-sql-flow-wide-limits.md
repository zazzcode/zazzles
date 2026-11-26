# Detection generalization 20 — a flow-wide reading limit does not withhold a SQL record

- **Series** [Contract, gates, held-out protocol and stop procedure](contract.md). They apply and are not repeated.
- **Authorized** by the owner, 2026-11-26: "can you fix deficiencies", on the finding that the judge's pre-send gate
  withholds SQL records with real injections, then "keep working through your list of improvements and loop to validate
  and commit and push at reasonable checkpoints".
- **Branch** `detgen-02-1-check-fields`, lane A. No pull request is opened by this specification.
- **Evidence** [SQL driver independence](../../learnings/detection-generalization/sql-driver-independence.md#judged-without-a-contract).

## The defect

A PHP or Python SQL record takes every unresolved construct of the whole entry flow as a blocker (`f.gaps`): a loop, a
call or a comprehension anywhere in the page or handler, related to the query or not. A blocker fixes the outcome at
Review, so the judge's gate does not send the record. In DVWA one `while` loop in `vulnerabilities/bac/index.php` withholds
eight SQL records of the included files; two of them put the `X-Forwarded-For` header into the SQL text.

The PHP command and path records already do the other thing: blockers ride the operand value's own gaps, and flow-wide
gaps stay visible as coverage ("shared helper bodies accumulate unrelated unresolved constructs", `langphp/command.go`).

## Capability

A SQL record is blocked only by a limit on the values that reach the operation or on the SQL text. A limit elsewhere in
the entry flow is recorded as a judged limit: the record is sent, the judge reads the source, and the record can be
Confirmed or Review, never Protected.

## Invariants

1. No scanner rule gives a verdict. The change only stops a rule from fixing one.
2. A record with a judged limit is never Protected: Protected rests on what the scanner read
   ([working rule 10](../../learnings/detection-generalization/README.md#the-working-rules-what-to-send-the-judge-and-what-to-ask)).
3. A record with no flow-wide gap keeps its record and its request byte for byte.
4. Limits on the operand values and on the SQL text stay blockers, as today.
5. No list of applications, files, drivers or routes.

## Scope

| Path | Change |
|---|---|
| `scan/internal/langphp/sql.go` | Blockers come from the text's and the values' gaps. A flow-wide gap of a blocking kind that is not among them goes to `Completeness.Judged` |
| `scan/internal/langpy/sql.go` | The same |
| `scan/internal/judge/policy.go` | A SQL injection claim answered `protected` with a judged limit is Review, with a reason that names the limit |
| Tests | One fixture per language: an unrelated loop beside an injectable query, a loop the value passes through, a bound query beside an unrelated loop; a policy test |
| Documents | This file, the series index row, results in the learnings page |

Out of scope: JavaScript (its SQL records do not take flow-wide gaps this way), `storage_origin_unresolved` and its
resolution question, `query_structure_unresolved`, other families, question wording, the request text, any threshold.

## Decisions

- **D-1. Judged limit, not dropped.** *Why:* the limit is real; it only does not decide an injection the source shows.
  *Rejected:* dropping the gap from the record as command and path do; a bound query beside an unread loop could then be
  Protected on code the scanner did not follow.
- **D-2. The record decides, not the gate.** *Why:* the gate is correct for a blocker that fixes the outcome. The defect is
  which gaps a SQL record calls blockers. `resolutionGate` is not changed.
- **D-3. Both languages, one rule.** *Why:* the two files hold the same loop over `f.gaps`.

## Acceptance

| | Check | Evidence |
|---|---|---|
| A1 | Unit and package tests pass; `go vet` clean; changed files formatted | Command output |
| A2 | JavaScript samples and every record without a flow-wide gap are byte-identical to `stage` | Report comparison on the nine samples of the learnings page |
| A3 | Offline: the count of SQL records per sample whose blockers changed, by kind | Table in the results |
| A4 | Paid, Gemini, only the records whose send state changed (written before sending): the two `X-Forwarded-For` records are Confirmed; no changed record is Protected; no record that was Confirmed or Protected changes | Reports and traces in `_test-findings/detgen-20/` |

## Stop

A changed record that is Protected, or a record without a flow-wide gap whose bytes change, stops the work.

## Results (2026-11-26)

| | Result |
|---|---|
| A1 | `go build`, `go vet`, `go test ./scan/...` pass; changed files formatted. No existing expectation changed |
| A2 | Eight samples byte-identical to `stage` (Juice Shop, vuln-demo-app, vuln-nextjs, oss-oopssec-store, vuln-symfony, ThreatByte, vulnerable-flask-app, vulnpy). DVWA: 8 uses differ, all PHP SQL records with the moved loop gap |
| A3 | 8 DVWA records move `php_loop_unresolved` from blocker to judged limit. 6 have no blocker left and are sent; 2 keep `storage_origin_unresolved` and are not. No Python record changes in any sample |
| A4 | Gemini, route `/vulnerabilities/bac/index.php`, 6 requests. Both `X-Forwarded-For` records Confirmed. No changed record Protected. Records without the gap are byte-identical, so their requests are unchanged |

**The six records now sent**

| Record | Truth | Outcome |
|---|---|---|
| `bac/source/low.php:81`, `medium.php:73` | Injectable: the header in a quoted literal, not escaped | Confirmed |
| `bac/source/low.php:23`, `low.php:36`, `medium.php:22` | Safe: digits check, `intval` | Answered protected; Review by the judged limit |
| `bac/source/medium.php:29` | Safe: the value passed `preg_match('/^\d+$/')` | **Confirmed at 0.90. A new false finding** |

- **Net: two true findings and one false finding**, where all six were Review without a request. Under
  [contract §7](contract.md#7-detection-and-false-positive-accuracy-must-not-fall) true findings come first, and a false
  one is removed by better evidence, not by withholding the record. The change is kept on that reading; the owner decides.
- **The false one is a judge error on evidence the request holds.** The same value at `medium.php:22` was answered
  protected, and the same call under the entry `/vulnerabilities/bac/source/medium.php` is Protected today. Specification
  17 states `digit_pattern_value` for line 22 and not for line 29; stating it there is the evidence fix to try.
- **A finding outside the brief.** A value assigned or changed inside a loop does not carry the loop gap in either
  language, so before this change the flow-wide gap was the only thing holding such a record. It is now sent with a judged
  limit: it can be Confirmed, never Protected. Tests cover it.
- **Not measured:** gpt-6-luna, the standing judge. PHP samples other than DVWA and vuln-symfony. Three safe records that
  could be Protected stay Review; that is invariant 2.

