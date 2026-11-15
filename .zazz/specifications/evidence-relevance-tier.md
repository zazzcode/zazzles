# Evidence relevance tier (S2/S5) — measured decision

## Assignment and boundaries

This is part of the remaining E3 work in `analyzer-assessment-coverage`. The owner told us to measure
after [JavaScript conditional flow](javascript-if-flow.md) (S4) and broader W6, then either implement
relevance filtering or record a rejection with its measurements. The
[request-size design](../architecture/request-size-and-evidence-relevance.md) owns the strategies
and the [ablation protocol](../architecture/request-size-and-evidence-relevance.md#ablation-protocol-for-lossy-changes).

This contract covers S2 (helper/model relevance filtering in the soft tier) and S5 (claim-relevant
coverage gaps). S1 data-path slicing has its own [contract](data-path-slicing.md).

## Measurement after S4 and W6

The digest inventory builds every request without sending it, across the eight sample applications
(3,934 assessed-family sample previews, excluding fixtures):

| Threshold | Requests above it, core v7 | After S4 + W6 |
|---|---:|---:|
| 55,000 bytes | 1 | 1 |
| 58,982 bytes (90% of the 65,536 limit) | 1 | 1 |
| 65,536 bytes (hard limit) | 0 | 0 |

The single record above the soft threshold is Juice Shop `routes/order.ts:164` (NoSQL). It fell from
61,735 to about 59,100 bytes and is judged under the existing hard-tier role budget without shedding.
The next largest request is about 48 KB. No other sample record is in or near the soft tier.

## Decision

**S2 and S5 are not adopted in E3.** They are lossy, and each needs paired protected/vulnerable paid
ablation. Under current evidence they would change one request. The hard-tier budget already handles
any request that grows past the limit, and it does so with a visible omission. Adding lossy selection
to tick a box would trade measured fidelity for no measured gain.

- The soft threshold stays a proposal (90% of `requestLimit`) and has no implementation.
- Re-open S2/S5 only when a measurement shows several real records in the soft tier, or a
  calibration shows that gap noise lowers answer accuracy (S5's accuracy hypothesis).
- When re-opened, the ablation protocol applies unchanged: arms differ by one change; stability
  criteria and a paid cap are declared before calls; every omission and tier stays visible; gates
  read the full original use; no helper that receives the request or a derived value disappears.

## Acceptance

| Criterion | Evidence |
|---|---|
| Post-S4 measurement on current wire/facts | Digest inventory `digests-s4w6-qa.tsv` (local), table above |
| Decision recorded with measurements | This contract and the request-size evidence ledger |
| No lossy change without ablation | No S2/S5 code exists; no paid ablation spent |

## Work checklist

- [x] Re-measure after S4 and broader W6.
- [x] Decide S2/S5 from evidence: not adopted; re-open criteria recorded.
