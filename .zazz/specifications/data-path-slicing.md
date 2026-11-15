# Data-path slicing (S1) — measured proposal and deferral

## Assignment and boundaries

S1 is part of the remaining E3 work in `analyzer-assessment-coverage`. The owner told us to measure
it after precise JavaScript conditionals ([S4](javascript-if-flow.md)), then implement it or record a
deferral with evidence. The
[request-size design](../architecture/request-size-and-evidence-relevance.md#s1-data-path-slicing--deferred-separate-contract)
owns the rationale.

## Proposed behavior, if it is adopted later

- Send the statements on each source-to-sink path: the source read, every transfer, writes to the
  carried names and fields, and the controls that dominate or enclose the sink. Replace the whole
  handler excerpt with that slice.
- Fall back to the whole handler whenever any relevant syntax or effect is unsupported. That includes
  unmodeled loops and `switch`, `try`/`finally`, unmodeled heap writes, request rebinding, callbacks,
  `eval` and unresolved helpers.
- Reuse the S4 arm preconditions and the shared lexical guard engine. No sample, file or identifier
  heuristic may decide relevance or protection.
- Every slice is visible: the request states which handler lines were omitted, and the gates read
  the full use.

Required regression pairs: writes and decoding after a check, reassignment after a check,
escaping/validation helpers, both branch polarities, sibling paths, nested fields. Each pair needs a
protected and a vulnerable case in JS and TS.

## Measurement and decision

After S4 and broader W6, one of 3,934 assessed sample requests exceeds 55,000 bytes, and none
exceeds the 65,536-byte limit. See the [relevance-tier decision](evidence-relevance-tier.md#measurement-after-s4-and-w6).
S1 is the most invasive lossy change in the design. Adopting it requires a paid paired ablation, and
that ablation would compete with the owner's capped budget for the fresh sample re-recording.

**Decision: S1 is deferred, not implemented in E3.** The measured size pressure does not justify a
lossy evidence change. The precise conditional engine it depends on is now delivered. Re-open S1
when real records approach the limit, or when E4/Node input work materially grows handler evidence.
The fallback and ablation requirements above then apply unchanged.

## Work checklist

- [x] Author the S1 contract with fallback, invariants and regression pairs.
- [x] Measure after S4: deferral recorded; no slicing code or paid ablation in E3.
