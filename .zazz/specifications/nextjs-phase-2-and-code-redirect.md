# Next.js phase 2 and code/redirect analyzers

**Status:** Implemented and verified; ready for owner review. Assigned on 2026-11-16.
**Delivery:** Existing `nextjs-support-phase-2` branch/worktree, one review artifact into `stage`.

## Capability and scope

This contract owns the combined code/redirect C0–C7 and Next.js phase 2 B–D implementation;
the [results](../evaluation/nextjs-phase-2-results.md) record delivered scope and verification.
Session A is complete. Prototype pollution, PHP, SCA and XXE remain outside this contract.

## Required reading

- [Orientation](../docs/zazzles-agent-orientation.md#code-structure) and
  [execution discipline](../docs/agent-execution-discipline.md#verification-discipline).
- [Next.js base contract](nextjs-support.md), [analysis rules](../../docs/analysis/nextjs.md).
- [Claim completeness](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
  [graph flow](../architecture/repository-graph.md#value-flow-guards-and-taint).
- [Standards index](../standards/index.yaml): code structure, testing, spec and documentation hygiene.

## Invariants and decisions

- Keep source acquisition, family interpretation and deterministic verdict gates separate.
- Add two independently selectable families, `code` and `redirect`, with versioned questions,
  verified operand contracts, path facts and conservative completeness gates.
- Preserve unrelated families and immutable sample source. Browser eval belongs to code only;
  navigation can carry both redirect and XSS claims.
- Practice checks are model-free observations. Unknown flow never establishes protection.
- Work stays in the assigned feature checkout. No integration merge or release action.
- Paid requests use only OpenAI `gpt-6-luna`, no fallback: 180 total, with 150 for code/redirect
  and 30 for Next.js C/D (owner response, 2026-11-16).

## Acceptance and test strategy

1. Paired sink fixtures establish code and redirect operand binding, raw/protected/unknown paths,
   shadowing, constants, data-only arguments and browser/server/Python contexts.
2. Component selection and policy tests cover both protocols, contradictions and missing evidence;
   CLI and report tests cover selection, finding types, guidance and SARIF.
3. Practice fixtures cover NX-BP-09,11,13,14,15,18,21,22 with safe controls. Measure OopsSec
   before adding answer-key assertions.
4. Flow fixtures cover modeled Prisma awaits, try/catch, child props, shared React state,
   SQL/Prisma storage and the proposed Next entry shapes.
5. Both real Next sample gates and the four Express sample comparisons verify regressions.
6. Pin and scan one non-intentionally-vulnerable Next app offline; record Review rate and inspect
   any false confirmed findings. Paid checks, if authorized, require exact replay.
7. Required contributor gates: changed-file formatting, vet, build and full race tests; check
   documentation links and whitespace.

## Execution sequence and records

Record attempts/evidence in `.zazz/ephemeral/nextjs-phase-2-run-log.md` (ignored).
Implement practice and shared flow slices, then family contracts/extraction, judgment/report wiring,
paired regressions, sample evaluation and final checks. Update this contract's evidence in place.
Allowed changes: `internal/`, `cmd/scan/`, `docs/`, `.zazz/` and the two proposal status records.
The lead agent executes directly. Preserve unrelated edits. The owner resolved the paid budget; no implementation question remains.

## Definition of done

- [x] All acceptance criteria have passing evidence.
- [x] Durable docs describe the implemented boundaries and measured evaluation.
- [x] Required checks pass and paid runs replay exactly where authorized.
- [x] Human review remains the owner step.

## Implementation And Review Change Log

Initial contract records the owner's combined implementation request and existing worktree assignment.

### 2026-11-16 — Source-backed acceptance refinements

The owner combined both proposals in the assigned worktree and authorized the 180-request allocation.
Actual OopsSec configuration does not warrant NX-BP-13/14 assertions; NX-BP-18 does. The lab redirect
control permits backslash-relative destinations, so Review replaces the proposal's Protected
expectation. Same-model read alternatives and same-route conditional client URLs complete the
analytics storage chain without assuming unknown routing or a different database model. Detailed
acceptance and calibration history live in the [results](../evaluation/nextjs-phase-2-results.md).
