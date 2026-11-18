# Architecture phase 1 completion — Dynamic imports and summary witnesses

**Worktree / branch:** `arch-review-clean-up`; no new worktrees.
**Parent contract:** [source index](architecture-phase-1-source-index.md), §8c/§14.
**Plan:** [architecture update](architecture-update-plan.md), phase 1.
**Starting HEAD:** `9d138d3`.
**Review shape:** extend the existing [draft PR #24](https://github.com/zazzcode/zazzles/pull/24)
into `stage`; no merge or ready-for-review transition.
**Run log:** `.zazz/ephemeral/architecture-phase-1-source-index-run-log.md`, append-only.
**Coordination:** lead integrates disjoint JS/TS, Python and PHP contributor work and a fresh verifier.

## 1. Capability

Finish the phase 1 accuracy work the closed/inert subset could not deliver: source-backed finite
Python dynamic-import dispatch and parameter-dependent summary witnesses for JS/TS, Python and PHP.
The owner rejected deferring the 64 vulnpy gaps, then authorized finishing remaining phase 1 work
here, explicitly keeping Symfony/Drupal route adapters in phases 6/9.

A supported callable is compiled once into parameter-indexed return/effect recipes with original
source spans. Per-caller instantiation reconstructs concrete dependency, control and sink evidence
through the existing language models. A dynamic selector closes only where source registration
already proves a finite target and the current call's inputs match that selection.

## 2. Required reading

- [Source index](architecture-phase-1-source-index.md) §2, §8a–§8c and every §14 entry.
- [Shared/common rules](architecture-update-plan.md#shared-rules-for-every-phase).
- [Repository graph](../architecture/repository-graph.md), source-index implementation direction.
- [Execution discipline](../docs/agent-execution-discipline.md); repository `spec-driven`,
  `spec-builder`, `doc-check` and `pr-builder` skills.
- [Code structure](../standards/code-structure.md), [testing](../standards/testing.md),
  [spec hygiene](../standards/spec-hygiene.md), [PR process](../standards/pr-process.md).
- Existing helper frames in `helper_flow.go`, `python_calls.go` and `php_calls.go`; language flow
  and sink recorders, static Python registration/selector model, current shadow tests.
- [Vulnpy guide](../evaluation/vulnpy-detection-guide.md), [DVWA guide](../evaluation/dvwa-detection-guide.md),
  matched root `docs/analysis/` guides before changing a family's evidence, and sample answer keys.

## 3. Invariants

- Existing resolved paths retain byte-identical candidate IDs, requests, signatures and reports.
- A summary is source-backed flow information, never a safe/protected bit.
- No dropped candidates. New candidates require source support in the guides/answer keys; an
  unsupported new candidate or any removed candidate is a halt for the owner.
- No executing imports, sample code, Composer, framework containers or models. Source files remain
  read-only at verified pins. All scan artifacts stay under `_test-findings/<app>/run-arch-1f/`.
- Preserve language merge/canonical ordering, CLI/schema/wire contracts and existing native models.
- No new dependency, worktree, graph database, general heap engine or duplicated sink analyzer.

## 4. Scope and review shape

| Paths | Change | Purpose |
|---|---|---|
| `internal/parse/*summary_witness*.go` and matching tests | new | Cached per-language witness recipes, caller instantiation and parity |
| `internal/parse/helper_flow.go`, `flow.go`, `modules.go` and matched JS model/clone helpers | modified | Native-value injection, witness application and cache ownership |
| `internal/parse/python_*.go` and matched tests | modified | Finite selector/import resolution, native-value injection and summary integration |
| `internal/parse/php_*.go` and matched tests | modified | Native evaluated-value seams, witness integration and cache ownership |
| `internal/parse/testdata/{javascript,typescript,python,php}/summary-witnesses/` | new if useful | Minimal positive/negative witness fixtures |
| `cmd/scan/testdata/architecture-baseline.json` | modified | Listed deltas only |
| This contract, parent §8d/§11/§14, evaluation, architecture README/repository graph, technical approach | modified | Current scope, evidence, phase closure |
| Existing local run log and PR body | append / update | Execution and draft review evidence |

The allowed implementation directory is `internal/parse/`; shared record/model changes need a
contract amendment before coding. Framework route adapters remain phases 6/9. Other plan phases
are not started. One draft milestone PR remains the review artifact.

## 5. Decisions

- **D-20 Concrete witnesses use existing evidence records.** Compile immutable expression DAGs
  and straight-line effect recipes with parameter indexes and original AST/span references.
  Instantiate argument values through existing parameter-binding, value-reference, assignment,
  transform/control, helper-call/return and sink recorders. This preserves real witnesses without
  caching caller-specific candidate IDs or blindly cloning model-dependent fact arrays.
- **D-21 Reuse semantic models.** Small evaluated-value injection seams may bypass repeated body
  walks, but operations and sinks call the same language flow/model functions as inline analysis.
  No second binary/call/protection implementation. Shared concepts may have language syntax adapters.
  Returns and sink/store effects retain parameter provenance; writes outside supported local state
  stay explicit blocking reasons rather than acquiring fabricated effects.
- **D-22 Bounded supported subset.** Start with straight-line parameters/literals/local assignments,
  native modeled transforms/controls, direct in-repository helper DAGs, returns and supported sinks.
  Compiler rejects unsupported binding, dynamic receiver/callee, ambient/closure or alias/global
  writes, includes and unsupported control flow. Recursion/instruction caps are checked before
  application. A failed plan cannot leak partial uses or side effects. Unknown effects retain inline
  behavior/gaps. This is not blanket purity for package imports.
- **D-23 Switch with parity.** Shadow the reconstructed complete return/use/context against
  successful inline expansions before application. At supported refusals, instantiate full parameter
  witnesses, including dependent arguments and sink effects. Successful inline paths remain the
  compatibility oracle; replacing a parity-proven supported path is allowed only with byte parity.
  Unsupported callables continue on existing inline analysis. No increased inline depth/work limit.
- **D-24 Finite Python imports are dispatch facts.** Reuse the source-only static registry's finite
  import/module/callable selections, including declaration identity and selector argument evidence.
  Match the current call and selected inputs to the proven target, preserving caller-specific input
  origin. Reject shadowed/mutated imports, unknown/outside-root module names, missing/ambiguous
  targets and mismatched selector inputs. Never treat `import_module` as an independent result.
- **D-25 Existing proof bytes first.** No new public witness schema. If a family cannot instantiate
  current facts correctly (dependency fan-out, operand/context indexes, controls, storage identity),
  retain its explicit gap and fix that recipe before claiming coverage.

## 6. Agent implementation rules

Parent/common rules apply. Commit this contract before implementation. Contributors own disjoint
language files; lead owns specs/docs/shared changes and runs final gates. No model calls or keys.
Build/test with the declared Go toolchain; a temporary writable Go cache is permitted. Local
httptest listeners may require sandbox exception; they are not live provider calls.

Before/after scans verify juice-shop `f189f52`, vulnpy `b81885e`, DVWA `a1978a2` and clean
`git status --porcelain --ignored`. Use distinct completion run labels under `run-arch-1f/`.
Commit with bracketed area labels, verify zazzcode Git/gh identity, push only the feature branch and
update draft PR #24. Never merge.

## 7. Acceptance criteria

1. **AC1 Witness recipes.** Table/integrated tests for all three languages demonstrate per-caller
   parameter→return and parameter→sink witnesses beyond previous helper bounds; modeled controls
   preserve their native evidence. Two callers with different sources cannot share provenance.
   Assert concrete call/parameter/transfer/sink spans, facts and candidate identity, not only counts.
2. **AC2 Parity and limits.** Compare supported recipe return/use/context bytes with successful
   inline execution on fixtures, including argument fan-out and supported helper chains. Unsupported
   syntax/state/binding, cycles and instruction limits retain explicit refusal behavior with no
   partial emission. Cache reuse is verified. A mutation check detects incorrect argument/span binding.
3. **AC3 Dynamic dispatch.** The 64 vulnpy `work_limit` gaps at util.py:54 go to zero through
   finite source-backed resolution, with no universal import purity rule. Tests include alias/shadow/
   mutation, wrong selector inputs, missing target, outside-root and nonfinite negative cases.
4. **AC4 Compatibility and recall.** Diff against the delivered 1F bundles and goldens before
   updating any baseline. Listed deltas: finite-selector call gaps/evidence and newly reachable
   summary-return/sink witnesses; exact fixtures/candidates are enumerated in the evaluation before
   rebaselining. Every new sample candidate is checked against source guides/answer keys. Any removed
   or unsupported new candidate halts. Successful old paths remain byte-identical.
5. **AC5 Performance.** Final full-bundle three-run medians on all samples are within 5% of
   delivered 1F's 9.34 / 3.43 / 0.62 seconds, or faster. Record RSS and cache/recipe counts.
   Investigate any miss; owner decides any changed threshold.
6. **AC6 Phase closure.** Changed-Go gofmt, vet, build, full race suite, architecture baseline,
   fresh-context verifier and docs/run-log evidence pass. Phase 1 is marked complete only when
   AC1–AC5 and all nondeferred phase 1 obligations have evidence. Push and update the existing draft.

## 8. Test strategy

Use native inline flow as the differential oracle, with small source fixtures for dependent return,
controlled return, source→sink, different caller provenance and helper chains past old limits.
A compile-only inspection proves cached per-callable facts; replay tests verify complete serialized
witnesses. Negative recipes must leave uses/state unchanged. Env-gated scans establish sample parity,
source-supported deltas and target gap removal. Mutation tests prove witness/binding checks are active.
Reuse existing family assertion helpers; avoid a second set of fact semantics.

## 9. Execution sequence

1. Contract commit; confirm current golden.
2. In parallel disjoint language slices: red witness/negative tests, cached recipe compiler,
   native semantic seams, shadow parity, then bounded production application.
3. Python finite-selector/import provenance tests, integrate exact target resolution and verify
   target gaps without broad purity. Review each sample delta before any golden refresh.
4. Integrate and run scoped/full gates, guides/keys, three-run timings and independent verification.
5. Update evaluation and parent phase status, append run log, commit/push, refresh draft #24.

## 10. Definition of done

- [ ] AC1–AC6 evidenced; all changed golden rows explained.
- [ ] No unsupported candidate or missing resolved-path witness.
- [ ] All 64 targeted dynamic-import limit gaps closed soundly.
- [ ] Phase 1 status and draft PR accurately describe delivered versus remaining limits.

## 11. Open questions

None blocks starting this bounded work. The owner explicitly keeps route adapters in phases 6/9.
Unexpected limitations that prevent an AC are surfaced; they are not silently redefined as complete.

## 12. Run log protocol

Append the existing phase 1 run log: user steering, contract and implementation SHAs, per-language
scope, differential results, exact golden/sample deltas, guide review, timings, verifier and PR update.

## 13. Agent implementation prompt

> Continue in arch-review-clean-up from the recorded head. Read this contract, parent and log.
> Compile concrete source-backed witness recipes, reuse native models and preserve prior bytes.
> Use disjoint language ownership. Do not raise inline limits or erase unknown effects. Halt on
> removed/unsupported candidates. Finish the gates, samples, verifier, documentation and existing
> draft PR update; never merge.

## 14. Implementation and review change log

### 2026-11-18 — Owner authorizes phase 1 completion

The owner chose “Keep phase 1 open for a separate dynamic-import contract,” then instructed
“lets fix all this stuff while we are here.” Clarification: “Finish remaining phase 1 work;
keep route adapters in phases 6/9.” This contract owns dynamic-import resolution and full
parameter-dependent summary witnesses. Existing phase 1 evidence remains the comparison baseline.
