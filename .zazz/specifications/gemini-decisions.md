# Shared Gemini Decisions provider

## Capability and boundary

Add `gemini` as one scan-wide judge provider for every implemented analyzer and optional route
discovery, restricted to `gemini-decision-1`. Work is assigned to `path-traversal`; one eventual draft
PR targets `stage`. This is an interactive provider delivery before a later path-analyzer session.
The analyzer itself is outside this contract. Implemented acceptance evidence is recorded in
[Gemini verification](../evaluation/gemini-decisions-results.md#offline-verification).

## Required reading and decisions

Read [agent rules](../../AGENTS.md#authorization-and-delivery),
[provider boundary](../architecture.md#provider-neutral-judge-boundary),
[claim gates](../architecture/evidence-and-claims.md#claim-specific-completeness-and-outcomes),
[testing](../standards/testing.md#7-semantic-adapter-stubbing) and
[code structure](../standards/code-structure.md#1-package-layout).

Official references, checked 2026-11-14:
[Gemini Decision 1](https://aistudio.google.com/docs/models/gemini-decision-1),
[Decisions API](https://aistudio.google.com/docs/decisions-api).
The guide provides Python/JS GenAI SDK 3.2+ examples and REST. The latest released Go SDK checked,
`google.golang.org/genai` v1.77.0, lacks Decisions. The user chose Go REST to retain one runtime,
source-containing exact traces and current transport bounds. No unused SDK dependency is added.

Google's API is `POST https://generativelanguage.googleapis.com/v1beta/decisions` with
`x-goog-api-key`, explicit model, shared `input` and named choice questions with `criteria`.
Answers and probabilities are maps; normalize scores deterministically into existing answer records.
Usage uses `total_input_tokens`, `total_output_tokens`, `total_tokens`. Missing response model is
attributed to the pinned requested model; a conflicting model is rejected.

## Invariants

- One `JUDGE_DECISION_MODEL` applies to all analyzers. Explicit `--judge` enables requests and must
  match the model. Conflicting CLI/environment models or model lists fail before scanning.
- Key fields may coexist; only the chosen provider's key goes to its client. No key in tracked
  files, arguments or printed output. Preserve user-owned `.env` files.
- No retries, redirects with credentials, or provider/model fallback. Retain cancellation,
  deadlines, 64 KiB requests, 1 MiB responses, caps and incomplete assessment semantics.
- Static evidence requirements and validation checks remain authoritative. Per-candidate question batching and legacy
  OpenAI/Jev payloads/replay stay unchanged. No live Jev tests.

## Scope and review shape

Allowed changes: `internal/judge/` provider/payload/decoding/replay tests; `cmd/scan/` configuration
and integration tests; `.env.sample`; README and `docs/` setup/analysis terminology; orientation,
implementation plan, provider architecture and specification index. All are in `path-traversal`.
The user separately authorized local key placeholders in `stage/.env`, then added keys and prohibited
further `.env` edits. Do not alter either local file again.

## Acceptance criteria and tests

1. Google model pin, endpoint/auth, response normalization and usage pass local HTTP tests.
2. Scan-wide configuration rejects lists, mismatches and obsolete competing settings without
   exposing secrets; existing explicit CLI behavior still works without environment selection.
3. Every implemented family and discovery can use Gemini's protocol. Malformed/missing/duplicate/
   wrong-choice responses, HTTP errors, cancellation and wrong model remain failures.
4. Exact replay preserves raw responses and rejects changed evidence; static blockers remain active.
5. Stubbed fixture scans produce JSON/HTML/SARIF with Gemini attribution, and cap exhaustion exits 1.
6. A small live Gemini scan on the pinned TypeScript sample completes and retains exact traces;
   record model, route, calls, independent expected result and report paths. This is transport and
   bounded scan validation, not proof of provider-wide accuracy.
7. Run scoped tests, then build, vet and race regressions; check changed docs/links.

Tests: `TestGemini*` in judge/CLI and `TestJudgeConfiguration`; existing provider suites protect
legacy behavior. Official REST examples define wire expectations, source-reviewed fixtures define
policy expectations. Unit tests never use live providers.

## Execution sequence

Start with failing Google transport/config tests. Add `New("gemini",...)`, shared payload dispatch,
Google decoding, authentication, then CLI model resolution. Verify all-family protocol/replay and
bundle/cap tests. Update user docs. Build/vet/race, then run the authorized sample smoke scan.
No dependency on a new analyzer or new worktree is required.

## Agent rules, halt conditions and run log

Execute sequentially; no contributor agents required. Read the local run log on resume and append
evidence to ignored `.zazz/ephemeral/path-traversal-run-log.md`. Load matched standards and doc-check.
Halt live calls on authentication/quota failure without switching providers; do not print credentials.
The user owns review/merge. No merge or integration push is authorized.

## Definition of done

- [ ] Adapter/configuration, offline regression and bundle evidence pass.
- [ ] Small live sample scan recorded with controls and limits.
- [ ] Setup/plan/orientation match implemented state.
- [ ] Human review completed.

## Open questions

None blocking; the user chose Go REST, one shared model variable, and authorized a small sample scan.
Broader live evaluation needs a separate declared scope/cap.

## Agent implementation prompt

Read this contract, AGENTS.md and the local run log. Finish shared Gemini interactively in
`path-traversal`, preserve the user's environment files, verify offline tests and a small Gemini-only
sample run, then report evidence. Do not launch or implement the later path analyzer.

## Implementation And Review Change Log

2026-11-14 — User separated shared provider delivery from the path-analyzer specification and
selected `JUDGE_DECISION_MODEL` as the sole environment model variable.
