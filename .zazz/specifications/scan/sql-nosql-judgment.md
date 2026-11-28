# SQL and NoSQL injection judgment

## Outcome and authorization

The user requests improving and running scan until SQL/NoSQL judgments are useful against known
Juice Shop answers, before logger-leak work. Use this same worktree, without manual verdict overrides.
The selected article is external evaluation evidence, not detector/model input.

## Scope

- Distinguish field validation, construction practice, and actual injection protection in typed assessments.
- Add an injection-specific semantic question for SQL/NoSQL uses; numeric conversion, verified binding,
  and enforcing constraints may protect syntax independently of the practice standard.
- Assemble bounded automatic source/binding/handler/middleware/control evidence for modeled query uses.
  Reuse existing checked-mode machinery and add verified MarsDB/MongoDB collection provenance.
- Require complete claim evidence and a completed injection-specific judgment before reporting a
  source-supported definitive vulnerability. Keep unresolved calls/paths/bindings Review; no route-name,
  challenge-label, manual-verification, or answer-file rules.
- Red marks scanner-supported vulnerability, orange construction practice, blue Review, green scoped
  protection. Upgrade one SQL issue instead of double-counting the same operation's practice finding.
- Reproduce login/search SQL and documented NoSQL expression/document cases plus safe/unknown controls.
  NoSQL document cases lacking established operator/type behavior remain explicit until evidence resolves.
- Per-alternative output constraints distinguish numeric/constant conditionals from raw-input siblings;
  native conversions require verified unshadowed bindings. Inconclusive is the human uncertainty label.
- Product analysis rules live under root `docs/analysis/`; `.zazz/` owns internal design/SDLC records.
- No target execution/exploitation. Offline tests first; at most six initial live OpenAI Decisions
  requests using gpt-6-luna, with no retries/fallback. Track calls/tokens; stop for unexpected provider errors.

## Acceptance

- Tests distinguish raw SQL, bound SQL, ORM values, numeric/allowlisted expression values, untrusted
  NoSQL selectors, fake same-name APIs, missing sources, guards, library bindings, and incomplete evidence.
- Injection answers are separate from practice protection; poor practice can coexist with protected syntax.
- Provider schemas reject missing/duplicate/invalid answers; legacy non-query question handling remains valid.
- Snapshot provenance and untrusted source/comments are retained; expected challenge outcomes stay outside bundles.
- Known-target runs record actual statuses, blockers, usage, and residual limitations. No red findings are
  manufactured to satisfy acceptance; unresolved cases require concrete diagnosis and follow-up implementation.
- JSON/HTML/SARIF share the verdict and preserve raw model answers and practice/validation evidence.

## Execution

Use the existing [execution discipline](../../docs/agent-execution-discipline.md),
[testing](../../standards/testing.md), [code structure](../../standards/code-structure.md), and
[report design](../../architecture/reporting-and-sarif.md). Keep bounded evidence and progress in ignored
`.zazz/ephemeral/sql-nosql-judgment-run-log.md`. No PR or merge; preserve unrelated existing edits.

## Implementation and review change log

### 2026-11-01 — Branch constraints and documentation ownership

User steering requests fixing a protected-control false positive, Inconclusive terminology, and
root product analysis guidelines. Added per-output numeric facts with nested/shadowed controls,
balanced question wording, public analysis guides, and internal query design. Protocol is v8.
The focused live pair now distinguishes protected and vulnerable conditionals while preserving
Juice Shop detection. Full latest-protocol corpus validation and final target reports remain pending;
logger-leak is handed off for a new session. See the [calibration record](../../evaluation/juice-shop/query-judgment-calibration.md).
