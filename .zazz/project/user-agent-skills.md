# User-agent scan and remediation skills

## Intent and ownership

Planned product capability: help a user's coding agent run scan against their repository, understand
its findings, and implement verified remediation. These are consumer-facing skills, distinct from
`.agents/skills/` and `.zazz/` guidance used to develop zazzles itself. Developer workspace orientation
must stay in contributor documentation, outside the primary user introduction.

Public usage and analysis guidance belongs in root `docs/`. Future distributable skills should link
to that guidance and the supported CLI/result contract, without requiring the user's agent to load
zazzles's internal SDLC material. Packaging and supported agent integrations remain to be decided.
This plan does not claim installed skills or automatic remediation exist today.

## Proposed workflow

| Skill | Outcome | Evidence and boundaries |
|---|---|---|
| Run a scan | Select the target/entry, run the CLI, and return JSON/HTML/SARIF artifact paths | Record scope, versions, completion and assessment coverage; configure model use deliberately and keep credentials out of artifacts |
| Interpret findings | Explain and prioritize actionable problems, separate from Inconclusive review items and protected claims | Read canonical JSON, source hashes, field/use evidence, library contracts and gaps; category pills are not additional independent findings |
| Remediate repository code | Apply appropriate code changes and verify that they fix the named issue while preserving intended behavior | Confirm evidence matches current source, inspect relevant helpers/guards, preserve existing protection, test behavior and rerun the affected analysis |

The agent should distinguish source-supported vulnerabilities from poor practice, uncertainty,
unassessed uses, and execution failures. Missing modeled validation is not automatically a proven
business-policy defect. SQL/NoSQL protection and field validation can require complementary fixes.
A generated remediation example is a starting point for inspection, not an already verified patch.

## Acceptance direction

- Exercise the workflow on fresh and existing target checkouts, preserving unrelated user changes.
- Detect stale report/source mismatches before applying edits; analyze the current code again.
- Use actual library APIs and preserve valid application behavior, supported guards, and redaction.
- Include positive, protected, inconclusive, unassessed, failed-run and partial-scope examples.
- Verify targeted regression tests and rescan results; do not equate an empty result with application safety.
- Produce a reviewable change summary naming the issue, fix, tests and remaining limits.
- Keep human HTML and agent JSON views consistent; skills consume actual results rather than
  manufacturing verdicts or treating benchmark labels as runtime rules.

Start with supported JS/TS input-validation and database-injection claims, then sensitive-data
logging as that detector is implemented. The public [analysis guidelines](../../docs/scan/analysis/README.md)
and [result guide](../../docs/scan/interpreting-results.md) supply the current semantics. Follow-on work
must pin a stable result contract and test fixtures before publishing installation instructions.
