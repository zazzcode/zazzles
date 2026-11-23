# Five-case Goof Decisions evaluation

2026-11-01. The user explicitly approved these five Goof source bundles to OpenAI Decisions at
`https://api.openai.com/v1/decisions`, using `gpt-6-luna`, capped at five requests, no retries/fallback.
All returned HTTP 200. Total usage: **23,436 input tokens; 0 output tokens**. No further paid requests
were made to retain confidence metadata or regenerate reports.

[Decoded decisions](decisions.json) retain the selected answers, policy status, usage and scores.
Each trace contains the exact JSON request and response bodies, byte lengths and HTTP status;
authentication headers are never stored. The original trace format was augmented offline with the
question version recorded by its original assessment. Insignificant JSON formatting may differ.

| Case | Request/response | Result |
|---|---|---|
| Reflected login | [trace](reflected.trace.json) | Vulnerable; complete static XSS policy accepts the judgment |
| Stored Markdown | [trace](stored.trace.json) | Inadequate encoding, ineffective sanitizer, exposure unknown; static orange construction finding remains |
| Request-controlled render options | [trace](render-options.trace.json) | Unknown; explicit source blockers prevent a definitive status |
| Whole-query logging | [trace](logging.trace.json) | Unknown sensitivity/content; no established sensitive-data leak |
| Login NoSQL | [trace](nosql-login.trace.json) | Validation insufficient, injection unknown; source/guard completeness blocks a stronger judgment |

The API returned choices, per-answer confidence and option probabilities. It returned no narrative
explanations. `Assessment.reason` is the scanner's policy explanation, not model-written reasoning.
Scores are uncalibrated provider metadata and never replace evidence or required policy gates.

These decisions are replayed into the [current report](https://zazzcode.github.io/zazzles/nodejs-goof/findings.html) only where the complete
request still matches: source/evidence, model, rules, questions and protocol. Replay/decoding is
offline. Since hardening 08, the stored Markdown request carries separate create/update path
evidence. It no longer matches its saved trace, so that answer is not applied to the current report.
The [independent answer key](../../xss-answer-key.md) supplies expected source properties;
the [hardening handoff](../../../../../.zazz/ephemeral/xss-analysis-handoff.md) records the remaining gaps.
