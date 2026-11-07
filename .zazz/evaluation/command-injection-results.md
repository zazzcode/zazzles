# Command Injection Analyzer: acceptance results

[Contract](../specifications/command-injection.md) · [Independent matrix](command-injection/matrix.json) ·
[Evaluator](command-injection/evaluate.py) · [Expected versus actual](command-injection/final-evaluation.json) ·
[Sample delivery gate](command-injection-sample-delivery.md) · [Public guide](../../docs/analysis/command-injection.md)

Recorded 2026-11-07 for the `command-injection` branch. Final scans used scanner revision
`6f5cb711fe06c6d538f636aaea9aad9b5500cbc9` (binary SHA-256
`0836b6e7e148ddff6b2c0e0a2dbfc5ae23dc95e239b4a25efd3e8abee16565be`), OpenAI Decisions `gpt-6-luna`, no
provider/model fallback, no target execution. At the original closeout, only tests, docs and curation
scripts changed after those scans. A later [bounded NoSQL follow-up](nodejs-goof-findbyid-results.md)
refreshed two Goof lookup judgments; command results are unchanged. Target checkouts stayed clean at their pins: Juice Shop `f189f521…`, VulnPy
`b81885e5…`, nodejs-goof `add14ba5…`, vulnerable-typescript-app `7f8b240a…`.

## Result

Every required command positive was a completed, gated `confirmed_vulnerability`, and every control was clean.
The machine evaluation ([final-evaluation.json](command-injection/final-evaluation.json)) passes with no
unexpected command candidate.

| Case | Expected contexts | Confirmed |
|---|---|---|
| EXPRESS-PING (TS app `src/server.ts:90`) | 1 | 1 |
| GOOF-CREATE-EXEC (`routes/index.js:174`, regex capture) | 1 | 1 |
| VP-CMDI-OS-SYSTEM (`trigger/cmdi.py:6`) across 11 adapters | 28 | 28 |
| VP-CMDI-SUBPROCESS-POPEN (`trigger/cmdi.py:10`) across 11 adapters | 28 | 28 |
| VP-CMDI-FASTAPI-LOOP / -UPLOAD, QUART-UPLOAD, FALCON-UPLOAD / -THREAD | 5 | 5 |
| Juice Shop direct command positives | 0 | 0 (SSTI, RCE/vm, packaging controls clean) |

The two VulnPy sinks are repeated exposures of two shared defects (61 framework/method/registration contexts
with the five app-specific witnesses), not 61 distinct defects. Juice Shop's disposition is source-reviewed, not
inferred from scanner output ([review](juice-shop/command-injection-review.md)). Erlik's two unsafe cases and
constant control are portable-fixture cases evaluated offline (`TestCommandSourceCases`, evaluator); that app
is not one of the four judged targets.

## Final scans (pass4, final revision)

| App | Positions | Provider requests | Input tokens | Command candidates | Command confirmed |
|---|---:|---:|---:|---:|---:|
| Juice Shop | 208 | 117 | 926,572 | 0 | 0 |
| nodejs-goof | 34 | 34 | 255,630 | 1 | 1 |
| vulnerable-typescript-app | 21 | 16 | 65,808 | 1 | 1 |
| VulnPy | 2,977 | 147 | 1,789,377 | 61 | 61 |

Positions are candidate records; requests are completed provider calls (the rest are observation-only
`not_run` records, pre-transport selection failures with zero calls, or the skipped family). Exit status 1 for
Juice Shop and the TypeScript app is the existing incompleteness rule for observation-only records, not a
required command case. Provider usage reports input tokens only. All four runs together with the earlier
exploratory passes used 628 provider requests (about 6.1M input tokens); passes 1–3 used an earlier revision
and are preserved as history.

### Scope departure (user direction)

**VulnPy skipped the input-validation family** (`--skip-family input-validation`, a standard option): its 2,830
input-validation records are `not_run` with the reason recorded, and the JSON, HTML and SARIF state the analyzer
was not used. This departs from the contract's no-family-filter rule on explicit user instruction, because the
newly covered frameworks make a full VulnPy pass about 3,000 requests (about 22M input tokens). Every other VulnPy
record, including all command, SQL and XSS records, was judged. Juice Shop, nodejs-goof and the TypeScript app
ran with no filter. Input-validation results for VulnPy are therefore unassessed, not adequate.

### Why there was a rescan

Pass 3 (previous revision) confirmed 60 of 61 VulnPy command contexts: one Django-ASGI context answered
`unknown` because an unresolved sibling path (Django<4 header fallback) hid its raw GET path, while three identical
contexts were confirmed. The question text and facts now state that a raw path is an independent witness and an
unknown sibling does not make it unknown, and a per-path fact line is supplied. All four apps were rescanned on the
final revision once; no unchanged request was resampled.

## Integrity and replay

- Predecessor identity: against a scanner built from the pre-command commit `e12873c`, every existing candidate of
  Juice Shop (208), goof (33), the TypeScript app (20) and VulnPy (827) is JSON-identical; VulnPy gains 2,089
  non-command candidates from newly covered framework entries (expected) plus the command contexts. Effective request bytes
  of existing families on eleven parsed fixtures match digests recorded at `e12873c` (`TestCommandPredecessorRequests`).
- Offline exact replay against a fresh analysis of each pinned target reproduced every saved assessment: Juice Shop
  117, goof 34, TypeScript app 16, VulnPy 147 (0 mismatches), using the saved request/response traces and the current
  decoder and policy (`ZAZZ_REPLAY_RUN` harness in `internal/judge/replay_saved_test.go`; no network).
- Published sample JSON, HTML and SARIF agree on use counts and statuses with the live reports (VulnPy's published
  copy omits the skipped records; see below). No home paths or credentials are present.

## Expected deltas to predecessor results

- New family and finding type; presentation version 6 to 7; the registry entry changes the outbound golden report
  hashes only (verified by reverting both).
- Non-command statuses are fresh model decisions, not policy changes. Against the predecessor paid evidence, Juice Shop
  has 199 identical statuses and 9 records that moved from `needs_evidence` to `confirmed_vulnerability` (two SQL,
  three NoSQL, two XSS, two logging; 116 of 117 raw answers differ); VulnPy's 21 SQL and 7 XSS records on existing
  Flask/FastAPI contexts moved the same way. They are known, documented vulnerabilities in those targets and no SQL,
  NoSQL, XSS or logging policy changed. Fresh answers differ run to run, so these are reviewed deltas, not regressions.
- VulnPy adds the Quart, Django (sync/ASGI), Falcon (sync/ASGI), Bottle, Pyramid, aiohttp and WSGI entries: 2,214
  entries (from 564) and 2,089 new non-command candidates (including thousands of input-validation records, which VulnPy did not judge).

## Verification

`gofmt -l .`, `go vet ./...`, `go build ./...`, `go test ./...` and `go test -race ./...` pass; `git diff --check`
passes. Source-case acceptance (`TestCommandSourceCases`, about 50 s without `-race`, about 3 min with it) runs against
the pinned targets when present under `DEV_ROOT`.

## Known limits

Static, bounded analysis. VulnPy WSGI uses finite-registry dispatch (each registry item is its own context); Pyramid
unconstrained routes are modeled as GET and POST; Django contexts count each URLconf that consumes the patterns. Unknown
utility options, Windows/PowerShell, dynamic shell options and unmodeled middleware stay Review. The Django-ASGI
version-specific header fallback remains an unresolved sibling path. Falcon thread witnesses are conditional on the
`contrast` import succeeding. Source confirmation is not runtime exploitation. Full reports and traces (which contain
transmitted source) are retained outside the repository.

## Artifacts

Retained under `<DEV_ROOT>/zazzcode/zazzles/_test-findings/command-injection/`: `pass1-juice-shop` … `pass4-*` (ledger,
traces, raw runs), `review-package/<app>/findings.{html,json,sarif}` (the twelve final artifacts, full size) and
`expected-vs-actual.json`. Curated, size-limited copies are published under `docs/samples/<app>/`.
