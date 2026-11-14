# Gemini Decisions verification

## Scope and outcome

On 2026-11-14, `gemini-decision-1` completed a two-request scan of `GET /api/ping` in the read-only
`vulnerable-typescript-app` checkout at `7f8b240a2f02beba099da3632d1ba679ff8bc32f`.
Source expectations: [TypeScript detection guide](vulnerable-typescript-app-detection-guide.md).
No application execution, dependency installation or target edits were performed. Target Git status
including ignored files was clean before and after, and HEAD remained pinned.

| Candidate | Result | Evidence / usage |
| --- | --- | --- |
| Command execution | confirmed_vulnerability, CWE-78 | shell_syntax_protection=vulnerable; protection_coverage=complete; 9,628 input tokens |
| Input validation | needs_evidence / Review | field_requirement=unknown; validation=uncertain; 4,282 input tokens |

Both HTTP responses were 200; total usage was 13,910 input tokens and zero output tokens.
Scanner exit was 0. There were exactly two requests, no retries and no fallback. No OpenAI or Jev
key was passed to the scanner child process. Static gates retained the unknown policy outcome.
This is bounded transport/scan validation, not whole-app coverage, runtime exploitation, independent
Findings Review or a claim of equal accuracy across providers.

## Reproduction and artifacts

With the selected Google key/model already loaded from the trusted ignored environment:

```bash
./bin/scan --analyze --json --entry src/server.ts --route /api/ping \
  --judge gemini --judge-limit 2 \
  --trace-dir <container>/_test-findings/vulnerable-typescript-app/gemini-smoke-traces \
  --output-dir <container>/_test-findings <DEV_ROOT>/vulnerable-typescript-app
```

Local canonical artifacts: `<container>/_test-findings/vulnerable-typescript-app/run-2314339227/`
contains `findings.json`, `findings.html` and `findings.sarif`; exact request/response traces are in
the sibling `gemini-smoke-traces/` directory. These source-containing artifacts remain untracked.
Both saved responses were replayed against newly parsed source with the current Gemini payload;
the same command and validation outcomes were reproduced with zero additional requests.

## Offline verification

`TestGemini*` and `TestJudgeConfiguration` cover Google auth/model/endpoint, every implemented
analyzer's question protocol, optional discovery, scores and usage, malformed and duplicate answers,
wrong model, cancellation, HTTP 429 without retry, exact replay, scan bundles and request limits.
Existing OpenAI/Jev stub tests protect their protocols; live Jev evaluation is excluded.
Verification passed:

- `GOFLAGS=-buildvcs=false go build ./...`
- `go vet ./...`
- `go test -race ./...` (all nine packages; parser suite 233.373 seconds)
- Focused `TestGemini*` / `TestJudgeConfiguration`, including subsequently added discovery coverage
- `git diff --check` and changed-document file/section links/final newlines
- Exact saved live-response replay against freshly parsed source, zero extra requests

Checks used native Go 1.27.3 (compatible patch of the declared 1.27.2) and a temporary build cache.
HTTP-stub tests required loopback access outside the execution sandbox.

## Remaining scope

The separate [path analyzer specification](../specifications/path-traversal.md#1-capability-and-prerequisite)
is prepared for a later user-launched implementation session. This provider verification does not
implement path traversal or authorize broader live sample evaluation.
