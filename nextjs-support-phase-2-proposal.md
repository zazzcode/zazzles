# Proposal: Next.js support, phase 2 (open items)

**Status:** Session A was delivered in PR #18. The owner assigned B–D with code/redirect in the
`nextjs-support-phase-2` worktree. The [implementation contract](.zazz/specifications/nextjs-phase-2-and-code-redirect.md)
and [results](.zazz/evaluation/nextjs-phase-2-results.md) own current implementation and acceptance.
**Drafted:** 2026-11-16, at the end of the Next.js MVP session.
**Base:** merged PR zazzcode/zazzles#18 (`nextjs-support-mvp`). Read its contract
`.zazz/specifications/nextjs-support.md` and the user docs `docs/nextjs-support.md` /
`docs/analysis/nextjs.md` first.

The MVP is complete for its owner-approved scope: N0–N5 and part of N6. Every row the PR claims
passes, and every item below is listed as a limit in the docs. The items are grouped so that each
group can be one session, one contract and one draft PR into `stage`.

## Session A: publish Next.js sample reports — implemented in PR #18

Completed in the assigned MVP worktree on 2026-11-16. The owner expanded publication from the saved
scoped runs to fresh full paid scans of both apps, including standalone input validation, with OpenAI
`gpt-6-luna`, no provider/model fallback, and a 180-request total cap.

- [OopsSec reports and provenance](docs/samples/oss-oopssec-store/README.md), including upstream license.
- [vuln-nextjs reports and provenance](docs/samples/vuln-nextjs/README.md), including upstream license.
- Source-backed [OopsSec detection guide](.zazz/evaluation/oss-oopssec-store-detection-guide.md) and
  [living lab guide](.zazz/evaluation/vuln-nextjs-detection-guide.md), linked from the sample catalog.
- Both names are in `docs/samples/refresh.py`, the Markdown/HTML sample indexes and the root README
  Saved results table. Exports normalize the public root and preserve the canonical evidence.

The [N5 closeout record](.zazz/specifications/nextjs-support.md#8-sample-publication-closeout) owns
final counts, exact-replay and contributor-check evidence. Session A adds no analyzer features;
Sessions B–D follow the owner-assigned combined contract linked above. PR #18 is merged; human review
of this follow-on implementation remains the owner step.

## Session B: remaining practice checks (N6 rest; no model)

Implement in `internal/parse/next_practice.go` with a fixture pair per check, in the style of the
existing NX-BP checks:

| Check | What the source must show |
| --- | --- |
| NX-BP-09 | A Server Action whose arguments reach a sink or data write with no enforcing validator and no authorization context |
| NX-BP-11 | `cookies().set` / `NextResponse.cookies.set` without `httpOnly`, `secure` or `sameSite`, or with `secure` tied to `NODE_ENV` |
| NX-BP-13 | `next.config` `images.remotePatterns` with wildcard hosts; `dangerouslyAllowSVG` without `contentSecurityPolicy` |
| NX-BP-14 | `experimental.serverActions.allowedOrigins` containing wildcards |
| NX-BP-15 | `dynamic = "force-static"`, `revalidate`, `force-cache` or `unstable_cache` without the user in the key, on an entry that reads cookies, headers or auth |
| NX-BP-18 | Sensitive columns (password hash, token, email) reaching the browser through client props, Server Action returns or whole-row `NextResponse.json` |
| NX-BP-21 | A `message` listener using `event.data` with no `event.origin` comparison; `postMessage(data, "*")` with sensitive data |
| NX-BP-22 | A client component that gates admin UI on `localStorage` or a decoded JWT with no matching server check on the API it calls (Review) |

Acceptance: fixtures green. The checks NX-BP-13, 14 and 18 are added to `TestNextJSOopsStoreAnswerKey`
where OopsSec shows them (measure first). Existing practice rows are unchanged. No paid calls.

## Session C: entry and flow coverage (offline first, then a capped paid check)

| Item | Detail | Evidence it is needed |
| --- | --- | --- |
| Prisma `await` as a modeled step | Awaiting a verified Prisma client call resolves to its result without `async_response_unresolved` | `OOPS-LOG-02` carries the gap; a test exemption in `nextjs_sample_test.go` should be removed |
| `try` blocks in Pages handlers | Model `try`/`catch` bodies in `flow.go` (today they go to `branches()` with `unsupported_control_flow`) | vuln-nextjs file-read, eval and SSRF handlers |
| Props into child components | Follow JSX props into an imported component one level (server and client) | Needed for code injection JS-001 as well (see the code-injection proposal C2) |
| React context and stores | `createContext`/`useContext`, Zustand/Redux selectors as state sources | OopsSec client paths that stay Review |
| Raw SQL to Prisma stored links | Link a raw-SQL `INSERT`/`UPDATE` into a Prisma model table with the Prisma read side | OopsSec `XSS-03` (analytics IP) stays Review |
| More entries | `getStaticProps` (build time: an observation only), `getInitialProps` (per request), App Router `export *` re-exports, layouts/templates as stages of their pages | Docs limits |

Acceptance: offline fixtures; both Next.js sample tests stay green. Regression comparison on the
four Express samples. A paid rerun only for records whose evidence changed (expect fewer than 30
requests; this needs an owner cap), then exact replay.

## Session D: false-positive measurement (proposal §13)

Pick and pin one Next.js app with **no intentional vulnerabilities**, for example an App Router and
Server Actions starter, or Vercel's commerce example. Scan it offline and record entries, records and
the Review rate. Any red needs a judged check under a small cap. Record the results in
`.zazz/project/vulnerable-sample-apps.md` (as "other evaluated applications") and fix false reds
that the source shows are wrong.

## Not in this proposal

- Code injection and open redirect: `code-injection-and-open-redirect-proposal.md` (owner
  decisions recorded; next up).
- Prototype pollution, then Drupal/PHP, then agent skills / loop / external SAST import: the
  implementation plan's "Next up" table.
- XXE and SCA: deferred.

## Handoff notes

- **Checkouts and permissions.** Sample checkouts are read-only.
  - OopsSec: `<DEV_ROOT>/oss-oopssec-store`, pinned `2d530ef`.
  - vuln-nextjs: `<DEV_ROOT>/zazzcode/vuln-nextjs`. It is owner-maintained and changes often;
    re-pin it in the catalog when rows are added.
  - Write only inside the session's worktree. A hook blocks writes elsewhere.
- **Offline gates.**
  - `ZAZZLES_NEXTJS_SAMPLE=<oopssec> go test ./internal/parse -run TestNextJSOopsStoreAnswerKey`
  - `ZAZZLES_VULN_NEXTJS=<lab> go test ./internal/parse -run TestNextJSVulnLab`
  - Exact replay: `ZAZZ_REPLAY_RUN`, `ZAZZ_REPLAY_TRACES` and `ZAZZ_REPLAY_ROOT` with
    `go test ./internal/judge -run TestReplaySavedRun`. The traces are in `_test-findings/*/traces-final*`.
- **Paid runs.** Load `.env` in a subshell, pass only the OpenAI key, never print it, use
  `--judge-model gpt-6-luna` and `--skip-family input-validation`, and save traces with `--trace-dir`.
  Paid use to date is 156 requests under the MVP's 300-request cap. New work needs a new owner cap.
