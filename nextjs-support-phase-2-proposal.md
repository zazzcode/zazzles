# Proposal: Next.js support, phase 2 (open items)

**Status:** Follow-on proposal for separate sessions. It authorizes no coding or paid calls until a
session is asked to implement it.
**Drafted:** 2026-11-16, at the end of the Next.js MVP session.
**Base:** draft PR zazzcode/zazzles#18 (`claude/nextjs-support-mvp-e1c7ea`). Read its contract
`.zazz/specifications/nextjs-support.md` and the user docs `docs/nextjs-support.md` /
`docs/analysis/nextjs.md` first.

The MVP is complete for its owner-approved scope: N0–N5 and part of N6. Every row the PR claims
passes, and every item below is listed as a limit in the docs. The items are grouped so that each
group can be one session, one contract and one draft PR into `stage`.

## Session A: publish Next.js sample reports (do first; small, no paid calls)

N5 asked for published sample reports and detection guides. PR #18 has neither yet. Do this in the
PR #18 worktree before merging, or as its own small PR right after.

1. **Reports.** Create `docs/samples/oss-oopssec-store/` and `docs/samples/vuln-nextjs/`, following
   `docs/samples/vulnerable-typescript-app/`.
   - Inputs: the final replayed runs.
     - OopsSec: `_test-findings/oss-oopssec-store/oss-oopssec-store/run-822779136/findings.json`.
     - vuln-nextjs: `_test-findings/vuln-nextjs/vuln-nextjs/run-1392915960/findings.json`.
     - `_test-findings/` is in the outer `zazzles` folder, outside the repository.
   - Outputs per folder: `findings.html`, `findings.json`, `findings.sarif`, `README.md` (target,
     pinned revision, current report counts, notable results, limits), `metadata.json` and the
     upstream license (`UPSTREAM-LICENSE.txt` from each sample's `LICENSE`).
2. **Refresh script.** Add both names to `docs/samples/refresh.py`. Run
   `python3 docs/samples/refresh.py --scan ./bin/scan --sample oss-oopssec-store --sample vuln-nextjs`
   so `root` becomes the public label and no home path is published. Check `reference-policy.md`.
3. **Links.** Add rows to the `docs/samples/README.md` table, `docs/samples/index.html` and the
   README "Saved results" table.
4. **Detection guides.** Write `.zazz/evaluation/oss-oopssec-store-detection-guide.md` and
   `vuln-nextjs-detection-guide.md`, in the format of `vulnerable-typescript-app-detection-guide.md`.
   - OopsSec: promote the proposal §9 answer key, including `OOPS-LOG-02`.
   - vuln-nextjs: point at the lab's `tests/expected-scanner-findings.json` as the source of truth;
     it is a living lab.
   - Link both from `.zazz/project/vulnerable-sample-apps.md`.
5. **Acceptance:** `go test ./...` passes. Opening the HTML locally shows the same counts as the
   saved runs: OopsSec 15 Confirmed; vuln-nextjs 10 Confirmed, 7 Protected. No absolute local paths
   appear in published files.

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
