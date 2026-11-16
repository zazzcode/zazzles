# Next.js phase 2 and code/redirect results

**Worktree/branch:** `nextjs-support-phase-2`, based on `3dec124`.
**Contract:** [combined implementation](../specifications/nextjs-phase-2-and-code-redirect.md).
**Date:** 2026-11-16. Session A's published reports remain unchanged.

## Delivered scope

Two independent analyzer families, `code` and `redirect`, include JS/TS server/browser and Python
operands, versioned component selection/questions, verified bindings, per-path completeness,
conservative judgment, CLI selection, findings/guidance and SARIF CWE identities. Request choices
remain protocol-specific even when question names overlap with SSRF. Budgeting preserves operand
controls; equivalent requests and retained traces use the existing scheduler and replay engine.

Next.js B adds NX-BP-09/11/13/14/15/18/21/22 as model-free observations. Paired fixtures include
safe cookie receivers/options, image/origin configuration, cache context, projected sensitive rows,
message origins and client-only admin gating. OopsSec's actual pin has safe image hosts and no
wildcard action origins, so NX-BP-13/14 are **not** added to its answer key. NX-BP-18 is measured
and required there.

C models Prisma awaits, Next Pages try/catch/finally, explicit one-hop JSX props/browser effects,
context/Redux/Zustand state sources, schema-mapped SQL-to-Prisma writes, same-model read alternatives,
conditional same-route client URLs, getInitialProps, bounded export-star expansion and layout/template
stages. getStaticProps is a build-time observation. Provider/reducer/updater transitions and deeper
component chains remain explicit bounds rather than protection claims.

## Source-backed correction

The proposal called `pages/secure/redirect.js` Protected. Its actual predicate permits `/\host`:
`^\/[^/]` excludes a second forward slash but permits a backslash, and the no-scheme test does not
exclude protocol-relative navigation. The source remains read-only. Its result stays **Review**;
the sample's “safe” label is not used as scanner or model evidence. This follows the proposal's
own requirement to exclude backslashes before establishing same-site relative protection.

## Capped paid evaluation

The owner authorized 180 total OpenAI `gpt-6-luna` requests: 150 for code/redirect and 30 for C/D.
The shared ledger records **149 code/redirect + 6 changed Next.js = 155 requests**, with no fallback.
Original runs and exact responses remain under `<container>/_test-findings/nextjs-phase-2/paid/`.

The initial Python calibration exposed an empty builtin operation label and retained Review despite
correct raw answers. The producer now supplies the verified builtin name, and structural tests
validate its facts. Final Python calibration covers all three interpreter APIs across nine framework
identities (27 representatives); all 90 request contexts remain inventoried offline. Earlier attempts
remain charged to the cap and are preserved, rather than rewritten as successful runs.

| Required source case | Final supported outcome |
|---|---|
| Lab JS-001 / JS-002 | Confirmed code injection; browser eval has no duplicate XSS claim |
| Lab REDIR-001 | Confirmed; proposed safe control remains Review for the source reason above |
| TypeScript eval / redirect | Confirmed |
| Goof login response forwarded through a helper | Confirmed open redirect |
| Juice Shop raw-string redirect allowlist | Confirmed open redirect |
| Juice Shop notevil invoked through a fixed VM context program | Poor practice, citing CVE-2021-23771 |
| OopsSec login navigation | Confirmed open redirect alongside its independently linked XSS record |
| VulnPy eval / exec / compile representatives | Confirmed across nine framework identities |
| OopsSec gift-card logging after Prisma await | Confirmed without the former async-gap exemption |
| OopsSec analytics IP → SQL INSERT → Prisma read → client HTML | Confirmed stored XSS |
| Changed lab path/SSRF and protected controls | Required positives Confirmed; unresolved controls retained as Review |

The notevil result is normalized by source-established library/advisory facts. The original paid
response is preserved; the final deterministic policy treats reliance on that library as poor
practice even if the model calls its restriction “none.” Final reports are produced from fresh-source
**exact request replay**, not by copying decisions onto changed evidence.

## Express regression comparison

A compiler overlay of unchanged HEAD, built in the assigned checkout, supplies the predecessor
binary; no extra checkout was created. Existing candidate records are byte-identical after projecting
away the two new kinds:

| Sample | Existing records before / after | Added code/redirect records |
|---|---:|---:|
| vuln-demo-app | 19 / 19 | 0 |
| vulnerable-typescript-app | 24 / 24 | 2 |
| nodejs-goof | 31 / 31 | 1 |
| Juice Shop | 247 / 247 | 4 |

Raw before/after JSON is retained under `nextjs-phase-2/express-regression/` in `_test-findings`.

## Non-intentionally-vulnerable reference (D)

[Vercel Commerce](https://github.com/vercel/commerce) is pinned to
[`f7521d57d29f0eb3d23c1399cf9bb299d61fcd21`](https://github.com/vercel/commerce/tree/f7521d57d29f0eb3d23c1399cf9bb299d61fcd21).
A source archive was evaluated without installing dependencies, executing the app or modifying its
source. Offline scanning initially exposed query-only router navigation as redirect candidates;
that false candidate was removed with fixed-origin/query/fragment controls.

The offline measurement has 16 entries and 23 records: 21 standalone validation records and two
HTML rendering records. All 23 are unjudged Review (**100% Review**), with zero red findings.
The two rendering records concern editorial HTML and JSON-LD; their trust/encoding cannot be
established from the bounded slice. No paid D check was needed for an offline red. This measures
coverage and Review burden, not a claim that the app is vulnerability-free or a statistical false-
positive rate. Practice observations remain separate from these counts.

## Verification and retained evidence

- Paired parser, component, policy, stub/replay and report tests pass.
- Both real Next.js answer-key gates pass; CWE-95/601 are required by the living lab key.
- Full `go test ./... -count=1` and `go test -race ./... -count=1` pass; Go 1.27.3.
- Vet/build, changed-file formatting and `git diff --check` are checked from the assigned worktree.
- Final exact-replay inventory, current-source hashes and post-fix verification are recorded below.
  No source application was executed or remediated.

Human review and integration remain the owner step.

## Final closeout

The repository's `TestReplaySavedRun` reparsed each target and reproduced all **51/51** final
assessments with **zero mismatches and zero missing traces**:

| Target | Exact replays | Final run beneath `nextjs-phase-2/final/` |
|---|---:|---|
| vulnerable-typescript-app | 2 | `vulnerable-typescript-app/run-834355082` |
| vuln-nextjs | 8 | `vuln-nextjs/run-2011024734` |
| nodejs-goof | 1 | `nodejs-goof/run-106441268` |
| Juice Shop | 4 | `juice-shop/run-3757015726` |
| VulnPy | 27 | `vulnpy/run-2256159336` |
| OopsSec | 9 | `oss-oopssec-store/run-3304220139` |

Each run contains JSON, HTML and SARIF; corresponding `traces-final-*` directories retain exact
requests/responses. Artifacts live outside the checkout under `<container>/_test-findings/`.
The final Commerce scan, `nextjs-phase-2/closeout-commerce/vercel-commerce-f7521d5/run-1092406658`,
reproduces 16 entries, 23 unjudged Review records and zero red findings.

`nextjs-phase-2/source-integrity.json` records revisions and SHA-256 file manifests. All seven Git
sample checkouts are clean, with zero tracked source/blob differences. All 78 Commerce source files
match the pinned downloaded archive. No target dependency installation or application execution
was used.

After the final flow/schema refinements, focused race tests for parser, judge and component
selection pass, as do current-source vet/build, formatting and whitespace checks. Earlier full
normal and race suites remain recorded in the ignored execution log directory. Manual documentation
checks cover all 16 changed Markdown files, including relative links, private paths, conflict markers,
trailing whitespace and final newlines; no repository documentation linter is declared.

Execution logs: `.zazz/ephemeral/replay-closeout.log`, `scoped-race-final.log`, `vet-final.log`,
`build-final.log`, `tests-final.log`, `race-closeout.log` and `sample-gates-final.log`.
All independent QA findings were resolved. The owner authorized commit, push and a draft PR after
this verification. Publication is recorded in Git/PR history; integration and release remain human-owned.
