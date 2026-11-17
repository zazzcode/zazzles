# Architecture update plan

**Status:** Plan only. No implementation, refactor, or paid calls are authorized by this document.
Each phase starts only when the owner assigns that worktree and a bounded spec exists for it.
**Baseline reviewed:** `arch-review-clean-up` at `3890c1cbb6ff8bebbd707052edaed3bf03bc0ae8`.
**Languages in scope:** JavaScript/TypeScript, Python, and PHP. Go as a target language is out of this plan.
**Durable design:** [package boundaries](../architecture.md#11-implemented-package-boundaries),
[language and framework layers](../architecture.md#shared-language-and-framework-layers),
[repository graph](../architecture/repository-graph.md),
[request size and evidence relevance](../architecture/request-size-and-evidence-relevance.md).
The owner's dynamic-route graph note is the implementation approach this plan follows: one typed
in-memory graph, no graph database, reports stay projections, judgments stay off the graph.

## Recommendation

Faster scans, more accurate findings, and room for Symfony, library mode, and Drupal come from
one seam: **language adapters write a shared registration-and-value graph, and the judge sees
only the slice for that use.**

| Goal | What actually moves it | What does not |
|---|---|---|
| **Faster** | One directory walk; skip languages that have no files; run JS/TS, Python, and PHP runners concurrently; send smaller evidence slices (fewer input tokens) | A package move by itself; parallel judge calls once the RPM/TPM window is already full |
| **More accurate** | Registration, dispatch, callback, and value edges the three current flows drop; evidence that omits unrelated handlers and middleware | A new analyzer per framework; asking the model to invent missing edges |
| **Easier to grow** | Symfony, Drupal, and npm library exports are new **registration producers** on an existing language package. New bug classes stay sink tables plus packs | A fourth copy of `flow.go`; a YAML or Twig language; forking the report model |

Today `internal/parse` (183 non-test files, about 42k lines) owns syntax, three flow engines
(`flow.go`, `python_flow.go`, `php_flow.go`), framework entries, and claim assembly.
`AnalyzeWithOptions` walks the tree once per language and merges Python and PHP only when
`--entry` is empty. `--only-family` filters in `internal/judge/schedule.go` after every family
is built. `internal/judge/transport.go` holds `limiter.series` across the HTTP call, so judge
work is one request at a time whenever limits are on. `judge.traceGraph` projects edges the
parsers already found. It does not discover registrations.

The request-size design already records the accuracy failure mode: a guarded JavaScript command
was judged vulnerable because unrelated gaps were in the prompt, while the same guard in Python
was protected. Smaller slices are both a cost cut and an accuracy fix. That work can proceed
from its own design while phase 1 lands. It does not replace the graph.

## Phase order

Library scanning is before Drupal. Go is not a phase.

| Phase | Spec to write at assignment | Worktree and branch | Depends on |
|---|---|---|---|
| 1 | `architecture-phase-1-registration-graph.md` | `graph-registration-store` | This plan accepted |
| 2 | `architecture-phase-2-language-packages.md` | `language-package-split` | Phase 1 merged |
| 3 | `architecture-phase-3-parallel-judge.md` | `parallel-judge` | Phase 2 merged |
| 4 | `architecture-phase-4-symfony.md` | `php-symfony` | Phase 2 merged. Phase 3 may land beside it |
| 5 | `architecture-phase-5-library-scan.md` | `npm-library-rce-mvp` | Phase 2 merged. Uses the container npm-library RCE proposal as product scope |
| 6 | `architecture-phase-6-drupal.md` | `php-drupal` | Phase 4 merged |
| 7 | `architecture-phase-7-value-flow.md` | `value-flow-graph` | Phase 1 merged. Best scheduled after phase 5 if accuracy of current apps outranks Drupal |

Phases 4 and 5 touch different language packages after phase 2. They can be separate worktrees
at the same time. Phase 6 waits for the Symfony registration pattern. Phase 7 is the accuracy
payoff for JS/TS and Python apps that already scan. It is not a gate for Symfony or library mode.

Each worktree is a direct sibling of `.bare/` under the container, branch name equal to the
directory name, draft PR into `stage`. Cut from current `origin/stage` at assignment time, not
from this baseline SHA. One phase, one worktree. Do not stack these branches.

## Shared rules for every phase

- Candidate identity, normalized reports, and exact-request replay stay stable unless that
  phase's spec says evidence changed. Changed evidence gets new judgments. It does not inherit
  old answers.
- Merge order is a stable sort after all runners finish. Completion order must not change IDs,
  JSON order, or request bytes.
- No graph database, no general heap engine, and no replacement of JSON, HTML, or SARIF.
- Protection stays per value, use, and path. The graph has no "safe function" bit.
- A missed edge is an accuracy bug. A smaller report caused by a dropped edge is not a speed win.
- Application scans of JS/TS, Python, and PHP stay supported. Framework adapters do not copy
  a security analyzer.

## Phase 1 — Registration graph

**Outcome.** One in-memory store (`Nodes`, `Edges`, outgoing and incoming indexes) that today's
entries project into. Reports are produced from that projection. Existing candidate bytes stay
the same on the current fixtures.

**Code.** New `internal/graph` for the store, dense IDs, and stable ordering. `internal/parse`
writes registration, callable, and dispatch records it already computes. `internal/analysis`
remains the report contract. `MergeEntries` keeps joining language results.

**Registration facts, stored separately.** Origin (static, dynamic, unknown), path shape
(literal, framework pattern, symbolic, unknown), resolution (resolved, partial, unresolved).
A pattern such as `/users/:id` is a static registration. A factory loop can emit literal paths
whose origin is still dynamic.

**Docs.** [repository graph](../architecture/repository-graph.md) and
[architecture](../architecture.md#4-normalized-representation-and-graph-views) state what is
implemented versus still proposed. Python is a current adapter. The graph note's "Python pending"
wording is not copied forward.

**Exit.** One dynamic-registration fixture (factory or loop) is visible as origin=dynamic with
its instances kept distinct. Pinned JS/TS, Python, and PHP fixtures match pre-change candidate
IDs and request bytes. Node, edge, and peak-memory counts are recorded for one sample app.

## Phase 2 — Language packages, one walk, parallel runners

**Outcome.** JS/TS, Python, and PHP each live in a package that emits a graph fragment.
A mixed TypeScript-and-Python repository is two fragments in one snapshot. There is no call
edge between them. A monorepo is one fragment per language that has files.

**Code.**

| Package | Responsibility |
|---|---|
| `internal/graph` | Store, indexes, sort-merge of fragments |
| `internal/langjs` | Current JS/TS flow, Next.js, Express/Fastify/Hapi, browser, GraphQL, gRPC |
| `internal/langpy` | Current Python flow and Flask/FastAPI/Django adapters |
| `internal/langphp` | Current PHP flow, includes, superglobals, server-mapped entries |
| `cmd/scan` | One `walk.Walk`, skip empty languages, run the three runners concurrently, sort-merge |

Shared claim records, packs, judge, and report stay where they are. Symfony and Drupal are
not started here. YAML, XML, and Twig are not languages.

**Speed.** A full scan stops walking the tree three times (`analysis.go`, `python_modules.go`,
`php_modules.go`). Empty languages do not open a grammar. Wall clock on a mixed tree becomes
the slowest language plus the merge. A single-language tree gains the skipped walks, not the
parallelism.

**Maintainability.** `p1_`–`p4_` files are renamed to the behavior they implement (zod field
reads, redirect fixed-origin, stored-code links, Prisma quote-doubling, and the other phase
names) while moving into `langjs` or `langpy`. Orientation's testdata row includes
`internal/parse/testdata/php/` until that tree moves with `langphp`.

**Exit.** `cmd/scan/php_test.go` and `python_test.go` mixed-repo cases pass. Candidate IDs and
request bytes match phase 1 on pinned fixtures. A timing note records walk count (one) and
per-language elapsed time on one mixed sample and one single-language sample.

## Phase 3 — Parallel judge

**Outcome.** Distinct candidate signatures run with a small in-flight cap. Equivalent
signatures are grouped first, so parallelism does not pay twice. Report order stays the
pre-change candidate order.

**Code.** `schedule.go` groups by equivalence signature, then dispatches unique signatures.
`transport.go` acquires the RPM/TPM slot, releases `series` for the HTTP call, and `complete`s
afterward. In-flight cap starts at 4 and is a flag, not an unbounded pool. Answers attach by
candidate ID.

**Speed.** This shortens wall clock when model latency dominates and the scan is under the
configured RPM/TPM. It does not reduce token cost. A saturated RPM window finishes in the
same time.

**Exit.** Stub transport tests show N distinct signatures in flight and one request per
equivalent group. Saved replay bytes match for unchanged evidence. Limit accounting still
halts the scan.

## Phase 4 — Symfony

**Outcome.** Symfony is a registration resolver inside `langphp`, on the current PHP flow.
Controller attributes, annotations, and `routing.yaml` / XML become registration nodes that
point at PHP callables. `Request` inputs reuse PHP input facts. Doctrine queries reuse the
SQL claim. Validator and security annotations are guard evidence. Twig is an output sink on
the existing XSS claim. The template body is not parsed in this phase.

**Accuracy.** A front-controller app no longer looks like one `index.php` server-mapped file
plus a pile of unrouted scripts. Unresolved routes stay visible as resolution=unresolved.
They are not dropped.

**Exit.** Paired fixtures: attribute route, YAML route, unresolved route, Doctrine placeholder
versus concatenated SQL, Twig raw output versus escaped output. Plain-PHP DVWA-style fixtures
from phase 2 still match.

## Phase 5 — npm library scan

**Outcome.** Before Drupal. An exported function is a registration on `langjs` whose kind is
library export, not HTTP. Parameter trust, conditional results, and the RCE scope (command,
code, compile-to-JS, deserialization-to-code, dynamic import, prototype-pollution write,
access, and gadget) come from the container npm-library RCE proposal. This phase's spec
records that product scope. It does not widen it.

**Accuracy.** Deserialization is a vector label on an existing claim (code sink, pollution
write, or pollution access), not a new analyzer. Same-package write-and-gadget links only.
Cross-package chains stay out of this phase.

**Exit.** The proposal's corpus pins and answer keys exist, and the phase's spec defines the
detection bar (including React2Shell Review-at-the-decoder). Application-scan candidate bytes
for HTTP apps stay unchanged.

## Phase 6 — Drupal

**Outcome.** Drupal is a second registration resolver in `langphp`, using the Symfony phase's
config-to-callable helper. It does not import Symfony. Routes come from `*.routing.yml`.
Access checks on those routes are guard evidence. Form API, hooks, and the database API are
PHP entries and sinks. Render arrays and Twig reuse the XSS claim.

**Code.** `internal/lang` gains the PHP extensions Drupal actually uses (`.module`, `.inc`,
`.install`, `.theme`, and the other PHP-bearing extensions the phase-6 spec lists). Those
files are selected only by the PHP runner.

**Exit.** A fixture module with `*.routing.yml`, a `.module` hook, a Form API input, and a
placeholder query produces entries and candidates. A Symfony fixture from phase 4 still passes
without the Drupal resolver enabled. Plain PHP still passes.

## Phase 7 — Value-flow graph

**Outcome.** This is the accuracy phase for applications that already scan. Bounded call,
callback, and value edges (`CALLS`, `ARG_TO_PARAM`, `RETURN_TO_CALL`, `TRANSFERS_TO`) are
stored for the dynamic-route cases the graph note names: Flask and FastAPI factories,
finite dispatch tables, SQL callbacks, and the matching Node factory/mount cases. The judge
receives the route-to-use slice, not the whole file and not the whole graph.

**Accuracy.** Newly resolved edges are allowed to add candidates and to change evidence.
Those cases are scored against the source answer key. They are not required to replay old
request bytes. Lost edges that shrink the report fail the phase.

**Exit.** The note's controls: two factory instances with different bindings, matched versus
mismatched callbacks, raw versus escaped siblings, symbolic paths, cycle limits, deterministic
order. Graph recall is reported separately from judge labels. Node, edge, memory, and
evidence-byte counts are compared with phase 1 on one JS sample and one Python sample.

## Explicitly later

- Go as a scanned language.
- Cross-package library chains, bundled-code follow-through, and non-RCE library classes.
- A graph database or a third-party graph library.
- Splitting claim packs, the judge, or the report by language.
- `--only-family` skipping parse work. Stored-code linking depends on stored-XSS linking, so
  a family cut can drop evidence. Revisit only with a measurement spec.

## Docs each phase updates

The phase spec lists the exact sections. At minimum, phase 1 and phase 2 update
[architecture](../architecture.md) package boundaries and
[repository graph](../architecture/repository-graph.md) so implemented behavior and proposed
behavior stay distinct. Later phases update the detection guide and the language-adapter
section when a registration source is added. User-facing docs change only when a scan flag
or a supported framework changes.
