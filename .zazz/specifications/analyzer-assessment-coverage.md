# Analyzer Assessment Coverage — Contract

**Worktree / branch:** `analyzer-assessment-coverage`, cut from `stage` after the E1 + E2 merge
**Deliverable:** `analyzer-assessment-coverage`
**Drafted:** 2026-11-15
**Review artifact:** Draft PR for `analyzer-assessment-coverage` targeting `stage`; never merge to `stage`
**Execution record:** Local run log `.zazz/ephemeral/analyzer-assessment-coverage-run-log.md`
**Companion skills:** `spec-driven`, `doc-check`

---

## 1. Capability

When the scanner cannot judge a record, the report must say why, and that reason should be rare and
honest. After the E2 sample rebuild, 95 of 223 Juice Shop records were not judged. This deliverable
removes four of the causes without weakening any existing answer. Every fix is generic: no code
names a sample application, file or framework to decide what to send, skip or shed. Each rule
applies to JavaScript, TypeScript and Python wherever the language has the construct, and the
Python sample applications are part of the regression set.

| Slice | Cause today | Juice Shop records | Other samples |
| --- | --- | ---: | --- |
| S1 | A MarsDB collection reached through an ES named import has no verified binding | 3 | — |
| S2 | A request over 64 KiB is skipped with no record of what it would have needed | 1 | none over the limit today; nearest is VulnPy path at 64,964 bytes |
| S3 | Outbound calls are observation-only, even when the request controls the destination | 66 | ThreatByte `requests.get(picture_url)`; vulnerable-typescript-app `axios.default.get(url)` |
| S4 | A call that only *contains* a Sequelize `Op.like` is a SQL candidate, and Sequelize finders have no contract | 2 | — |

Measured baseline (step 0, offline, 4,404 candidates over the eight samples and the parser
fixtures): one request over the limit, Juice Shop `routes/order.ts:164` at 72,580 bytes after the
existing compaction (119,336 uncompacted). The full table is in the run log.

## 2. Required reading

- [Handoff §8.1–8.4](../ephemeral/HANDOFF-assessment-coverage.md) (local, gitignored) — the
  investigation this contract bounds.
- [E2 contract](shared-guard-and-manifest-engine.md) — the guard and manifest engine this builds on.
- [Outbound contract](components-03-outbound.md) — the observation boundary S3 narrows.
- [Path traversal contract](path-traversal.md) — the three-facet question and gate pattern S3 reuses.
- [Database injection rules](../../docs/scan/analysis/database-injection.md) — SQL/NoSQL scope that S1 and S4 extend.
- Standards: [code structure](../standards/code-structure.md), [testing](../standards/testing.md),
  [docs hygiene](../standards/docs-hygiene.md), [spec hygiene](../standards/spec-hygiene.md).

## 3. Invariants

1. **Request bytes under the limit do not change** except for candidates this contract lists in §6.
   Proven by the differential digest comparison (base commit vs working tree, every sample and
   parser fixture as its own root) and by `TestOutboundPredecessorRequests` and
   `TestCommandPredecessorRequests` passing without edits.
2. **Absence is not a verdict.** An unknown binding, operand origin or omitted evidence stays
   unknown; nothing becomes protected because evidence is missing.
3. **Nothing is omitted silently.** Evidence left out of a request is listed in the request (so the
   model can lower its confidence), in the decision trace and in the report.
4. **Verdict stability.** Evidence that a saved model answer cites is never shed; the saved exact
   replays still pass.
5. **Determinism.** The same input produces the same bytes; ordering never depends on map iteration.

## 4. Scope

May change: `internal/parse/`, `internal/analysispacks/`, `internal/guidelines/`, `internal/judge/`,
`internal/report/`, `internal/analysis/` (additive fields only), `cmd/scan/` tests, `docs/analysis/`,
user docs that describe the changed behavior, and `.zazz/` project records. The wire
`evidence_version` and report `schema_version` do not change; new JSON fields are additive and
omitted when empty.

| Path | Change | Reason |
| --- | --- | --- |
| `internal/parse/automatic_queries.go` | Modified | S1: follow ES named imports, export aliases and re-exports to the declaring module |
| `internal/judge/budget.go` (new), `client.go`, `trace.go` | New / Modified | S2: role-classified shedding over the limit, omission gap and trace, floor reason |
| `internal/analysis/analysis.go` | Modified | Additive: assessment omission record; outbound destination origin; grouped observation count |
| `internal/parse/flow.go`, `python_frameworks.go`, `outbound_*.go` (new) | Modified / New | S3: destination-slot origin, verified `fetch`/`axios`/Python client binding, SSRF candidate |
| `internal/analysispacks/ssrf*.go` (new), `families.go`, `outbound.go` | New / Modified | S3: SSRF family, contracts, questions, components |
| `internal/guidelines/` | Modified | S3: SSRF language guidance |
| `internal/judge/ssrf.go` (new), `policy.go` | New / Modified | S3: SSRF consistency gates |
| `internal/report/` | Modified | S2 omission wording; S3 grouped observation and SSRF finding type |
| `internal/parse/query_shape.go`, `sequelize_finders.go` (new), `checks.go` | Modified / New | S4: finder-only `Op.like` detection, finder binding |
| `internal/analysispacks/contracts.go`, `internal/judge/policy.go` | Modified | S4: Sequelize finder contract; wildcard is not injection |
| `*_test.go`, `internal/parse/testdata/…` | New / Modified | Acceptance tests below |
| `docs/analysis/*.md`, `docs/interpreting-results.md`, `.zazz/project/implementation-plan.md`, spec index, orientation | Modified | Describe the new behavior |

### Explicitly out of scope

- JavaScript `if` modeling and guard confidence (handoff Appendix A §1–6): changes flow evidence for
  every JS analyzer; sequenced with the E3 wire bump.
- Goof `adm-zip` Zip Slip Review (Appendix A §7): E3 catalog prose.
- Data-only XSS linkage (handoff §8.5): its own contract.
- Handler slicing (handoff §8.1 step 5): not needed; S2 brings every measured record under the limit.
- SSRF for second-order destinations (a URL read from storage or a remote response), redirects
  followed at runtime, DNS rebinding and deployment network policy: the claim stays observation or
  unknown.
- Python ORM finders (SQLAlchemy `filter`/`like`): no sample uses them through a request value.

## 5. Decisions

### D-1 — Oversize outcome reuses the Review outcome with a distinct reason (owner choice B)

A record whose blocking and path evidence alone exceed the limit is not sent. It keeps
`status: not_run`, `finding_status: needs_evidence`, `protection: uncertain`, and its reason starts
with the stable code `evidence_too_large:` followed by the request size, the limit and the bytes by
section. **Why:** no report or SARIF schema change; the reason is specific and greppable.
**Rejected:** a new outcome — the owner chose B at kickoff.

### D-2 — The budget acts only over the limit and sheds by role

`payload` keeps today's two steps (full form, then the existing lossless compact form). Only when the
compact form is still over 65,536 bytes does the budget run, on the candidate's evidence, and the
request is rebuilt from the reduced candidate so every reference stays consistent. Evidence classes:

- **blocking** — the sink and every item in a role the claim requires (`Completeness.Required`);
- **path** — dependency sources and transfers, control-edge endpoints, and any item whose span
  contains a dependency source/transfer or a blocking gap;
- **context** — everything else supplied as context or in a non-required role.

Shedding order: context items whose text is wholly contained in another kept item (lossless), then
context in other files than the sink (largest first), then same-file context furthest from the sink.
Blocking and path items are never shed and no excerpt is cut. Ties break on file, start byte and
kind. **Why:** the class comes from the roles and trace the adapters already supply, so each family
needs no extra code and no framework list. **Rejected:** a per-framework list of "harmless"
middleware — name-based and not generic; relevance tuning of helper selection — the measurement shows
role shedding alone is sufficient.

### D-3 — The omission is a coverage gap, an assessment record and a trace field

The reduced request carries one `evidence_omitted_for_size` coverage gap at the sink whose detail
states the count, kinds and bytes omitted and lists each omitted span (`file:start-end`). The
assessment carries `evidence_omissions` (kind and span per item) and the decision trace records the
same list, so a replay rebuilds identical bytes. The report states the omission in the record's
uncertainty text.

### D-4 — Outbound destination origin and grouping

Every outbound record gets a `destination_origin` from the destination slot only (`fetch` argument 0,
`axios` method argument 0 / call argument 0, Python URL argument or `url=` keyword):
`request` (a request input reaches it), `external_data` (only storage or remote-response data reaches
it), `constant` (a string literal or substitution-free template), `environment` (an unshadowed
`process.env.*` / `os.environ` read, directly or through a single local or parameter default), or
`unestablished`. Observation findings that share one sink span and are not `request` are one finding
that names the number of entries reaching it. **Why:** the 65 Juice Shop records describe one call.

### D-5 — SSRF claim for request-derived destinations with a verified client binding

A new `ssrf` family (`ssrf_candidate`, protocol `ssrf-components-v1`) replaces the observation when the
destination origin is `request` and the call binding is verified:

| Contract | Binding the parser must verify |
| --- | --- |
| `fetch-url-v1` | global `fetch` not declared, imported or shadowed in scope (WHATWG Fetch, Node 18+) |
| `axios-url-v1` | `axios` (or `axios.default`) imported or required from `axios`; method `get/post/put/patch/delete/head/options/request` or direct call |
| `python-http-url-v1` | the existing requests/httpx/urllib binding |

Three questions, each a separate facet: `destination_control` (`full_url`, `host`, `path_or_query`,
`none`, `unknown`), `destination_restriction` (`host_allowlist`, `scheme_and_host_check`,
`prefix_only`, `none`, `unknown`) and `protection_coverage` (`complete`, `incomplete`, `unknown`).
Gates (`internal/judge/ssrf.go`): `confirmed_vulnerability` needs a consistent `full_url`/`host`
answer, restriction `none`, no claim blockers and a `request` destination; `protected_for_claim`
needs `host_allowlist` or `scheme_and_host_check` with complete coverage and a source-backed guard
on the destination value; `none` control with a `request` destination is a contradiction. A
second-order or unverified call stays an observation. **Why:** the request-controlled destination is
the classic SSRF shape and the evidence gates mirror Path. **Rejected:** assessing every outbound
call — most destinations are not request-derived and have no claim.

### D-6 — `Op.like` is detected on finder calls, and finders have a contract

The text heuristic in `queryKind` applies only to a member call whose method is a Sequelize finder
(`findAll`, `findOne`, `findAndCountAll`, `count`, `findByPk`) and only to `Op.like` text outside
nested function bodies in its own arguments. A finder whose receiver resolves to a class that extends
a `sequelize` `Model` (or a `sequelize.define` result) gets `sequelize-model-finder-v1`: `where`
values, including `Op.like` operands, are bound parameters, so request text cannot change SQL
syntax, while `%` and `_` inside a `like` operand are wildcards. The SQL gate never reports injection
for this contract unless the model cites raw SQL (`Sequelize.literal`, `sequelize.literal`,
`Op.literal` text) in the same call; a vulnerable injection answer without one is inconsistent.

## 6. Acceptance criteria

- **AC1 — Named-import MarsDB binding.** Named, aliased, export-clause-aliased, re-exported and
  aliased re-exported imports of a `marsdb` `Collection` yield `sink_binding` evidence and
  `marsdb-collection-v1`; a shadowed name, a reassigned export, a name exported twice, a non-MarsDB
  constructor, a package (non-relative) import and a missing export do not. Verified by
  `TestCollectionBindingNamedImports`.
- **AC2 — Budget under the limit is a no-op.** For every candidate under 65,536 bytes the request is
  byte-identical to the base commit (digest comparison, §7) and `evidence_omissions` is empty.
  Verified by `TestRequestBudgetUnderLimitUnchanged` and the digest comparison.
- **AC3 — Budget shedding.** With the limit forced small, shedding follows D-2 order, is
  deterministic across runs, never removes blocking or path evidence, and the omission gap's count and
  spans match `evidence_omissions`. Verified by `TestRequestBudgetShedsContextByRole`.
- **AC4 — Floor.** When blocking and path evidence alone exceed the limit, no request is sent and the
  reason starts `evidence_too_large:` with section sizes. Verified by `TestRequestBudgetFloor`.
- **AC5 — Synthetic oversize per growth shape.** A very large handler, many middleware
  registrations, many repeated gaps and a long helper chain, for at least SQL, NoSQL, Command, Path,
  XSS and validation and in JS and Python where the family exists, each fits with an omission gap or
  reaches the floor; none is skipped silently. Verified by `TestRequestBudgetSyntheticShapes`.
- **AC6 — Replay stability.** The saved exact replays pass, and for each saved answer no cited
  evidence item is in the shed set when the limit is forced to 32 KiB. Verified by the local replay
  check recorded in the run log (not committed: it reads local bundles).
- **AC7 — Destination origin.** Each origin class in D-4 is assigned for JS/TS and Python fixtures;
  a body-only request value with a fixed URL is not `request`. Verified by `TestOutboundDestinationOrigin`.
- **AC8 — Grouped observation.** N entries reaching one non-request outbound call produce one
  finding that names N; distinct calls stay distinct. Verified by `TestOutboundObservationGrouping`.
- **AC9 — SSRF candidates.** `fetch(req…)`, `axios.get(req…)`, `axios.default.get(req…)` and Python
  `requests.get(request…)` with a verified binding become `ssrf_candidate` with the matching contract
  and a `destination` sink slot; a shadowed `fetch`, a local `axios` object, a fixed URL and a
  second-order URL stay observations. Verified by `TestSSRFCandidates`.
- **AC10 — SSRF gates.** Table-driven: consistent vulnerable → `confirmed_vulnerability`; protected
  without a destination guard → inconsistent; restriction `none` with `protected` → inconsistent;
  blockers → `needs_evidence`. Verified by `TestSSRFPolicy`.
- **AC11 — `tool(...)` is not SQL.** A call whose arguments merely contain a nested function with a
  Sequelize `Op.like` finder is not a SQL candidate; the nested finder is. Verified by
  `TestSequelizeFinderDetection`.
- **AC12 — Finder contract.** A finder on a verified Sequelize model with `Op.like` over a request
  value selects `sequelize-model-finder-v1`; an injection-vulnerable answer without raw SQL in the call
  is inconsistent and not a SQL injection finding; an unverified receiver has no contract. Verified by
  `TestSequelizeFinderContract` and `TestSequelizeFinderPolicy`.
- **AC13 — Byte stability.** The digest comparison shows changes only for: the three MarsDB records
  (S1), the oversize record (S2), outbound records that become `ssrf_candidate` (S3), and the
  Juice Shop chat records (S4); `TestOutboundPredecessorRequests` and `TestCommandPredecessorRequests`
  pass unedited. Recorded in the run log.
- **AC14 — Build, vet, format, docs, race.** `go build ./...`, `go vet ./...`, empty
  `gofmt -l cmd internal`, `go test -race ./... -count=1`, `git diff --check` and the doc checker pass;
  no working-doc identifiers (`AC`, `D-`, `SPEC`) in Go source or tests.
- **AC15 — Live confirmation (OpenAI `gpt-6-luna`, at most 8 requests, no fallback).** Juice Shop
  `routes/order.ts:164`, the three MarsDB records, `profileImageUrlUpload.ts`, `chat.ts` finder, and
  one Python SSRF record (ThreatByte) are judged. Then the Juice Shop sample is rebuilt (owner
  approved) and its README counts updated.

## 7. Test strategy

- Parser: fixture-per-case temp roots with `writeSource`/`Analyze`, table-driven per binding shape.
- Budget: unit tests on synthetic `CandidateUse` values with an injectable limit; synthetic oversize
  fixtures parsed from source for the growth shapes.
- Judge: table-driven policy tests over answers × facts, mirroring the Path policy tests.
- Regression: the local differential digest tool (each sample and fixture root, base archive vs
  working tree) and the saved exact replays; both are scratch, never committed.

## 8. TDD entry point and sequence

```bash
GOFLAGS=-buildvcs=false go test ./internal/parse -run 'TestCollectionBindingNamedImports' -count=1
```

1. S1 tests red → binding → green → digest diff.
2. S2 budget tests red → budget, omission, floor, report → green → digest diff, replay check.
3. S3 origin/grouping/SSRF tests red → parser, family, gates, report → green → digest diff.
4. S4 detection/contract tests red → detection, contract, gate → green → digest diff.
5. Full verification, docs, live confirmation within the cap, sample rebuild.

## 9. Halt conditions

Stop and surface to the owner if (1) a request under the limit outside the §6 AC13 list changes
bytes, (2) a saved replay fails, (3) a live run needs more than 8 requests before the rebuild, or
(4) the diff needs a change outside §4.

## 10. Definition of done

- [x] AC1–AC5 and AC7–AC14 baseline checks verified in the run log; the later [wire v7 contract](wire-bundle-v7.md) supersedes the original request-byte freeze.
- [ ] AC6 citation-specific retention remains uncheckable because saved answers contain no citations. The 360 historical exact replays and the decisive-evidence retention proxy passed; an explicit citation/proxy decision remains open.
- [x] AC15 live results recorded; samples rebuilt; README counts match `findings.json`.
- [x] Analysis docs, interpretation guide, plan, spec index and orientation match the code.
- [x] Draft PR [#14](https://github.com/zazzcode/zazzles/pull/14) targets `stage`.

## 11. Open questions

None. Owner decisions at kickoff (2026-11-15): oversize uses option B; S3 includes the first SSRF
contract, not classification only; up to 8 live `gpt-6-luna` requests plus a Juice Shop sample
rebuild; commit, push and open a draft PR; every fix must apply to the Python sample applications.

## 12. Implementation and review change log

### 2026-11-15 — Implementation findings folded into the contract

**Source.** Differential digests and test runs during implementation.

**Changed Sections.** AC13 (predecessor test wording), §4 scope (fixture edit), D-6 (gap and slot).

**Rationale.** (1) `TestCommandPredecessorRequests` covers `javascript/outbound`, where one fetch becomes an
SSRF claim with a new identity, so "unedited" cannot hold: SSRF is excluded as a new family exactly like
Command, and the new four-line baseline equals the digest of the unchanged base lines. (2) The Python
outbound fixture gained a second-order call so the Python observation path keeps test coverage. (3) A
finder's `where` dependency is tagged `finder_value`, and a LIKE pattern records
`like_pattern_interpolated` instead of `query_text_interpolated`. (4) A request-derived destination in
JS uses the stage-resolved chain shared with Path, so a wrapper-registered handler keeps
`unresolved_wrapper` blockers; wrapper modeling is a follow-up across families.

**Summary.** Every sample request outside the AC13 list is byte-identical to the base commit.

**Verification Impact.** Recorded in the run log per slice.
