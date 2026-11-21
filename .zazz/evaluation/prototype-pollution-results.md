# Prototype pollution stage 1 results

[Implementation contract](../specifications/prototype-pollution.md) · [Analysis guide](../../docs/analysis/prototype-pollution.md)

Verified on 2026-11-20 in `prototype-polution-analyzer` against the `ec29e49` integration
baseline. The sample checkouts matched their pins and stayed clean. Scans read source and package
files. The assessment tests used fixed responses through an in-memory transport.

## Pinned application scans

| Case | Sample pin | Anchor | Baseline | Stage 1 |
|---|---|---|---|---|
| GOOF-PP-01 | `add14ba59e98` | `routes/index.js:360` | No record | One complete raw candidate, `lodash-merge-v1`, Lodash 4.17.4 |
| TS-PP-01 | `7f8b240a2f02` | `src/server.ts:246` | No record | One complete raw candidate, `lodash-merge-v1`, Lodash 4.17.4 |
| JS-PP-N01 / N01b | `f189f521266f` | `server.ts:351`, `routes/recycles.ts:14` | No record | No pollution record across the sample |
| OSS-PP-N01 | `2d530ef3c0e6` | `packages/react-toastfy/index.js:33` | No record | No pollution record across the sample |

The two candidates have `assessment.status: not_run`. Vuln Demo App and the pinned vuln-nextjs
snapshot also produced no pollution records. An independent verifier repeated the four keyed
sample scans and the partial-guard test with the same outcomes.

## Automated verification

- **AC1** Affected, patched, and range-only Lodash snapshots distinguish raw candidates,
  excluded operations, and `version_unresolved`. Tests cover alias and reassignment behavior,
  package-specific fixes, source operand order, and verified JSON parsing.
- **AC2–AC4** Source fixtures cover recursive merges, split paths, and direct nested writes.
  A literal deny-list and an own-property test cover complete guards. An incomplete guard
  keeps its open lookup visible. Shallow assignment, parsing alone, scalar route parameters,
  and affected or patched deletion APIs produce no assignment claim. A null-prototype root
  on a deep merge is Review. A fresh null-prototype object can protect one direct lookup.
- **AC5** Nine stub cases cover Confirmed, Protected, Review, contradictory answers, request
  replay, findings, and SARIF CWE-1321.
- **AC6–AC7** The six offline sample reruns preserved all existing use records. The recall
  checker moved only the two new positive rows from missing to witnessed. The architecture
  baseline added two fixture rows and preserved all 46 prior rows, including request digests.
- **AC10** `gofmt -l cmd internal`, `go vet ./...`, `go build ./...`,
  `go test -race ./... -count=1`, and `git diff --check` passed on Go 1.27.3.

## Guard coverage follow-up

The helper regression suite checks three cases with multiple merge loops. An incomplete guard on
a later loop leaves a raw path. Two fully guarded loops preserve guarded status and attach both
write sites. Separate request-derived arguments produce separate candidates. The Next.js lab
exercises the application analyzer through its Pages and App Router source fixtures.
[Next.js scanner regressions](https://github.com/zazzcode/vuln-nextjs/tree/main/tests/scanner)

## Imported helper coverage

A source-only regression verifies three distinct records from an imported module. An aliased
recursive merge reached through a forwarding helper and an unbraced split-path loop each yield
a raw candidate. An own-property check yields a guarded path. A read-only traversal produces
no prototype-write candidate. The records carry the request operand and the write location in
the imported module. The architecture baseline is unchanged.

## Remaining verification

AC8 awaits an owner-authorized live judgment. AC9 follows phase 7 corpus keys and phase 8
library entries. The newer Lodash deletion advisories and additional npm packages are documented
for source-only corpus follow-up. [Version and corpus cases](../specifications/prototype-pollution.md#5-decisions).
