# Testing

Testing conventions for `zazzles`. Applies to `cmd/`, `internal/`, `testdata/`, and CI workflow changes.

## 1. Principles

- Tests are the acceptance evidence for a deliverable. A deliverable that changes behavior without a
  test change has no evidence.
- Tests must be deterministic. No wall-clock dependence, no map-iteration-order dependence, no
  goroutine-scheduling dependence, no network access.
- Unit tests never call live Jev or LLM services. Semantic adapters use fixed typed responses.
- A test that can only pass on the author's machine is a bug in the test.

## 2. Test kinds

| Kind | Scope | What it proves |
|---|---|---|
| Unit | one function or rule | classification and transformation logic in isolation |
| Table-driven | rules, resolvers, bundlers | many inputs against expected outputs in one readable table |
| Golden file | parsing and resolution | a fixture repository produces the expected normalized graph |
| Graph fixture | path search and pruning | a hand-built graph yields the expected paths |
| End-to-end | the whole pipeline | a fixture repo plus a stubbed semantic adapter produces the expected JSON report |

Not every deliverable needs every kind. Every deliverable needs at least one that would fail if the
behavior regressed.

## 3. Table-driven tests

Prefer one table over many near-identical test functions:

- name each case with a short, specific string
- give each case the smallest input that exercises the difference
- assert on the specific field that matters, not on a whole struct dump, unless the whole struct is
  the contract
- keep the table next to the assertions so a reader can see input and expectation together

## 4. Golden files

Parsing and resolution are golden-file tested because the output is large and structural:

- fixtures live under the owning package's `testdata/` (for example `internal/langjs/testdata/<language>/<case>/`,
  `internal/langpy/testdata/<case>/`; multi-language fixtures in `internal/pipeline/testdata/mixed/`) as real source files
- expected output lives beside them as a descriptive `.json` golden file
- update goldens with an explicit `-update` flag, never by hand-editing
- always review the golden diff in the PR — an unexplained golden change is the whole review
- golden files are ordered deterministically; if they are not, fix the emitter, not the test

## 5. Graph fixtures

Path search and pruning are tested against hand-built graphs rather than parsed source. This keeps the
test about the traversal algorithm:

- construct nodes and edges directly in the test
- assert on the exact ordered node IDs of each returned path
- include a case with a cycle, a case with an unreachable sink, and a case where a middleware node
  gates a sink
- assert that dead-end pruning removes what it should and nothing more

## 6. Concurrency

Parallel stages are tested for equivalence, not just for absence of races:

- run `go test -race ./...` as part of the change
- for any stage with a worker pool, assert that parallel output equals sequential output for the same
  input
- never assert on goroutine counts, timing, or completion order

## 7. Semantic adapter stubbing

Current semantic judge adapters (`internal/judge`) MUST be tested against a local `httptest`
server, never a live endpoint. The same requirement applies to a future independent reviewer:

- the stub returns fixed, schema-valid responses
- test the failure paths explicitly: timeout, malformed JSON, non-200 status, and retry exhaustion
- structural-only mode is tested with no endpoint configured at all
- missing/wrong-kind answers, invalid ranges/options, partial failure, cancellation, and exhausted
  budgets remain explicit; they never become safe results
- live semantic evaluation is a separate opt-in experiment on versioned human-labeled cases; its
  credentials and results are not unit-test requirements

## 8. Commands

```bash
go test ./...                    # all tests
go test -race ./...              # race detector
go test ./internal/langjs/...    # one package while iterating
go test ./internal/pipeline/... -run TestExpressLoginGolden -update   # refresh goldens
go vet ./...                     # static checks
gofmt -l .                       # must print nothing
```

## 9. Evidence expected on a PR

- the exact command(s) run and their result
- for golden changes, the golden diff reviewed and explained
- for concurrency changes, the `-race` result
- for anything touching a semantic adapter, the stubbed-path results including the failure cases
- no skipped tests left behind, and no test disabled to make the change land
