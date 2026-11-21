# Prototype pollution walk start results

[Contract](../specifications/pollution-walk-start.md) · [Coverage and known gaps](../../docs/detection-capabilities/prototype-pollution.md)

## Probe and policy outcomes

AC1 passed at `c7d781638988e089b6b222cc1b6734b1f3e327ae` before recognizer changes. This
was the merge of PR #35 and included the probe baseline revision `dafd25d`.

| Probe | Start | Baseline | Final offline result |
|---|---|---|---|
| p0 | Parameter | 1 | One raw path walk |
| p1 | Module binding | 0 | One raw path walk with the binding declaration |
| p2 | Local object | 0 | One raw path walk with the local declaration |
| p3 | Fixed property | 0 | One raw path walk with the object declaration |
| p4 | Module binding through `reduce` | 0 | One raw path walk with the binding declaration |
| p5 | Inline handler | 0 | One complete raw path walk at the final assignment |
| p6 | Class field | 0 | No record. Instance-to-method resolution is outside the existing call resolver |
| p7 | Null-prototype module binding | 0 | One Review record with `null_prototype_root` |

Seven fixture sets cover index loops into module, local and fixed-property state, module
`reduce`, `forEach` and `while`, and a walk in the handler. Each includes a raw write,
a complete deny-list, a deny-list that omits `constructor` and `prototype`, and a
constant-path control. The 35 corresponding stubbed judgment cases passed. Complete guards
can be Protected. The partial guards list their open route and reject Protected answers.
Separate controls check root reassignment, cursor replacement, fixed bracket properties,
opaque and imported initializers, distinct starts at one call, and repeated null roots.

The positive expectation for p6 failed with the current resolver. It resolves plain and
imported function names but cannot connect `settings.set` on `new Settings()` to the class
method, so it cannot verify `this.state`. The existing probe now pins zero records and the
coverage page tracks `PP-N15`.

## Six-sample noise check

The baseline, post-blocker, post-deny-list, post-walk and final scanners used
`scan --analyze --json --output-dir ""` with an empty environment apart from `PATH`.
Five source checkouts were clean at their recorded pins before and after. The local vuln-nextjs
checkout had advanced, so the scan used a Git archive of the pinned revision.

| Sample | Pin | All records before → after | Pollution before → after |
|---|---|---|---|
| Juice Shop | `f189f521266f` | 255 → 255 | 4 → 4 |
| Node.js Goof | `add14ba59e98` | 36 → 36 | 1 → 1 |
| OSS OopsSec Store | `2d530ef3c0e6` | 128 → 128 | 0 → 0 |
| Vuln Demo App | `d27b35bdd2d5` | 19 → 19 | 0 → 0 |
| Vulnerable TypeScript App | `7f8b240a2f02` | 27 → 27 | 1 → 1 |
| vuln-nextjs | `a6f6c815e4ca` | 54 → 54 | 0 → 0 |

The blocker and deny-list changes did not make any sample record complete. No new write site
or entry path appeared. All 88 keyed app rows and all 32 pinned lab rows matched. No keyed
control gained a record. `GOOF-PP-01` and `TS-PP-01` kept one
complete raw candidate each, at `routes/index.js:360` and `src/server.ts:246`, respectively.
The other analysis families had identical candidate evidence, 421 matching offline request
digests and 92 matching preview errors. The architecture baseline retained all 59 existing
rows byte-for-byte and added seven fixture rows.

### Juice Shop `JS-PP-R01`

All four records still point to `lib/accuracy.ts:71`. The two
`POST /snippets/verdict` paths now carry `map_membership` evidence from
`routes/vulnCodeSnippet.ts` and `lib/codingChallenges.ts`. This changes their candidate
IDs. The Map is filled from keys parsed from files at runtime, so the analyzer leaves its
coverage unknown. The two `POST /snippets/fixes` paths use an object cache and a property
access that throws for the reviewed inherited inputs. Their existing Review records stayed
the same. The source-reviewed verdict for this pin is that confirming any of the four paths
would be a false positive. The same key row covers all four under `review`.

## Final checks

Go 1.27.3 passed `gofmt -l cmd internal` with no output, `go vet ./...`, `go build ./...`,
and `go test -race ./... -count=1`. The race suite used loopback access for local HTTP
stubs. The independent focused pollution and architecture tests also passed. Documentation
checks covered changed relative links and anchors, JSON syntax and `git diff --check`.

## Carryover closeout

- `PP-R06` and `PP-R11` have separate changes and failing-first tests. Unresolved calls before
  the write and mutable or escaped collections have negative controls.
- The `set-in` 2.0.3 advisory reading still rests on source and the earlier transcription.
  The downloaded package's runtime reproduction remains unverified. [Prior library evaluation](pollution-write-shapes-results.md#real-advisory-libraries)
- The prototype-pollution coverage page is present on the starting revision. Coverage pages
  for the other classes belong to the separate documentation work.
- Independent verification used static probes and offline judgment stubs. The sample
  applications and Node payload checks were not executed.
