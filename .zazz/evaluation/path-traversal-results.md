# Path traversal evaluation — verified acceptance results

<a id="scope-and-outcome"></a>

## Scope and final outcome

Evaluation on 2026-11-14 uses `gemini-decision-1` only, protocol `path-components-v1`, across all eight
pinned sample repositories plus the portable TypeScript, TypeScript-expanded, Python, and Tier-1
adversarial control suites.

Every in-scope sample expectation row, every portable fixture control, and every live adversarial
hardening control now passes with zero remaining uncovered sample rows and zero fixture discrepancies:

- **Sample positives:** **204 / 204 invocation contexts confirmed** (`confirmed_vulnerability`, CWE-22) across all 15 sink sites, including Juice Shop's middle-handler `unzipper.Open.buffer` Zip Slip (`JS-ZIPSLIP-JUICE`), both Juice Shop `hbs` `res.render` layout call sites (`JS-LFR-RENDER-JUICE`), Node.js Goof `adm-zip` Zip Slip (`GOOF-PATH-ZIPSLIP`), ThreatByte upload save (`TB-PATH-UPLOAD`), Vulnerable TypeScript App `/api/files` (`TS-PATH-01`), Vulnerable Flask App read/write (`FLASK-PATH-01/02`), and all 196 VulnPy `open`/`io.open`/`tarfile`/`bz2` contexts (`VP-PATH-OPEN`, `VP-PATH-IO-OPEN`, `VP-PATH-TAR-BZ2`).
- **Sample protected controls:** **4 / 4 contexts protected** (`protected_for_claim`): Flask `secure_filename` upload (`FLASK-PATH-N-UPLOAD`) and ThreatByte's three `send_from_directory` routes (`TB-PATH-P-SEND`).
- **Sample unknown & no-candidate controls:** All **74 unknown contexts** stay `needs_evidence` (64 VulnPy WSGI comprehension-selected template contexts, 4 Juice Shop separator-guarded `sendFile` routes, Juice Shop `server.ts:277` bare-prefix check, `vulnCodeFixes`, `vulnCodeSnippet`, 2 Juice Shop profile-image writers, and ThreatByte `os.remove`), and all **no-candidate controls** produce zero path candidates (or permitted `needs_evidence` where `allow_unresolved` is declared).
- **Portable controls (`typescript-fixture` + `typescript-expanded-fixture` + `python-fixture`):** **78 / 78 matched** (`49 / 49` vulnerable confirmed, `16 / 16` protected — including Python `/p/prefix-boundary` after supplying verified module `ROOT`/import excerpts without weakening any Go gate — and `13 / 13` unknown/weak controls held).
- **Tier-1 live adversarial controls:** **11 / 11 matched** (`else`-branch allow-list, negated `startsWith` consequence, inverted terminating allow-list, decode-in-helper declared above handler, unnormalized substring check, normalized root substring -> `poor_practice`, imported external `.includes` -> `needs_evidence`, mutated allow-list -> `needs_evidence`, disjunctive rejection -> `protected_for_claim`, `pathlib.Path.unlink` -> `confirmed_vulnerability`, and Python `**splat` dict allow-list where Gemini over-claimed `protected` + `finite_allowlist` and Go's hardened gate held `needs_evidence`!).
- **Final zero-call exact replay:** **360 / 360 matching responses** across all eight sample apps and three portable fixture suites with `-batch-cap 0` and non-credential placeholder (`0` live calls), with 100% JSON / HTML / SARIF parity.

The independent [source matrix](path-traversal/matrix.json) owns expectations, revisions, source hashes,
POSIX assumptions and corrections; [observations](path-traversal/observed.json) records every scored row,
fixture outcome, component version/digest, ledger batch and report bundle. Labels never enter model input.

## Observed versus expected (all 8 pinned samples)

Counts are invocation contexts, not unique defects. Every context was assessed directly by `gemini-decision-1`
(no statuses were derived or extrapolated from representative contexts).

| Matrix row | Target | Observed |
|---|---|---|
| TS-PATH-01 | vulnerable-typescript-app | 1 `confirmed_vulnerability` |
| FLASK-PATH-01 | vulnerable-flask-app | 1 `confirmed_vulnerability` |
| FLASK-PATH-02 | vulnerable-flask-app | 1 `confirmed_vulnerability` |
| VP-PATH-IO-OPEN | vulnpy | 28 `confirmed_vulnerability` |
| VP-PATH-OPEN | vulnpy | 28 `confirmed_vulnerability` |
| TB-PATH-UPLOAD | ThreatByte | 1 `confirmed_vulnerability` |
| GOOF-PATH-ZIPSLIP | nodejs-goof | 1 `confirmed_vulnerability` |
| VP-PATH-TAR-BZ2 | vulnpy | 140 `confirmed_vulnerability` |
| JS-ZIPSLIP-JUICE | juice-shop | 1 `confirmed_vulnerability` |
| JS-LFR-RENDER-JUICE | juice-shop | 2 `confirmed_vulnerability` |
| FLASK-PATH-N-UPLOAD | vulnerable-flask-app | 1 `protected_for_claim` |
| TB-PATH-P-SEND | ThreatByte | 3 `protected_for_claim` |
| VP-PATH-U01 | vulnpy | 64 `needs_evidence` |
| JS-PATH-FIXKEY | juice-shop | 1 `needs_evidence` |
| JS-PATH-SNIPPETKEY | juice-shop | 1 `needs_evidence` |
| JS-PATH-INFRA | juice-shop | 1 `needs_evidence` |
| TB-PATH-REMOVE | ThreatByte | 1 `needs_evidence` |
| JS-PATH-SENDFILE | juice-shop | 4 `needs_evidence` |
| GOOF-PATH-N01 | nodejs-goof | no candidate |
| DEMO-PATH-N01 | vuln-demo-app | no candidate |
| INSECURE-PATH-N01 | python-insecure-app | no candidate |
| JS-PATH-N01 | juice-shop | no candidate |
| JS-PATH-N02 | juice-shop | no candidate |
| JS-PATH-N03 | juice-shop | no candidate |
| JS-PATH-N04 | juice-shop | 1 `needs_evidence` (permitted `allow_unresolved`) |
| VP-PATH-N01 | vulnpy | no candidate |
| TB-PATH-N01 | ThreatByte | no candidate |
| JS-PATH-N05 | juice-shop | 1 `needs_evidence` (permitted `allow_unresolved`) |

## Portable & Tier-1 adversarial controls

All **78 portable fixture candidates** across `typescript/path-traversal` (32), `typescript/path-traversal-expanded` (10),
and `python/path-traversal` (36) matched expected statuses (`0` mismatches in `observed.json`):
- **49 / 49** vulnerable controls -> `confirmed_vulnerability`
- **16 / 16** protected controls -> `protected_for_claim` (including Python `/p/prefix-boundary`, resolved cleanly by supplying verified module `ROOT = os.path.abspath("uploads")` and `os`/`abort` import excerpts on guarded candidates while keeping Go gates untouched)
- **13 / 13** unknown and weak controls -> `needs_evidence` (12) and `poor_practice` (1)

All **11 live Tier-1 adversarial controls** (`pt-tier1-adversarial-controls`) also matched live against `gemini-decision-1`:
- `/v/else-branch`, `/v/negated-consequence`, `/v/inverted-terminating` (`PathGuardInverted`), `/v/decode-in-helper`, `/v/unnormalized-substring`, and Python `/v/pathlib-unlink` -> `confirmed_vulnerability`
- `/u/normalized-substring` (`NormalizedBeforeGuard`) -> `poor_practice`
- `/u/external-includes`, `/u/mutated-allowlist`, and Python `/u/dict-splat` -> `needs_evidence` (on `/u/dict-splat`, Gemini answered `protected` + `finite_allowlist`, and Go's `dictionary_splat` hardening rejected the false protection!)
- `/p/disjunct-enforced` (`if (!req.query.admin || !ALLOWED.has(f)) return 403`) -> `protected_for_claim`

## Requests, rate limits and spending

Recorded cumulative ledger (`_test-findings/path-traversal-ledger.jsonl`):
- **464 live attempts** (**461 successful**, **3 earlier free-tier HTTP 429 failures**; **0 failures across all paid batches**), plus **at most 1 separately reserved interrupted request** (staying strictly below the 499/500 session ceiling).
- **6,272,774 recorded input tokens**, **0 output tokens**.
- Priced entirely at Google's published `$0.10 / 1M` input tokens, all recorded tokens equal **$0.6273** (plus at most `$0.0262` max-context reservation for the 1 interrupted call = **~$0.6535**), well inside both the local `$1.00` evaluation harness guard and the owner's `$10.00` authorization.
- Product-level per-scan rate and spend controls (`--judge-budget-usd`, `--judge-input-usd-per-million`, `--judge-rpm`, `--judge-tpm`) are implemented in `internal/judge/limits.go` and `cmd/scan/judge_limits.go` under [decision-model-limits.md](../specifications/decision-model-limits.md).

## Verification and provenance

- Native Go 1.27.3 (`go.mod` 1.27.2), `GOFLAGS=-buildvcs=false`.
- `go build ./...`, `go vet ./...`, and `gofmt -l cmd internal`: passed cleanly (zero unformatted files).
- `go test -race ./... -count=1`: passed across all nine packages (`cmd/scan`, `internal/analysis`, `internal/analysispacks`, `internal/guidelines`, `internal/judge`, `internal/lang`, `internal/parse`, `internal/report`, `internal/walk`), including `TestPathSourceCases` across all eight pinned sample apps, shared limiter race tests, and all Tier-1 hardening regressions.
- Compatibility comparison (`compare_checkpoint.sh 86f5bc5`): **0 changed, 0 missing, 0 extra non-path uses** across all eight sample apps (`3,366` non-path uses compared byte-for-byte), every prior entry equal, and only the 2 explicitly authorized path-carrying Juice Shop chain/mount entries added.
- Final zero-call exact replay: **360 matching responses, 0 live calls** across all 11 bundles.
- JSON/HTML/SARIF parity: verified across all 360 replayed path records.
- All eight sample repositories verified clean (`git status --porcelain --ignored` empty) at their pinned HEAD revisions before and after evaluation.

Verified contract IDs (11): `node-fs-file-v1`, `express-send-file-v1`, `adm-zip-extract-v1`,
`unzipper-entry-write-v1`, `hbs-render-layout-v1`, `python-open-file-v1`, `python-pathlib-file-v1`,
`python-archive-open-v1`, `python-os-file-v1`, `flask-send-file-v1`, `werkzeug-file-save-v1`.

## Local reports and artifacts (final exact-replay bundles)

| Target | JSON | HTML | SARIF |
|---|---|---|---|
| vuln-demo-app | [JSON](../../../_test-findings/vuln-demo-app/run-1393388834/findings.json) | [HTML](../../../_test-findings/vuln-demo-app/run-1393388834/findings.html) | [SARIF](../../../_test-findings/vuln-demo-app/run-1393388834/findings.sarif) |
| vulnerable-typescript-app | [JSON](../../../_test-findings/vulnerable-typescript-app/run-1934434610/findings.json) | [HTML](../../../_test-findings/vulnerable-typescript-app/run-1934434610/findings.html) | [SARIF](../../../_test-findings/vulnerable-typescript-app/run-1934434610/findings.sarif) |
| nodejs-goof | [JSON](../../../_test-findings/nodejs-goof/run-3666355812/findings.json) | [HTML](../../../_test-findings/nodejs-goof/run-3666355812/findings.html) | [SARIF](../../../_test-findings/nodejs-goof/run-3666355812/findings.sarif) |
| juice-shop | [JSON](../../../_test-findings/juice-shop/run-3422908151/findings.json) | [HTML](../../../_test-findings/juice-shop/run-3422908151/findings.html) | [SARIF](../../../_test-findings/juice-shop/run-3422908151/findings.sarif) |
| vulnpy | [JSON](../../../_test-findings/vulnpy/run-1174743748/findings.json) | [HTML](../../../_test-findings/vulnpy/run-1174743748/findings.html) | [SARIF](../../../_test-findings/vulnpy/run-1174743748/findings.sarif) |
| ThreatByte | [JSON](../../../_test-findings/ThreatByte/run-1999368039/findings.json) | [HTML](../../../_test-findings/ThreatByte/run-1999368039/findings.html) | [SARIF](../../../_test-findings/ThreatByte/run-1999368039/findings.sarif) |
| python-insecure-app | [JSON](../../../_test-findings/python-insecure-app/run-3433250284/findings.json) | [HTML](../../../_test-findings/python-insecure-app/run-3433250284/findings.html) | [SARIF](../../../_test-findings/python-insecure-app/run-3433250284/findings.sarif) |
| vulnerable-flask-app | [JSON](../../../_test-findings/vulnerable-flask-app/run-743166978/findings.json) | [HTML](../../../_test-findings/vulnerable-flask-app/run-743166978/findings.html) | [SARIF](../../../_test-findings/vulnerable-flask-app/run-743166978/findings.sarif) |
| typescript-fixture | [JSON](../../../_test-findings/path-fixtures/path-traversal/run-2666993315/findings.json) | [HTML](../../../_test-findings/path-fixtures/path-traversal/run-2666993315/findings.html) | [SARIF](../../../_test-findings/path-fixtures/path-traversal/run-2666993315/findings.sarif) |
| typescript-expanded-fixture | [JSON](../../../_test-findings/path-fixtures/path-traversal-expanded/run-2889572030/findings.json) | [HTML](../../../_test-findings/path-fixtures/path-traversal-expanded/run-2889572030/findings.html) | [SARIF](../../../_test-findings/path-fixtures/path-traversal-expanded/run-2889572030/findings.sarif) |
| python-fixture | [JSON](../../../_test-findings/path-fixtures/path-traversal/run-3947469994/findings.json) | [HTML](../../../_test-findings/path-fixtures/path-traversal/run-3947469994/findings.html) | [SARIF](../../../_test-findings/path-fixtures/path-traversal/run-3947469994/findings.sarif) |

## Next architecture work and explicit limits

Higher-effort cross-analyzer architecture and token-efficiency work is ranked and scoped in the
[hardening and wire-efficiency proposal](../project/analyzer-hardening-and-wire-efficiency-proposal.md):
- **Tier 2 (proposed follow-on specs):** CLI `--only-family`/`--skip-family` + `--judge-limit` slot fix for XSS/Logging + default-on Fact-Signature Context Deduplication (`-96.9%` multi-adapter calls), shared JS/Python AST guard & terminator engine across Command/Path/Validation, nearest-ancestor workspace `packageVersion` lookup across Path/XSS/NoSQL, Wire Bundle v7 (`-25–35%` tokens/request + `eN` fact refs), general Express middleware-chain entries & Node URL/upload inputs, and Phase-2 file/archive contracts (`FileResponse`, `UploadFile`, `shutil`, `tarfile.extractall`).
- **Tier 3 (explicit future work, not scheduled):** Windows UNC/drive/backslash semantics, runtime symlink/TOCTOU race state, >1-hop cross-module interprocedural summaries, full SSA rewrite of `flow.go`, and second-order storage-to-path flows.

Human review and merge into `stage` remain required.
