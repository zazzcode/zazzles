# PHP adapter implementation and evaluation

[Contract](../specifications/scan/php-support.md) · [User guide](../../docs/scan/php-support.md) ·
[DVWA detection guide](dvwa-detection-guide.md) · [Published sample](../../docs/samples/dvwa/README.md)

All fourteen acceptance criteria are complete on branch `php-dvwa` (milestone `b825f5b`, gap
fixes `6b60ced`, gate `b921976`, docs `97fbbe0`, judge-contract alignment `1fa7b70`/`4744919`/`1deee35`).
The paid capped pass ran after explicit user re-confirmation.

## Delivered behavior

The PHP adapter uses tree-sitter-php v0.23.12 and supplies the existing graph, versioned decision
protocols and JSON/HTML/SARIF pipeline. It discovers server-mapped `.php`/`.phtml` file entries,
tracks a bounded value-flow subset (interpolation templates, conditional switch alternatives,
helper expansion with `$GLOBALS` propagation, `require`/`include` dispatch over finite
alternatives), and verifies mysqli/PDO/SQLite3, program-execution, filesystem/upload/include,
eval and header-redirect bindings. Input facts assemble under `source.php-input-v1`. No
application code, dependency installation, database query or outbound request from the target was
executed.

Contracts: `php-mysqli-v1`, `php-pdo-v1`, `php-sqlite3-v1`, `php-program-execution-v1`,
`php-include-v1`, `php-upload-move-v1`, `php-filesystem-v1`, `php-eval-v1`,
`php-header-redirect-v1`, `render.php-html-output-v1`, `source.php-input-v1`. Selection closure
covers the six families plus validation; NoSQL/SSRF/logging never select for PHP.

Documented deviations from the Python adapter bounds: helper work budget is 256 calls per entry (DVWA
page assembly chains more helpers than a Flask handler; depth 3 kept), gap/evidence merges dedupe
by content (branch clones inherit parent state; plain append doubles per conditional), and
conditional joins use a dirty-set (only changed variables rejoin). These took a DVWA entry from
unbounded growth to ~0.3 s.

## DVWA offline scan (AC12)

Full-tree offline scan of the pinned checkout (`a1978a2fed195acd093010af6395f86a281537ca`), clean
before and after; artifacts under `_test-findings/dvwa/run2/` (46 MB JSON, 278 findings).

| Family | Findings | Notes |
| --- | --- | --- |
| SQL injection | 172 | All four security-level alternatives per module, including impossible-level PDO/SQLite3 prepare+bind claims with binding controls |
| Reflected XSS | 76 | Sinks physically shared in `dvwaPage.inc.php:388`; module attribution rides input-fact source spans |
| Stored XSS | 9 | `php-sql:guestbook.{comment,name}` links resolve to the writing entry (INSERT column attribution + numeric `fetch_row` SELECT-header resolution) |
| Path traversal | 18 | fi include dispatch, upload moves, `file_get_contents` reads (incl. `view_help.php`, `view_source*.php`) |
| Command injection | 16 | `shell_exec` ping chains; `escapeshellarg` recorded as a quoting control |
| Open redirect | 3 | Lowercase `location:` accepted case-insensitively |
| Code injection | 2 | `view_help.php:20`/`:22` eval over `file_get_contents` concat; path control is content control |

All twelve required modules of the detection guide produce their required candidate kind, every
record survives judge selection, and no parse errors were reported. `ZAZZLES_DVWA=<checkout>
go test ./internal/parse -run TestDVWASourceKey` verifies this offline (pin enforced).

Accuracy iterations during the offline scan:

- **Stored link empty column.** `dvwaGuestbook()` reads `mysqli_fetch_row` numeric subscripts;
  the read key was `php-sql:guestbook.` (no column) and never matched the INSERT-recorded writes.
  Numeric subscripts now resolve through the SELECT header columns (`TestPHPXSSStoredNumericRow`).
- **Missing eval taint.** `file_get_contents` returned an unknown value and dropped its
  argument's dependency paths, so the `view_help.php` eval operand was untainted. The return now
  carries the path's dependency paths with literal identity cleared (`TestCodePHPFileEval`).

## Remaining boundaries (bounded, reported honestly)

- `php-session:session_token` / `php-session:id` reads stay origin-unresolved: the session write
  helper expands in a different entry than its readers; cross-entry session write ordering is not
  established.
- `php-sql:bac_log.timestamp` stays origin-unresolved: the `bac_log` INSERT mixes a
  non-dependency `NOW()` column with one interpolation; exact-count-or-skip declines to invent a
  mapping.
- Loops, references/aliases, dynamic calls by variable name, object polymorphism and interface
  inheritance are unmodeled; unresolved dynamic includes yield `php_dynamic_include` gaps.
- SSRF, sensitive-data logging and NoSQL are out of contract scope for this deliverable; Drupal,
  Symfony and Twig support is separate future work.

## Verification and provenance

- `go test ./... -count=1`, `go vet ./...`, changed-file `gofmt`, `git diff --check` green at each
  pushed commit; full `-race` snapshot green before the milestone, re-run before the PR.
- Hermetic PHP suites: routes golden, entries, include dispatch, SQL contracts, command operands,
  XSS reflected/stored (+numeric row), path operands (+allowlist guard), code eval (+file eval),
  redirect, input facts, mixed repository, selection closures, CLI.
- DVWA integrity: `git status --porcelain` clean at `a1978a2` before and after every scan; no
  artifacts inside the sample tree.

## Paid capped pass (AC14)

User re-confirmed the capped run (quota reset twice after provider-side interruptions). Final
run `run-1226915911` at scanner `1deee35`, OpenAI `gpt-6-luna` via `--judge openai`, no
fallback, `--judge-limit 300`: **292 of 296 records assessed (2,417,921 input tokens), 292/292
replayed exactly offline** (`TestReplaySavedRun`). Outcomes: 107 Confirmed, 9 Protected,
30 needs-evidence, 150 practice, 4 unsent. The sample is published under
[docs/samples/dvwa/](../../docs/samples/dvwa/README.md).

Gate results against the detection guide: every cataloged required positive is Confirmed —
SQLI-001/002, AUTH-001, CSRF-001, CMD-001, XSSR-001, XSSS-001 (INSERT construction; the stored
render link resolves and the four render records exceed the 64KB wire limit, documented), FI-001,
REDIR-001, CODE-001. No record whose dependency sources are exclusively impossible-level is red;
impossible-level controls ride dispatch-merged records as sibling paths with their own recorded
protections. Guide corrections from deeper source review during the paid phase: AUTH-002
(captcha) is candidate-only (md5-hashed and session-sourced operands — no raw request→SQL path);
UPLD-001 (upload) is a control outcome (basename guards the destination at every level).

Diagnostic runs before the final pass, each with a bounded adapter fix (no provider retries):
run `4262277296` (292 requests) exposed claim-kind/evidence-role mismatches that made every
non-SQL family unjudgeable (`command`/`path` vs `command_execution`/`path_traversal`, missing
`input_source` and `render_binding` roles) and flow-wide gap blockers vetoing raw witnesses;
run `1574628177` (292) exposed invalid path-facts slots/roles (`uploaded_tmp_name`,
`destination_path`, include `execute`) and the unmodeled `!in_array` membership guard that made
fi's impossible level red; run `274306850` stopped after 153 requests on provider HTTP 503s (a
15-request probe confirmed recovery); run `paid4` (292) confirmed every family and exposed the
remaining fi-impossible false positive fixed by guard modeling at `1deee35`.

**Cumulative paid usage: 1,336 requests** (292 + 292 + 154 + 14 probe + 292 + 292), all against
the user's OpenAI account with per-run caps honored; the 300-request contract cap applies to the
accepted final pass.


## Independent review (post-AC14)

The review rebased the branch onto `stage` `86efc7e` (replay of the AC14 run still 292/292 exact),
fixed the flow, guard, include, storage and fact-contract defects listed in the contract change
log, and re-ran paid passes on DVWA and on a second sample, php-goof. Regressions live in
`internal/parse/php_flow_test.go`. Evaluation of record at scanner `bc40266` (OpenAI `gpt-6-luna`,
no fallback, per-family runs that each replay exactly at that commit): **115 Confirmed, 12
Protected, 110 Review, 2 Practice** over 240 records (AC14 at `1deee35`, counted the same way:
107 / 10 / 177 / 2 over 296). Every detection-guide positive has its expected outcome, apart from
the documented render wire limit and two judge disagreements (CMD-001 impossible, UPLD-001).
`TestDVWASourceKey` passes. php-goof: all three source-reviewed SQL injections are Confirmed; the
reflected attribute XSS stays Review on a judge context disagreement.

Case-by-case expected-vs-found tables, findings beyond the guide, practice and input-validation
results, and the 8 records changed after the paid runs are in the
[sample analysis](php-sample-analysis.md).

**Review paid usage: 721 requests** (php-goof 64 across six runs including three 7-request XSS
probes; DVWA 657 across four runs: 222 + 230 full, 124 SQL/command, 81 XSS), about 6.6M input
tokens, per-run caps honored. Cumulative PHP paid usage including AC14: 2,057 requests.
