# PHP adapter implementation and evaluation (offline)

[Contract](../specifications/php-support.md) · [User guide](../../docs/php-support.md) ·
[DVWA detection guide](dvwa-detection-guide.md)

Offline ACs 1–13 of the contract are complete on branch `php-dvwa` (milestone `b825f5b`, gap
fixes `6b60ced`, gate `b921976`). The paid capped DVWA pass (AC14) is a separate, user-confirmed
step; its results will be recorded here when run. No paid requests have been spent.

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

Documented deviations from the Python adapter bounds: helper work budget is 96 per entry (DVWA
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
  XSS reflected/stored (+numeric row), path operands, code eval (+file eval), redirect, input
  facts, mixed repository, selection closures, CLI.
- DVWA integrity: `git status --porcelain` clean at `a1978a2` before and after every scan; no
  artifacts inside the sample tree.
- Paid usage: 0 requests (AC14 pending user confirmation; offline ACs 1–13 green).
