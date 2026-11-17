# PHP analysis

[Documentation](README.md) · [Analysis rules](analysis/README.md) · [PHP evaluation](../.zazz/evaluation/php-support-results.md)

Zazzles analyzes a bounded plain-PHP subset through the same evidence, decision and reporting
pipeline as JavaScript/TypeScript and Python. It reads source; it does not execute the
application, install its dependencies, open its database, or make the outbound requests found in
the code. The acceptance corpus is DVWA at revision `a1978a2`; framework-specific PHP (Drupal,
Symfony, Twig) is separate future work.

```sh
go build -o bin/scan ./cmd/scan
./bin/scan --routes --json /path/to/php-app
./bin/scan --analyze --entry vulnerabilities/sqli/index.php --output-dir /path/to/findings /path/to/php-app
```

Omit `--entry` to discover all server-mapped `.php`/`.phtml` files, including mixed
JS/TS/Python/PHP repositories. The output directory receives `<app>/run-<id>/findings.json`,
`findings.html` and `findings.sarif`. Optional [decision assessment](decision-models.md)
transmits bounded evidence only when requested. Structural findings remain useful without a
model; neither mode certifies an application as safe.

| Area | Implemented subset |
| --- | --- |
| Entries | Server-mapped `.php`/`.phtml` file entries with deterministic identity and normalized path metadata |
| Sources | `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/`$_FILES` superglobals, `php://input` body origin, `$_SESSION` as storage with write→read transfers, `$GLOBALS` idiom |
| Flow | Assignments/reassignments, string interpolation and concatenation with raw templates, conditional (switch/if) value alternatives, helper expansion with global propagation, `require`/`include` dispatch over finite switch alternatives |
| SQL | mysqli (OO and procedural, including the `$GLOBALS["___mysqli_ston"]` converter idiom), PDO and SQLite3 prepare/bind/execute with binding controls, interpolated-statement claims with storage attribution |
| Command | `shell_exec`/`exec`/`system`/`passthru`/`popen`/`proc_open`/backticks with shell-operand facts; `escapeshellarg` is a control |
| XSS | `echo`/`print` HTML render values, reflected and stored claims, `php-sql:<table>.<column>` storage links from INSERT column attribution (string and numeric `fetch_row` access), `htmlspecialchars`/`htmlentities` transforms |
| Path | `include`/`require` dynamic targets, `move_uploaded_file` upload moves, filesystem read/write calls; `basename`/allowlist restrictions are controls, not sink removals |
| Code | `eval`, string `assert`, `create_function` as whole-program interpreter operands; `file_get_contents` returns carry their path's dependency paths (path control is content control) |
| Redirect | `header('Location: …')` (prefix case-insensitive) with destination facts; non-Location headers are not redirects |
| Validation | Superglobal-to-field policy from source-backed forms; a browser constraint is not server enforcement. Missing business requirements stay uncertain. |

SQL construction is a practice finding independently of an injection judgment. Bound parameters
protect their data slots, not interpolated identifiers. Input-validation policy, injection
protection and HTML context remain distinct questions; per-family interpretation lives in the
[analysis rules](analysis/README.md).

Stored links use literal INSERT column attribution and SELECT header resolution, retaining
writing entries, source hashes and transfer evidence. They are potential field flows, not proof
that a particular row was written or a deployed database matches the source. Column attribution
is exact-count-or-skip: an INSERT whose interpolation count does not match its column list
produces no invented origin, and the read stays an unresolved-origin Review. Cross-entry session
write ordering is not established; a `$_SESSION` read whose writing helper expanded in another
entry stays unresolved rather than linked.

Helper expansion is bounded to depth 3 and 96 work units per entry, source files to 2 MiB,
dependency paths to 64 and evidence merges are content-deduplicated. Conditional dispatch
switches join only changed variables. Loops, references/aliases, dynamic calls by variable name,
object polymorphism, interface inheritance and unresolved dynamic includes
(`php_dynamic_include` gaps) are incomplete. Reached bounds and unresolved values stay visible
and cannot establish protection.

Library contracts: [mysqli](https://www.php.net/manual/en/book.mysqli.php),
[PDO](https://www.php.net/manual/en/book.pdo.php),
[SQLite3](https://www.php.net/manual/en/book.sqlite3.php),
[escapeshellarg](https://www.php.net/manual/en/function.escapeshellarg.php),
[htmlspecialchars](https://www.php.net/manual/en/function.htmlspecialchars.php).

The shared [trace judgment design](../.zazz/architecture/trace-judgment.md) documents evidence
roles, trace/control edges, exact named-field policies, model consistency gates and reporting.
Only Protected is green. See the [PHP evaluation](../.zazz/evaluation/php-support-results.md)
for DVWA coverage, the detection guide and remaining gaps.
