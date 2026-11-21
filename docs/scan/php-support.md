# PHP analysis

[Documentation](../README.md) · [Analysis rules](analysis/README.md) · [PHP evaluation](../../.zazz/evaluation/php-support-results.md)

Zazzles analyzes a bounded plain-PHP subset through the same evidence, decision and reporting
pipeline as JavaScript/TypeScript and Python. It reads source; it does not execute the
application, install its dependencies, open its database, or make the outbound requests found in
the code. The acceptance corpus is DVWA at revision `a1978a2`; framework-specific entry discovery for Drupal and Symfony is planned. Verified Twig template-source
operations are covered by the [template injection analyzer](detection-capabilities/template-injection.md).

```sh
go build -o bin/scan ./scan/cmd/scan
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
| Sources | `$_GET`/`$_POST`/`$_REQUEST`/`$_COOKIE`/`$_SERVER`/`$_FILES` superglobals (keyed and whole, e.g. `reset($_GET)`, `foreach ($_POST …)`), `php://input` body origin (and `json_decode` of that raw body, whose fields stay request values), `$_SESSION` as storage linked to writes from every entry, `$GLOBALS` idiom |
| Flow | Assignments (including `=&`), string interpolation and concatenation with raw templates, `if`/`elseif`/`else` (braced, braceless and colon forms), `switch`, loops and `foreach` bindings, `die`/`exit` termination, helper expansion with global propagation, flow-scoped `define()` constants, `require`/`include` dispatch over finite switch alternatives with the selector narrowed per alternative, `__DIR__`/`dirname(__FILE__)` paths |
| Classes | Every class, interface, trait and enum is indexed by the fully qualified name its file declares; a name resolves through the module's namespace, `use` clauses (aliases and group use) and leading-backslash form, and only when exactly one declaration exists (otherwise `php_class_unresolved` names the reason). `new C(...)` binds the object to its class across files and expands `__construct`; `$obj->m()`, `$this->m()`, `self::`, `static::` and `parent::` resolve through the class, its used traits and its in-repository `extends` chain to depth 4, regardless of visibility. Objects carry a property map written by `$this->p = v` and promoted constructor parameters and read by `$this->p`/`$obj->p`; a dynamic property name or an unexpanded method marks the map unknown. A `switch` on a finite literal set (for example a property set from a constant) enters only the matching cases |
| SQL | mysqli (OO and procedural, including the `$GLOBALS["___mysqli_ston"]` converter idiom), PDO and SQLite3 prepare/bind/execute with binding controls, interpolated-statement claims with storage attribution |
| Command | `shell_exec`/`exec`/`system`/`passthru`/`popen`/`proc_open`/backticks with shell-operand facts; `escapeshellarg` is a control; a literal `str_replace` deny-list that leaves a shell metacharacter stays raw; `is_numeric` on `explode` elements constrains them; a `preg_match` capture group records a `regex_capture` transform ([command rules](analysis/command-injection.md#facets-and-outcomes)) |
| XSS | `echo`/`print`/`<?= ?>` render values with the output context taken from the surrounding inline HTML (text, attribute, URL, script, style), reflected and stored claims, `php-sql:<table>.<column>` storage links from INSERT and UPDATE column attribution across branch joins (string and numeric `fetch_row` access), `htmlspecialchars`/`htmlentities` transforms, `urlencode` as a markup/URL-scoped control |
| Path | `include`/`require` dynamic targets, `move_uploaded_file` upload moves, filesystem read/write calls; `basename`/allowlist restrictions are controls, not sink removals |
| Upload | `move_uploaded_file` also yields a `file_upload_candidate` with stored-name, type-control and served-destination facts ([file upload rules](analysis/file-upload.md)) |
| Code and templates | `eval`, string `assert` and `create_function` as interpreter operands. A `file_get_contents` return retains its path's dependencies. Verified Twig `createTemplate` and `template_from_string` take a template-source operand |
| Redirect | `header('Location: …')` (prefix case-insensitive) with destination facts; non-Location headers are not redirects |
| Validation | Superglobal-to-field policy from source-backed forms; a browser constraint is not server enforcement. Missing business requirements stay uncertain. |

SQL construction is a practice finding independently of an injection judgment. Bound parameters
protect their data slots, not interpolated identifiers. Input-validation policy, injection
protection and HTML context remain distinct questions; per-family interpretation lives in the
[analysis rules](analysis/README.md).

Stored links use INSERT/UPDATE column attribution and SELECT header resolution, retaining
writing entries, source hashes and transfer evidence. They are potential field flows, not proof
that a particular row was written or a deployed database matches the source. Column attribution
is exact-count-or-skip: a write whose interpolation count does not match its column list
produces no invented origin, and the read stays an unresolved-origin Review. `$_SESSION` reads
link the writes found in every entry once all entries are analyzed; this establishes possible
writers, not request ordering. A key with no writer stays unresolved, and a render whose stored
writers are all server-generated (`md5(uniqid())`, literals) carries no request content. A render
that also has a direct raw request path stays a reflected claim with its unresolved stored
siblings visible.

Helper expansion is bounded to depth 4 and 256 helper calls per entry, include nesting to 8
(include cycles are not re-entered), source files to 2 MiB,
dependency paths to 64 and evidence merges are content-deduplicated. Conditional dispatch
switches join only changed variables. A method call that the expansion bound stops keeps its
unresolved result and marks its object's properties unknown. A parent class or trait outside the
scanned files leaves a gap only when the method is not found before it. Loops, references/aliases,
dynamic calls by variable name, polymorphic dispatch through interfaces, Composer autoload
mapping (namespace declarations are read directly) and unresolved dynamic includes
(`php_dynamic_include` gaps) are incomplete. Reached bounds and unresolved values stay visible
and cannot establish protection.

Library contracts: [mysqli](https://www.php.net/manual/en/book.mysqli.php),
[PDO](https://www.php.net/manual/en/book.pdo.php),
[SQLite3](https://www.php.net/manual/en/book.sqlite3.php),
[escapeshellarg](https://www.php.net/manual/en/function.escapeshellarg.php),
[htmlspecialchars](https://www.php.net/manual/en/function.htmlspecialchars.php).

The shared [trace judgment design](../../.zazz/architecture/trace-judgment.md) documents evidence
roles, trace/control edges, exact named-field policies, model consistency gates and reporting.
Only Protected is green. See the [PHP evaluation](../../.zazz/evaluation/php-support-results.md)
for DVWA coverage, the detection guide and remaining gaps.
