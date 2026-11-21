# Path traversal analysis

[Analysis index](README.md) · [Command injection](command-injection.md) · [Input validation](input-validation.md) · [Coverage and known gaps](../detection-capabilities/path-traversal.md)

The Path Traversal Analyzer traces request values into the file-path argument of verified
filesystem reads and writes in JavaScript, TypeScript, Python and plain PHP. It separates three claims: whether
request text can select a file outside the intended location, what enforced **containment** (if any)
prevents that, and whether every request-derived path and branch is covered. Field validation is a
different claim with its own record. Reports state a static source judgment (CWE-22) under a declared
POSIX assumption; they never claim runtime exploitation, symbolic-link or filesystem-state analysis,
or independent Findings Review.

## What is verified

| Language | Verified operations (actual binding required) | Effective path operand |
|---|---|---|
| JS/TS | `fs.readFile`, `readFileSync`, `writeFile`, `writeFileSync`, `appendFile`, `appendFileSync`, `createReadStream`, `createWriteStream`, `unlink`, `unlinkSync`, `rm`, `rmSync`; `fs/promises` and `fs.promises` forms | first argument; the data argument of a write is not a path |
| JS/TS | Node `fs.open`, `readdir`, `stat`, `lstat` and their supported synchronous variants | first path argument |
| JS/TS | Node `fs.copyFile`, `fs.rename` and their supported synchronous variants | source and destination are independent paths |
| JS/TS | Express `res.sendFile`, `res.download` (a parameter of the enclosing handler, module imports `express`) | first argument; a constant `root` option adds library-enforced containment |
| JS | `adm-zip` `extractAllTo` on an `AdmZip(...)` instance | the request-supplied archive (entry names), see below |
| JS/TS | Caller writes from verified `unzipper.Open.buffer(...).files` entry names; `hbs` `res.render` with verified view-engine registration | archive `entry.path`, or the effective `options.layout` after spreads/overrides |
| Python | builtin `open`, `io.open` | first positional argument or `file=`; the mode decides read or write |
| Python | `pathlib.Path.open/read_text/read_bytes/write_text/write_bytes/unlink` | the `Path` receiver (built by `Path(...)`, a module-level `Path`, or the `/` operator) |
| Python | `tarfile.open`, `TarFile`, `TarFile.open`, `bz2.open`, `BZ2File`, `gzip.open`, `GzipFile`, `lzma.open`, `LZMAFile` | the file name argument |
| Python | `os.remove`, `os.unlink` | first argument |
| Python | Flask `send_file`, `send_from_directory` | `send_file`: first argument; `send_from_directory`: its `path` argument (library `safe_join` against a directory that is not request-derived) |
| Python | Starlette or FastAPI `FileResponse` | response file path |
| Python | `shutil.copy`, `copy2`, `copyfile`, `move` | source and destination are independent paths |
| Python | `TarFile.extractall` | archive member provenance and extraction destination. Missing or dynamic filters leave a runtime-policy gap |
| Python | werkzeug `FileStorage.save` on a value from `request.files` | the destination argument; `secure_filename` is a verified control |

Bindings come from ESM default, namespace and named imports, CommonJS `require` and destructuring (including
`require('fs').promises`), `fs.promises`, Python module and from imports and the unshadowed builtin `open`. A fake object, a local
module named `fs`, a reassigned binding, a parameter, a local `def open` or `def secure_filename`, an import
named `open` from another module, or a source-visible patch earns no verified contract. Spreads and
`*args`/`**kwargs` stay visible blockers.

A call whose path operand has no request-derived value is not a candidate. Request data written as file
**content** (the data argument of `writeFile`, `handle.write(text)`, `write_text(text)`) or passed as an
option (encoding, mode, flags) is shown with the record but is never a path source. A value that comes
from a database row, a file, an API response or another stored origin is not a request field: second-order
flows need their own write-side evidence and are not invented here. One exception keeps a record
visible rather than dropping it: a Next.js server helper that fetches a same-origin route of the
repository and returns its JSON. A path built from a field of that response takes the origin the
route gives the field (see [XSS stored and browser analysis](xss.md#stored-and-browser-analysis)); a
stored row column then holds the record at Review with `storage_origin_unresolved`, and a request
echo stays a request source.

**Request sources.** Express `req.body`, `query`, `params`, `headers` and `cookies`; for path claims only,
`req.path`, `req.url`, `req.originalUrl`, `req.baseUrl`, `req.file` and `req.files` (a second pass of the
same handler, so no other analyzer's evidence changes); Flask `request` containers and `request.files`;
GraphQL and gRPC request fields through the shared entry model.

**Zip Slip (archive extraction).** For a request-supplied archive, the stored entry names are the
attacker-controlled path components. This is the archive variant of CWE-22 and is reported under the same
finding type with the title "Path traversal through archive extraction (Zip Slip)" and its own SARIF rule
id. Only libraries with a source-reviewed contract are modeled (currently `adm-zip` `extractAllTo`).
Whether the extractor validates entry names is a dependency fact: an exact version from the lockfile or
manifest below the fixed release (0.4.11) is a witness; a fixed release is a library control; a range or a
missing declaration stays unresolved. Other archive libraries and hand-written entry loops are not covered.

## Operation semantics that matter

`path.join` concatenates and normalizes, so `..` still climbs and an absolute later segment is appended.
`path.resolve`, Python `os.path.join` and the `pathlib` `/` operator replace everything before an absolute
later segment, so an absolute request value replaces a trusted base. `normalize`, `normpath` and
`abspath` are lexical. None of them checks containment. Only `fs.realpath`, `os.path.realpath` and
`Path.resolve` resolve symbolic links. Windows drive, UNC and backslash behavior is not modeled, and the
scanner host is never evidence of the target platform.

## Facets and outcomes

Each filesystem use is one record. A model decision answers three questions (path traversal,
containment control, protection coverage); evidence validation checks the answers against the source
facts before classification:

- **vulnerable** needs a request-derived flow that is an independent unsafe witness: raw, or guarded
  only by controls that cannot establish containment. A `..` substring blacklist is a witness when an
  absolute value can replace the base (`path.resolve`, `os.path.join`, `/`, a direct operand) or when a
  decode follows the check. A bare prefix comparison without a separator, an unclassified or unmodeled
  control, a `basename`/`dirname` reduction and an operand selected from a collection by comparison are
  **not** witnesses: they stay Review.
- **Protection** needs an enforcing control on the **same value** on **every** request-derived path
  that rejects before the operation: a finite allow-list of constant identities (set, list, tuple,
  dict), a separator-bounded prefix (`startsWith(root + path.sep)`), a `path.relative` result that is
  neither `..`-prefixed nor absolute, `os.path.commonpath`, `is_relative_to`, a verified
  `secure_filename`, a constant Express `root`, Flask `send_from_directory`, or a fixed extractor release.
  The search follows a local helper back to its call sites; with several call sites, one without a
  control leaves the flow unresolved. Normalization, a join,
  a type cast, a length limit, a `..` blacklist, `try`/`except` and an error response after the
  read never count. Presence-only tests are not controls.
- A check that is followed by a decode (locally or inside a called helper), assigned over, placed in a
  sibling or negated branch, conditionally bypassed via a conjunction (`if (!admin && !allowed) reject`),
  or checked against a mutated or splatted collection does not cover the call. The control attaches only
  to the values whose derived names it mentions, and multi-caller helpers require every call site to
  enforce containment.
- Resolved containment is claimed only when the compared value comes from a realpath/resolve call in the
  source **before** the boundary check (`realpath` after a lexical check does not establish a resolved
  boundary); a lexical boundary check says nothing about links created after the check, and the report says
  so. Races and filesystem state are never inferred.
- An unsafe witness needs only its own source-to-operand path; unresolved siblings remain visible and
  never become protection. An all-unknown or all-not-applicable answer is not green.

Status follows the shared vocabulary: `confirmed_vulnerability` (finding), `poor_practice` (finding),
`protected_for_claim` (protection) or `needs_evidence` (Review). Only a final protected record is green.

**Poor practice.** When every request-derived flow is guarded only by a recognized weak control (a prefix
comparison without a separator boundary, a normalized positive root substring test, a `..` text test or a
separator-only test) and the assessment finds no enforced containment, the record is a `poor_practice`
finding: an established construction weakness, not a proven exploit. Unnormalized substring checks and
substring blacklists remain unsafe witnesses; an unverified collection membership check stays Review.

## Coverage and limits

Entry coverage rides the shared model plus path-scoped Express route-chain handlers, explicit local export
lists, verified configuration-parameter router mounts and immediate closures: Express routes and `app.use`
handlers, GraphQL and unary gRPC contexts, and Python Flask, FastAPI, Quart, Django, Falcon, Bottle,
Pyramid, aiohttp and WSGI dispatch. Repeated exposures of one sink are separate contexts, not separate defects.

For PHP, [server-mapped file entries](../php-support.md) cover dynamic `include`/`require`
(`php-include-v1`), `move_uploaded_file` (`php-upload-move-v1`) and filesystem read/write calls
(`php-filesystem-v1`) with PathFacts operands. `basename`, finite allowlists and verified
renaming are controls the judge weighs, never sink removals; an unresolvable dynamic include
yields a `php_dynamic_include` gap with no invented edge.

The [coverage page](../detection-capabilities/path-traversal.md) lists unsupported operations
and the gaps that leave a recognized path in Review. Unmodeled upload filters, helpers, mutations
and cross-module guards can leave the effective path or its containment unresolved.

A Next.js catch-all parameter joined with a literal separator (`params.path.join('/')`) is a modeled
transfer of the request array when the receiver is read once in its function and never reassigned,
so a later reject guard on the joined string (for example `includes('..')`) attaches to the final
operand. A check after the read, on another variable, a single-pass `replace('..', '')` or a decode
after the check is not such a guard; the guard's adequacy remains a judged question.

## Remediation guidance

Select files by a trusted identifier or a finite allow-list instead of accepting a path. Otherwise resolve
the final path and enforce a path-component-boundary check against the trusted directory before the
operation, rejecting on failure, and decide deliberately how symbolic links are treated (resolve with
`realpath` before comparing when links must not be followed, and account for races). Do not rely on a
join or resolve call, normalization, a `..` blacklist or a prefix check without a separator. Reports never
export a verified patch.

See the [path contract](../../.zazz/specifications/path-traversal.md),
[Tier-1 hardening contract](../../.zazz/specifications/path-traversal-hardening.md), and the
[acceptance results](../../.zazz/evaluation/path-traversal-results.md) for the verified matrix and limits.
