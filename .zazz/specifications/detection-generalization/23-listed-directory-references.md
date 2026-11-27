# Detection generalization 23 — what the source puts in a listed directory

- **Series** [Contract, gates, held-out protocol, stop procedure and prompt](contract.md). They apply and are not
  repeated. **Approved by the owner, 2026-11-27** ("Implement spec 23"); decisions taken as proposed.
- **Branch** `docs-cleanup`, by the owner's word, on top of specification 22.
- **Asked for by the owner**, 2026-11-27, with [22](22-owner-reference-fields.md).
- **Evidence** [Gemini sample runs, model or scanner](../../evaluation/gemini-sample-runs-20261127.md#juice-shop-model-or-scanner):
  on `JS-CONF-03`, `server.ts:302`, both judges answer the listing in effect with no mitigation; `gpt-6-luna` answers
  `weakens` at 0.52 and Gemini `unknown` at 0.57. The directory `logs` is not in the scanned tree, so the existing
  `directory_contents` fact says only that its contents are unknown.
- **Order** independent. **Effort** small. **Value** low: serve-index is used in one of five local Node development
  samples. **Review artifact** one draft PR to `stage`. **Drafted** 2026-11-27 from `85f39fd`.

## Capability

A `directory_listing` record (serve-index on a mount) already joins the mount path, the directory argument, the
mount's access and the directory's entries in the scanned tree
([configuration rules](../../../docs/scan/analysis/configuration.md)). When the directory is absent or empty in the
tree, the model has no way to know what a visitor would see. This specification adds what the source itself says goes
there: every other source location whose path literal resolves into the listed directory, with its enclosing call.
In Juice Shop that is the access-log stream (`server.ts:358` to `366`) writing `logs/access.log.%DATE%`, and the log
file route reading `logs/` (`routes/logfileServer.ts:14`).

## Semantics

**S-1. Directory references.** For a listing record whose directory argument is a literal relative path (the existing
`directoryContents` rule), collect in the selected modules every string literal, and every `path.join` or
`path.resolve` of literals, whose cleaned value is the directory or lies under it. Leave out the listing call itself
and the other serve-index or `express.static` registrations of the same directory. Each reference is one evidence item
`directory_reference` with the enclosing call or property as text, at most eight per record, sorted by file and line,
with the total.

**S-2. Model text.** "The source refers to paths inside the listed directory at N places:" followed by the items. The
scanner states nothing about whether they are writes, logs or secrets.

**S-3. The request.** The evidence is added to the record's joined facts. No question changes. Only records with at
least one reference change their request.

## Invariants

1. No list of logging, file or stream libraries; a reference is a path literal, whatever reads or writes it.
2. A listing record with no reference keeps its request byte for byte.
3. Other configuration checks and PHP are unchanged.

## Scope

`scan/internal/langjs/configuration.go` (the new fact beside `directoryContents`), its tests and
`langjs/testdata/configuration/listing-refs/`; the [configuration rules](../../../docs/scan/analysis/configuration.md)
and the [capability page](../../../docs/scan/detection-capabilities/insecure-configuration.md); the series index; the
results file. Out of scope: PHP and server configuration files; paths built from variables or environment values (a
reference is a literal); reading files outside the scan root.

## Decisions

- **D-1. References, not writers.** *Why:* a writer list (fs, winston, file-stream-rotator, multer) is the per-library
  enumeration this series removes; the call text lets the model see what each reference does. *Rejected:* a list of
  file-writing APIs.
- **D-2. Leave out the directory's own serve registrations.** *Why:* they say nothing the record does not already hold,
  and they would add a reference to every listing, so invariant 2 would never apply.
- **D-3. At most eight.** *Why:* as `directory_contents`; the total is kept.

## Fixtures

Positive: a rotating access-log stream into the listed directory; `fs.createWriteStream` into it; an upload
destination option naming it; a database backup path in it. Negative: a listed directory referenced only by its own
serve-index and `express.static` calls (no fact, request unchanged); a path that only shares a prefix (`logs-public`);
a reference outside the scan root.

## Held-out

Not required (owner, 2026-11-27; [contract §3](contract.md#3-held-out-protocol)). Accepted on fixtures, the gates and
the Juice Shop acceptance check, and the results say that accuracy elsewhere is not measured.

## G7 bound

The challenge code-fix snippets under `data/static/codefixes/` repeat the listing lines; they are expected outside
the selected modules, and the first offline run confirms it.

No record is added. Requests change only for listing records with a reference: on the nine samples, at most the
Juice Shop listings, read and explained.

## Acceptance criteria

| AC | Criterion | Verified by |
|---|---|---|
| AC1 | S-1 on every fixture | `go test ./scan/internal/langjs -run TestDirectoryReferences` |
| AC2 | Request digests equal base for every record with no reference | `judge.Preview` (G2) |
| AC3 | G1 to G7 | Comparison |
| AC4 | Paid, fixtures: every positive Confirmed, no negative Confirmed, on both judges | Results |
| AC5 | Juice Shop acceptance check, read last: `JS-CONF-03` Confirmed on both judges, and the keyed control `JS-CONF-N01` (`.well-known`) reported as before. Both judges already Confirm it without this fact (a standing false positive), and the seed data refers to `.well-known/csaf/provider-metadata.json` (`data/datacreator.ts:800`), so the control gains a reference. Reported; not a merge gate | Results |
| AC6 | Pages updated | `doc-check` |

## Paid checkpoints

Fixtures and the changed Juice Shop listing records only: about 10 requests per judge, cap 20. No full scan unless it
runs with 22's.

## Stop rule

Stop when a negative fixture is Confirmed on either judge. `JS-CONF-N01` cannot serve: both judges Confirm it today.

## First failing test and order

`TestDirectoryReferences/rotating_log_stream`. Then the other positives, the negatives, the previews, the paid
checkpoint.

## Run log, definition of done, prompt

[Series contract §6](contract.md#6-agent-rules-standards-and-documents). Its own feature worktree, on the owner's word.

## Implementation and review change log

### 2026-11-27 — Approved

Approved as drafted. Built on `docs-cleanup` after specification 22; its base is that working tree.
