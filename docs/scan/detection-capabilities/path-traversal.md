# Path traversal coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/path-traversal.md) · [CWE-22](https://cwe.mitre.org/data/definitions/22.html)

The claim concerns the effective filesystem path or archive entry name. For operations that touch two paths, the source and destination are assessed separately.
In a judged scan, select this family with `--only-family path`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Verified file and archive paths | Node `fs.readFile` or `fs.rename`, Python `open` or `shutil.move`, plain-PHP filesystem APIs | Assess the request-derived path at the verified operand under the declared POSIX assumptions |
| Archive extraction paths | A verified `adm-zip` extraction, `unzipper` entry write, or Python `TarFile.extractall` | Follow the archive or entry path and record supported extractor controls |
| Contained paths | A resolved value is checked against a trusted directory at a component boundary | May be Protected when every relevant path is contained |
| Weak containment tests | A raw prefix check does not enforce a path separator boundary | Can support a construction-practice finding |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `PATH-R01` | Tar filter depends on runtime defaults | `extractall` omits `filter`, or the filter is dynamic | Review with `tar_filter_unresolved` | Establish the Python runtime and the effective filter |
| `PATH-R02` | Unresolved effective path | An unmodeled helper or middleware transforms the final filesystem operand | Review when containment on the same operand is unresolved | Follow the transformation and its enforcing controls |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `PATH-N01` | Unverified serving wrapper | `express.static` or a project-specific filesystem wrapper | Model the effective filesystem operation and its root semantics |
| `PATH-N02` | Runtime filesystem behavior | A path traverses symlinks or relies on race-dependent state | Establish runtime filesystem behavior and deployment conditions |
| `PATH-N03` | Windows path semantics | A Windows drive or UNC path reaches an otherwise supported file API | Add platform-specific path and containment rules |
