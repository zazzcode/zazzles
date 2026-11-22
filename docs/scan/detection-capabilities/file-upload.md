# Unrestricted file upload coverage

[Detection capabilities](../detection-capabilities.md) · [Analysis rules](../analysis/file-upload.md) · [CWE-434](https://cwe.mitre.org/data/definitions/434.html)

The claim concerns what uploaded content can become when stored where it may be served. Path traversal at the same write is a separate claim.
In a judged scan, select this family with `--only-family upload`.

## Recorded and decidable

| Form | Example | What the scanner can establish |
| --- | --- | --- |
| Verified upload writes | PHP `move_uploaded_file` or a Flask/Werkzeug `FileStorage.save` on a `request.files` value | Track the source, stored name, extension controls and destination exposure |
| Client-selected extension | A client filename is written into a verified served destination with no server-side type control | May be Confirmed when executable exposure is established. The unrestricted naming can also be a practice finding |
| Server-controlled format | The application generates a filename with a fixed extension or writes outside a served destination | May be Protected for executable-file storage when evidence is complete |
| Symfony UploadedFile | `move` uses its directory and optional stored name | Record the destination, file name origin, and pre-move type controls |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `UPLOAD-R01` | Unknown destination exposure | A Flask upload wrapper stores the file in a directory whose serving behavior is unresolved | Review when the destination exposure cannot be established | Resolve the storage and serving configuration |
| `UPLOAD-R02` | Client-selected filename behind a partial control | The application checks an extension while the client still chooses the stored name | Review when the combined name and type policy is unclear | Establish the effective filename and content policy |
| `UPLOAD-R03` | Unresolved Symfony upload destination | The target directory depends on unavailable configuration | Review when served-destination evidence is unknown | Resolve the parameter and compare it with the document root |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `UPLOAD-N01` | Registered contracts without a source adapter | A Node `multer` storage callback, Starlette `UploadFile`, or Symfony `UploadedFile::move` | Discover and verify the framework binding and destination write |
