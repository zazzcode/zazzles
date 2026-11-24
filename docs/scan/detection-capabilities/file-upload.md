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
| Express `multer` disk storage | `multer({ storage: multer.diskStorage({ destination, filename }) })` or `multer({ dest })` used as `single`, `array`, `fields` or `any` on a route | Record the name the `filename` callback passes on, the origin of its extension, the type tests in the storage and `fileFilter` callbacks, and whether an `express.static` or `serve-index` directory covers the destination |

## Recorded in Review

| ID | Form | Example | Why it is in Review | Evidence needed |
| --- | --- | --- | --- | --- |
| `UPLOAD-R01` | Unknown destination exposure | A Flask upload wrapper stores the file in a directory whose serving behavior is unresolved | Review when the destination exposure cannot be established | Resolve the storage and serving configuration |
| `UPLOAD-R02` | Client-selected filename behind a partial control | The application checks an extension while the client still chooses the stored name | Review when the combined name and type policy is unclear | Establish the effective filename and content policy |
| `UPLOAD-R03` | Unresolved Symfony upload destination | The target directory depends on unavailable configuration | Review when served-destination evidence is unknown | Resolve the parameter and compare it with the document root |
| `UPLOAD-R04` | Express `multer` memory storage | `multer({ storage: multer.memoryStorage() })` or `multer()` on a route | `multer` writes no file. The stored name, the extension and the destination are unknown, and the handlers that receive the buffer are attached as evidence | Follow the handler's write of the buffer to its path and directory |
| `UPLOAD-R05` | `multer` destination that cannot be compared with a served directory | The destination is relative to the working directory and the static mount is built from `__dirname` | Review when the served-destination fact is unknown | Establish the directory the process starts in |

## Not recorded

| ID | Form | Example | Boundary or evidence needed |
| --- | --- | --- | --- |
| `UPLOAD-N01` | Registered contracts without a source adapter | Node `express-fileupload` `mv` or a Starlette `UploadFile` write | Discover and verify the framework binding and destination write |
| `UPLOAD-N02` | `multer` binding that is not verified | The `multer(...)` instance is imported from another module, its options hold a spread, or its storage is a third-party engine | Resolve the binding across modules and model the engine's write |
| `UPLOAD-N03` | `multer` middleware on a mount with no route entry | `app.use(upload.any())` | Recorded as an `upload_entry_missing` gap. Attach the middleware to the routes the mount covers |
