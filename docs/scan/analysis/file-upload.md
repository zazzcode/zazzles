# Unrestricted file upload

[Analysis rules](README.md) · [Path traversal](path-traversal.md) · [Detection capabilities](../detection-capabilities.md) · [Coverage and known gaps](../detection-capabilities/file-upload.md)

The `upload` family asks one question about a verified upload write: can the client choose what the
stored file becomes where it is served (CWE-434)? Path containment is a different question, asked by
the [path family](path-traversal.md) at the same call. The two claims coexist: `basename()` can
contain the path while the file type stays unrestricted.

## Verified operations

| Language | Operation | Contract |
|---|---|---|
| PHP | `move_uploaded_file($tmp, $destination)` | `php-move-uploaded-file-v1` |
| Python | Werkzeug `FileStorage.save(dst)` on a `request.files` value (Flask) | `python-werkzeug-save-v1` |
| JavaScript, TypeScript | A `multer` disk-storage middleware (`single`, `array`, `fields`, `any`) on an Express route | `node-multer-disk-v1` |
| JavaScript, TypeScript | A `multer` memory-storage middleware on an Express route | `node-multer-memory-v1` |

Node `express-fileupload` `mv` and Starlette/FastAPI `UploadFile` writes have registered contracts
but no adapter yet; they produce no upload record.

## Facts

Each `file_upload_candidate` records, from source:

- **`stored_name`**: `client` (the client name), `client_basename` (`basename()` or
  `secure_filename` of it), `server_generated` (no request-derived part), `mixed` (a generated name
  with a client-derived part such as its extension) or `unknown`.
- **`extension_origin`**: `client`, `fixed` (a literal extension the server chose), `allow_listed`
  (a client extension tested against literals before the write), `content_derived` or `unknown`.
- **`type_controls`**: each condition dominating the write, by kind. `client_declared_type`
  (`$_FILES[...]['type']`, `FileStorage.mimetype`) is recorded as client-controlled and constrains
  nothing. `extension_allow_list`, `content_sniff` (`getimagesize`, `finfo`, `exif_imagetype`,
  `imghdr`, `magic`) and `re_encode` are server-side controls.
- **`destination_served`**: for plain PHP every file under the scan root is server-mapped, so a
  destination whose literal directory, resolved against the entry file's directory, stays inside the
  scan root is `yes`; one that leaves it is `no`; an absolute or dynamic directory is `unknown`.
  Python destinations are `unknown`: a Flask application serves no directory but its static folder
  unless a route does.

The uploaded content (`$_FILES[...]['tmp_name']`, the `FileStorage` value) is the claim's source
path; request-derived parts of the destination are its `stored_name` paths.

## Express and multer

The operation is the middleware, not a call in the handler: `multer` reads the multipart body
before the handlers run. One record is made per middleware per route. The binding is verified from
the `multer` import to the one `multer(...)` call the middleware's receiver is bound to.

- **Disk storage.** The stored name is the value the `filename` callback passes to its `cb`.
  `file.originalname` alone is `client`, `path.basename` of it is `client_basename`, a name with a
  part computed from `file.originalname` or `file.mimetype` is `mixed`. The extension is the last
  piece of that value: a literal extension is `fixed`, a lookup in a module table whose values are
  string literals is `allow_listed`, a piece computed from a client field is `client`. With no
  `filename` callback, and with the `dest` shorthand, `multer` generates a name with no extension
  (`server_generated`, `fixed`).
- **Type controls** are the `if` and conditional tests inside the `destination`, `filename` and
  `fileFilter` callbacks. A test that reads `file.mimetype` is `client_declared_type`. A test that
  compares `file.originalname` with a regular expression, a string or a list is
  `extension_allow_list`.
- **`destination_served`** is `yes` when the directory given to an `express.static` or
  `serve-index` call covers the destination. It is `no` when every such directory in the project
  can be compared with the destination and none covers it. Directories compare only when both are
  relative to the working directory, both start at `__dirname`, or both are absolute.
- **Memory storage** writes no file. The three facts are `unknown`, the handlers after the
  middleware are attached as evidence, and the record stays in Review. A write of `file.buffer`
  by a handler is a [path](path-traversal.md) record of its own.

## Outcomes

- **Practice finding without a model:** a client-chosen extension with no server-side type control
  and no blocker, like SQL construction.
- **Confirmed:** the same facts, a served destination and consistent answers (`type_restriction`
  `none` or `client_declared_only`, `execution_exposure` `served_executable`).
- **Protected:** a generated name with a fixed extension, or a generated name with an allow-listed or
  content-derived extension and a matching restriction answer, or a destination that is not served;
  with complete coverage. Protection applies to executable-file storage only.
- **Review:** everything else, including an unknown destination and an extension allow-list beside a
  client-chosen name. Answers that contradict the facts are `upload_answers_inconsistent`.

The protocol is `upload-components-v2`: `type_restriction`, `execution_exposure`,
`protection_coverage`.

## Symfony

Symfony UploadedFile::move uses the directory at argument 0 and the optional stored name at argument 1. Client file properties, content-derived types, and allow-list guards are separate inputs to the storage and type facts. The document root determines whether a known destination is served.

[Symfony analysis coverage](../symfony-support.md)
