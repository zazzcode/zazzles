# Unrestricted file upload

[Analysis rules](README.md) · [Path traversal](path-traversal.md) · [Detection capabilities](../detection-capabilities.md)

The `upload` family asks one question about a verified upload write: can the client choose what the
stored file becomes where it is served (CWE-434)? Path containment is a different question, asked by
the [path family](path-traversal.md) at the same call. The two claims coexist: `basename()` can
contain the path while the file type stays unrestricted.

## Verified operations

| Language | Operation | Contract |
|---|---|---|
| PHP | `move_uploaded_file($tmp, $destination)` | `php-move-uploaded-file-v1` |
| Python | Werkzeug `FileStorage.save(dst)` on a `request.files` value (Flask) | `python-werkzeug-save-v1` |

Node `express-fileupload` `mv` and `multer` disk storage, Starlette/FastAPI `UploadFile` writes and
Symfony `UploadedFile::move` have registered contracts but no adapter yet; they produce no upload
record.

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

The protocol is `upload-components-v1`: `type_restriction`, `execution_exposure`,
`protection_coverage`.
