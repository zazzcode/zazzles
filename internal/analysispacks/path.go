package analysispacks

import "github.com/zazzcode/zazzles/internal/analysis"

// PathProtocol is the path-traversal question/envelope protocol.
const PathProtocol = "path-components-v1"

// Operation-contract identifiers. Each is selected only after the parser
// verified the actual import or builtin binding of the called filesystem API.
const (
	UnzipperEntryContract = "unzipper-entry-write-v1"
	HbsLayoutContract     = "hbs-render-layout-v1"
	NodeFSContract        = "node-fs-file-v1"
	PythonOpenContract    = "python-open-file-v1"
	PythonPathlibContract = "python-pathlib-file-v1"
	PythonArchiveContract = "python-archive-open-v1"
	PythonSaveContract    = "werkzeug-file-save-v1"
	ExpressSendContract   = "express-send-file-v1"
	AdmZipContract        = "adm-zip-extract-v1"
	PythonOSFileContract  = "python-os-file-v1"
	FlaskSendContract     = "flask-send-file-v1"
)

var pathContractIDs = []string{NodeFSContract, PythonOpenContract, PythonPathlibContract, PythonArchiveContract, PythonSaveContract, ExpressSendContract, AdmZipContract, PythonOSFileContract, FlaskSendContract, UnzipperEntryContract, HbsLayoutContract}

// PathContract returns a copy of the supported operation contract by verified ID.
// Semantics follow the cited official documentation; the declared platform is a
// posix assumption and neither the scanner host nor a moving documentation
// version is evidence of the target's deployed runtime.
func PathContract(id string) *analysis.APIModel {
	switch id {
	case UnzipperEntryContract:
		return &analysis.APIModel{ID: id, Library: "unzipper", Reference: "https://github.com/ZJONSSON/node-unzipper#openbuffer", Semantics: "unzipper.Open.buffer(buffer) returns the ZIP central directory with a files array. Each entry.path is the stored archive name and entry.stream() is content. When a request supplies buffer, entry names are request-derived path text. Caller code that passes an entry name to fs.createWriteStream writes the selected path; Open.buffer does not validate that caller's destination. A substring includes(root) check is not component containment: a normalized path can still leave the intended extraction directory or enter a sibling sharing text. A path.join/resolve alone is not containment. Only the write path, not stream content, is the path operand. This is the caller-controlled ZIP entry write (Zip Slip) contract, not a claim that unzipper's extract helper or every release is vulnerable. POSIX is a declared assumption; no symlink/race state is inferred."}
	case HbsLayoutContract:
		return &analysis.APIModel{ID: id, Library: "hbs", Reference: "https://github.com/pillarjs/hbs/blob/v4.2.0/lib/hbs.js", Semantics: "With a source-verified Express view engine setting of hbs, res.render(view, options) passes options.layout to hbs. hbs joins each configured views directory with layout, appends the view extension only when none is present, then reads and compiles that file. A layout with '..' components can leave the views directory; path.join does not enforce containment. layout false disables the layout read. Options object spreads and later properties follow JavaScript overwrite order; only the effective layout value is the file path operand, while other locals are template data. A request-body layout option is not contained by checking a different derived path against a substring blacklist. Other engines, dynamically overridden engine registrations and missing settings are not covered. POSIX is declared; deployment, filesystem links and runtime exploitability are not inferred."}

	case NodeFSContract:
		return &analysis.APIModel{ID: id, Library: "fs", Reference: "https://nodejs.org/api/fs.html#fsreadfilepath-options-callback",
			Semantics: "fs.readFile, readFileSync, writeFile, writeFileSync and the fs/promises (fs.promises) readFile and writeFile take the file path as their first argument; the second argument of the write forms is the data written, a separate operand and never a path source, and encoding, mode, flag and callback arguments are configuration or output, not a path. A string path is interpreted relative to the process working directory when it is not absolute and is not resolved against any directory by the API. path.join concatenates its segments and normalizes them, so an absolute later segment is appended rather than replacing the earlier segments, while '..' segments can still climb above the earlier segments; path.resolve processes right to left, so an absolute later segment replaces everything before it; path.normalize resolves '.' and '..' lexically without a root. None of join, resolve or normalize checks containment within a directory, and all three are lexical: only fs.realpath and fs.promises.realpath resolve symbolic links. This contract is not evidence of the deployed platform."}
	case PythonOpenContract:
		return &analysis.APIModel{ID: id, Library: "open", Reference: "https://docs.python.org/3/library/functions.html#open",
			Semantics: "The builtin open and io.open take the file as their first positional argument or the file keyword; the mode argument (default read, 'w', 'a', 'x' and '+' variants write or create) selects read or write and is not a path. Text written through the returned object is a separate operand and never a path source. A relative file is resolved against the process working directory. os.path.join returns the later segment alone when it is absolute, so a request value can replace a trusted base; '..' segments stay in the string until a normalization call. os.path.normpath and abspath are lexical; os.path.realpath also resolves symbolic links. None of join, normpath, abspath or realpath checks containment. A function, import or assignment named open that shadows the builtin does not carry this contract. This contract is not evidence of the deployed platform."}
	case PythonPathlibContract:
		return &analysis.APIModel{ID: id, Library: "pathlib", Reference: "https://docs.python.org/3/library/pathlib.html#pathlib.Path.read_text",
			Semantics: "pathlib.Path.open, read_text and read_bytes read, and write_text and write_bytes write, the file named by the Path receiver; text, bytes, encoding and mode arguments are separate operands, not path sources. Building a Path from a request string, or joining with the '/' operator, keeps '..' segments and replaces the base when a later segment is absolute (Path('/srv') / '/etc/passwd' is '/etc/passwd'). Path.resolve makes the path absolute and resolves symbolic links (it is not lexical, unlike os.path.abspath); is_relative_to compares path components lexically. A Path object is not a containment guarantee. This contract is not evidence of the deployed platform."}
	case PythonArchiveContract:
		return &analysis.APIModel{ID: id, Library: "archive", Reference: "https://docs.python.org/3/library/tarfile.html#tarfile.open",
			Semantics: "tarfile.open, tarfile.TarFile and TarFile.open, bz2.open and BZ2File, gzip.open and GzipFile, and lzma.open and LZMAFile open the file named by their first positional argument (tarfile: name; the others: filename) or that keyword; the mode argument (default read) selects read or write and is not a path. The name is resolved against the process working directory when relative, with no containment check, so '..' segments and an absolute value select any file the process can open. Entry names stored inside a tar archive are separate data and are not this operand; extracting them is a different operation that this contract does not model. The same join, normalization and containment rules as the builtin open apply to how the name was built. This contract is not evidence of the deployed platform."}
	case ExpressSendContract:
		return &analysis.APIModel{ID: id, Library: "express", Reference: "https://expressjs.com/en/api.html#res.sendFile",
			Semantics: "res.sendFile(path [, options] [, callback]) and res.download(path [, filename] [, options] [, callback]) read the file named by their first argument and stream it in the response; the filename and callback arguments are not paths. Without the options.root setting the path must be absolute and the library applies no containment: '..' segments and any absolute value select any file the process can read, so path.resolve of a request value is not containment. With a constant options.root the path is resolved relative to that root and the library rejects a path that would escape it with 403; a null byte is rejected with 400; dotfiles are ignored by default. A root that is itself request-derived is not a trusted root. A directory is not served as a file. Express does not resolve symbolic links on the caller's behalf. This contract is not evidence of the deployed platform."}
	case AdmZipContract:
		return &analysis.APIModel{ID: id, Library: "adm-zip", Reference: "https://github.com/snyk/zip-slip-vulnerability",
			Semantics: "new AdmZip(data) parses an archive from a buffer or path; zip.extractAllTo(targetPath [, overwrite]) writes every entry under targetPath. The stored entry names are attacker-controlled when the archive comes from a request, and an entry name such as '../../x' joined to targetPath writes outside it (Zip Slip, CWE-22). The destination argument is not the traversal operand: the archive is. adm-zip releases before 0.4.11 do not reject entry names that escape the destination (CVE-2018-1002204); releases from 0.4.11 do. Which release is installed is a dependency fact: an exact version declaration is trusted, a range or a missing declaration is unknown, and a name or comment never establishes it. Extraction does not resolve symbolic links on the caller's behalf. This contract is not evidence of the deployed platform."}
	case PythonOSFileContract:
		return &analysis.APIModel{ID: id, Library: "os", Reference: "https://docs.python.org/3/library/os.html#os.remove",
			Semantics: "os.remove and os.unlink delete the file named by their first argument (path) or that keyword; a relative path is resolved against the process working directory with no containment check, so '..' segments and an absolute value select any file the process may delete. os.path.join returns an absolute later segment alone, so a request value can replace a trusted base. Deleting is a write-class effect on the selected file. This contract is not evidence of the deployed platform."}
	case FlaskSendContract:
		return &analysis.APIModel{ID: id, Library: "flask", Reference: "https://flask.palletsprojects.com/en/stable/api/#flask.send_from_directory",
			Semantics: "flask.send_file(path_or_file) streams the file at its first argument; a relative path is resolved against the application root and the library applies no containment, so '..' and absolute values select any readable file. flask.send_from_directory(directory, path) joins path to directory with werkzeug safe_join and raises NotFound for a path that is absolute or would escape the directory, which is library-enforced lexical containment of the path argument; it holds only when the directory is not itself request-derived. Neither resolves symbolic links on the caller's behalf. This contract is not evidence of the deployed platform."}
	case PythonSaveContract:
		return &analysis.APIModel{ID: id, Library: "werkzeug", Reference: "https://werkzeug.palletsprojects.com/en/stable/datastructures/#werkzeug.datastructures.FileStorage.save",
			Semantics: "FileStorage.save(dst) on an object taken from request.files writes the uploaded stream to dst; a string or path-like dst is the file path operand, the stream content is separate data, and a file object dst is not a path. save does not check or sanitize dst, and FileStorage.filename is the client-supplied name, unmodified, so it may contain separators and '..'. werkzeug.utils.secure_filename reduces a name to one component of ASCII letters, digits and '._-' by replacing separators and stripping leading and trailing dots and underscores; the result cannot contain a path separator or '..', and may be empty. Joining a secure_filename result to a fixed directory therefore cannot leave that directory lexically. Neither save nor secure_filename resolves symbolic links. This contract is not evidence of the deployed platform."}
	}
	return nil
}

func pathQuestionNames() []string {
	var names []string
	for _, q := range PathQuestions() {
		names = append(names, q.Name)
	}
	return names
}

// PathQuestions returns the exact ordered path claim protocol. Traversal,
// containment control and coverage are separate atomic facets.
func PathQuestions() []Question {
	return []Question{
		{"path_traversal", "Can supported external text select a file outside the intended location through the effective path operand of this filesystem use? vulnerable requires a verified binding, a request-derived value in the effective path operand (not in write content or options) and no enforced containment on that supported path; '..' segments, an absolute value that replaces a base, or an unconstrained filename all qualify, and a path.join/resolve/normalize or os.path.join/abspath/normpath call, a type annotation, an error branch, try/except or a blacklist of substrings is not containment. protected requires an enforced source-backed containment on every relevant path: a finite allow-list of trusted identities or an actual boundary check of the same value against the trusted root that rejects before use. not_applicable means no request-derived value reaches the path operand. unknown covers missing bindings, helpers, guards or platform facts, and a bare prefix comparison without a separator boundary (a sibling directory sharing the prefix satisfies it). Judge each request-derived path separately: one supported unguarded path to the path operand is vulnerable even if another path is unresolved."},
		{"containment_control", "What enforced containment, if any, protects the path operand on the supplied source-to-operand path? finite_allowlist requires a finite set of trusted constant file identities that the same value must be a member of, with a rejecting branch that terminates before use. lexical_boundary requires the same value, compared against the trusted root at a path-component boundary (separator-bounded prefix, path.relative result that is neither '..'-prefixed nor absolute, commonpath equal to the root, or is_relative_to), with a rejecting branch that terminates before use; it is lexical and says nothing about symbolic links. resolved_boundary additionally requires the compared value to come from a symbolic-link-resolving call such as realpath or Path.resolve in the supplied source; a race or symlink created after the check is an explicit assumption. none means no enforced containment: normalization alone, a join or resolve call, a bare prefix comparison without a separator, a '..' substring blacklist, type casts and annotations, length limits, exception handling and an error response after the read are not containment. unknown covers unmodeled helpers and checks whose semantics the supplied source does not establish."},
		{"protection_coverage", "Are the relevant operand and path protection obligations established? complete requires every request-derived path to the path operand and every feasible branch to be covered by the answers above, with no unknown relevant helper, reassignment, decode after the check or mutable operand. incomplete means a supported unprotected sibling path, branch or invocation remains. unknown means coverage cannot be determined. A control on one value, branch or invocation does not cover another, and a guard that the value passes before a later decode or reassignment does not cover the decoded or reassigned value. An all-not_applicable result is not protection."},
	}
}

// PathChoices returns the choices of one path question.
func PathChoices(name string) []map[string]string {
	var values [][2]string
	switch name {
	case "path_traversal":
		values = [][2]string{{"vulnerable", "The supplied source and verified contract establish a request value selecting a file outside any intended location on a supported path with no enforced containment."}, {"protected", "An enforced source-backed containment keeps the request value inside the trusted location on every relevant path."}, {"not_applicable", "No request-derived value reaches the effective path operand."}, {"unknown", "Required binding, helper, guard or platform evidence is missing or ambiguous."}}
	case "containment_control":
		values = [][2]string{{"finite_allowlist", "The same value must be one of a finite set of trusted constant identities, rejecting before use."}, {"lexical_boundary", "The same value is checked against the trusted root at a path-component boundary, rejecting before use; symbolic links are not addressed."}, {"resolved_boundary", "As lexical_boundary, on a value produced by a symbolic-link-resolving call in the supplied source."}, {"none", "No enforced containment is established."}, {"unknown", "Control semantics are not established by the supplied source."}}
	case "protection_coverage":
		values = [][2]string{{"complete", "Relevant operand and path protection obligations are established."}, {"incomplete", "A relevant operand, path or sibling remains unprotected or unanalyzed."}, {"unknown", "Coverage cannot be determined from the supplied evidence."}}
	default:
		return nil
	}
	out := make([]map[string]string, 0, len(values))
	for _, v := range values {
		out = append(out, map[string]string{"value": v[0], "description": v[1]})
	}
	return out
}

var pathOwners = map[string]string{
	UnzipperEntryContract: "internal/parse/path_unzipper.go",
	HbsLayoutContract:     "internal/parse/path_render.go",
	NodeFSContract:        "internal/parse/path_node.go",
	PythonOpenContract:    "internal/parse/python_path.go",
	PythonPathlibContract: "internal/parse/python_path.go",
	PythonArchiveContract: "internal/parse/python_path.go",
	PythonSaveContract:    "internal/parse/python_path.go",
	ExpressSendContract:   "internal/parse/path_node.go",
	AdmZipContract:        "internal/parse/path_archive.go",
	PythonOSFileContract:  "internal/parse/python_path.go",
	FlaskSendContract:     "internal/parse/python_path.go",
}
