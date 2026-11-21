package analysispacks

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// UploadProtocol versions the unrestricted-upload claim (close-findings-gaps
// W5). Path containment and file-type restriction are separate questions:
// the upload family asks only the second.
const UploadProtocol = "upload-components-v2"

// Upload contracts: verified operations that store a client upload (D-19).
const (
	PHPMoveUploadedFile   = "php-move-uploaded-file-v1"
	NodeExpressFileupload = "node-express-fileupload-mv-v1"
	NodeMulterDisk        = "node-multer-disk-v1"
	PythonWerkzeugSave    = "python-werkzeug-save-v1"
	PythonStarletteUpload = "python-starlette-upload-v1"
)

var uploadContracts = []string{PHPMoveUploadedFile, NodeExpressFileupload, NodeMulterDisk, PythonWerkzeugSave, PythonStarletteUpload}

// operandFamily reports the operand-path families that share the
// interpreter descriptor and selection shape.
func operandFamily(name string) bool {
	return name == "code" || name == "redirect" || name == "upload" || name == "deserialization"
}

// UploadContract returns the semantics of a verified upload write.
func UploadContract(id string) *analysis.APIModel {
	semantics := map[string]string{
		PHPMoveUploadedFile:   "PHP move_uploaded_file(tmp, destination) stores a file the client uploaded at the destination path. $_FILES[f]['name'] and its extension and $_FILES[f]['type'] are client-supplied; basename() removes directories but keeps the client extension.",
		NodeExpressFileupload: "express-fileupload req.files.<field>.mv(path) stores the client upload at path. file.name and file.mimetype are client-supplied.",
		NodeMulterDisk:        "multer diskStorage stores each upload under the name its filename callback returns. file.originalname and file.mimetype are client-supplied.",
		PythonWerkzeugSave:    "Werkzeug FileStorage.save(dst) (Flask request.files) stores the client upload at dst. FileStorage.filename and mimetype are client-supplied; secure_filename removes path syntax but keeps the client extension.",
		PythonStarletteUpload: "A Starlette/FastAPI UploadFile written to a path stores the client upload there. UploadFile.filename and content_type are client-supplied.",
	}
	text, ok := semantics[id]
	if !ok {
		return nil
	}
	return &analysis.APIModel{ID: id, Library: id, Semantics: text + " A file stored under a served directory with an executable extension (for example .php under a PHP document root) can be requested and run.", Reference: "https://cwe.mitre.org/data/definitions/434.html"}
}

func uploadQuestionNames() []string {
	return []string{"type_restriction", "execution_exposure", "protection_coverage"}
}

func uploadQuestions() []Question {
	return []Question{
		{"type_restriction", "Classify the server-side restriction on the stored file's type: none, client_declared_only (only a client-supplied MIME type or name is checked), extension_allow_list, content_check (magic bytes, getimagesize, finfo), re_encoded (the content is re-encoded and the name generated), unknown. A check of the client-declared type constrains nothing the client cannot choose. use.upload.type_controls lists each dominating control the scanner recorded, by kind."},
		{"execution_exposure", "Classify whether the stored file can be requested and executed: served_executable (a served directory where a client-chosen extension such as .php can run), served_static (served, but no client-chosen executable extension can reach it), not_served, unknown. use.upload states stored_name, extension_origin and destination_served (yes when the destination resolves inside the scan root, which plain PHP serves); do not answer unknown when those facts settle it."},
		{"protection_coverage", "Is the type restriction enforced before the write on every relevant path? complete, incomplete, unknown. Missing flow is unknown."},
	}
}

func uploadChoices(question string) []string {
	switch question {
	case "type_restriction":
		return []string{"none", "client_declared_only", "extension_allow_list", "content_check", "re_encoded", "unknown"}
	case "execution_exposure":
		return []string{"served_executable", "served_static", "not_served", "unknown"}
	}
	return []string{"complete", "incomplete", "unknown"}
}

// UploadQuestions returns the upload question protocol.
func UploadQuestions() []Question { return uploadQuestions() }
