package analysispacks

import (
	"fmt"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
)

// Question/envelope protocols. A changed request composition for a family
// takes a new protocol identifier; historical answers under an older protocol
// are retained but cannot replay onto changed requests.
const (
	SQLProtocol        = "sql-components-v4"
	NoSQLProtocol      = "nosql-components-v2"
	ValidationProtocol = "validation-components-v2"
	XSSProtocol        = "xss-components-v4"
	// CommandProtocol and PathProtocol are declared in command.go and path.go.
)

// Family registers one claim family's selection contract. Registrations are
// scanner configuration: an unknown candidate kind keeps its existing runtime
// path and never falls through to a generic trusted security judgment.
type Family struct {
	Name string
	// ObservationOnly selects static knowledge without a model protocol.
	ObservationOnly bool
	// Label names the family in selection-failure messages.
	Label string
	// Kinds lists the candidate kinds eligible for this family.
	Kinds []string
	// QuestionNames defines the family protocol by exact question names, not
	// by a universal count.
	QuestionNames []string
	// Languages lists the source languages with verified adapters.
	Languages []lang.Language
	// Entries lists required entry capabilities; standalone claims need none.
	Entries []string
	// RequiresAPI marks families whose operations need a verified contract.
	RequiresAPI bool
	// PythonHTTPOnly restricts Python candidates to HTTP entries.
	PythonHTTPOnly bool
	// PHPHTTPOnly restricts PHP candidates to HTTP entries.
	PHPHTTPOnly bool
	Pack        string
	Claim       string
	Evidence    string
	PolicyOwner string
}

func (f Family) supports(language lang.Language) bool {
	for _, l := range f.Languages {
		if l == language {
			return true
		}
	}
	return false
}

func (f Family) rootIDs() []string {
	ids := []string{f.Pack, f.Claim, f.Evidence, flowID(&f)}
	if f.ObservationOnly {
		ids = append(ids, "api.python-http-destination-v1")
	}
	for _, language := range f.Languages {
		ids = append(ids, languageID(&f, language))
	}
	for _, entry := range f.Entries {
		if f.Name == "pollution" {
			entry = "entry.pollution." + entry[len("entry."):]
		} else if entry == "entry.browser" && operandFamily(f.Name) {
			entry = "entry." + f.Name + ".browser"
		}
		ids = append(ids, entry)
	}
	if f.Name == "xss" {
		ids = append(ids, "render.html-output-v1", "render.browser-output-v1", "render.python-html-output-v1", "render.php-html-output-v1", "context.xss", "protection.xss", "browser.xss", "storage.xss", "response.xss")
	}
	if f.RequiresAPI || f.Name == "pollution" {
		for _, id := range contractIDs(&f) {
			ids = append(ids, "api."+id)
		}
	}
	return ids
}

func languageID(f *Family, language lang.Language) string {
	if f.Name == "sql" {
		// The SQL projection keeps the accepted language component identities.
		if language == lang.Python {
			return "language.python"
		}
		if language == lang.PHP {
			return "language.php"
		}
		return "language.javascript"
	}
	name := "javascript"
	if language == lang.Python {
		name = "python"
	}
	if language == lang.PHP {
		name = "php"
	}
	return "language." + f.Name + "." + name
}

// Families returns the registered component families in stable order.
func Families() []Family {
	return []Family{
		{Name: "code", Label: "code", Kinds: []string{"code_execution_candidate", "template_injection_candidate"}, QuestionNames: codeQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP}, Entries: []string{"entry.http", "entry.graphql", "entry.grpc", "entry.browser"}, RequiresAPI: true, Pack: "pack.code", Claim: "claim.code", Evidence: "evidence.code", PolicyOwner: "internal/judge/code_redirect.go"},
		{Name: "pollution", Label: "Prototype pollution", Kinds: []string{analysis.PollutionKind}, QuestionNames: pollutionQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript}, Entries: []string{"entry.http", "entry.graphql", "entry.grpc"}, Pack: "pack.pollution", Claim: "claim.pollution", Evidence: "evidence.pollution", PolicyOwner: "internal/judge/pollution.go"},
		{Name: "redirect", Label: "redirect", Kinds: []string{"open_redirect_candidate"}, QuestionNames: redirectQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP}, Entries: []string{"entry.http", "entry.graphql", "entry.grpc", "entry.browser"}, RequiresAPI: true, Pack: "pack.redirect", Claim: "claim.redirect", Evidence: "evidence.redirect", PolicyOwner: "internal/judge/code_redirect.go"},
		{Name: "upload", Label: "upload", Kinds: []string{"file_upload_candidate"}, QuestionNames: uploadQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP}, Entries: []string{"entry.http"}, RequiresAPI: true, Pack: "pack.upload", Claim: "claim.upload", Evidence: "evidence.upload", PolicyOwner: "internal/judge/upload.go"},
		{Name: "logging", Label: "Sensitive-data logging", Kinds: []string{"log_sink_candidate"}, QuestionNames: loggingQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python}, Pack: "pack.logging", Claim: "claim.logging", Evidence: "evidence.logging", PolicyOwner: "internal/judge/logging.go"},
		{Name: "outbound", Label: "Outbound observation", ObservationOnly: true, Kinds: []string{"outbound_http_candidate"}, Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python}, Pack: "pack.outbound", Claim: "observation.outbound", Evidence: "evidence.outbound", PolicyOwner: "internal/parse/flow.go + internal/parse/python_frameworks.go"},
		{Name: "xss", Label: "XSS", Kinds: []string{"xss_candidate"}, QuestionNames: xssQuestionNames(), Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP}, Pack: "pack.xss", Claim: "claim.xss", Evidence: "evidence.xss", PolicyOwner: "internal/judge/xss.go"},
		{
			Name: "sql", Label: "SQL", Kinds: []string{"sql_query_candidate"}, QuestionNames: sqlQuestionNames(),
			Languages:      []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP},
			Entries:        []string{"entry.http", "entry.graphql", "entry.grpc"},
			RequiresAPI:    true,
			PythonHTTPOnly: true,
			PHPHTTPOnly:    true,
			Pack:           "pack.sql", Claim: "claim.sql", Evidence: "evidence.sql",
			PolicyOwner: "internal/judge/policy.go",
		},
		{
			Name: "nosql", Label: "NoSQL", Kinds: []string{"nosql_query_candidate"}, QuestionNames: noSQLQuestionNames(),
			Languages:   []lang.Language{lang.JavaScript, lang.TypeScript},
			Entries:     []string{"entry.http", "entry.graphql", "entry.grpc"},
			RequiresAPI: true,
			Pack:        "pack.nosql", Claim: "claim.nosql", Evidence: "evidence.nosql",
			PolicyOwner: "internal/judge/policy.go",
		},
		{
			Name: "command", Label: "Command execution", Kinds: []string{"command_execution_candidate"}, QuestionNames: commandQuestionNames(),
			Languages:      []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP},
			Entries:        []string{"entry.http", "entry.graphql", "entry.grpc"},
			RequiresAPI:    true,
			PythonHTTPOnly: true,
			PHPHTTPOnly:    true,
			Pack:           "pack.command", Claim: "claim.command", Evidence: "evidence.command",
			PolicyOwner: "internal/judge/command.go",
		},
		{
			Name: "path", Label: "Path traversal", Kinds: []string{"path_traversal_candidate"}, QuestionNames: pathQuestionNames(),
			Languages:      []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP},
			Entries:        []string{"entry.http", "entry.graphql", "entry.grpc"},
			RequiresAPI:    true,
			PythonHTTPOnly: true,
			PHPHTTPOnly:    true,
			Pack:           "pack.path", Claim: "claim.path", Evidence: "evidence.path",
			PolicyOwner: "internal/judge/path.go",
		},
		{
			Name: "ssrf", Label: "Server-side request forgery", Kinds: []string{"ssrf_candidate"}, QuestionNames: ssrfQuestionNames(),
			Languages:      []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python},
			Entries:        []string{"entry.http", "entry.graphql", "entry.grpc"},
			RequiresAPI:    true,
			PythonHTTPOnly: true,
			Pack:           "pack.ssrf", Claim: "claim.ssrf", Evidence: "evidence.ssrf",
			PolicyOwner: "internal/judge/ssrf.go",
		},
		{
			Name: "validation", Label: "Standalone validation", Kinds: []string{"input_validation_candidate"}, QuestionNames: validationQuestionNames(),
			Languages: []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python, lang.PHP},
			// A standalone field claim needs an explicit/source-backed
			// requirement and enforcing path, never a database API contract.
			Pack: "pack.validation", Claim: "claim.validation", Evidence: "evidence.validation",
			PolicyOwner: "internal/judge/validation.go",
		},
	}
}

// FamFamily returns the registered family for a candidate kind, or nil.
func FamFamily(kind string) *Family {
	for _, f := range Families() {
		for _, k := range f.Kinds {
			if k == kind {
				value := f
				return &value
			}
		}
	}
	return nil
}

// ProtocolFor returns the request protocol of a registered family kind.
func ProtocolFor(kind string) string {
	if f := FamFamily(kind); f != nil && !f.ObservationOnly {
		return familyProtocol(f.Name)
	}
	return ""
}

func familyProtocol(name string) string {
	switch name {
	case "pollution":
		return PollutionProtocol
	case "code":
		return CodeProtocol
	case "redirect":
		return RedirectProtocol
	case "upload":
		return UploadProtocol
	case "logging":
		return LoggingProtocol
	case "outbound":
		return "outbound-observation-v1" // Catalog compatibility only; no assessment protocol.
	case "xss":
		return XSSProtocol
	case "sql":
		return SQLProtocol
	case "nosql":
		return NoSQLProtocol
	case "validation":
		return ValidationProtocol
	case "command":
		return CommandProtocol
	case "path":
		return PathProtocol
	case "ssrf":
		return SSRFProtocol
	}
	return ""
}

func familyContract(f *Family, id string) *analysis.APIModel {
	switch f.Name {
	case "pollution":
		return PollutionContract(id)
	case "code":
		return CodeContract(id)
	case "redirect":
		return RedirectContract(id)
	case "upload":
		return UploadContract(id)
	case "sql":
		return SQLContract(id)
	case "nosql":
		return NoSQLContract(id)
	case "command":
		return CommandContract(id)
	case "path":
		return PathContract(id)
	case "ssrf":
		return SSRFContract(id)
	}
	return nil
}

func contractIDs(f *Family) []string {
	switch f.Name {
	case "pollution":
		return pollutionContracts
	case "code":
		return codeContracts
	case "redirect":
		return redirectContracts
	case "upload":
		return uploadContracts
	case "sql":
		return sqlContractIDs
	case "command":
		return commandContractIDs
	case "path":
		return pathContractIDs
	case "ssrf":
		return ssrfContractIDs
	}
	return noSQLContractIDs
}

// claimQuestions decodes and validates one family's claim component against its
// registered question protocol: exact names in order, each with choices.
func (c *catalog) claimQuestions(f *Family) ([]Question, map[string][]map[string]string, error) {
	component, ok := c.components[f.Claim]
	if !ok {
		return nil, nil, fmt.Errorf("family %s claim component missing", f.Name)
	}
	var payload claimMaterial
	if err := decode(component.Material, &payload); err != nil {
		return nil, nil, fmt.Errorf("family %s claim material: %w", f.Name, err)
	}
	names := make([]string, 0, len(payload.Questions))
	for _, q := range payload.Questions {
		names = append(names, q.Name)
		if len(payload.Choices[q.Name]) == 0 {
			return nil, nil, fmt.Errorf("family %s question %s has no choices", f.Name, q.Name)
		}
	}
	if len(names) != len(f.QuestionNames) {
		return nil, nil, fmt.Errorf("family %s claim questions %v do not match registration %v", f.Name, names, f.QuestionNames)
	}
	for i := range names {
		if names[i] != f.QuestionNames[i] {
			return nil, nil, fmt.Errorf("family %s claim questions %v do not match registration %v", f.Name, names, f.QuestionNames)
		}
	}
	return payload.Questions, payload.Choices, nil
}

func flowID(f *Family) string {
	if f.Name == "pollution" || operandFamily(f.Name) {
		return "flow." + f.Name
	}
	if f.ObservationOnly {
		return "flow.outbound"
	}
	if f.Name == "xss" {
		return "flow.xss"
	}
	if f.Name == "command" {
		return "flow.command"
	}
	if f.Name == "path" {
		return "flow.path"
	}
	if f.Name == "ssrf" {
		return "flow.ssrf"
	}
	return "flow.local"
}

// FamilySlugForKind returns the canonical CLI name of a candidate family.
func FamilySlugForKind(kind string) string {
	switch kind {
	case "log_sink_candidate":
		return "logging"
	case "xss_data_candidate":
		return "xss"
	}
	if f := FamFamily(kind); f != nil {
		if f.Name == "validation" {
			return "input-validation"
		}
		return f.Name
	}
	return ""
}

// ValidCLIFamily reports whether name is a canonical analyzer selection.
func ValidCLIFamily(name string) bool {
	if name == "logging" {
		return true
	}
	for _, f := range Families() {
		if FamilySlugForKind(f.Kinds[0]) == name {
			return true
		}
	}
	return false
}
