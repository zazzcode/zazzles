package analysispacks

// PHP input interpretation is separately versioned so the shared acquisition
// schema gains a PHP identity without changing any existing request bytes.
func phpInputComponent() Component {
	return Component{
		ID: "source.php-input-v1", Version: "1", Kind: "input_interpretation",
		Owner: "internal/analysispacks", CompiledOwner: "internal/parse/php_flow.go + internal/parse/php_input_facts.go",
		Domains:       []string{"security", "input_origin"},
		Applicability: []string{"sql_query_candidate", "xss_candidate", "input_validation_candidate", "command_execution_candidate", "path_traversal_candidate", "code_execution_candidate", "open_redirect_candidate"},
		Compatibility: []string{SQLProtocol, ValidationProtocol, XSSProtocol, CommandProtocol, PathProtocol, CodeProtocol, RedirectProtocol},
		Tests:         []string{"TestPHPInputFacts", "TestPHPComponentSelection"},
		Limits:        []string{"existing bounded PHP adapters; runtime types remain unknown; unresolved helper bodies, loops and dynamic includes retain existing gaps"},
		Material:      "PHP input facts separate acquisition origin from initial runtime type and type at the actual sink. Superglobals map to request origins ($_GET query, $_POST form, $_REQUEST query-or-form, $_COOKIE cookies, $_FILES upload, selected $_SERVER keys headers/path, php://input body). $_SESSION is a storage container linked to prior writes as transfers, never an untrusted request origin. Unknown types are explicit uncertainty, not evidence of vulnerability or protection. Casts and annotations alone do not prove runtime validation; helper behavior requires its actual supplied implementation and binding evidence. Source-present application logic is assessed from its context and exact transfers, including conditional siblings and include-composed scopes. Keep business validation, authorization and operation-specific syntax protection independent. Acquisition facts never replace the selected operation contract.",
	}
}
