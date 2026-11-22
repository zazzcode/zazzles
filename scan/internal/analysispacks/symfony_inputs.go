package analysispacks

func symfonyInputComponent() Component {
	return Component{
		ID: "source.symfony-input-v1", Version: "1", Kind: "input_interpretation",
		Owner: "internal/analysispacks", CompiledOwner: "internal/langphp/symfony_request.go",
		Domains:       []string{"security", "input_origin"},
		Applicability: []string{"sql_query_candidate", "xss_candidate", "input_validation_candidate", "command_execution_candidate", "path_traversal_candidate", "code_execution_candidate", "template_injection_candidate", "open_redirect_candidate", "file_upload_candidate", "deserialization_candidate", "ssrf_candidate", "outbound_http_candidate", "log_sink_candidate"},
		Compatibility: []string{SQLProtocol, ValidationProtocol, XSSProtocol, CommandProtocol, PathProtocol, CodeProtocol, RedirectProtocol, UploadProtocol, DeserializationProtocol, SSRFProtocol, familyProtocol("outbound"), LoggingProtocol},
		Tests:         []string{"TestSymfonyInputs"},
		Limits:        []string{"source-only Symfony route and argument binding; runtime container and framework validation are not inferred"},
		Material:      "Symfony Request bags distinguish path, query, form, body, cookie, header and upload acquisition. Request::get reads path attributes, then query, then form. A named acquisition identifies a field, and a typed conversion describes a transformation whose security impact depends on the sink operand. A route entity argument or session user supplies stored fields. A request-chosen identifier does not establish who wrote those fields. Reference: https://symfony.com/doc/6.4/components/http_foundation.html#accessing-request-data",
	}
}
