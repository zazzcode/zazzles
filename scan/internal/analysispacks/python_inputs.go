package analysispacks

// Python input interpretation is separately versioned so adopting the shared
// acquisition schema does not change existing Node or historical request bytes.
func pythonInputComponent() Component {
	return Component{
		ID: "source.python-input-v1", Version: "1", Kind: "input_interpretation",
		Owner: "internal/analysispacks", CompiledOwner: "internal/parse/python_input_adapters.go + internal/parse/python_input_facts.go",
		Domains:       []string{"security", "input_origin"},
		Applicability: []string{"sql_query_candidate", "xss_candidate", "input_validation_candidate", "command_execution_candidate", "outbound_http_candidate", "log_sink_candidate", "path_traversal_candidate", "ssrf_candidate"},
		Compatibility: []string{SQLProtocol, ValidationProtocol, XSSProtocol, CommandProtocol, LoggingProtocol, PathProtocol, SSRFProtocol, familyProtocol("outbound")},
		Tests:         []string{"TestPythonInputFacts", "TestPythonInputRequestCompatibility", "TestPythonInputPredecessorBaseline"},
		Limits:        []string{"existing bounded Python HTTP adapters; runtime types remain unknown; unresolved lifecycle/dependency bodies and unsupported continuations retain existing gaps"},
		Material:      "Python input facts separate acquisition origin from initial runtime type and type at the actual sink. Unknown types are explicit uncertainty, not evidence of vulnerability or protection. Python annotations alone do not prove runtime validation. Framework-bound coercion, dependencies, model configuration and custom validators require their actual supplied implementations and binding evidence. Do not infer hook order, dispatch, missing implementations or type guarantees from function names or framework names. Source-present application logic is assessed from its context and exact transfers, including replacement after validation, conditional siblings, uploads and thread boundaries. Keep business validation, authorization and operation-specific syntax protection independent. Acquisition facts never replace the selected operation contract.",
	}
}
