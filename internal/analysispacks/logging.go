package analysispacks

// LoggingProtocol versions catalog-backed sensitive data logging assessments.
const LoggingProtocol = "log-components-v2"

// LoggingQuestions returns the independent content and redaction facets.
func LoggingQuestions() []Question {
	return []Question{
		{"data_class", "Classify the data carried by the request value(s) that this logging operation receives, as named in the evidence. credential = a secret that authenticates or authorizes (password, token, API key, session cookie, Authorization header value, one-time code). personal_data = information that identifies or describes a person (email, phone, government ID, payment card, birth date). other = neither. Use the request contract, how the route uses the value (hashing, comparison with a stored credential, storage in a credential attribute) and HTTP semantics. A field or variable name alone is a hint, not proof; choose unknown when the evidence does not establish the class."},
		{"content_exposure", "Does this emission write the content of that value, wholly or in part, into log output? yes = the value, a substring, or a text-preserving conversion reaches a logged argument or the logged URL; no = only derived facts (length, presence, equality result, type) or a verified redacted form are logged, or the value is not logged; unknown = an unmodeled transformation, serializer or format decides. For request-line logging, the logged URL includes its query string when the format contains :url or is a predefined morgan format."},
		{"redaction", "Is effective redaction or masking applied to that value before this emission on every relevant path? yes = a supplied transformation or logger configuration demonstrably removes or masks the content before emission; no = no redaction is shown; unknown = a call or configuration whose effect is not shown may redact; not_applicable = no content is exposed. A function named mask or redact whose body is not shown is unknown. Redaction after the emission does not count."},
		{"log_exposure", "Does this logging operation expose sensitive data content to the log? vulnerable = credential or personal-data content reaches the log without effective redaction on a supported path; protected = only non-revealing facts or effectively redacted content is logged; unknown = data class, content or redaction cannot be decided from the supplied evidence; not_applicable = the logged data is not sensitive. Constant messages, startup banners, ports, and error stacks without sensitive request data are not exposures. Do not judge who reads the log or its retention; that is outside this question."},
	}
}

// LoggingChoices returns the choices for a logging facet.
func LoggingChoices(name string) []map[string]string {
	switch name {
	case "data_class":
		return []map[string]string{
			{"value": "credential", "description": "The value authenticates or authorizes a principal."},
			{"value": "personal_data", "description": "The value identifies or describes a person."},
			{"value": "other", "description": "The evidence establishes that the value is neither a credential nor personal data."},
			{"value": "unknown", "description": "The evidence does not establish the data class."},
		}
	case "content_exposure":
		return []map[string]string{
			{"value": "yes", "description": "The value's content, or part of it, is written to the log."},
			{"value": "no", "description": "Only derived non-content facts or a verified redacted form are written, or the value is not logged."},
			{"value": "unknown", "description": "An unmodeled transformation, serializer or format decides what is written."},
		}
	case "redaction":
		return []map[string]string{
			{"value": "yes", "description": "Effective redaction before emission is shown on every relevant path."},
			{"value": "no", "description": "No redaction is shown."},
			{"value": "unknown", "description": "A call or configuration whose effect is not shown may redact."},
			{"value": "not_applicable", "description": "No content of the value is exposed."},
		}
	case "log_exposure":
		return []map[string]string{
			{"value": "vulnerable", "description": "Sensitive content reaches the log without effective redaction on a supported path."},
			{"value": "protected", "description": "Only non-revealing facts or effectively redacted content are logged."},
			{"value": "unknown", "description": "Data class, content or redaction cannot be decided from the supplied evidence."},
			{"value": "not_applicable", "description": "The logged data is not sensitive."},
		}
	}
	return nil
}

func loggingQuestionNames() []string {
	var names []string
	for _, q := range LoggingQuestions() {
		names = append(names, q.Name)
	}
	return names
}
