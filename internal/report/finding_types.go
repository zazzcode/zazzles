package report

import "github.com/zazzcode/zazzles/internal/analysis"

// findingTypes is the shared terminology registry, independent of detector verdicts.
var findingTypes = []analysis.FindingType{
	{ID: "dom-xss", Label: "Client-side XSS", Coverage: "bounded browser DOM and Angular/React/Vue analysis",
		Description:    "Browser or API data reaches a DOM or framework rendering operation in an active output context.",
		Interpretation: "Client entries identify browser sources and verified sinks. Raw flows are construction findings; unknown origin, trust-to-template linkage or API response mapping remains Review. Framework defaults can protect a specific output.",
		Remediation:    "Prefer text APIs and default framework escaping/sanitization. Sanitize rich HTML before rendering, remove unnecessary trust bypasses and verify API origins."},
	{ID: "rendering-flow-review", Label: "Rendering Flow Review", Coverage: "bounded API response evidence",
		Description:    "Data returned by an API needs its browser consumer linked before a rendering claim can be assessed.",
		Interpretation: "JSON output alone is not an XSS sink or a vulnerability. This record is incomplete flow context for further analysis.",
		Remediation:    "Locate the browser consumer, establish its output context and protections, and assess that rendering flow before changing API data handling."},
	{ID: "sql-injection", Label: "SQL Injection", Coverage: "bounded analysis",
		Description:    "Input changes executable SQL structure instead of remaining a data value, potentially changing what the database reads or writes.",
		Interpretation: "An SQL Injection pill identifies the risk family being reviewed. String-built executable SQL is poor practice to remediate even without a proven exploit; a library-managed search value may remain unresolved. The finding status and evidence determine the actual claim. The pill alone does not confirm injection.",
		Remediation:    "Use the verified driver's parameter-binding API for values. Review dynamic identifiers separately. Keep business-field validation independent of query-structure protection."},
	{ID: "nosql-injection", Label: "NoSQL Injection", Coverage: "bounded analysis",
		Description:    "Untrusted input changes a NoSQL query's operators, selector structure, or executable expression rather than remaining an allowed data value.",
		Interpretation: "Executable $where string construction is poor practice to refactor even without a proven exploit. An unmodeled document constraint alone is Review, not an established defect. Inspect actual value types, keys, transformations, library behavior, and the named status.",
		Remediation:    "Prefer data-only query APIs, constrain scalar slots and permitted keys/operators, and avoid building executable $where strings from input."},
	{ID: "command-injection", Label: "Command Injection", Coverage: "bounded Node child_process and Python os/subprocess analysis",
		Description:    "Request-controlled values reach an operating-system process: shell command text, the executable, a separate argument or process shell configuration.",
		Interpretation: "One record per process use, with separate shell-syntax, executable-selection and argument facets under a declared POSIX assumption. A confirmed record is a static source judgment, not runtime exploitation or independent Findings Review. Shell-disabled argument arrays do not by themselves establish protection; an unknown utility's options and unmodeled platform behavior remain Review.",
		Remediation:    "Prefer eliminating process execution. Otherwise use a fixed trusted absolute executable, pass values as separate arguments with the shell disabled, and enforce utility-specific constraints such as a finite set of permitted values. Do not rely on stripping punctuation or on `--` as a universal option terminator."},
	{ID: "input-validation", Label: "Input Validation", Coverage: "bounded analysis",
		Description:    "Server-side checks enforce the business requirements for a field, such as required presence, runtime type, permitted format, range, or length.",
		Interpretation: "Poor input validation means an applicable requirement is not adequately enforced. This neutral family label also covers unresolved checks and supported protection: no validator identified in an analyzed slice is not proof that every execution path lacks validation. Free-text punctuation is not itself a defect.",
		Remediation:    "Define field-specific requirements and enforce them before use on all applicable paths. Verify guard behavior and middleware. Apply destination-specific protection separately."},
	{ID: "account-creation-validation", Label: "Account Creation Validation", Coverage: "bounded analysis",
		Description:    "Required account fields and enforcing guards must be checked before an account is persisted.",
		Interpretation: "Review field requirements, conditional bypasses, and generated persistence behavior. A modeled create operation alone does not prove a registration bypass.",
		Remediation:    "Enforce required fields before persistence, terminate rejected paths, add appropriate database constraints, and test the persisted result."},
	{ID: "outbound-request-safety", Label: "Outbound Request Safety", Coverage: "bounded analysis",
		Description:    "Input used in an outbound request may affect its destination, headers, or other request values. Unrestricted destination control can lead to server-side request forgery (SSRF).",
		Interpretation: "The current scanner records bounded outbound-use evidence. A pill does not establish SSRF, destination reachability, or complete response-flow analysis.",
		Remediation:    "Verify allowed destinations and protocols, redirect handling, network boundaries, and sensitive request values for the specific HTTP client."},
	{ID: "reflected-xss", Label: "Reflected XSS", Coverage: "bounded server response and template analysis",
		Description:    "Request-controlled content is reflected into a browser response in a context that allows it to execute as script.",
		Interpretation: "Request input reaches an HTML response or template output. Raw output is a construction finding; unknown context or sanitizers remain Review. Escaping protects only its modeled output context. Runtime exploitation is not implied.",
		Remediation:    "Use context-appropriate output encoding and safe template or DOM APIs. Input validation alone does not replace correct output handling."},
	{ID: "stored-xss", Label: "Stored XSS", Coverage: "bounded model-field write/read and server template analysis",
		Description:    "Untrusted data is persisted and later rendered in an active browser context.",
		Interpretation: "A matching model and field link source writes to rendering reads. Unresolved write origins remain Review; a verified raw path is a construction finding. A dependency version alone does not establish a reachable XSS flow.",
		Remediation:    "Preserve the intended stored data; apply context-appropriate escaping or maintained sanitization at every rendering sink, and review existing stored content."},
	{ID: "sensitive-data-logging", Label: "Sensitive Data Logging", Coverage: "bounded analysis",
		Description:    "Logs expose credentials, tokens, personal information, or other sensitive values to readers or storage that should not receive them.",
		Interpretation: "Covers verified console and winston calls in analyzed route handlers that receive request values with credential or personal-data evidence. A field name is a hint for review, not proof; Authorization and Cookie headers are credentials by HTTP semantics. Morgan request logging that records URLs is checked against credentials read from the query string. Constant messages are not leaks. Non-request secrets and logger redaction configuration are not yet analyzed.",
		Remediation:    "Avoid logging secrets; minimize sensitive fields and apply verified redaction before emission. Review log access and retention."},
	{ID: "sensitive-operation-review", Label: "Sensitive Operation Review", Coverage: "bounded analysis",
		Description:    "A possible sensitive use was recorded but does not yet map to a more specific supported risk family.",
		Interpretation: "This is an analysis category. Inspect the evidence and missing operation semantics before making a security claim.",
		Remediation:    "Resolve the source, operation, API behavior, and required protection before selecting a fix."},
}

var findingTypesByID = func() map[string]analysis.FindingType {
	index := make(map[string]analysis.FindingType, len(findingTypes))
	for _, t := range findingTypes {
		index[t.ID] = t
	}
	return index
}()

func findingTypeIDs(u analysis.CandidateUse) []string {
	kind := u.Kind
	if u.Check != nil {
		kind = u.Check.Kind
	}
	ids := []string{}
	switch kind {
	case "xss_data_candidate":
		return append(ids, "rendering-flow-review")
	case "sql_query", "sql_query_candidate":
		ids = append(ids, "sql-injection")
	case "nosql_query", "nosql_query_candidate":
		ids = append(ids, "nosql-injection")
	case "command_execution_candidate":
		return append(ids, "command-injection")
	case "input_validation", "input_validation_candidate":
		ids = append(ids, "input-validation")
	case "account_creation", "account_creation_candidate":
		ids = append(ids, "account-creation-validation", "input-validation")
	case "outbound_http", "outbound_http_candidate":
		ids = append(ids, "outbound-request-safety")
	case "log_sink", "log_sink_candidate":
		// Field validation does not change what a log line contains; it is reported on its own record.
		return append(ids, "sensitive-data-logging")
	case "xss_candidate":
		if u.XSS != nil && u.XSS.EntryKind == "client" {
			return append(ids, "dom-xss")
		}
		if u.XSS != nil && u.XSS.Type == "stored" {
			return append(ids, "stored-xss")
		}
		return append(ids, "reflected-xss")
	default:
		ids = append(ids, "sensitive-operation-review")
	}
	if kind != "input_validation" && kind != "input_validation_candidate" && kind != "account_creation" && kind != "account_creation_candidate" {
		for _, g := range u.Gaps {
			switch g.Kind {
			case "input_validation_absent", "input_validation_unresolved", "input_validation_middleware", "validation_insufficient_for_sink", "validation_type_only", "sink_must_bind_free_text", "validation_free_text_bound":
				return append(ids, "input-validation")
			}
		}
		if u.Check != nil && u.Check.Validation != "" {
			ids = append(ids, "input-validation")
		}
	}
	return ids
}
