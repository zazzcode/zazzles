package report

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// Guidance is evidence-scoped help, not a generated or verified patch.
// Every result includes the hardening posture: report proven vulnerabilities and
// weak or poor practice, because an agent can fix both cheaply.
type Guidance = analysis.Recommendation

func guidance(use analysis.CandidateUse) Guidance {
	kind := use.Kind
	if use.Check != nil {
		kind = use.Check.Kind
	}
	var g Guidance
	switch kind {
	case "xss_candidate", "xss_data_candidate":
		g = Guidance{Title: "Protect the specific browser rendering context", Actions: []string{
			"Use escaped template output for HTML text and quoted non-active attributes; use textContent for plain DOM text.",
			"For intentional rich HTML, apply a verified maintained sanitizer before every sink; inspect its configuration and version.",
			"Treat script, URL, event-handler and unquoted-attribute contexts separately. HTML entity encoding alone does not protect them.",
			"Preserve source, storage and output links when fixing reflected or stored flows; test the protected counterpart."}}
	case "sql_query", "sql_query_candidate":
		g = Guidance{Title: "Separate input data from SQL structure", Actions: []string{
			"Pass untrusted values through the verified driver's parameter-binding API. Keep SQL query, update, and insert structure separate from data. Review NoSQL APIs separately.",
			"Restrict each field as far as its business requirement allows. A string or length check is not injection protection. A comment or other free-text field may contain any character, so the sink construction is the injection control.",
			"Add regression cases for normal input, rejected malformed input and query-structure preservation; resolve inconclusive guard and binding evidence before applying a fix.",
		}, ExampleStatus: "not_generated; driver-specific adaptation and tests required"}
		if use.Completeness != nil && len(use.Completeness.Evidence["sink_binding"]) > 0 && use.APIModel != nil && use.APIModel.Library == "sequelize" {
			g.Example = "// Illustrative Sequelize binding pattern; adapt schema and full authentication logic.\nconst rows = await sequelize.query(\n  'SELECT id FROM accounts WHERE email = $email',\n  { bind: { email: req.body.email } }\n);"
			g.ExampleStatus = "illustrative_template; not a verified application patch"
		}
	case "nosql_query", "nosql_query_candidate":
		g = Guidance{Title: "Keep request data out of NoSQL query structure", Actions: []string{
			"Reject objects and operators in fields that should be scalars before they reach a query, update, or insert document.",
			"Do not concatenate or interpolate request values into $where strings.",
			"Inspect numeric conversions and character filters on each actual path before judging their effect. Prefer data-only query APIs over executable $where strings.",
		}, ExampleStatus: "not_generated; driver-specific adaptation and tests required"}
	case "command_execution_candidate":
		g = commandGuidance()
	case "path_traversal_candidate":
		g = pathGuidance()
	case "template_injection_candidate":
		g = Guidance{Title: "Keep request text out of template source", Actions: []string{"Compile a constant template and pass request values as render variables.", "Do not rely on a sandboxed environment alone; keep the template source constant."}}
	case analysis.PollutionKind:
		g = Guidance{Title: "Restrict prototype traversal before writing keys", Actions: []string{"Use a patched version of the write library.", "Allow known keys or reject prototype-related names at every traversal level. Require own-property access for existing target containers."}}
	case "code", "code_execution_candidate":
		g = Guidance{Title: "Keep request text out of code", Actions: []string{"Replace eval/exec with data parsing or a restricted expression grammar.", "Do not rely on vm or a sandbox library as a security boundary; constrain every code operand."}}
	case "deserialization", analysis.DeserializationKind:
		g = Guidance{Title: "Parse untrusted bytes as plain data", Actions: []string{"Choose a data-only format or a verified safe loader or schema.", "When trusted serialized messages are required, enforce keyed integrity verification of the same bytes before deserializing."}}
	case analysis.ExposureKind:
		g = Guidance{Title: "Keep diagnostic output away from callers", Actions: []string{"Remove phpinfo(), backtraces and environment dumps from served code.", "Where a diagnostic page is required, restrict it to an authenticated administrator and disable it outside development."}}
	case analysis.MassAssignmentKind:
		g = Guidance{Title: "Let the code, not the request, choose written fields", Actions: []string{"Write each permitted field through a named setter from a named request field.", "If a generic copy is required, intersect the request keys with a literal allow-list that excludes privilege, credential and identity fields; property_exists restricts nothing."}}
	case analysis.AuthorizationKind:
		if authorizationAddressOnly(use) {
			g = Guidance{Title: "Do not authorize an operation from the caller's address", Actions: []string{"Require an authenticated caller.", "Authorize the operation on the selected record. An address check is a property of the connection."}}
		} else {
			g = Guidance{Title: "Authorize the operation on the selected record", Actions: []string{"Check that the caller may perform this operation on this record.", "Require the same access on every entry that writes the field."}}
		}
	case "upload", "file_upload_candidate":
		g = Guidance{Title: "Restrict what an upload can become", Actions: []string{"Generate the stored file name and choose its extension on the server from an allow-list or the verified content type.", "Check the content (magic bytes, image decoding) or re-encode it, and store uploads outside the served document root."}}
	case "redirect", "open_redirect_candidate":
		g = Guidance{Title: "Constrain navigation destinations", Actions: []string{"Prefer an identifier mapped to fixed trusted destinations.", "Otherwise parse the URL and enforce same-origin or a finite host allowlist on every path; reject protocol-relative and backslash-relative destinations."}}
	case "ssrf_candidate":
		g = ssrfGuidance()
	case "input_validation", "input_validation_candidate":
		g = Guidance{Title: "Validate and sanitize each request input", Actions: []string{
			"Define the server-side field policy, then enforce applicable type, presence, length, range, and format constraints before use. Free text must remain valid for its business purpose.",
			"Use destination-specific protection independently of field validation: SQL parameter binding or a verified NoSQL document API with constrained keys and scalar types. Do not apply a generic sanitizer as a substitute.",
			"Preserve an explicit Inconclusive result when a call receives the field but its effect has not been established.",
		}, ExampleStatus: "not_generated; field policy is route-specific"}
	case "account_creation", "account_creation_candidate":
		g = Guidance{Title: "Enforce required fields before account creation", Actions: []string{
			"Validate required fields independently of optional confirmation fields and before the persistence operation.",
			"Check runtime types, normalize according to policy, then enforce nonempty/format constraints; return immediately on rejection.",
			"Add appropriate model/database constraints as defense in depth and test actual persisted state, not only an HTTP response or challenge flag.",
		}, Example: "// Illustrative middleware; add the route's remaining schema requirements.\nconst { email, password } = req.body;\nif (typeof email !== 'string' || typeof password !== 'string' ||\n    email.trim().length === 0 || password.trim().length === 0) {\n  return res.status(400).json({ error: 'Invalid required fields' });\n}\n// Continue only after applying the remaining field policy.\nreturn next();", ExampleStatus: "illustrative_template; not a verified application patch"}
	case "log_sink", "log_sink_candidate":
		g = Guidance{Title: "Keep credential and personal-data content out of logs", Actions: []string{
			"Remove the value from the log entry, or log a non-revealing fact (presence, length, match result, or a non-reversible identifier) instead.",
			"Log an allowlist of fields rather than whole request bodies, queries, or header sets. Never log Authorization or Cookie header values.",
			"If redaction is required, apply a verified redaction before the logger call or in the logger's configuration, and test that emitted lines no longer contain the value.",
			"Do not send credentials in URL query strings; access logs, proxies, and browser history record URLs. Use a request body or header instead.",
		}, Example: "// Illustrative: log a fact about the credential, not the credential.\nconsole.info('login attempt', { username, passwordProvided: typeof password === 'string' && password.length > 0 });", ExampleStatus: "illustrative_template; not a verified application patch"}
		if hasGap(use, "log_request_line_credential") || hasGap(use, "log_request_line_hint") {
			g.Title = "Keep credentials out of URLs and access logs"
			g.Actions = []string{
				"Move the credential from the URL query string to the request body (for example change GET to POST) and update every client that calls the route.",
				"Until clients change, exclude this route's query string from access logs or use a format without :url for it, and rotate any credentials already written to existing logs.",
				"Restrict who can read access-log files; a log directory served over HTTP exposes every recorded URL.",
			}
			g.Example = "// Illustrative: accept the credentials in the body, not the URL.\napp.post('/rest/user/change-password', express.json(), (req, res) => {\n  const { current, new: next, repeat } = req.body;\n  // ...existing checks and update\n});"
		}
	default:
		g = Guidance{Title: "Review protection for the named use", Actions: []string{"Resolve the source-to-use relationship and applicable guards.", "Apply the destination/API-specific protection and the route's declared field requirements.", "Add vulnerable, protected and inconclusive regression cases."}, ExampleStatus: "no code example for an unverified library model"}
	}
	// Project tenet: an agent can harden weak practice cheaply, so every result says so.
	g.Actions = append([]string{"Remediate established vulnerabilities and poor practice. For Review items, resolve the named evidence before deciding whether or how behavior needs to change."}, g.Actions...)
	return g
}
