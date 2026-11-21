package report

import (
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// describeLog applies the sensitive-data logging outcome rules: an established
// protocol credential in log content is a finding, hints and unresolved
// transformations are Review, and only non-content facts are Protected.
func describeLog(u analysis.CandidateUse, f *analysis.Finding) {
	var details []string
	for _, g := range u.Gaps {
		switch g.Kind {
		case "log_protocol_credential", "log_sensitive_field_hint", "log_request_container", "log_transform_unresolved", "log_non_content_only",
			"log_request_line_credential", "log_request_line_hint", "log_request_line_conditional":
			details = append(details, g.Detail)
		}
	}
	f.Validation = "Field validation is reported separately; it does not change what this log line contains."
	f.Protection = "Logging evidence: " + strings.Join(details, "; ") + "."
	switch {
	case hasGap(u, "log_request_line_credential") && !hasGap(u, "log_request_line_conditional"):
		f.RecordType = "finding"
		f.Status = "poor_practice"
		f.Title = "Credential in the URL query is written to access logs"
		f.Summary = "The route reads a credential from the URL query string, and request logging registered before the route records the full URL. Send the credential in the request body (for example with POST) instead of the URL, and keep query strings out of access logs for sensitive routes."
	case hasGap(u, "log_request_line_credential") || hasGap(u, "log_request_line_hint"):
		f.RecordType = "analysis"
		f.Status = "needs_review"
		f.Title = "Possible sensitive data in the URL query of an access log"
		f.Summary = "Request logging records the URL of this route, and a query field may carry a credential or personal data, or the logging may not apply to every request. Confirm what the field contains and whether the access log records it before changing behavior."
	case hasGap(u, "log_protocol_credential"):
		f.RecordType = "finding"
		f.Status = "poor_practice"
		f.Title = "Request credential is written to logs"
		f.Summary = "A credential carried by the request reaches a verified logging call with its content intact. Remove it from the log entry or log a non-revealing fact, such as whether it was present."
	case hasGap(u, "log_request_container") && !hasGap(u, "log_sensitive_field_hint"):
		container := "request data"
		for _, dependency := range u.Dependencies {
			if strings.HasSuffix(dependency.Source.Text, ".query") {
				container = "request query"
			} else if strings.HasSuffix(dependency.Source.Text, ".body") {
				container = "request body"
			}
		}
		f.RecordType, f.Status = "analysis", "needs_review"
		f.Title = "Whole " + container + " is sent to a logging call"
		f.Summary = "The handler passes a whole request container to a verified logging call. This is logging evidence, not an established sensitive-data leak: no credential or personal-data field has been identified in this container. Review which fields are logged and retain only necessary data."
	case hasGap(u, "log_sensitive_field_hint") || hasGap(u, "log_transform_unresolved"):
		f.RecordType = "analysis"
		f.Status = "needs_review"
		f.Title = "Possible sensitive data in a log entry"
		f.Summary = "A verified logging call receives a request value whose field name or container suggests credentials or personal data, or that passes through an unresolved transformation. Confirm what the value contains and whether redaction applies before changing behavior. A field name is a hint, not proof."
	case hasGap(u, "log_non_content_only"):
		f.RecordType = "protection"
		f.Status = "protected_for_claim"
		f.Title = "Only non-revealing facts are logged"
		f.Summary = "Values derived from hinted request fields are reduced to length, comparison, type, or presence facts before logging. Their content is not written by this call."
	}
}
