package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// logQuestionVersion is versioned separately so query assessments keep their protocol.
const logQuestionVersion = analysispacks.LoggingProtocol

var logQuestions = componentQuestions(analysispacks.LoggingQuestions())

func logChoices(name string) []map[string]string { return analysispacks.LoggingChoices(name) }

func logUse(use analysis.CandidateUse) bool { return use.Kind == "log_sink_candidate" }

// applyLogPolicy requires binding and source evidence and answers that agree with
// each other and with the scanner's own content facts before a definitive status.
func applyLogPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	ans := a.Answers
	switch ans["log_exposure"] {
	case "vulnerable":
		a.Protection = "insufficient"
	case "protected":
		a.Protection = "sufficient"
	case "not_applicable":
		a.Protection = "not_applicable"
	default:
		a.Protection = "uncertain"
	}
	var blockers []analysis.Gap
	for _, g := range use.Gaps {
		switch g.Kind {
		case "log_literal_sensitivity_unresolved", "log_transform_unresolved", "input_helper_unresolved", "python_decorator_unresolved", "route_mount_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, g)
		}
	}
	binding := false
	for _, e := range use.Context {
		binding = binding || e.Kind == "logger_binding"
	}
	if !binding {
		blockers = append(blockers, analysis.Gap{Kind: "logger_binding_missing", Detail: "verified logger or request-logging binding is required"})
	}
	source := false
	for _, d := range use.Dependencies {
		source = source || d.Source.Kind == "input_source" || d.Source.Kind == "literal_sensitive_source" || d.Source.Kind == "storage_source"
	}
	if !source {
		blockers = append(blockers, analysis.Gap{Kind: "log_source_missing", Detail: "request, literal personal-data or verified storage source evidence is required"})
	}
	a.BlockingGaps = blockers
	if len(blockers) > 0 {
		a.FindingStatus = "needs_evidence"
		a.Protection = "uncertain"
		a.Reason = "logging claim evidence is incomplete"
		return
	}
	sensitive := ans["data_class"] == "credential" || ans["data_class"] == "personal_data"
	nonContentOnly := hasLogGap(use, "log_non_content_only") && !hasLogGap(use, "log_protocol_credential", "log_sensitive_field_hint", "log_request_container", "log_transform_unresolved", "log_request_line_credential", "log_request_line_hint")
	switch ans["log_exposure"] {
	case "vulnerable":
		if !sensitive || ans["content_exposure"] != "yes" || (ans["redaction"] != "no" && ans["redaction"] != "not_applicable") || nonContentOnly {
			a.FindingStatus = "needs_evidence"
			a.Protection = "uncertain"
			a.Reason = "Exposure answer is not supported by consistent data-class, content and redaction answers, or contradicts the scanner's non-content facts."
			return
		}
		a.FindingStatus = "confirmed_vulnerability"
		a.Reason = "Verified logger binding and source evidence, with consistent answers that sensitive content reaches the log without redaction; this is a static judgment, not runtime confirmation."
	case "protected":
		if ans["content_exposure"] != "no" && ans["redaction"] != "yes" && ans["data_class"] != "other" {
			a.FindingStatus = "needs_evidence"
			a.Protection = "uncertain"
			a.Reason = "Protection answer is not supported by content, redaction or data-class answers."
			return
		}
		a.FindingStatus = "protected_for_claim"
		a.Reason = "Assessment supports that this emission does not expose sensitive content for the supplied claim."
	case "not_applicable":
		if ans["data_class"] != "other" {
			a.FindingStatus = "needs_evidence"
			a.Protection = "uncertain"
			a.Reason = "Not-applicable exposure requires a non-sensitive data class."
			return
		}
		a.FindingStatus = "not_applicable"
		a.Reason = "Assessment establishes that the logged data is not sensitive."
	default:
		a.FindingStatus = "needs_evidence"
		a.Reason = "Logging exposure assessment is missing or inconclusive."
	}
}

func hasLogGap(use analysis.CandidateUse, kinds ...string) bool {
	for _, g := range use.Gaps {
		for _, k := range kinds {
			if g.Kind == k {
				return true
			}
		}
	}
	return false
}
