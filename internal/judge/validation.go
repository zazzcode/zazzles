package judge

import (
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// validationUse covers standalone field-policy records: Python claims with
// assembled policy evidence and JS/TS field records that only carry gaps.
func validationUse(u analysis.CandidateUse) bool {
	return u.Kind == "input_validation_candidate"
}

// validationEvidenceBlockers returns the scanner-side gaps that keep a
// validation record from passing its policy gate whatever the model answers:
// completeness blockers and required roles with no evidence.
func validationEvidenceBlockers(u analysis.CandidateUse) []analysis.Gap {
	blockers := []analysis.Gap{}
	roles := []string{"input_source", "field_policy", "invoked_callable", "control_flow"}
	if u.Completeness != nil {
		blockers = append(blockers, u.Completeness.Blockers...)
		roles = append(append([]string{}, u.Completeness.Required...), roles...)
	}
	if u.Components != nil {
		// Selected obligations extend, never replace, the adapter's roles.
		roles = append(roles, u.Components.Required...)
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if seen[role] {
			continue
		}
		seen[role] = true
		if u.Completeness == nil || len(u.Completeness.Evidence[role]) == 0 {
			blockers = append(blockers, analysis.Gap{Kind: "validation_evidence_missing", Detail: role, At: u.Sink.Span})
		}
	}
	return blockers
}

// validationGate settles, before any request, a validation record whose
// policy gate cannot pass: no model answer could change its outcome, so it is
// not sent. Records named by --checks, and every validation record when the
// run selects only the input-validation family, are judged as before.
func validationGate(u analysis.CandidateUse, opts ScheduleOptions) (analysis.Assessment, bool) {
	if !validationUse(u) || u.Check != nil || containsFamily(opts.OnlyFamilies, "input-validation") {
		return analysis.Assessment{}, false
	}
	blockers := validationEvidenceBlockers(u)
	if len(blockers) == 0 {
		return analysis.Assessment{}, false
	}
	roles := []string{}
	for _, g := range blockers {
		if g.Kind == "validation_evidence_missing" {
			roles = append(roles, g.Detail)
		} else {
			roles = append(roles, g.Kind)
		}
	}
	return analysis.Assessment{Status: "not_run", Reason: ValidationUndecidable + ": the policy gate needs " + strings.Join(roles, ", ") + "; no model answer could change this outcome, so no request was sent",
		BlockingGaps: blockers}, true
}

// ValidationUndecidable prefixes the not-run reason of a validation record
// the decidability gate kept from the judge.
const ValidationUndecidable = "validation_evidence_missing"

func applyValidationPolicy(u analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	blockers := validationEvidenceBlockers(u)
	if a.QuestionVersion != analysispacks.ValidationProtocol {
		blockers = append(blockers, analysis.Gap{Kind: "validation_protocol_missing"})
	}
	a.BlockingGaps = blockers
	if len(blockers) > 0 || a.Answers["enforcement_coverage"] != "complete" || a.Answers["field_requirement"] != "established" {
		a.Reason = "The field policy or relevant enforcement implementation is incomplete; supply the named evidence rather than inferring a validation defect."
		return
	}
	switch a.Answers["validation"] {
	case "insufficient":
		a.FindingStatus, a.Protection = "poor_practice", "insufficient"
		a.Reason = "A source-backed field requirement is not enforced on a supported server path; sink protection is a separate claim."
	case "sufficient":
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The supplied policy, enforcing guards/helpers and path evidence support this exact field constraint."
	default:
		a.Reason = "The supplied implementation does not support a definite validation judgment."
	}
}
func protocolVersion(u analysis.CandidateUse) string {
	if version := analysispacks.ProtocolFor(u.Kind); version != "" {
		return version
	}
	if logUse(u) {
		return logQuestionVersion
	}
	return questionVersion
}
