package judge

import (
	"slices"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// applyMassAssignmentPolicy follows the lane contract policy order (section
// 2.7) with the mass-assignment table of branch 1 D-13.
func applyMassAssignmentPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "mass_assignment_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.MassAssignmentProtocol {
		gap("protocol_missing", "Versioned mass-assignment answers are required.")
		return
	}
	f, c := use.MassAssignment, use.Completeness
	if f == nil || c == nil || c.ClaimKind != "mass_assignment" {
		gap("claim_missing", "Mass assignment requires source-backed facts and completeness.")
		return
	}
	if err := f.Validate(); err != nil {
		gap("facts_invalid", err.Error())
		return
	}
	for _, role := range append(analysispacks.MassAssignmentRoles(), c.Required...) {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing mass-assignment evidence role "+role+".")
			return
		}
	}
	control, restriction, impact := a.Answers["key_control"], a.Answers["key_restriction"], a.Answers["field_impact"]
	allowList := f.HasKeyGuard(analysis.KeyAllowList)
	wholeBag := len(c.Evidence["key_origin"]) > 0
	if restriction == "adequate" && !allowList || impact == "privileged_field" && len(f.SecurityFields) == 0 || control == "fixed" && wholeBag {
		gap("answers_inconsistent", "The answers contradict the recorded key origin, key guards or security fields.")
		return
	}
	blocking := slices.Clone(c.Blockers)
	for _, g := range append(slices.Clone(use.Gaps), c.Coverage...) {
		switch g.Kind {
		case analysis.MassAssignmentFormUnmodeled, analysis.MassAssignmentSerializerUnmodeled, analysis.MassAssignmentPayloadUnmodeled:
		case analysis.SecurityFieldsUnresolved:
			if len(f.SecurityFields) > 0 {
				continue
			}
		default:
			continue
		}
		if !slices.ContainsFunc(blocking, func(b analysis.Gap) bool { return b.Kind == g.Kind }) {
			blocking = append(blocking, g)
		}
	}
	if len(blocking) > 0 {
		a.BlockingGaps = append(a.BlockingGaps, blocking...)
		a.Reason = "Claim-relevant mass-assignment evidence is incomplete."
		return
	}
	if restriction == "adequate" && allowList {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "A recorded key allow-list limits the request-chosen names to an adequate set."
		return
	}
	if control == "request_chosen" && (restriction == "none" || restriction == "inadequate") && impact == "privileged_field" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		a.Reason = "The request chooses property names on an object with a field it should not choose, and no adequate key restriction applies."
		return
	}
	if impact == "no_sensitive_field" {
		a.Reason = "The request chooses property names, but no field it should not choose is established: poor practice, not a confirmed privilege defect."
		return
	}
	a.Reason = "The answers do not establish a privileged write or a protection."
}
