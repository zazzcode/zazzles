package judge

import (
	"slices"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// applyAuthorizationPolicy follows the lane contract policy order (section 2.7)
// with the authorization table of branch 2 D-13.
func applyAuthorizationPolicy(use analysis.CandidateUse, a *analysis.Assessment) {
	a.FindingStatus, a.Protection = "needs_evidence", "uncertain"
	gap := func(kind, detail string) {
		a.Reason = detail
		a.BlockingGaps = append(a.BlockingGaps, analysis.Gap{Kind: "authorization_" + kind, Detail: detail, At: use.Sink.Span})
	}
	if a.QuestionVersion != analysispacks.AuthorizationProtocol {
		gap("protocol_missing", "Versioned authorization answers are required.")
		return
	}
	f, c := use.Authorization, use.Completeness
	if f == nil || c == nil || c.ClaimKind != "authorization" || use.APIModel == nil || use.APIModel.ID != analysispacks.PHPAuthorizationOperation {
		gap("claim_missing", "Authorization requires source-backed facts, completeness and the operation contract.")
		return
	}
	if err := f.Validate(); err != nil {
		gap("facts_invalid", err.Error())
		return
	}
	for _, role := range append(analysispacks.AuthorizationRoles(), c.Required...) {
		if len(c.Evidence[role]) == 0 {
			gap("evidence_missing", "Missing authorization evidence role "+role+".")
			return
		}
	}
	subject, guard, access := a.Answers["subject_control"], a.Answers["guard_adequacy"], a.Answers["access_adequacy"]
	auth := ""
	if use.EntryFacts != nil && use.EntryFacts.Access != nil {
		auth = use.EntryFacts.Access.Authentication
	}
	routeSelected := f.SubjectProvenance == analysis.SubjectRequestSelected && routePlaceholder(use)
	switch {
	case guard == "none" && len(f.Guards) > 0:
		gap("answers_inconsistent", "guard_adequacy none contradicts a recorded guard.")
		return
	case guard == "adequate" && len(f.Guards) == 0:
		gap("answers_inconsistent", "guard_adequacy adequate contradicts an operation with no guard.")
		return
	case access == "adequate" && auth == analysis.AccessNone:
		gap("answers_inconsistent", "access_adequacy adequate contradicts authentication none.")
		return
	case subject == "not_selected" && routeSelected:
		gap("answers_inconsistent", "not_selected contradicts a route-placeholder subject.")
		return
	}
	var blocking []analysis.Gap
	for _, g := range c.Blockers {
		if g.Kind == "address_trust_configuration_unread" {
			continue
		}
		if g.Kind == analysis.SecurityFieldsUnresolved && !censusOnly(f) {
			continue
		}
		if authorizationBlocking(g.Kind) {
			blocking = append(blocking, g)
		}
	}
	if len(blocking) > 0 {
		a.BlockingGaps = append(a.BlockingGaps, blocking...)
		a.Reason = "Claim-relevant authorization evidence is incomplete."
		return
	}
	if guard == "adequate" || guard == "none" && access == "adequate" {
		a.FindingStatus, a.Protection = "protected_for_claim", "sufficient"
		a.Reason = "The assessment supports that a recorded guard or the entry's access covers the operation."
		return
	}
	enumeratedExposure := slices.Contains(f.Facets, analysis.FacetDataExposure) && f.SubjectProvenance == analysis.SubjectEnumerated
	subjectOK := subject == "request_selected" || enumeratedExposure
	if subjectOK && (guard == "none" || guard == "inadequate") && access == "inadequate" {
		a.FindingStatus, a.Protection = "confirmed_vulnerability", "insufficient"
		if enumeratedExposure && subject != "request_selected" {
			a.Reason = "Enumerated census fields are returned without an adequate guard, and the entry's access is not enough."
		} else {
			a.Reason = "The request selects the record, no adequate guard is recorded, and the entry's access is not enough."
		}
		return
	}
	a.Reason = "The answers do not establish a missing authorization or a protection."
}

func routePlaceholder(use analysis.CandidateUse) bool {
	for _, d := range use.Dependencies {
		if d.Source.ModelText == "route placeholder" {
			return true
		}
	}
	return false
}

func censusOnly(f *analysis.AuthorizationFacts) bool {
	if len(f.Facets) != 1 {
		return false
	}
	return f.Facets[0] == analysis.FacetFunctionLevel || f.Facets[0] == analysis.FacetDataExposure
}

func wireAuthorization(use analysis.CandidateUse, ref func(analysis.Evidence) string) any {
	f := use.Authorization
	if f == nil {
		return nil
	}
	guards := make([]map[string]any, 0, len(f.Guards))
	for _, g := range f.Guards {
		item := map[string]any{"kind": g.Kind, "evidence": ref(g.Evidence)}
		if g.Form != "" {
			item["form"] = g.Form
		}
		if g.AddressSource != "" {
			item["address_source"] = g.AddressSource
		}
		if len(g.Literals) > 0 {
			item["literals"] = g.Literals
			item["literal_class"] = g.LiteralClass
		}
		if g.AddressTrust != nil {
			item["address_trust"] = g.AddressTrust
		}
		guards = append(guards, item)
	}
	out := map[string]any{
		"facets": f.Facets, "subject_class": f.SubjectClass, "subject_provenance": f.SubjectProvenance,
		"operation": f.Operation, "security_fields": f.SecurityFields, "guards": guards, "method_safe": f.MethodSafe,
	}
	if len(f.PeerAccess) > 0 {
		out["peer_access"] = f.PeerAccess
	}
	// Use ids embed a snapshot hash. The saved candidate lists them; the
	// request does not, so a judge payload never carries that hash.
	if use.EntryFacts != nil && use.EntryFacts.Access != nil {
		out["access"] = use.EntryFacts.Access
	}
	return out
}

func authorizationBlocking(kind string) bool {
	switch kind {
	case "access_rule_unresolved", "access_rule_condition_unmodeled", "voter_unmodeled", "access_expression_unmodeled", "authenticator_unmodeled", "guard_unclassified", "symfony_config_unread", analysis.SecurityFieldsUnresolved:
		return true
	default:
		return false
	}
}
