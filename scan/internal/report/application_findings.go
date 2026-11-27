package report

import (
	"slices"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// linkJudgedSSRFFindings adds the reverse presentation link without changing uses.
func linkJudgedSSRFFindings(r *analysis.AnalysisReport) {
	judgedSSRF := map[string]int{}
	for i, u := range r.Uses {
		if u.Kind == "ssrf_candidate" && u.Assessment.Status == "completed" {
			judgedSSRF[u.ID] = i
		}
	}
	if len(judgedSSRF) == 0 {
		return
	}
	for i, u := range r.Uses {
		if u.Authorization == nil {
			continue
		}
		for _, id := range u.Authorization.ServerSideRequests {
			if j, ok := judgedSSRF[id]; ok {
				related := &r.Findings[j].RelatedFindings
				if ref := r.Findings[i].ID; !slices.Contains(*related, ref) {
					*related = append(*related, ref)
				}
			}
		}
	}
}

// describeExposure presents the diagnostic operation and the judged status.
func describeExposure(u analysis.CandidateUse, f *analysis.Finding) {
	x := u.Exposure
	a := u.Assessment
	if f.Status != "protected_for_claim" {
		f.Title = "Diagnostic output needs review"
		f.Summary = "The entry reaches " + x.Operation + ", which can reveal " + displayLabel(x.Subject) + "."
	}
	if a.Status == "completed" && a.QuestionVersion == analysispacks.ExposureProtocol && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability" {
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title = "Information exposure supported by source analysis"
		f.Summary = "A caller of the entry reaches " + x.Operation + ", which discloses " + displayLabel(x.Subject) + " (CWE-200)."
	} else if f.Status == "protected_for_claim" {
		f.Title = "Diagnostic output is restricted"
		f.Summary = "The assessment supports that a recorded guard restricts " + x.Operation + " or that it discloses nothing internal."
	}
	if a.Reason != "" {
		f.Protection = "Exposure assessment: output " + displayLabel(a.Answers["exposure_output"]) + ", reach " + displayLabel(a.Answers["exposure_reach"]) + ". Scanner policy: " + a.Reason
	}
}

// describeMassAssignment presents the key-controlled write and the judged status.
func describeMassAssignment(u analysis.CandidateUse, f *analysis.Finding) {
	x := u.MassAssignment
	a := u.Assessment
	if f.Status != "protected_for_claim" {
		f.Title = "Request-chosen property names need review"
		f.Summary = "The request chooses which properties of " + x.TargetClass + " are written (" + displayLabel(x.Shape) + ")."
	}
	if a.Status == "completed" && (a.QuestionVersion == analysispacks.MassAssignmentProtocol || a.QuestionVersion == analysispacks.MassAssignmentProtocolV2) && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability" {
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title = "Mass assignment supported by source analysis"
		f.Summary = "The request chooses property names written on " + x.TargetClass + ", which has a field the request should not choose (CWE-915)."
	} else if f.Status == "protected_for_claim" {
		f.Title = "Request-chosen property names are restricted"
		f.Summary = "A recorded key allow-list limits the property names the request can write on " + x.TargetClass + "."
	}
	if a.Reason != "" {
		f.Protection = "Mass-assignment assessment: key control " + displayLabel(a.Answers["key_control"]) + ", restriction " + displayLabel(a.Answers["key_restriction"]) + ", field impact " + displayLabel(a.Answers["field_impact"]) + ". Scanner policy: " + a.Reason
	}
}

func describeAuthorization(u analysis.CandidateUse, f *analysis.Finding) {
	x := u.Authorization
	a := u.Assessment
	address := authorizationAddressOnly(u)
	if f.Status != "protected_for_claim" {
		if address {
			f.Title = "Address check needs review"
			f.Summary = "The operation is dominated by a check of the caller's network address."
		} else {
			f.Title = "Authorization of the operation needs review"
			f.Summary = "The operation acts on " + x.SubjectClass + " (" + displayLabel(x.SubjectProvenance) + ")."
		}
	}
	if a.Status == "completed" && a.QuestionVersion == analysispacks.AuthorizationProtocol && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability" {
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		if address {
			f.Title = "Address-based access supported by source analysis"
			f.Summary = "The operation is limited by the caller's network address (CWE-291)."
		} else {
			f.Title = "Missing authorization supported by source analysis"
			f.Summary = "The operation acts on a record the request selects without a guard or an entry rule that covers it (CWE-862)."
		}
	} else if f.Status == "protected_for_claim" {
		f.Title = "The operation is covered for this claim"
		f.Summary = "The assessment supports that a recorded guard or the entry's access covers the operation."
	}
	if a.Reason != "" {
		f.Protection = "Authorization assessment: subject " + displayLabel(a.Answers["subject_control"]) + ", guard " + displayLabel(a.Answers["guard_adequacy"]) + ", access " + displayLabel(a.Answers["access_adequacy"]) + ". Scanner policy: " + a.Reason
	}
	for _, id := range x.ServerSideRequests {
		f.RelatedFindings = append(f.RelatedFindings, "finding:"+id)
	}
}

func authorizationAddressOnly(u analysis.CandidateUse) bool {
	if u.Authorization == nil || len(u.Authorization.Guards) == 0 {
		return false
	}
	for _, g := range u.Authorization.Guards {
		if g.Kind != analysis.GuardAddress {
			return false
		}
	}
	return true
}

func authorizationRule(u analysis.CandidateUse) (string, string) {
	if authorizationAddressOnly(u) {
		return "scan/address-based-access", "CWE-291"
	}
	if u.Authorization != nil {
		for _, facet := range u.Authorization.Facets {
			if facet == analysis.FacetObjectLevel {
				return "scan/missing-authorization", "CWE-639"
			}
		}
	}
	return "scan/missing-authorization", "CWE-862"
}
