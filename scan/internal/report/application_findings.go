package report

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

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
	if a.Status == "completed" && a.QuestionVersion == analysispacks.MassAssignmentProtocol && len(a.BlockingGaps) == 0 && a.FindingStatus == "confirmed_vulnerability" {
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
