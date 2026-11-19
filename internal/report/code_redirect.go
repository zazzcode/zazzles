package report

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func describeInterpreter(u analysis.CandidateUse, f *analysis.Finding) {
	family, protocol, label := "code", analysispacks.CodeProtocol, "Code injection"
	if u.Redirect != nil {
		family, protocol, label = "redirect", analysispacks.RedirectProtocol, "Open redirect"
	}
	f.Title = label + " needs operand review"
	f.Summary = "Request-derived data reaches a verified " + family + " operand. Review the independent paths and enforcing restrictions."
	if u.Code != nil {
		f.Summary += " Execution context: " + u.Code.ExecutionContext + "."
	}
	if u.Redirect != nil && u.Redirect.RelatedUse != "" {
		f.Summary += " This navigation also has a separate XSS record (" + u.Redirect.RelatedUse + ")."
	}
	a := u.Assessment
	if a.Status != "completed" || a.QuestionVersion != protocol || len(a.BlockingGaps) > 0 {
		return
	}
	switch a.FindingStatus {
	case "confirmed_vulnerability":
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title = label + " supported by source analysis"
		f.Summary += " A complete raw operand path and consistent family assessment support the static claim."
	case "poor_practice":
		f.RecordType, f.Status = "finding", "poor_practice"
		f.Title = label + " protection relies on weak practice"
	case "protected_for_claim":
		f.Title = label + " operand is constrained"
		f.Summary += " Source-established protection covers every relevant path."
	}
	f.Protection = a.Reason
}

// describeUpload presents an upload claim. A client-chosen extension with no
// server-side type control is a practice finding without a model, like SQL
// construction (close-findings-gaps D-21); a consistent assessment can raise
// it to Confirmed or support protection.
func describeUpload(u analysis.CandidateUse, f *analysis.Finding) {
	x := u.Upload
	f.Title = "File upload needs type review"
	f.Summary = "A client upload is stored by " + x.Operation + ". Stored name: " + x.StoredName + "; extension: " + x.ExtensionOrigin + "; destination served: " + x.DestinationServed + "."
	blocked := u.Completeness == nil || len(u.Completeness.Blockers) > 0
	if x.ExtensionOrigin == "client" && !x.ServerTypeControl() && !blocked {
		f.RecordType, f.Status = "finding", "poor_practice"
		f.Title = "Uploaded file keeps its client-chosen type"
		f.Summary += " No server-side type control precedes the write. Generate the name and allow-list or verify the type on the server; this practice finding stands even before exploitability is judged."
	}
	a := u.Assessment
	if a.Status != "completed" || a.QuestionVersion != analysispacks.UploadProtocol || len(a.BlockingGaps) > 0 {
		return
	}
	switch a.FindingStatus {
	case "confirmed_vulnerability":
		f.RecordType, f.Status = "finding", "confirmed_vulnerability"
		f.Title = "Unrestricted file upload supported by source analysis"
	case "protected_for_claim":
		if f.Status != "poor_practice" {
			f.Title = "Upload type is constrained"
		}
	}
	f.Protection = "Upload assessment: type restriction " + displayLabel(a.Answers["type_restriction"]) + ", exposure " + displayLabel(a.Answers["execution_exposure"]) + ", coverage " + displayLabel(a.Answers["protection_coverage"]) + ". Scanner policy: " + a.Reason
}
