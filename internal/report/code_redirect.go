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
