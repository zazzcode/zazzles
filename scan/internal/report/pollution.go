package report

import "github.com/zazzcode/zazzles/scan/internal/analysis"

var pollutionFindingType = analysis.FindingType{
	ID: analysis.PollutionFinding, Label: "Prototype Pollution", Coverage: "bounded JS/TS prototype writes",
	Description:    "Request-derived keys reach a write that can pollute Object.prototype.",
	Interpretation: "The write and its controls are evaluated for each recorded key operand path.",
	Remediation:    "Use a patched library and restrict key traversal at every level.",
}

func describePollution(f *analysis.Finding) {
	switch f.Status {
	case "confirmed_vulnerability":
		f.Title = "Request-controlled prototype pollution"
		f.Summary = "The request-derived key operand can make this write pollute Object.prototype. Its effect depends on what reads the polluted property."
	case "protected_for_claim":
		f.Title = "Prototype write paths are protected"
		f.Summary = "The recorded controls prevent the key operand from reaching Object.prototype at this write."
	default:
		f.Title = "Prototype write needs review"
		f.Summary = "The scanner recorded a key-bearing operand and a potential prototype write. Review the version, key origin, and the controls on each path."
	}
}
