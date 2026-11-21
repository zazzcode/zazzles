package analysis

// Resolution is one model-resolved fact: the scanner question about an
// unresolved point, the model's answer, the evidence items it cited and the
// scanner's verification of that citation. Every family uses this one shape.
// A resolution changes a record's evidence only when Verified is true; an
// unverified or rejected answer is kept for review and changes nothing.
type Resolution struct {
	// Question is the request question that asked about this point.
	Question string `json:"question"`
	// QuestionVersion versions the resolution question's wording and choices.
	QuestionVersion string `json:"question_version"`
	// Blocker is the scanner blocker the question answers, when it answers one.
	Blocker *Gap `json:"blocker,omitempty"`
	// Answer is the model's choice for the question.
	Answer string `json:"answer"`
	// Citation is the cited chain of request evidence IDs (eN, gN), in order.
	Citation []string `json:"citation,omitempty"`
	// CitedSpans are the source spans of the cited items, in citation order.
	CitedSpans []Span `json:"cited_spans,omitempty"`
	// Dependency is the record dependency a verified chain follows.
	Dependency *int `json:"dependency,omitempty"`
	// Verified reports that every cited ID was in the request and every hop is
	// a scanner edge or the asked gap.
	Verified bool `json:"verified"`
	// Rejection says why a citation did not verify.
	Rejection string `json:"rejection,omitempty"`
	// Discharged reports that policy treated this resolution as discharging
	// its blocker or supplying its witness.
	Discharged bool `json:"discharged,omitempty"`
	// Verifier names who bound the answer to its chain when that was not a
	// model citation: "scanner" for a chain the scanner already held complete.
	Verifier string `json:"verifier,omitempty"`
	// Provider and Model name who answered.
	Provider string `json:"provider,omitempty"`
	Model    string `json:"model,omitempty"`
}

// ModelResolved reports whether policy used any verified resolution to reach
// the record's status.
func (a Assessment) ModelResolved() bool {
	for _, r := range a.Resolutions {
		if r.Discharged {
			return true
		}
	}
	return false
}
