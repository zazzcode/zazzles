package analysis

// Finding is a human-readable interpretation of one evidence use, not a new detector verdict.
type Finding struct {
	TypeIDs             []string       `json:"type_ids"`
	ID                  string         `json:"id"`
	UseID               string         `json:"use_id"`
	EntryID             string         `json:"entry_id"`
	InvocationContextID string         `json:"invocation_context_id"`
	RecordType          string         `json:"record_type"`
	Status              string         `json:"status"`
	Title               string         `json:"title"`
	Summary             string         `json:"summary"`
	Validation          string         `json:"input_validation"`
	Protection          string         `json:"use_protection"`
	Uncertainty         string         `json:"uncertainty"`
	Recommendations     Recommendation `json:"recommendations"`
	// AssessmentState separates unjudged records ("not_run") from completed
	// ("completed") and failed ("failed") semantic assessments.
	AssessmentState string `json:"assessment_state,omitempty"`
	// BlockingEvidence names, for a Review record, the claim-relevant evidence
	// that prevents a final outcome. It never discharges or invents a blocker.
	BlockingEvidence []BlockingReason `json:"blocking_evidence,omitempty"`
	// LinkedUseIDs lists independent claims on the same operation (for example
	// a redirect and an XSS claim on one navigation); each keeps its own record.
	LinkedUseIDs []string `json:"linked_use_ids,omitempty"`
	// GroupedUseIDs lists the other records an observation finding stands for:
	// entries that reach the same call site. GroupedInto marks such a record with
	// the finding that represents it; renderers show only the representative.
	GroupedUseIDs []string `json:"grouped_use_ids,omitempty"`
	GroupedInto   string   `json:"grouped_into,omitempty"`
	// ModelResolved marks a record whose status rests on a verified model
	// resolution. The status is the ordinary one; this is its provenance.
	ModelResolved *ModelResolvedMark `json:"model_resolved,omitempty"`
}

// ModelResolvedMark is the visible provenance of a model-resolved record:
// who answered, under which question versions, and the cited evidence.
type ModelResolvedMark struct {
	Provider         string   `json:"provider"`
	Model            string   `json:"model"`
	QuestionVersions []string `json:"question_versions"`
	Questions        []string `json:"questions"`
	CitedIDs         []string `json:"cited_ids,omitempty"`
	CitedSpans       []Span   `json:"cited_spans,omitempty"`
	Resolved         []string `json:"resolved,omitempty"`
}

// BlockingReason is one machine-readable reason a record stays in Review.
// Source is "scanner" for candidate gaps/completeness, "policy" for
// deterministic verdict gates.
type BlockingReason struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
	Source string `json:"source"`
	At     *Span  `json:"at,omitempty"`
}

// Recommendation describes actions to review; examples are never verified patches.
type Recommendation struct {
	Title         string   `json:"title"`
	Actions       []string `json:"actions"`
	Example       string   `json:"illustrative_example,omitempty"`
	ExampleStatus string   `json:"example_status"`
}

// FindingType defines a risk family independently of a result's assessment status.
type FindingType struct {
	ID             string `json:"id"`
	Label          string `json:"label"`
	Description    string `json:"description"`
	Interpretation string `json:"interpretation"`
	Remediation    string `json:"remediation"`
	Coverage       string `json:"coverage"`
}
