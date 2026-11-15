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
	// GroupedUseIDs lists the other records an observation finding stands for:
	// entries that reach the same call site. GroupedInto marks such a record with
	// the finding that represents it; renderers show only the representative.
	GroupedUseIDs []string `json:"grouped_use_ids,omitempty"`
	GroupedInto   string   `json:"grouped_into,omitempty"`
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
