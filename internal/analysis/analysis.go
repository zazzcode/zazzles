package analysis

// ReportSchemaVersion identifies fresh analysis reports with component provenance.
const ReportSchemaVersion = 4

// Evidence binds an observed operation to an immutable source file snapshot.
type Evidence struct {
	ModelText string `json:"model_text,omitempty"`
	Kind      string `json:"kind"`
	Text      string `json:"text"`
	Span      Span   `json:"span"`
	SHA256    string `json:"sha256"`
}

// Dependency records a local value relationship; use-level gaps distinguish
// supported expression dependencies from uncertain transfers. It is not a runtime trace.
type Dependency struct {
	SinkSlot   string     `json:"sink_slot,omitempty"`
	StorageKey string     `json:"storage_key,omitempty"`
	Source     Evidence   `json:"source"`
	Transfers  []Evidence `json:"transfers"`
	// OutputContext and ResponseField are extraction-only path facts: the HTML
	// context a server template gave this value, and the JSON or token field a
	// browser value was read from. Neither is serialized or sent to a model.
	OutputContext string `json:"-"`
	ResponseField string `json:"-"`
}

// CandidateUse is a security-sensitive value use needing claim-specific analysis.
type CandidateUse struct {
	InputFacts          *InputFacts         `json:"input_facts,omitempty"`
	Components          *ComponentSelection `json:"analysis_components,omitempty"`
	XSS                 *XSSFacts           `json:"xss,omitempty"`
	Command             *CommandFacts       `json:"command,omitempty"`
	APIModel            *APIModel           `json:"api_model,omitempty"`
	ControlEdges        []ControlEdge       `json:"control_edges,omitempty"`
	Check               *Check              `json:"check,omitempty"`
	Completeness        *Completeness       `json:"completeness,omitempty"`
	ID                  string              `json:"id"`
	EntryID             string              `json:"entry_id"`
	InvocationContextID string              `json:"invocation_context_id"`
	EntryKind           string              `json:"-"`
	EntryFacts          *EntryPoint         `json:"-"`
	InvocationFacts     *InvocationContext  `json:"-"`
	DispatchFacts       *DispatchBinding    `json:"-"`
	Kind                string              `json:"kind"`
	Sink                Evidence            `json:"sink"`
	Dependencies        []Dependency        `json:"dependencies"`
	Context             []Evidence          `json:"context"`
	Gaps                []Gap               `json:"gaps"`
	Assessment          Assessment          `json:"assessment"`
}

// Assessment preserves the judge's result independently from structural evidence.
type Assessment struct {
	RequestDigest   string                  `json:"request_digest,omitempty"`
	AnswerDetails   map[string]AnswerDetail `json:"answer_details,omitempty"`
	FindingStatus   string                  `json:"finding_status,omitempty"`
	BlockingGaps    []Gap                   `json:"blocking_gaps,omitempty"`
	Answers         map[string]string       `json:"answers,omitempty"`
	Usage           map[string]int64        `json:"usage,omitempty"`
	Status          string                  `json:"status"`
	Provider        string                  `json:"provider,omitempty"`
	Model           string                  `json:"model,omitempty"`
	QuestionVersion string                  `json:"question_version,omitempty"`
	Protection      string                  `json:"protection,omitempty"`
	Reason          string                  `json:"reason,omitempty"`
}

// AnalysisReport contains bounded security analysis, separate from the route inventory.
type AnalysisReport struct {
	Discovery           []DiscoveryProposal `json:"discovery_proposals,omitempty"`
	FindingTypes        []FindingType       `json:"finding_types,omitempty"`
	PresentationVersion int                 `json:"presentation_version,omitempty"`
	Findings            []Finding           `json:"findings,omitempty"`
	SelectedScope       *EntrySelection     `json:"selected_scope,omitempty"`
	CheckMatches        []CheckMatch        `json:"check_matches,omitempty"`
	SelectedRoute       string              `json:"selected_route,omitempty"`
	SchemaVersion       int                 `json:"schema_version"`
	Root                string              `json:"root"`
	SourceSchemaVersion int                 `json:"source_schema_version,omitempty"`
	Registrations       []EntryRegistration `json:"registrations"`
	DispatchBindings    []DispatchBinding   `json:"dispatch_bindings"`
	Callables           []Callable          `json:"callables"`
	InvocationContexts  []InvocationContext `json:"invocation_contexts"`
	Entries             []EntryPoint        `json:"entries"`
	Uses                []CandidateUse      `json:"uses"`
	Gaps                []Gap               `json:"gaps"`
	Files               []Evidence          `json:"files"`
	Limitations         []string            `json:"limitations"`
	AnalysisGuidelines  []GuidelinesRef     `json:"analysis_guidelines,omitempty"`
	// SkippedFamilies lists analyzer families deliberately not judged in this run
	// (--skip-family). Their records stay in the report as not_run Review.
	SkippedFamilies []string `json:"skipped_families,omitempty"`
}

// GuidelinesRef identifies the embedded language analysis guidelines used for a report.
// The full text is sent with a decision request, not copied into every use.
type GuidelinesRef struct {
	ID        string   `json:"id"`
	Version   string   `json:"version"`
	Languages []string `json:"languages"`
}

// Check declares a security requirement independently of the expected test answer.
type Check struct {
	Selector   *EntrySelector `json:"selector,omitempty"`
	ID         string         `json:"id"`
	Method     string         `json:"method,omitempty"`
	Path       string         `json:"path,omitempty"`
	Kind       string         `json:"kind"`
	Fields     []string       `json:"fields"`
	Validation string         `json:"validation"`
	Protection string         `json:"protection"`
}

// Completeness separates claim blockers from unrelated coverage limitations.
type Completeness struct {
	ModelFacts []string              `json:"model_facts,omitempty"`
	Resolved   []Gap                 `json:"resolved_gaps,omitempty"`
	ClaimKind  string                `json:"claim_kind,omitempty"`
	Required   []string              `json:"required"`
	Evidence   map[string][]Evidence `json:"evidence"`
	Blockers   []Gap                 `json:"blockers"`
	Coverage   []Gap                 `json:"coverage"`
	Scope      string                `json:"scope"`
}

// ControlEdge records a source-backed local successor, including both guard outcomes.
type ControlEdge struct {
	From Evidence `json:"from"`
	To   Evidence `json:"to"`
	Kind string   `json:"kind"`
}

// APIModel describes a versioned library contract separately from source evidence.
type APIModel struct {
	ID        string `json:"id"`
	Library   string `json:"library"`
	Semantics string `json:"semantics"`
	Reference string `json:"reference"`
}
