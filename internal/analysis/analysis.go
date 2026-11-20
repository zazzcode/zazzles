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
	// Transforms are source-backed transforms on this chain that the scanner
	// states exactly, such as a regular-expression capture.
	Transforms []ValueTransform `json:"transforms,omitempty"`
}

// ValueTransform is one exactly stated transform on a dependency chain. For
// kind regex_capture the value is group Group of a literal regular
// expression: Pattern and Flags are the expression, SubPattern the group's
// own pattern, and Class/Alphabet what that sub-pattern accepts.
type ValueTransform struct {
	Kind       string `json:"kind"`
	At         Span   `json:"at"`
	Flavor     string `json:"flavor,omitempty"`
	Pattern    string `json:"pattern"`
	Flags      string `json:"flags,omitempty"`
	Group      int    `json:"group"`
	SubPattern string `json:"sub_pattern"`
	Class      string `json:"class"`
	Alphabet   string `json:"alphabet,omitempty"`
	// Regex is the source text naming the expression (a literal or the name
	// bound to it); Tests are the source texts of match tests of the same
	// expression on the same value. Both are extraction-only.
	Regex string   `json:"-"`
	Tests []string `json:"-"`
}

// CandidateUse is a security-sensitive value use needing claim-specific analysis.
type CandidateUse struct {
	InputFacts *InputFacts         `json:"input_facts,omitempty"`
	Components *ComponentSelection `json:"analysis_components,omitempty"`
	XSS        *XSSFacts           `json:"xss,omitempty"`
	Command    *CommandFacts       `json:"command,omitempty"`
	Path       *PathFacts          `json:"path,omitempty"`
	Pollution  *PollutionFacts     `json:"pollution,omitempty"`
	Code       *CodeFacts          `json:"code,omitempty"`
	Redirect   *RedirectFacts      `json:"redirect,omitempty"`
	Upload     *UploadFacts        `json:"upload,omitempty"`
	Outbound   *OutboundFacts      `json:"outbound,omitempty"`
	// StoredOrigin is write-set evidence for a record whose stored origin is
	// unresolved (blocked by storage_origin_unresolved). It is evidence, not a
	// verdict: the record stays Review.
	StoredOrigin        *StoredOriginFacts `json:"stored_origin,omitempty"`
	APIModel            *APIModel          `json:"api_model,omitempty"`
	ControlEdges        []ControlEdge      `json:"control_edges,omitempty"`
	Check               *Check             `json:"check,omitempty"`
	Completeness        *Completeness      `json:"completeness,omitempty"`
	ID                  string             `json:"id"`
	EntryID             string             `json:"entry_id"`
	InvocationContextID string             `json:"invocation_context_id"`
	EntryKind           string             `json:"-"`
	EntryFacts          *EntryPoint        `json:"-"`
	InvocationFacts     *InvocationContext `json:"-"`
	DispatchFacts       *DispatchBinding   `json:"-"`
	Kind                string             `json:"kind"`
	Sink                Evidence           `json:"sink"`
	Dependencies        []Dependency       `json:"dependencies"`
	Context             []Evidence         `json:"context"`
	Gaps                []Gap              `json:"gaps"`
	Assessment          Assessment         `json:"assessment"`
}

// Assessment preserves the judge's result independently from structural evidence.
type Assessment struct {
	// EvidenceOmissions lists context evidence left out of an over-limit request.
	// The request itself names the same items in an evidence_omitted_for_size gap.
	EvidenceOmissions []EvidenceOmission      `json:"evidence_omissions,omitempty"`
	DeduplicatedFrom  string                  `json:"deduplicated_from,omitempty"`
	RequestDigest     string                  `json:"request_digest,omitempty"`
	AnswerDetails     map[string]AnswerDetail `json:"answer_details,omitempty"`
	FindingStatus     string                  `json:"finding_status,omitempty"`
	BlockingGaps      []Gap                   `json:"blocking_gaps,omitempty"`
	Answers           map[string]string       `json:"answers,omitempty"`
	Usage             map[string]int64        `json:"usage,omitempty"`
	Status            string                  `json:"status"`
	Provider          string                  `json:"provider,omitempty"`
	Model             string                  `json:"model,omitempty"`
	QuestionVersion   string                  `json:"question_version,omitempty"`
	Protection        string                  `json:"protection,omitempty"`
	Reason            string                  `json:"reason,omitempty"`
	// Resolutions are the record's model-resolved facts and their citation
	// verification; see Resolution.
	Resolutions []Resolution `json:"resolutions,omitempty"`
	// FollowUp records the one evidence follow-up request, when one was
	// asked for.
	FollowUp *FollowUp `json:"follow_up,omitempty"`
	// PathGroups records the per-group requests of a record whose evidence
	// exceeded the request limit and was judged in path groups.
	PathGroups []PathGroupResult `json:"path_groups,omitempty"`
}

// PathGroupResult is one path-group request of an over-limit record: the
// record dependencies it carried, those it withheld, and its own outcome.
type PathGroupResult struct {
	Group         int    `json:"group"`
	Key           string `json:"key"`
	Dependencies  []int  `json:"dependencies"`
	Omitted       []int  `json:"omitted,omitempty"`
	Status        string `json:"status"`
	FindingStatus string `json:"finding_status,omitempty"`
	Protection    string `json:"protection,omitempty"`
	RequestDigest string `json:"request_digest,omitempty"`
	RequestBytes  int    `json:"request_bytes,omitempty"`
	Reason        string `json:"reason,omitempty"`
}

// FollowUp is the single evidence follow-up of a record: the item the model
// named, whether the snapshot resolved it, and whether a request was sent.
type FollowUp struct {
	Kind   string `json:"kind"`
	Symbol string `json:"symbol"`
	// Status is "sent", "unresolved" (the snapshot did not resolve the
	// symbol exactly), "answered_by_contract" (a guard contract on the
	// request already describes the member), "follow_up_cap_reached" or
	// "failed".
	Status   string    `json:"status"`
	Evidence *Evidence `json:"evidence,omitempty"`
	Reason   string    `json:"reason,omitempty"`
}

// EvidenceOmission identifies one supplied evidence item that a size-bounded
// request did not carry. It is a reviewable record, never a judgment.
type EvidenceOmission struct {
	Kind  string `json:"kind"`
	Span  Span   `json:"span"`
	Bytes int    `json:"bytes"`
	// Lossless is true when the item's source text is still supplied inside
	// another evidence item, so leaving it out removed no source.
	Lossless bool `json:"lossless,omitempty"`
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
	OnlyFamilies []string `json:"only_families,omitempty"`
	// Practice lists source-established framework practice observations (for
	// example the Next.js NX-BP checks). They are not vulnerability findings and
	// never use a model request.
	Practice        []PracticeObservation `json:"practice_observations,omitempty"`
	SkippedFamilies []string              `json:"skipped_families,omitempty"`
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

// PracticeObservation is one source-established practice check result. Status is
// "observed" when the source establishes the condition and "review" when a
// heuristic part (such as matcher intent) needs a person to confirm it.
type PracticeObservation struct {
	ID       string     `json:"id"`
	Check    string     `json:"check"`
	Title    string     `json:"title"`
	Status   string     `json:"status"`
	Detail   string     `json:"detail"`
	Entry    string     `json:"entry,omitempty"`
	Evidence []Evidence `json:"evidence"`
}
