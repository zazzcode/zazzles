package analysis

// DiscoveryProposal contains snapshot-bound alternatives for model-assisted
// acquisition discovery. It is not an entry, invocation or security assessment.
type DiscoveryProposal struct {
	ID              string           `json:"id"`
	Registration    Evidence         `json:"registration"`
	Handler         Evidence         `json:"handler"`
	Context         []Evidence       `json:"context,omitempty"`
	Middleware      []Evidence       `json:"middleware,omitempty"`
	VerifiedEntryID string           `json:"verified_entry_id,omitempty"`
	State           string           `json:"state"`
	Protocol        string           `json:"protocol,omitempty"`
	ModelStatus     string           `json:"model_status,omitempty"`
	Usage           map[string]int64 `json:"usage,omitempty"`
	ModelChoice     string           `json:"model_choice,omitempty"`
	Provider        string           `json:"provider,omitempty"`
	Model           string           `json:"model,omitempty"`
	Reason          string           `json:"reason,omitempty"`
	RequestDigest   string           `json:"request_digest,omitempty"`
}
