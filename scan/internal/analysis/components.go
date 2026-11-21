package analysis

// ComponentRef identifies exact scanner-authored knowledge, independently of source evidence.
type ComponentRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

// ComponentSelection records the family interpretation selected for one invocation.
// Failure is retained without dropping an unsupported candidate or inventing protection.
type ComponentSelection struct {
	Pack       ComponentRef   `json:"pack,omitzero"`
	Components []ComponentRef `json:"components,omitempty"`
	Digest     string         `json:"digest,omitempty"`
	Required   []string       `json:"required,omitempty"`
	Limits     []string       `json:"limits,omitempty"`
	Failure    string         `json:"failure,omitempty"`
}
