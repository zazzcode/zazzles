package analysis

// XSSFacts describes a rendering claim independently of the source language or
// framework. Parser adapters establish these facts; views do not infer them.
type XSSFacts struct {
	Type             string   `json:"type"`
	EntryKind        string   `json:"entry_kind"`
	OutputContext    string   `json:"output_context"`
	ContentType      string   `json:"content_type"`
	Protection       string   `json:"protection"`
	ProtectionReason string   `json:"protection_reason"`
	RelatedEntries   []string `json:"related_entries,omitempty"`
	StorageKey       string   `json:"storage_key,omitempty"`
	OriginResolved   bool     `json:"origin_resolved"`
	ResponsePath     string   `json:"response_path,omitempty"`
	ResponseMethod   string   `json:"response_method,omitempty"`
	// ResponseField is the JSON path a browser output reads from that response.
	ResponseField string `json:"response_field,omitempty"`
	// Paths is present only when sibling source paths differ in protection, so a
	// protected or unknown path is never read as covering an unsafe one.
	Paths []XSSPath `json:"paths,omitempty"`
}

// XSSPath is the protection of one dependency (by index) of a rendering claim.
// Entry names the writing entry of a stored path when it is known.
type XSSPath struct {
	Dependency int    `json:"dependency"`
	Entry      string `json:"entry,omitempty"`
	Protection string `json:"protection"`
	// OutputContext is the HTML context where this path's value lands, when
	// an adapter establishes it per path (PHP templates).
	OutputContext string `json:"output_context,omitempty"`
}
