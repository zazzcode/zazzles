package analysis

// StoredOriginFacts lists, per storage key a record reads, every write the
// scanner found for that key and the facts a reviewer or model needs to decide
// whether a request value can reach the stored data. It never changes the
// record's status by itself.
type StoredOriginFacts struct {
	Stores []StoredWriteSet `json:"stores"`
}

// StoredWriteSet is the write census of one storage key.
type StoredWriteSet struct {
	Key string `json:"key"`
	// Writes are every write statement found for the key, literal or not.
	Writes []StoredWrite `json:"writes"`
	// StaticRead reports that the read query text is a literal with no
	// interpolated or concatenated value.
	StaticRead bool `json:"static_read"`
	// ClosedStore is "closed" when the store's schema and every writer are in
	// scanned source (an in-memory database created there), "open" when the
	// schema is not in scanned source, and "unknown" otherwise.
	ClosedStore string    `json:"closed_store"`
	Schema      *Evidence `json:"schema,omitempty"`
}

// StoredWrite is one write: Literal reports that every written value is a
// source literal (no placeholder, interpolation or concatenation).
type StoredWrite struct {
	Evidence Evidence `json:"evidence"`
	Literal  bool     `json:"literal"`
}
