package judge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// SavedDecisions indexes successful traces from an earlier run by the SHA-256
// of their compacted request bytes. It is read-only after construction and
// safe for concurrent use. A hit is only a candidate for reuse; Replay decides.
type SavedDecisions struct {
	byRequest  map[string]DecisionTrace
	unreadable int
}

// NamedTrace is one loaded trace file; Name orders duplicate requests.
type NamedTrace struct {
	Name  string
	Trace DecisionTrace
}

// NewSavedDecisions indexes the HTTP 200 traces. When two traces hold the same
// request, the lexically first Name wins. unreadable counts files the caller
// could not load; a trace whose request is not valid JSON is counted there too.
func NewSavedDecisions(traces []NamedTrace, unreadable int) *SavedDecisions {
	sorted := append([]NamedTrace(nil), traces...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	s := &SavedDecisions{byRequest: map[string]DecisionTrace{}, unreadable: unreadable}
	for _, t := range sorted {
		if t.Trace.HTTPStatus != 200 {
			continue
		}
		key, ok := requestKey(t.Trace.Request)
		if !ok {
			s.unreadable++
			continue
		}
		if _, dup := s.byRequest[key]; !dup {
			s.byRequest[key] = t.Trace
		}
	}
	return s
}

func requestKey(payload []byte) (string, bool) {
	var compact bytes.Buffer
	if len(payload) == 0 || json.Compact(&compact, payload) != nil {
		return "", false
	}
	sum := sha256.Sum256(compact.Bytes())
	return hex.EncodeToString(sum[:]), true
}

// lookup returns the saved trace whose request equals payload, and its key.
func (s *SavedDecisions) lookup(payload []byte) (DecisionTrace, string, bool) {
	if s == nil {
		return DecisionTrace{}, "", false
	}
	key, ok := requestKey(payload)
	if !ok {
		return DecisionTrace{}, "", false
	}
	t, ok := s.byRequest[key]
	return t, key, ok
}

// Completed returns the number of indexed successful saved decisions.
func (s *SavedDecisions) Completed() int {
	if s == nil {
		return 0
	}
	return len(s.byRequest)
}

// Unreadable returns the number of trace files that could not be used.
func (s *SavedDecisions) Unreadable() int {
	if s == nil {
		return 0
	}
	return s.unreadable
}
