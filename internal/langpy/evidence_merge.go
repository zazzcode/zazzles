package langpy

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func pythonMergeGaps(a, b []analysis.Gap) []analysis.Gap {
	out := []analysis.Gap{}
	seen := map[analysis.Gap]bool{}
	for _, g := range append(append([]analysis.Gap{}, a...), b...) {
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	return out
}
func pythonMergeEvidence(a, b []analysis.Evidence) []analysis.Evidence {
	out := []analysis.Evidence{}
	seen := map[string]bool{}
	for _, e := range append(append([]analysis.Evidence{}, a...), b...) {
		raw, _ := json.Marshal(e)
		key := string(raw)
		if !seen[key] {
			seen[key] = true
			out = append(out, e)
		}
	}
	return out
}
