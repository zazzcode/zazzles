package parse

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPathComprehensionSelectionIsUnknown(t *testing.T) {
	src := analysis.Evidence{Kind: "input_source", Text: `environ["PATH_INFO"]`, Span: analysis.Span{File: "app.py"}}
	for name, tt := range map[string]struct {
		transfer string
		kind     string
		want     string
	}{
		"registry element selected by equality": {`[s for s in TRIGGER_MAP.keys() if s == name][0]`, "field_projection", "unknown"},
		"plain index of a list":                 {`parts[1]`, "field_projection", "raw"},
		"comprehension without an index":        {`[s for s in names]`, "field_projection", "raw"},
	} {
		t.Run(name, func(t *testing.T) {
			dep := analysis.Dependency{SinkSlot: analysis.PathSlotFile, Source: src, Transfers: []analysis.Evidence{{Kind: tt.kind, Text: tt.transfer, Span: analysis.Span{File: "app.py"}}}}
			u := &analysis.CandidateUse{Dependencies: []analysis.Dependency{dep}, Path: &analysis.PathFacts{Operation: "open", Platform: "posix", Role: "read",
				Operands: []analysis.PathOperand{{Slot: analysis.PathSlotFile}}, Paths: []analysis.PathFlow{{Dependency: 0, Operand: analysis.PathSlotFile, Protection: "raw"}}}}
			c := &analysis.Completeness{Evidence: map[string][]analysis.Evidence{}}
			finishPathFlows(u, c, nil, nil, newPathGuardInfo(), func(analysis.Gap, analysis.Dependency) bool { return false })
			if got := u.Path.Paths[0].Protection; got != tt.want {
				t.Fatalf("protection %s, want %s", got, tt.want)
			}
		})
	}
}
