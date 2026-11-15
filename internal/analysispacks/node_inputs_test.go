package analysispacks

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestSharedNodeURLUploadSelection(t *testing.T) {
	src := analysis.Evidence{Kind: "input_source", Text: "req.originalUrl", Span: analysis.Span{File: "server.js"}, SHA256: "abc"}
	binding := analysis.Evidence{Kind: "entry_registration", Span: analysis.Span{File: "server.js"}, SHA256: "def"}
	use := selectionUse()
	use.Dependencies = []analysis.Dependency{{Source: src}}
	use.InputFacts = &analysis.InputFacts{
		Version:     1,
		Acquisition: "http",
		Binding:     binding,
		Values:      []analysis.InputValueFact{{Dependency: 0, Origin: "http.original_url", InitialType: "unknown", SinkType: "unknown", Source: src}},
	}
	use.EntryFacts = &analysis.EntryPoint{Kind: "http", Location: binding}
	sel, err := Select(use)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range sel.Components {
		if c.ID == "source.node-input-v2" {
			found = true
		}
		if c.ID == "source.node-input-v1" {
			t.Fatal("v1 still selected")
		}
	}
	if !found {
		t.Fatalf("source.node-input-v2 missing: %+v", sel.Components)
	}
}
