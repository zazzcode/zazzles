package analysis

import "testing"

func TestInputFactsPreserveTransfers(t *testing.T) {
	source := Evidence{Kind: "input_source", Text: "request.params.id", SHA256: "snapshot", Span: Span{File: "server.js", StartByte: 10, EndByte: 27}}
	parse := Evidence{Kind: "call_argument_dependency", Text: "JSON.parse(request.params.id)", SHA256: "snapshot", Span: Span{File: "server.js", StartByte: 0, EndByte: 28}}
	deps := []Dependency{{Source: source, Transfers: []Evidence{parse}}}
	f := InputFacts{Version: 1, Acquisition: "http", Binding: source, Values: []InputValueFact{{Dependency: 0, Origin: "http.path", InitialType: "string", SinkType: "unknown", Source: source, Transfers: []Evidence{parse}}}}
	if err := f.Validate(deps); err != nil {
		t.Fatal(err)
	}
	if f.ScalarInputs() {
		t.Fatal("initial string type leaked past JSON parsing")
	}
	f.Values[0].Transfers = nil
	if f.Validate(deps) == nil {
		t.Fatal("omitted transformation accepted")
	}
	f.Controls = []Evidence{{Kind: "http_options"}}
	if f.HasValueControls() {
		t.Fatal("route/logging options became value constraints")
	}
}
