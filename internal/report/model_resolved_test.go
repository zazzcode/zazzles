package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// TestModelResolvedProvenance (AC7): a model-resolved finding keeps the
// ordinary finding status and shows its provenance mark (provider, model,
// question version, cited IDs) in JSON, HTML and SARIF; an ordinary finding
// carries no mark.
func TestModelResolvedProvenance(t *testing.T) {
	e := analysis.Evidence{Kind: "input_source", Text: "request.args.get('name')", Span: analysis.Span{File: "app.py", StartLine: 8, EndLine: 8, StartByte: 10, EndByte: 30}, SHA256: "snapshot"}
	gap := analysis.Gap{Kind: "python_comprehension_unresolved", Detail: "iteration, key restrictions and comprehensions require review", At: e.Span}
	build := func(resolved bool) *analysis.AnalysisReport {
		a := analysis.Assessment{Status: "completed", Provider: "openai", Model: "gpt-6-luna", QuestionVersion: "path-components-v3", FindingStatus: "confirmed_vulnerability", Protection: "insufficient"}
		if resolved {
			d := 0
			a.Resolutions = []analysis.Resolution{{Question: "resolve_flow_g0", QuestionVersion: "flow-gap-v1", Blocker: &gap, Answer: "value_preserved", Citation: []string{"e3", "g0", "e5", "e9"}, CitedSpans: []analysis.Span{e.Span}, Dependency: &d, Verified: true, Discharged: true, Provider: "openai", Model: "gpt-6-luna"}}
		}
		use := analysis.CandidateUse{ID: "use", EntryID: "r", Kind: "path_traversal_candidate", Sink: e, Dependencies: []analysis.Dependency{{Source: e, Transfers: []analysis.Evidence{}}}, Assessment: a, Completeness: &analysis.Completeness{Evidence: map[string][]analysis.Evidence{"sink_binding": {e}}}}
		r := &analysis.AnalysisReport{Root: ".", Entries: []analysis.EntryPoint{testHTTPEntry(analysis.Route{ID: "r", Method: "GET", PathPattern: "/read", Registration: e.Span})}, Uses: []analysis.CandidateUse{use}, Files: []analysis.Evidence{}}
		Enrich(r)
		return r
	}
	plain, resolved := build(false), build(true)
	if plain.Findings[0].ModelResolved != nil {
		t.Fatal("a scanner-proven finding has no model-resolved mark")
	}
	f := resolved.Findings[0]
	if f.RecordType != plain.Findings[0].RecordType || f.Status != plain.Findings[0].Status {
		t.Fatalf("model-resolved status %s/%s differs from ordinary %s/%s", f.RecordType, f.Status, plain.Findings[0].RecordType, plain.Findings[0].Status)
	}
	m := f.ModelResolved
	if m == nil || m.Provider != "openai" || m.Model != "gpt-6-luna" || strings.Join(m.QuestionVersions, ",") != "flow-gap-v1" || strings.Join(m.CitedIDs, ",") != "e3>g0>e5>e9" || strings.Join(m.Resolved, ",") != "python_comprehension_unresolved" {
		t.Fatalf("mark: %+v", m)
	}
	data, _ := json.Marshal(resolved)
	if !bytes.Contains(data, []byte(`"model_resolved"`)) || !bytes.Contains(data, []byte(`"resolutions"`)) {
		t.Fatal("JSON lacks the mark or the resolution record")
	}
	var html bytes.Buffer
	if err := HTML(&html, resolved); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Model-resolved", "flow-gap-v1", "e3&gt;g0&gt;e5&gt;e9", "gpt-6-luna"} {
		if !strings.Contains(html.String(), want) {
			t.Fatalf("HTML lacks %q", want)
		}
	}
	sarif, _ := json.Marshal(SARIF(resolved))
	for _, want := range []string{"scan.modelResolved", "model-resolved: openai/gpt-6-luna flow-gap-v1", `e3\u003eg0\u003ee5\u003ee9`} {
		if !bytes.Contains(sarif, []byte(want)) {
			t.Fatalf("SARIF lacks %q", want)
		}
	}
}
