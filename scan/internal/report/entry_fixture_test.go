package report

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func testHTTPEntry(r analysis.Route) analysis.EntryPoint {
	return analysis.EntryPoint{ID: r.ID, Kind: "http", HTTP: &analysis.HTTPEntryMetadata{Method: r.Method, Path: r.PathPattern, Framework: r.Framework}, Location: analysis.Evidence{Span: r.Registration}}
}

func TestEntryDispatchGapsVisibleWithoutUses(t *testing.T) {
	r := &analysis.AnalysisReport{Entries: []analysis.EntryPoint{testHTTPEntry(analysis.Route{ID: "entry", Method: "GET", PathPattern: "/unknown"})}, DispatchBindings: []analysis.DispatchBinding{{ID: "binding", EntryID: "entry", Resolution: "unresolved", Gaps: []analysis.Gap{{Kind: "unknown_alternative", Detail: "runtime target remains unresolved"}}}}, InvocationContexts: []analysis.InvocationContext{{ID: "context", EntryID: "entry", Gaps: []analysis.Gap{{Kind: "unknown_invocation"}}}}}
	var html bytes.Buffer
	if err := HTML(&html, r); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "unknown_alternative") || !strings.Contains(html.String(), "unknown_invocation") {
		t.Fatal("zero-use dispatch/context gaps hidden in HTML")
	}
	data, _ := json.Marshal(SARIF(r))
	if !strings.Contains(string(data), "unknown_alternative") || !strings.Contains(string(data), "unknown_invocation") {
		t.Fatal("zero-use dispatch/context gaps hidden in SARIF")
	}
	if len(r.Findings) != 0 {
		t.Fatal("coverage gap manufactured finding")
	}
}
