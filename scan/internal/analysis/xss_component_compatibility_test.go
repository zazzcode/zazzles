package analysis_test

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/report"
	"reflect"
	"testing"
)

func TestXSSComponentHistory(t *testing.T) {
	for _, schema := range []int{1, 2, 3, 4} {
		a := analysis.Assessment{Status: "completed", QuestionVersion: "xss-use-v1", Answers: map[string]string{"output_context": "html_text", "xss_exposure": "vulnerable"}, FindingStatus: "confirmed_vulnerability"}
		c := modelCatalog()
		u := analysis.CandidateUse{ID: "old-xss", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "xss_candidate", Sink: origin("old.html", 20), Assessment: a, XSS: &analysis.XSSFacts{Type: "reflected", OutputContext: "html_text", Protection: "raw", OriginResolved: true}}
		var data []byte
		if schema < 3 {
			data, _ = json.Marshal(map[string]any{"schema_version": schema, "entries": []any{map[string]any{"route": analysis.Route{ID: "r", Method: "GET", PathPattern: "/", Registration: origin("app.js", 0).Span}, "resolved_handler": origin("app.js", 5)}}, "uses": []any{map[string]any{"id": u.ID, "route_id": "r", "kind": u.Kind, "sink": u.Sink, "xss": u.XSS, "assessment": a}}})
		} else {
			data, _ = json.Marshal(analysis.AnalysisReport{SchemaVersion: schema, Entries: c.Entries, Registrations: c.Registrations, DispatchBindings: c.DispatchBindings, Callables: c.Callables, InvocationContexts: c.InvocationContexts, Uses: []analysis.CandidateUse{u}})
		}
		var saved analysis.AnalysisReport
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		var html bytes.Buffer
		if err := report.HTML(&html, &saved); err != nil {
			t.Fatal(err)
		}
		report.SARIF(&saved)
		if !reflect.DeepEqual(a, saved.Uses[0].Assessment) || saved.Uses[0].Components != nil || saved.Uses[0].Assessment.RequestDigest != "" {
			t.Fatalf("schema %d historical provenance rewritten", schema)
		}
		round, _ := json.Marshal(saved)
		var again analysis.AnalysisReport
		if err := json.Unmarshal(round, &again); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(a, again.Uses[0].Assessment) {
			t.Fatal("answer changed on roundtrip")
		}
	}
}
