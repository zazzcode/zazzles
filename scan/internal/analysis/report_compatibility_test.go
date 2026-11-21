package analysis_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

func TestReportSchemaCompatibility(t *testing.T) {
	for _, version := range []int{1, 2} {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			evidence := origin("handler.ts", 20)
			assessment := map[string]any{"status": "completed", "answers": map[string]string{"protection": "sufficient"}, "answer_details": map[string]any{"protection": map[string]any{"choice": "sufficient", "confidence": 0.91}}, "question_version": "historical", "provider": "fixture", "model": "fixture-model", "finding_status": "protected_for_claim"}
			old := map[string]any{"schema_version": version, "root": "/source/no-longer-exists", "entries": []any{map[string]any{"route": analysis.Route{ID: "old-route", Method: "GET", PathPattern: "/x", Registration: origin("server.ts", 0).Span}, "resolved_handler": evidence}}, "uses": []any{map[string]any{"id": "old-use", "route_id": "old-route", "kind": "outbound_http_candidate", "sink": evidence, "assessment": assessment}}, "files": []analysis.Evidence{origin("server.ts", 0)}}
			key := "analysis_guidelines"
			if version == 1 {
				key = "practice"
			}
			old[key] = []any{map[string]any{"id": "javascript", "version": "old"}}
			data, _ := json.Marshal(old)
			unchanged := append([]byte{}, data...)
			var decoded analysis.AnalysisReport
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.SchemaVersion != analysis.ReportSchemaVersion || decoded.SourceSchemaVersion != version || len(decoded.Uses) != 1 || decoded.Handler(decoded.Entries[0].ID) == nil {
				t.Fatal("legacy source/association dropped")
			}
			if decoded.Callables[0].Definition != evidence || decoded.Uses[0].Sink != evidence || decoded.AnalysisGuidelines[0].Version != "old" {
				t.Fatal("snapshot or guideline metadata changed")
			}
			actual, _ := json.Marshal(decoded.Uses[0].Assessment)
			var actualFields map[string]any
			json.Unmarshal(actual, &actualFields)
			expectedJSON, _ := json.Marshal(assessment)
			var expectedFields map[string]any
			json.Unmarshal(expectedJSON, &expectedFields)
			if !reflect.DeepEqual(actualFields, expectedFields) {
				t.Fatalf("raw answers changed: %s", actual)
			}
			if decoded.DispatchBindings[0].Resolution != "partial" || len(decoded.InvocationContexts[0].Gaps) == 0 || len(decoded.InvocationContexts[0].Inputs) != 0 {
				t.Fatal("legacy invocation facts invented")
			}
			var html bytes.Buffer
			if err := report.HTML(&html, &decoded); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(html.String(), "GET /x") {
				t.Fatal("legacy presentation lost entry")
			}
			if len(report.SARIF(&decoded)["runs"].([]any)) != 1 {
				t.Fatal("SARIF export missing")
			}
			encoded, err := json.Marshal(decoded)
			if err != nil {
				t.Fatal(err)
			}
			for _, obsolete := range []string{`"route_id":`, `"client_id":`, `"client_entries":`, `"practice":`} {
				if bytes.Contains(encoded, []byte(obsolete)) {
					t.Fatalf("duplicate current authority: %s", obsolete)
				}
			}
			var roundtrip analysis.AnalysisReport
			if err := json.Unmarshal(encoded, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if roundtrip.Uses[0].Sink != evidence || !bytes.Equal(data, unchanged) {
				t.Fatal("export rewrote historical evidence")
			}
		})
	}
	c := modelCatalog()
	current := analysis.AnalysisReport{SchemaVersion: 3, Root: "missing", Entries: c.Entries, Registrations: c.Registrations, DispatchBindings: c.DispatchBindings, Callables: c.Callables, InvocationContexts: c.InvocationContexts, Uses: []analysis.CandidateUse{{ID: "use", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Sink: origin("handler.ts", 20), Assessment: analysis.Assessment{Status: "not_run"}}}}
	data, _ := json.Marshal(current)
	var decoded analysis.AnalysisReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(map[string]any)
	}{
		{"unsupported schema", func(v map[string]any) { v["schema_version"] = 99 }},
		{"missing uses", func(v map[string]any) { delete(v, "uses") }},
		{"legacy authority", func(v map[string]any) { v["uses"].([]any)[0].(map[string]any)["route_id"] = "other" }},
		{"cross context", func(v map[string]any) {
			v["uses"].([]any)[0].(map[string]any)["invocation_context_id"] = c.InvocationContexts[1].ID
		}},
		{"dangling dispatch", func(v map[string]any) {
			v["invocation_contexts"].([]any)[0].(map[string]any)["dispatch_binding_id"] = "missing"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var v map[string]any
			json.Unmarshal(data, &v)
			tc.edit(v)
			changed, _ := json.Marshal(v)
			var r analysis.AnalysisReport
			if err := json.Unmarshal(changed, &r); err == nil {
				t.Fatal("invalid current report accepted")
			}
		})
	}
	t.Run("legacy orphan", func(t *testing.T) {
		raw := `{"schema_version":2,"uses":[{"id":"orphan","route_id":"absent","assessment":{"status":"not_run"}}]}`
		var r analysis.AnalysisReport
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 1 || r.Entries[0].Kind != "unknown" || len(r.Entries[0].Gaps) == 0 || r.Uses[0].InvocationContextID == "" {
			t.Fatal("unresolved legacy use disappeared")
		}
	})
}

func TestLegacyEntryNamespacesRemainDistinct(t *testing.T) {
	raw := `{"schema_version":2,"entries":[{"route":{"id":"same","method":"GET","path_pattern":"/http"}}],"client_entries":[{"id":"same","kind":"script","name":"browser"}],"uses":[{"id":"http-use","route_id":"same"},{"id":"browser-use","client_id":"same"},{"id":"ambiguous-use","route_id":"same","client_id":"same"}]}`
	var r analysis.AnalysisReport
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	if r.Uses[0].EntryKind != "http" || r.Uses[1].EntryKind != "browser" || r.Uses[2].EntryKind != "unknown" {
		t.Fatal("legacy namespaces or ambiguity collapsed")
	}
	if r.Uses[0].EntryID == r.Uses[1].EntryID {
		t.Fatal("separate legacy identities merged")
	}
}
