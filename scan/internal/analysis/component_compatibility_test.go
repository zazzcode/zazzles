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

func TestComponentReportCompatibility(t *testing.T) {
	// Schema 3 is already canonical. Export must not invent components or rewrite
	// its historical question protocol and raw answers as a new assessment.
	c := modelCatalog()
	// Historical NoSQL and validation assessments keep their pre-component
	// protocols and answers; absence of provenance remains absence.
	for _, historical := range []analysis.CandidateUse{
		{ID: "old-sql", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "sql_query_candidate", Sink: origin("handler.ts", 20), Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "candidate-injection-v1", Answers: map[string]string{"injection_protection": "protected", "protection": "insufficient"}}},
		{ID: "old-nosql", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "nosql_query_candidate", Sink: origin("handler.ts", 40), Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "candidate-injection-v1", Answers: map[string]string{"injection_protection": "vulnerable", "protection": "insufficient", "all_paths_protected": "no"}}},
		{ID: "old-validation", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "input_validation_candidate", Sink: origin("handler.ts", 60), Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "validation-use-v2", Answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"}, FindingStatus: "poor_practice"}},
	} {
		t.Run(historical.ID, func(t *testing.T) {
			old := analysis.AnalysisReport{SchemaVersion: 3, Root: "missing-source", Entries: c.Entries, Registrations: c.Registrations, DispatchBindings: c.DispatchBindings, Callables: c.Callables, InvocationContexts: c.InvocationContexts, Uses: []analysis.CandidateUse{historical}}
			data, _ := json.Marshal(old)
			original := append([]byte{}, data...)
			var saved analysis.AnalysisReport
			if err := json.Unmarshal(data, &saved); err != nil {
				t.Fatal(err)
			}
			if saved.SchemaVersion != 3 || saved.Uses[0].Components != nil || saved.Uses[0].Assessment.RequestDigest != "" || !reflect.DeepEqual(saved.Uses[0].Assessment, historical.Assessment) {
				t.Fatal("historical assessment/provenance relabeled")
			}
			var html bytes.Buffer
			if err := report.HTML(&html, &saved); err != nil {
				t.Fatal(err)
			}
			if historical.Kind == "input_validation_candidate" && !strings.Contains(html.String(), "Declared field validation is not enforced") {
				t.Fatal("historical validation-use-v2 display lost")
			}
			report.SARIF(&saved)
			if !bytes.Equal(data, original) || saved.SchemaVersion != 3 || !reflect.DeepEqual(saved.Uses[0].Assessment, historical.Assessment) {
				t.Fatal("export changed historical source/answer bytes")
			}
		})
	}
	// A schema-4 export of freshly selected NoSQL/validation uses keeps the
	// component provenance and request digests of the current protocols.
	fresh := analysis.AnalysisReport{SchemaVersion: analysis.ReportSchemaVersion, Root: "missing-source", Entries: c.Entries, Registrations: c.Registrations, DispatchBindings: c.DispatchBindings, Callables: c.Callables, InvocationContexts: c.InvocationContexts, Uses: []analysis.CandidateUse{
		{ID: "new-nosql", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "nosql_query_candidate", Sink: origin("handler.ts", 80), Components: &analysis.ComponentSelection{Pack: analysis.ComponentRef{ID: "pack.nosql", Version: "1", Digest: "d"}, Digest: "s"}, Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "nosql-components-v1", RequestDigest: "r", Answers: map[string]string{"injection_protection": "vulnerable"}}},
		{ID: "new-validation", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "input_validation_candidate", Sink: origin("handler.ts", 100), Components: &analysis.ComponentSelection{Pack: analysis.ComponentRef{ID: "pack.validation", Version: "1", Digest: "d"}, Digest: "s"}, Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "validation-components-v1", RequestDigest: "r", Answers: map[string]string{"validation": "insufficient"}}},
	}}
	data, _ := json.Marshal(fresh)
	var saved analysis.AnalysisReport
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"pack.nosql", "pack.validation"} {
		if saved.Uses[i].Components == nil || saved.Uses[i].Components.Pack.ID != want || saved.Uses[i].Assessment.RequestDigest != "r" {
			t.Fatalf("%s provenance lost on export", want)
		}
	}
}
