package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func TestDeserializationPolicy(t *testing.T) {
	fixtureUses := map[string]analysis.CandidateUse{}
	for _, project := range []struct{ dir, marker string }{
		{"langpy/testdata/deserialization", " # "},
		{"langjs/testdata/deserialization/js", " // "},
		{"langphp/testdata/deserialization", " // "},
	} {
		root := filepath.Join("..", filepath.FromSlash(project.dir))
		r, err := pipeline.AnalyzeWithOptions(root, "", nil, pipeline.Options{})
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range r.Uses {
			if u.Kind != analysis.DeserializationKind {
				continue
			}
			at := u.Sink.Span
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(at.File)))
			if err != nil {
				t.Fatal(err)
			}
			line := strings.Split(string(raw), "\n")[at.StartLine-1]
			if _, id, ok := strings.Cut(line, project.marker); ok {
				fixtureUses[strings.TrimSpace(id)] = u
			}
		}
	}
	for _, tt := range []struct {
		id, fixture, exposure, integrity, classes, coverage, outcome, gap string
	}{
		{"P-01", "PY-01", "vulnerable", "none", "none", "incomplete", "confirmed_vulnerability", ""},
		{"P-02", "JS-04", "vulnerable", "none", "none", "incomplete", "confirmed_vulnerability", ""},
		{"P-03", "PHP-01", "vulnerable", "none", "none", "incomplete", "confirmed_vulnerability", ""},
		{"P-04", "PY-01", "not_applicable", "none", "none", "unknown", "needs_evidence", "answers_inconsistent"},
		{"P-05", "PHP-01", "protected", "verified_before_decode", "none", "complete", "needs_evidence", "answers_inconsistent"},
		{"P-06", "PY-C1", "protected", "verified_before_decode", "none", "complete", "protected_for_claim", ""},
		{"P-07", "PHP-C4", "protected", "none", "adequate", "complete", "protected_for_claim", ""},
		{"P-08", "PY-C2", "protected", "verified_before_decode", "none", "complete", "needs_evidence", "answers_inconsistent"},
		{"P-09", "JS-C1", "vulnerable", "none", "none", "incomplete", "needs_evidence", ""},
		{"P-10", "PY-U1", "vulnerable", "none", "none", "incomplete", "needs_evidence", "capability_unresolved"},
		{"P-11", "PY-12", "vulnerable", "none", "none", "incomplete", "needs_evidence", "capability_unresolved"},
		{"P-12", "PY-01", "vulnerable", "none", "none", "incomplete", "needs_evidence", "origin_unresolved"},
		{"P-13", "PY-01", "vulnerable", "none", "none", "incomplete", "needs_evidence", "protocol_missing"},
	} {
		t.Run(tt.id, func(t *testing.T) {
			u, ok := fixtureUses[tt.fixture]
			if !ok {
				t.Fatalf("missing %s fixture record", tt.fixture)
			}
			client, err := New("openai", "fixture-model", "fixture-key")
			if err != nil {
				t.Fatal(err)
			}
			names := []string{"deserialization_exposure", "integrity_control", "class_restriction", "protection_coverage"}
			choices := []string{tt.exposure, tt.integrity, tt.classes, tt.coverage}
			answers := make([]map[string]string, len(names))
			for i, name := range names {
				answers[i] = map[string]string{"type": "choice", "name": name, "choice": choices[i]}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request map[string]any
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
				}
				if err := json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			if tt.id == "P-12" {
				u.Dependencies = slices.Clone(u.Dependencies)
				u.Dependencies[0].Source.Kind = "storage_source"
				// The original input projection references the original request.
				u.InputFacts, u.Components = nil, nil
				analysispacks.Attach(&u)
			}
			client.UseEndpoint(server.URL, server.Client())
			got, trace := client.AssessTrace(context.Background(), u)
			if got.Status != "completed" || got.QuestionVersion != analysispacks.DeserializationProtocol {
				t.Fatalf("bad assessment: %+v", got)
			}
			if tt.id == "P-13" {
				got.QuestionVersion = analysispacks.CodeProtocol
				applyPolicy(u, &got)
			} else if replay := client.Replay(u, trace); replay.FindingStatus != got.FindingStatus || replay.RequestDigest != got.RequestDigest {
				t.Fatalf("bad replay: %+v", replay)
			}
			if got.FindingStatus != tt.outcome {
				t.Fatalf("outcome %s, want %s: %+v", got.FindingStatus, tt.outcome, got)
			}
			if tt.gap != "" && !slices.ContainsFunc(got.BlockingGaps, func(g analysis.Gap) bool { return g.Kind == "deserialization_"+tt.gap }) {
				t.Errorf("missing gap %s: %+v", tt.gap, got.BlockingGaps)
			}
		})
	}
}

func TestDeserializationControlReferences(t *testing.T) {
	u := analysis.CandidateUse{
		Context: []analysis.Evidence{{Span: analysis.Span{File: "a", StartByte: 1, EndByte: 2}}, {Span: analysis.Span{File: "a", StartByte: 3, EndByte: 4}}},
		Deserialization: &analysis.DeserializationFacts{
			Controls: []analysis.DeserializationControl{{Kind: "integrity_check", Context: 1}},
			Paths:    []analysis.CommandPath{{Operand: "data", Dependency: 0, Protection: "guarded", Controls: []int{1}}},
		},
	}
	budgeted := withoutContext(u, map[spanKey]bool{keyOf(u.Context[0]): true}, nil)
	raw, err := json.Marshal(wireDeserialization(budgeted.Deserialization, []string{"e3"}))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"controls":[{"context":"e3","kind":"integrity_check"}]`) ||
		!strings.Contains(string(raw), `"controls":["e3"]`) || u.Deserialization.Controls[0].Context != 1 {
		t.Fatalf("incorrect wire references or changed input: %s", raw)
	}
}
