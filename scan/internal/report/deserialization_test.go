package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func TestDeserializationFinding(t *testing.T) {
	var r analysis.AnalysisReport
	for _, row := range []struct{ id, file, capability, operation, status string }{
		{"PY-01", "a.py", analysis.DeserializationCodeExecution, "pickle.loads", "confirmed_vulnerability"},
		{"PHP-01", "a.php", analysis.DeserializationObjectInjection, "unserialize", "confirmed_vulnerability"},
		{"PY-U1", "b.py", analysis.DeserializationUnresolved, "yaml.load", "needs_evidence"},
	} {
		r.Uses = append(r.Uses, analysis.CandidateUse{
			ID: row.id, Kind: analysis.DeserializationKind,
			Sink:            analysis.Evidence{Span: analysis.Span{File: row.file, StartLine: 1, EndLine: 1}},
			Deserialization: &analysis.DeserializationFacts{Operation: row.operation, Capability: row.capability},
			Assessment:      analysis.Assessment{Status: "completed", FindingStatus: row.status, QuestionVersion: analysispacks.DeserializationProtocol},
		})
	}
	out, err := json.Marshal(SARIF(&r))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"id":"scan/unsafe-deserialization"`) || !strings.Contains(string(out), `"tags":["security","CWE-502"]`) {
		t.Fatalf("missing CWE-502 rule")
	}
	for i, want := range []string{"code execution by format design", "object injection"} {
		f := r.Findings[i]
		if f.RecordType != "finding" || len(f.TypeIDs) != 1 || f.TypeIDs[0] != "unsafe-deserialization" || !strings.Contains(f.Summary, want) {
			t.Errorf("finding %d: %+v", i, f)
		}
	}
	if strings.Contains(r.Findings[1].Summary, "code execution") {
		t.Errorf("PHP impact exceeds contract: %s", r.Findings[1].Summary)
	}
	if f := r.Findings[2]; f.RecordType != "analysis" || !strings.Contains(f.Title, "review") {
		t.Errorf("unresolved candidate should be Review: %+v", f)
	}
}
