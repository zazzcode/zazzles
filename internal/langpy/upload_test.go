package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// TestPythonUploadFacts (close-findings-gaps AC6, D-19, D-20).
func TestPythonUploadFacts(t *testing.T) {
	r := analyzeFixture(t, "upload")
	byLine := map[int]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "file_upload_candidate" {
			byLine[u.Sink.Span.StartLine] = u
		}
	}
	for _, tt := range []struct {
		line              int
		stored, extension string
		controls          int
	}{
		{13, "client", "client", 0},
		{21, "client_basename", "client", 1},
		{28, "server_generated", "unknown", 0},
	} {
		u, ok := byLine[tt.line]
		if !ok {
			t.Fatalf("no upload record at line %d (%v)", tt.line, byLine)
		}
		x := u.Upload
		if err := x.Validate(len(u.Dependencies), len(u.Context)); err != nil {
			t.Fatal(err)
		}
		if x.StoredName != tt.stored || x.ExtensionOrigin != tt.extension || len(x.TypeControls) != tt.controls || x.DestinationServed != "unknown" {
			t.Fatalf("line %d facts %+v", tt.line, x)
		}
		if tt.controls > 0 && (x.TypeControls[0].Kind != analysis.UploadClientDeclaredType || !x.TypeControls[0].ClientControlled) {
			t.Fatalf("line %d control %+v", tt.line, x.TypeControls)
		}
		if _, err := analysispacks.Select(u); err != nil {
			t.Fatalf("line %d selection: %v", tt.line, err)
		}
	}
}
