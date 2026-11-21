package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
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

// TestJinjaEnvironmentFromString (close-findings-gaps D-24): from_string on a
// Jinja environment compiles template source; constant source with render
// variables creates no template claim.
func TestJinjaEnvironmentFromString(t *testing.T) {
	r := analyzeFixture(t, "templates")
	lines := map[int]bool{}
	for _, u := range r.Uses {
		if u.Kind == analysispacks.TemplateKind {
			lines[u.Sink.Span.StartLine] = true
			if u.Sink.Span.StartLine == 26 && (u.Code == nil || u.Code.Operation != "jinja2.Environment.from_string" || len(u.Dependencies) == 0) {
				t.Fatalf("from_string record %+v", u.Code)
			}
		}
	}
	if !lines[26] || lines[32] {
		t.Fatalf("template claims at lines %v, want 26 and not 32", lines)
	}
}
