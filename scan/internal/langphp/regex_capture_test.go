package langphp

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// TestRegexCapturePHP (close-findings-gaps AC2, D-4, D-6): preg_match capture
// groups reach the shell operand with a regex_capture transform.
func TestRegexCapturePHP(t *testing.T) {
	r := phpAnalyze(t, filepath.Join("testdata", "regex-capture"), "index.php")
	byLine := map[int]analysis.CandidateUse{}
	for _, u := range phpUsesOfKind(r, "command_execution_candidate") {
		byLine[u.Sink.Span.StartLine] = u
	}
	for _, tt := range []struct {
		name       string
		line       int
		protection string
		class      string
	}{
		{"a capture that admits any character is raw", 5, "raw", analysispacks.CaptureAdmitsAny},
		{"an explicit alphabet stays guarded", 11, "guarded", analysispacks.CaptureExplicitAlphabet},
		{"quoting after the capture keeps the path guarded", 17, "guarded", analysispacks.CaptureAdmitsAny},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u, ok := byLine[tt.line]
			if !ok {
				t.Fatalf("no command candidate at line %d", tt.line)
			}
			if err := u.Command.Validate(len(u.Dependencies), len(u.Context)); err != nil {
				t.Fatal(err)
			}
			if u.Completeness == nil || len(u.Completeness.Blockers) > 0 {
				t.Fatalf("blockers %+v", u.Completeness)
			}
			if len(u.Command.Paths) != 1 || u.Command.Paths[0].Protection != tt.protection {
				t.Fatalf("paths %+v", u.Command.Paths)
			}
			x, ok := phpSoleCapture(u.Dependencies[0])
			if !ok || x.Class != tt.class || x.Group != 1 || x.Flavor != analysispacks.FlavorPCRE {
				t.Fatalf("capture %+v", x)
			}
			if tt.protection == "guarded" && len(analysispacks.GuardContracts(u)) == 0 {
				t.Fatal("a guarded capture path carries a guard contract")
			}
		})
	}
}
