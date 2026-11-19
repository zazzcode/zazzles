package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// TestRegexCapturePython (close-findings-gaps AC2, D-4, D-6): m.group(n) of a
// literal re match reaches the shell operand with a regex_capture transform.
func TestRegexCapturePython(t *testing.T) {
	r := analyzeFixture(t, "regex-capture")
	byLine := map[int]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "command_execution_candidate" {
			byLine[u.Sink.Span.StartLine] = u
		}
	}
	for _, tt := range []struct {
		name       string
		line       int
		protection string
		class      string
	}{
		{"a capture that admits any character is raw", 14, "raw", analysispacks.CaptureAdmitsAny},
		{"an explicit alphabet stays guarded", 23, "guarded", analysispacks.CaptureExplicitAlphabet},
		{"another control keeps the path guarded", 33, "guarded", analysispacks.CaptureAdmitsAny},
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
				t.Fatalf("blockers %+v", u.Completeness.Blockers)
			}
			if len(u.Command.Paths) != 1 || u.Command.Paths[0].Protection != tt.protection {
				t.Fatalf("paths %+v", u.Command.Paths)
			}
			var x *analysis.ValueTransform
			for i, tr := range u.Dependencies[0].Transforms {
				if tr.Kind == "regex_capture" {
					x = &u.Dependencies[0].Transforms[i]
				}
			}
			if x == nil || x.Class != tt.class || x.Group != 1 || x.Flavor != analysispacks.FlavorPython {
				t.Fatalf("capture %+v", x)
			}
		})
	}
}
