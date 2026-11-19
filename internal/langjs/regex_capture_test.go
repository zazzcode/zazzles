package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// commandAtLine returns the command candidate whose sink starts on line.
func commandAtLine(t *testing.T, r *analysis.AnalysisReport, line int) analysis.CandidateUse {
	t.Helper()
	for _, u := range commandUses(r) {
		if u.Sink.Span.StartLine == line {
			return u
		}
	}
	t.Fatalf("no command candidate at line %d", line)
	return analysis.CandidateUse{}
}

func captureOf(t *testing.T, u analysis.CandidateUse) analysis.ValueTransform {
	t.Helper()
	var found []analysis.ValueTransform
	for _, d := range u.Dependencies {
		for _, x := range d.Transforms {
			if x.Kind == "regex_capture" {
				found = append(found, x)
			}
		}
	}
	if len(found) == 0 {
		t.Fatalf("line %d: no regex_capture transform on %+v", u.Sink.Span.StartLine, u.Dependencies)
	}
	return found[0]
}

// TestRegexCaptureCommandPaths (close-findings-gaps AC2, D-4, D-6).
func TestRegexCaptureCommandPaths(t *testing.T) {
	r := analyzeFixture(t, "javascript/regex-capture")
	for _, tt := range []struct {
		name       string
		line       int
		protection string
		class      string
		sub        string
	}{
		{"a capture that admits any character is raw", 10, "raw", analysispacks.CaptureAdmitsAny, "http.*"},
		{"an explicit alphabet stays guarded", 21, "guarded", analysispacks.CaptureExplicitAlphabet, "[a-z0-9.-]+"},
		{"another control keeps the path guarded", 31, "guarded", analysispacks.CaptureAdmitsAny, "http.*"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := commandAtLine(t, r, tt.line)
			validCommandFacts(t, u)
			if u.Completeness == nil || len(u.Completeness.Blockers) > 0 {
				t.Fatalf("blockers %+v", u.Completeness)
			}
			if len(u.Command.Paths) != 1 || u.Command.Paths[0].Protection != tt.protection {
				t.Fatalf("paths %+v", u.Command.Paths)
			}
			x := captureOf(t, u)
			if x.Class != tt.class || x.SubPattern != tt.sub || x.Group != 1 || x.Flavor != analysispacks.FlavorECMAScript {
				t.Fatalf("capture %+v", x)
			}
		})
	}
}
