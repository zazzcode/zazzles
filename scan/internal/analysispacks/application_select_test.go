package analysispacks_test

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

// Every candidate of the new fixtures selects its family's own components.
func TestApplicationFamiliesSelect(t *testing.T) {
	for _, dir := range []string{"exposure", "symfony/exposure", "symfony/mass-assignment", "symfony/mass-assignment-transfer", "mass-assignment-plain", "symfony/authorization", "symfony/authorization-transfer", "authorization-plain"} {
		t.Run(dir, func(t *testing.T) {
			r, err := pipeline.AnalyzeWithOptions(filepath.Join("..", "langphp", "testdata", filepath.FromSlash(dir)), "", nil, pipeline.Options{})
			if err != nil {
				t.Fatal(err)
			}
			seen := 0
			for _, u := range r.Uses {
				if u.Kind != analysis.ExposureKind && u.Kind != analysis.MassAssignmentKind && u.Kind != analysis.AuthorizationKind {
					continue
				}
				seen++
				s, err := analysispacks.Select(u)
				if err != nil {
					t.Fatalf("%s %s:%d: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
				}
				family := analysispacks.FamFamily(u.Kind)
				if s.Pack.ID != family.Pack || analysispacks.ProtocolFor(u.Kind) == "" {
					t.Fatalf("selection %+v", s)
				}
				if _, err := analysispacks.ForUse(u); err != nil {
					t.Fatalf("material: %v", err)
				}
			}
			if seen == 0 {
				t.Fatal("fixture has no candidate of the new families")
			}
		})
	}
	for _, f := range []string{"exposure", "mass-assignment"} {
		family := analysispacks.FamilyForName(f)
		if family == nil || len(family.QuestionNames) == 0 || !analysispacks.ValidCLIFamily(f) {
			t.Fatalf("family %s is not registered with questions", f)
		}
	}
	model := analysispacks.ExposureContract(analysispacks.PHPDiagnosticOutput)
	if model == nil || model.Semantics == "" || model.Reference == "" {
		t.Fatal("diagnostic contract lacks semantics or reference")
	}
}
