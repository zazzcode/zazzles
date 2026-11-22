package analysispacks_test

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

// Every account candidate of the account fixtures selects the account
// family's components and assembles its material.
func TestAccountFixturesSelect(t *testing.T) {
	for _, dir := range []string{"symfony/account", "symfony/account-transfer", "account-plain"} {
		t.Run(dir, func(t *testing.T) {
			r, err := pipeline.AnalyzeWithOptions(filepath.Join("..", "langphp", "testdata", filepath.FromSlash(dir)), "", nil, pipeline.Options{})
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]int{}
			for _, u := range r.Uses {
				if u.Kind != analysis.AccountEnumerationKind && u.Kind != analysis.RecoveryDeliveryKind && u.Kind != analysis.PasswordHashKind {
					continue
				}
				seen[u.Kind]++
				s, err := analysispacks.Select(u)
				if err != nil {
					t.Fatalf("%s %s:%d: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
				}
				if s.Pack.ID != "pack.account" {
					t.Fatalf("selection %+v", s)
				}
				if _, err := analysispacks.ForUse(u); err != nil {
					t.Fatalf("material %s %s:%d: %v", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, err)
				}
			}
			for _, kind := range []string{analysis.AccountEnumerationKind, analysis.RecoveryDeliveryKind, analysis.PasswordHashKind} {
				if seen[kind] == 0 {
					t.Fatalf("fixture has no %s", kind)
				}
			}
		})
	}
}
