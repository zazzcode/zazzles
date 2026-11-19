package judge

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/pipeline"
	"github.com/zazzcode/zazzles/internal/report"
)

// TestTemplateInjectionPairs (close-findings-gaps AC7, D-23 to D-26): request
// text compiled as template source is a template_injection_candidate linked
// to the XSS record of the same construction; request data passed only as
// render variables creates no template claim.
func TestTemplateInjectionPairs(t *testing.T) {
	for _, tt := range []struct {
		name, root, contract string
		line, safeLine       int
	}{
		{"jinja2 Template", filepath.Join("..", "langpy", "testdata", "templates"), "python-template-source-v1", 11, 17},
		{"ejs.render", filepath.Join("..", "langjs", "testdata", "javascript", "template-injection"), "js-template-source-v1", 6, 10},
		{"Twig createTemplate", filepath.Join("..", "langphp", "testdata", "templates"), "php-template-source-v1", 7, 8},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r, err := pipeline.Analyze(tt.root, "")
			if err != nil {
				t.Fatal(err)
			}
			report.Enrich(r)
			findings := map[string]analysis.Finding{}
			for _, f := range r.Findings {
				findings[f.UseID] = f
			}
			var got *analysis.CandidateUse
			for i, u := range r.Uses {
				if u.Kind != analysispacks.TemplateKind {
					continue
				}
				if u.Sink.Span.StartLine == tt.safeLine {
					t.Fatalf("render variables created a template claim: %s", u.Sink.Text)
				}
				if u.Sink.Span.StartLine == tt.line {
					got = &r.Uses[i]
				}
			}
			if got == nil {
				t.Fatalf("no template_injection_candidate at line %d", tt.line)
			}
			if got.Code == nil || got.Code.ContractID != tt.contract || got.Code.ExecutionContext != "template_engine" || len(got.Dependencies) == 0 || got.Dependencies[0].Source.Kind != "input_source" {
				t.Fatalf("facts %+v deps %+v", got.Code, got.Dependencies)
			}
			if _, err := analysispacks.Select(*got); err != nil {
				t.Fatalf("selection: %v", err)
			}
			linked := false
			for _, id := range findings[got.ID].LinkedUseIDs {
				for _, u := range r.Uses {
					linked = linked || u.ID == id && u.Kind == "xss_candidate"
				}
			}
			if !linked {
				t.Fatalf("no linked xss_candidate: %v", findings[got.ID].LinkedUseIDs)
			}
		})
	}
}
