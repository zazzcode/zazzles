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

// TestTemplateOriginScoping: a template-source witness rests on its own
// request path; a sibling path from a remote response stays recorded and
// blocks only when no path has a request origin.
func TestTemplateOriginScoping(t *testing.T) {
	r, err := pipeline.Analyze(filepath.Join("..", "langpy", "testdata", "templates"), "")
	if err != nil {
		t.Fatal(err)
	}
	var base analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == analysispacks.TemplateKind {
			base = u
		}
	}
	if base.Code == nil || len(base.Dependencies) != 1 {
		t.Fatalf("fixture wants one request path: %+v", base.Dependencies)
	}
	remote := base.Dependencies[0]
	remote.Source.Kind = "external_response_source"
	remote.Source.Span.StartLine, remote.Source.Span.StartByte = 3, 3
	both := base
	both.Dependencies = append(append([]analysis.Dependency{}, base.Dependencies...), remote)
	code := *base.Code
	code.Paths = append(append([]analysis.CommandPath{}, base.Code.Paths...), analysis.CommandPath{Dependency: 1, Operand: "code", Protection: "raw"})
	both.Code = &code
	only := base
	only.Dependencies = []analysis.Dependency{remote}
	answers := map[string]string{"code_control": "whole_program", "code_restriction": "none", "protection_coverage": "incomplete"}
	for _, tt := range []struct {
		name   string
		use    analysis.CandidateUse
		status string
	}{
		{"request path beside a remote path is Confirmed", both, "confirmed_vulnerability"},
		{"a remote path alone stays blocked", only, "needs_evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.CodeProtocol, Answers: answers}
			applyPolicy(tt.use, &a)
			if a.FindingStatus != tt.status {
				t.Fatalf("status %s blockers %+v", a.FindingStatus, a.BlockingGaps)
			}
		})
	}
}
