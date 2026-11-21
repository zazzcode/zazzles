package report

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestRenderingGuidanceMatchesRenderer(t *testing.T) {
	for _, tc := range []struct{ name, file, text, want string }{
		{"Markdown in EJS", "views/index.ejs", "<%- marked(new String(todo.content)) %>", "Markdown"},
		{"plain raw EJS", "views/page.ejs", "<%- value %>", "<%="},
		{"raw Handlebars", "views/page.hbs", "{{{value}}}", "{{value}}"},
		{"server HTML response", "server.ts", "res.send('<h1>'+input+'</h1>')", "HTML"},
		{"Python template source", "app.py", "Template(content).render()", "Jinja"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := analysis.CandidateUse{Kind: "xss_candidate", Sink: analysis.Evidence{Text: tc.text, Span: analysis.Span{File: tc.file, StartLine: 20}}, XSS: &analysis.XSSFacts{OutputContext: "html_text", Protection: "raw"}}
			g := scopedGuidance(u, analysis.Finding{RecordType: "finding"})
			text := strings.Join(g.Actions, "\n")
			if !strings.Contains(text, tc.want) {
				t.Fatalf("missing renderer advice %q: %s", tc.want, text)
			}
			if !strings.HasSuffix(tc.file, ".py") && (strings.Contains(text, "Jinja") || strings.Contains(text, "Template.render")) {
				t.Fatalf("Python-only advice leaked into %s: %s", tc.file, text)
			}
		})
	}
}
