package parse_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

func TestXSSUnknownContextProtection(t *testing.T) {
	use := func(id, context string) analysis.CandidateUse {
		return analysis.CandidateUse{ID: id, Kind: "xss_candidate", Sink: analysis.Evidence{Text: "res.send(body)", Span: analysis.Span{File: "route.ts", StartLine: 4}},
			Dependencies: []analysis.Dependency{{Source: analysis.Evidence{Kind: "file_read", Text: "readFile(p)", Span: analysis.Span{File: "route.ts", StartLine: 3}}}},
			XSS: &analysis.XSSFacts{Type: "reflected", EntryKind: "server", OutputContext: context, ContentType: "unknown", Protection: "raw",
				Paths: []analysis.XSSPath{{Protection: "raw"}}}}
	}
	r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{use("unknown", "unknown"), use("html", "html_text")}}
	parse.AssembleXSSClaims(r)
	unknown, html := r.Uses[0].XSS, r.Uses[1].XSS
	if unknown.Protection != "unknown" || unknown.Paths[0].Protection != "raw" {
		t.Fatalf("unknown context: protection %q, path %q", unknown.Protection, unknown.Paths[0].Protection)
	}
	if html.Protection != "raw" {
		t.Fatalf("known context changed: %q", html.Protection)
	}
	found := false
	for _, f := range r.Uses[0].Completeness.ModelFacts {
		found = found || f == "protection=unknown"
	}
	if !found {
		t.Fatalf("model facts keep the raw label: %v", r.Uses[0].Completeness.ModelFacts)
	}
	report.Enrich(r)
	var page bytes.Buffer
	if err := report.HTML(&page, &analysis.AnalysisReport{Uses: r.Uses[:1], Findings: r.Findings[:1]}); err != nil {
		t.Fatal(err)
	}
	sarif, _ := json.Marshal(report.SARIF(&analysis.AnalysisReport{Uses: r.Uses[:1], Findings: r.Findings[:1]}))
	for name, out := range map[string]string{"finding": r.Findings[0].Protection + r.Findings[0].Summary, "HTML": page.String(), "SARIF": string(sarif)} {
		if strings.Contains(out, "protection: raw") || strings.Contains(out, "Protection: raw") || strings.Contains(out, `"protection":"raw"`) {
			t.Fatalf("%s shows raw protection for an unknown context", name)
		}
	}
}
