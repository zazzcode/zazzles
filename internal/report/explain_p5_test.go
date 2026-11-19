package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func p5Span(file string, start int) analysis.Span {
	return analysis.Span{File: file, StartLine: 3, EndLine: 3, StartByte: start, EndByte: start + 20}
}

func p5Report() *analysis.AnalysisReport {
	sink := analysis.Evidence{Kind: "browser_output", Text: "window.location.href = r", Span: p5Span("app/Login.tsx", 100)}
	return &analysis.AnalysisReport{Uses: []analysis.CandidateUse{
		{ID: "redirect", EntryID: "e", InvocationContextID: "c", Kind: "open_redirect_candidate", Sink: sink, Redirect: &analysis.RedirectFacts{},
			Assessment: analysis.Assessment{Status: "not_run"}},
		{ID: "xss", EntryID: "e", InvocationContextID: "c", Kind: "xss_candidate", Sink: sink,
			Assessment: analysis.Assessment{Status: "completed", FindingStatus: "needs_evidence", BlockingGaps: []analysis.Gap{{Kind: "z_policy", Detail: "policy gap", At: p5Span("app/Login.tsx", 100)}, {Kind: "z_policy", Detail: "policy gap", At: p5Span("app/Login.tsx", 100)}}}},
		{ID: "poor-unjudged", EntryID: "e2", Kind: "sql_query_candidate", Sink: analysis.Evidence{Text: "q", Span: p5Span("a.js", 1)}, Dependencies: requestDependency(), Gaps: []analysis.Gap{{Kind: "query_text_interpolated", Detail: "built"}},
			Assessment: analysis.Assessment{Status: "not_run"}},
		{ID: "scanner", EntryID: "e3", Kind: "xss_candidate", Sink: analysis.Evidence{Text: "x", Span: p5Span("b.js", 1)},
			Completeness: &analysis.Completeness{Required: []string{"render_source", "render_binding"}, Evidence: map[string][]analysis.Evidence{"render_binding": {{Kind: "render_binding"}}},
				Blockers: []analysis.Gap{{Kind: "render_protection_unresolved", Detail: "unknown"}}}, Assessment: analysis.Assessment{Status: "not_run"}},
		{ID: "const", EntryID: "e4", Kind: "outbound_http_candidate", Sink: analysis.Evidence{Text: "fetch('https://api.example')", Span: p5Span("c.js", 1)},
			Outbound: &analysis.OutboundFacts{DestinationOrigin: analysis.DestinationConstant}, Assessment: analysis.Assessment{Status: "not_run"}},
		{ID: "dynamic", EntryID: "e5", Kind: "outbound_http_candidate", Sink: analysis.Evidence{Text: "fetch(u)", Span: p5Span("d.js", 1)},
			Outbound: &analysis.OutboundFacts{DestinationOrigin: analysis.DestinationRequest}, Assessment: analysis.Assessment{Status: "not_run"}},
	}}
}

func TestP5AssessmentStateJudgedVersusUnjudged(t *testing.T) {
	r := p5Report()
	Enrich(r)
	want := map[string]string{"redirect": "not_run", "xss": "completed", "poor-unjudged": "not_run"}
	for _, f := range r.Findings {
		if w, ok := want[f.UseID]; ok && f.AssessmentState != w {
			t.Errorf("%s: state %q want %q", f.UseID, f.AssessmentState, w)
		}
	}
	if r.Findings[2].Status != "poor_practice" || r.Findings[2].AssessmentState != "not_run" {
		t.Fatalf("unjudged poor practice not distinguishable: %+v", r.Findings[2])
	}
	raw, _ := json.Marshal(r.Findings[2])
	if !strings.Contains(string(raw), `"assessment_state":"not_run"`) {
		t.Errorf("json: %s", raw)
	}
	var html bytes.Buffer
	if err := HTML(&html, p5Report()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(html.String(), "Not judged") || !strings.Contains(html.String(), ">Judged<") {
		t.Errorf("html lacks judged markers")
	}
	var text bytes.Buffer
	Text(&text, p5Report())
	if !strings.Contains(text.String(), "assessment=not_run (Not judged)") || !strings.Contains(text.String(), "assessment=completed (Judged)") {
		t.Errorf("text: %s", text.String())
	}
	props := SARIF(p5Report())["runs"].([]any)[0].(map[string]any)["results"].([]any)[2].(map[string]any)["properties"].(map[string]any)
	if props["assessmentState"] != "not_run" {
		t.Errorf("sarif props: %v", props["assessmentState"])
	}
}

func TestP5BlockingEvidenceSources(t *testing.T) {
	r := p5Report()
	Enrich(r)
	policy := r.Findings[1].BlockingEvidence
	if len(policy) != 1 || policy[0].Source != "policy" || policy[0].Kind != "z_policy" {
		t.Errorf("policy blockers must be deduplicated: %+v", policy)
	}
	var kinds []string
	for _, b := range r.Findings[3].BlockingEvidence {
		if b.Source != "scanner" {
			t.Errorf("source: %+v", b)
		}
		kinds = append(kinds, b.Kind)
	}
	if strings.Join(kinds, ",") != "missing_evidence:render_source,render_protection_unresolved" {
		t.Errorf("kinds: %v", kinds)
	}
	if len(r.Findings[2].BlockingEvidence) != 0 {
		t.Errorf("a poor_practice record is not a Review record: %+v", r.Findings[2].BlockingEvidence)
	}
	props := SARIF(p5Report())["runs"].([]any)[0].(map[string]any)["results"].([]any)[1].(map[string]any)["properties"].(map[string]any)
	if props["scan.blockingEvidence"] == nil {
		t.Errorf("sarif lacks blocking evidence")
	}
}

func TestP5LinkedClaimsKeptAndListed(t *testing.T) {
	r := p5Report()
	Enrich(r)
	if len(r.Findings) != 6 {
		t.Fatalf("records dropped: %d", len(r.Findings))
	}
	if got := r.Findings[0].LinkedUseIDs; len(got) != 1 || got[0] != "xss" {
		t.Errorf("redirect links: %v", got)
	}
	if got := r.Findings[1].LinkedUseIDs; len(got) != 1 || got[0] != "redirect" {
		t.Errorf("xss links: %v", got)
	}
	if len(r.Findings[3].LinkedUseIDs) != 0 {
		t.Errorf("unrelated record linked")
	}
}

func TestP5ConstantDestinationExplained(t *testing.T) {
	r := p5Report()
	Enrich(r)
	c, d := r.Findings[4], r.Findings[5]
	if c.Status != "needs_review" || !strings.Contains(c.Summary, "headers or body") {
		t.Errorf("constant summary: %s", c.Summary)
	}
	found := false
	for _, b := range c.BlockingEvidence {
		found = found || b.Kind == "constant_destination_no_request_dependency"
	}
	if !found {
		t.Errorf("constant destination reason missing: %+v", c.BlockingEvidence)
	}
	if strings.Contains(d.Summary, "headers or body") {
		t.Errorf("request destination must not claim a constant: %s", d.Summary)
	}
}
