package judge

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func ssrfUse(t *testing.T, guarded bool) analysis.CandidateUse {
	t.Helper()
	route := `app.get('/x',(req,res)=>{const url=req.query.url;fetch(url);res.send('ok')});`
	if guarded {
		route = `const HOSTS=new Set(['api.invalid']);app.get('/x',(req,res)=>{const url=req.query.url;if(!HOSTS.has(new URL(url).hostname)){return res.sendStatus(400)}fetch(url);res.send('ok')});`
	}
	u, _ := familyFixtureUse(t, map[string]string{"server.js": "const express=require('express');const app=express();" + route}, "ssrf_candidate")
	if u.Outbound == nil || u.Completeness == nil {
		t.Fatal("no SSRF claim")
	}
	return u
}

func TestSSRFPolicy(t *testing.T) {
	raw, guarded := ssrfUse(t, false), ssrfUse(t, true)
	if raw.Outbound.Paths[0].Protection != "raw" || guarded.Outbound.Paths[0].Protection != "guarded" {
		t.Fatalf("fixture paths: %+v / %+v", raw.Outbound.Paths, guarded.Outbound.Paths)
	}
	blocked := ssrfUse(t, false)
	blocked.Completeness.Blockers = append(blocked.Completeness.Blockers, analysis.Gap{Kind: "applicable_middleware_unresolved", Detail: "x", At: analysis.Span{File: "server.js", StartByte: 0, EndByte: 1}})
	for _, tt := range []struct {
		name                        string
		use                         analysis.CandidateUse
		control, restrict, coverage string
		status, gap                 string
	}{
		{"raw full url", raw, "full_url", "none", "incomplete", "confirmed_vulnerability", ""},
		{"raw host", raw, "host", "none", "complete", "confirmed_vulnerability", ""},
		{"raw prefix only", raw, "full_url", "prefix_only", "incomplete", "poor_practice", ""},
		{"protected without a guard", raw, "full_url", "host_allowlist", "complete", "needs_evidence", "ssrf_answers_inconsistent"},
		{"control none with a request destination", raw, "none", "none", "unknown", "needs_evidence", "ssrf_answers_inconsistent"},
		{"guarded allow-list", guarded, "full_url", "host_allowlist", "complete", "protected_for_claim", ""},
		{"guarded but answered vulnerable", guarded, "full_url", "none", "incomplete", "needs_evidence", ""},
		{"path or query only", raw, "path_or_query", "none", "incomplete", "needs_evidence", ""},
		{"blocker voids the witness", blocked, "full_url", "none", "incomplete", "needs_evidence", "applicable_middleware_unresolved"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.SSRFProtocol, Answers: map[string]string{"destination_control": tt.control, "destination_restriction": tt.restrict, "protection_coverage": tt.coverage}}
			applyPolicy(tt.use, &a)
			if a.FindingStatus != tt.status {
				t.Fatalf("status=%s want %s (%s) gaps=%+v", a.FindingStatus, tt.status, a.Reason, a.BlockingGaps)
			}
			if tt.gap != "" {
				found := false
				for _, g := range a.BlockingGaps {
					found = found || g.Kind == tt.gap
				}
				if !found {
					t.Fatalf("missing %s: %+v", tt.gap, a.BlockingGaps)
				}
			}
		})
	}
	// A wrong protocol or missing facts never classify.
	a := analysis.Assessment{Status: "completed", QuestionVersion: "other", Answers: map[string]string{"destination_control": "full_url", "destination_restriction": "none", "protection_coverage": "incomplete"}}
	applyPolicy(raw, &a)
	if a.FindingStatus != "needs_evidence" {
		t.Fatalf("protocol gate: %+v", a)
	}
	missing := raw
	missing.Outbound = nil
	a = analysis.Assessment{Status: "completed", QuestionVersion: analysispacks.SSRFProtocol, Answers: map[string]string{"destination_control": "full_url", "destination_restriction": "none", "protection_coverage": "incomplete"}}
	applyPolicy(missing, &a)
	if a.FindingStatus != "needs_evidence" || !strings.Contains(a.Reason, "lacks source-backed") {
		t.Fatalf("missing facts: %+v", a)
	}
}

// An SSRF request carries only the destination facts, the selected contract and
// the three SSRF questions; outbound observations still send nothing.
func TestSSRFRequestShape(t *testing.T) {
	c, _ := New("openai", "fixture-model", "key")
	u := ssrfUse(t, false)
	p, err := c.payload(u)
	if err != nil {
		t.Fatal(err)
	}
	body := string(p)
	for _, want := range []string{`destination_control`, `destination_restriction`, `protection_coverage`, `fetch-url-v1`, `\"outbound\":`, `sink_slot\":\"destination`} {
		if !strings.Contains(body, want) {
			t.Fatalf("request lacks %s", want)
		}
	}
	if len(questionsFor(u)) != 3 {
		t.Fatal("SSRF questions")
	}
}
