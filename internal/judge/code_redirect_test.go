package judge

import (
	"context"
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/report"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCodeRedirectPolicy(t *testing.T) {
	for _, tt := range []struct{ family, body, control, restriction, coverage, want string }{
		{"code", `eval(req.body.code)`, "whole_program", "none", "incomplete", "confirmed_vulnerability"},
		{"code", `eval(Number(req.body.code))`, "whole_program", "type_conversion", "complete", "protected_for_claim"},
		{"code", `eval(Number(req.body.code)+req.body.code)`, "whole_program", "type_conversion", "complete", "needs_evidence"},
		{"redirect", `if(!req.query.url.startsWith('https://trusted.example/'))return;res.redirect(req.query.url)`, "full_url", "prefix_or_substring", "complete", "protected_for_claim"},

		{"code", `eval(req.body.code)`, "whole_program", "blacklist_only", "incomplete", "confirmed_vulnerability"},
		{"code", `eval(req.body.code)`, "whole_program", "allowlist_grammar", "complete", "needs_evidence"},
		{"code", `if(!/^[0-9+ -]+$/.test(req.body.code))return;eval(req.body.code)`, "whole_program", "allowlist_grammar", "complete", "protected_for_claim"},
		{"redirect", `res.redirect(req.query.url)`, "full_url", "none", "complete", "confirmed_vulnerability"},
		{"redirect", `if(!req.query.url.startsWith('https://trusted.example/'))return;if(!req.query.url.includes('trusted.example'))return;res.redirect(req.query.url)`, "full_url", "prefix_or_substring", "complete", "protected_for_claim"},
		{"redirect", `let target;if(req.query.branch){const a=req.query.a;if(!a.startsWith('https://trusted.example/'))return;target=a}else{const b=req.query.b;if(!b.startsWith('https:'))return;target=b}res.redirect(target)`, "full_url", "prefix_or_substring", "complete", "poor_practice"},

		{"redirect", `res.redirect('/'+req.query.url)`, "path_only", "none", "incomplete", "confirmed_vulnerability"},
		{"redirect", `res.redirect(req.query.url)`, "full_url", "host_allowlist", "complete", "needs_evidence"},
		{"redirect", `if(!['good.example'].includes(new URL(req.query.url).hostname))return;res.redirect(req.query.url)`, "full_url", "host_allowlist", "complete", "protected_for_claim"},
		{"redirect", `if(!req.query.url.includes('good.example'))return;res.redirect(req.query.url)`, "full_url", "prefix_or_substring", "complete", "confirmed_vulnerability"},
	} {
		t.Run(tt.family+"/"+tt.restriction+"/"+tt.body, func(t *testing.T) {
			kind, protocol, key := "code_execution_candidate", analysispacks.CodeProtocol, "code"
			if tt.family == "redirect" {
				kind, protocol, key = "open_redirect_candidate", analysispacks.RedirectProtocol, "destination"
			}
			u, _ := familyFixtureUse(t, map[string]string{"server.js": `const express=require('express');const app=express();app.post('/x',(req,res)=>{` + tt.body + `;res.end()});`}, kind)
			a := analysis.Assessment{Status: "completed", QuestionVersion: protocol, Answers: map[string]string{key + "_control": tt.control, key + "_restriction": tt.restriction, "protection_coverage": tt.coverage}}
			applyPolicy(u, &a)
			if a.FindingStatus != tt.want {
				t.Fatalf("got %s want %s gaps=%+v facts=%+v", a.FindingStatus, tt.want, a.BlockingGaps, u.CodePaths())
			}
			c, _ := New("openai", "fixture-model", "key")
			p, err := c.payload(u)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(p), key+"_control") || len(questionsFor(u)) != 3 {
				t.Fatal("missing family questions")
			}
			// No confidence or answer can fill a missing verified binding.
			u.APIModel = nil
			applyPolicy(u, &a)
			if a.FindingStatus != "needs_evidence" {
				t.Error("missing API classified")
			}
		})
	}
}

func TestInterpreterDecoderProtocols(t *testing.T) {
	c, _ := New("openai", "fixture-model", "key")
	for _, family := range []string{"code", "redirect"} {
		names, values := []string{"code_control", "code_restriction", "protection_coverage"}, []string{"whole_program", "type_conversion", "complete"}
		if family == "redirect" {
			names, values = []string{"destination_control", "destination_restriction", "protection_coverage"}, []string{"path_only", "same_site_relative", "complete"}
		}
		list := []map[string]string{}
		for i, name := range names {
			list = append(list, map[string]string{"type": "choice", "name": name, "choice": values[i]})
		}
		data, _ := json.Marshal(map[string]any{"model": "fixture-model", "answers": list})
		got, _, _, err := c.decodeQuestions(data, interpreterComponentQuestions(family))
		if err != nil || len(got) != 3 {
			t.Fatalf("%s decoder: %v %+v", family, err, got)
		}
		if family == "redirect" {
			if _, _, _, err := c.decodeQuestions(data, componentQuestions(analysispacks.SSRFQuestions())); err == nil {
				t.Error("redirect-specific choices accepted under SSRF protocol")
			}
		}
	}
}

func TestInterpreterStubReplayAndReports(t *testing.T) {
	for _, family := range []string{"code", "redirect"} {
		kind, body, key, control := "code_execution_candidate", `eval(req.body.q)`, "code", "whole_program"
		if family == "redirect" {
			kind, body, key, control = "open_redirect_candidate", `res.redirect(req.query.q)`, "destination", "full_url"
		}
		u, _ := familyFixtureUse(t, map[string]string{"server.js": `const express=require('express');const app=express();app.post('/x',(req,res)=>{` + body + `;res.end()});`}, kind)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": []map[string]string{{"type": "choice", "name": key + "_control", "choice": control}, {"type": "choice", "name": key + "_restriction", "choice": "none"}, {"type": "choice", "name": "protection_coverage", "choice": "incomplete"}}})
		}))
		defer s.Close()
		c, _ := New("openai", "fixture-model", "key")
		c.UseEndpoint(s.URL, s.Client())
		a, tr := c.AssessTrace(context.Background(), u)
		if a.Status != "completed" || a.FindingStatus != "confirmed_vulnerability" {
			t.Fatalf("%s assessment %+v", family, a)
		}
		replay := c.Replay(u, tr)
		if replay.RequestDigest != a.RequestDigest || replay.FindingStatus != a.FindingStatus {
			t.Fatal("exact replay mismatch")
		}
		u.Assessment = a
		r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{u}}
		report.Enrich(r)
		if len(r.Findings) != 1 || r.Findings[0].Status != "confirmed_vulnerability" || r.Findings[0].TypeIDs[0] != (map[string]string{"code": "code-injection", "redirect": "open-redirect"})[family] {
			t.Fatalf("report %+v", r.Findings)
		}
	}
}
