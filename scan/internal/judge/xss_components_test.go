package judge

import (
	"context"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestXSSComponentPayloadsAndPolicy(t *testing.T) {
	_, u := parsedXSS(t, map[string]string{"client.js": `document.body.innerHTML=location.hash`})
	for _, provider := range []string{"openai", "jev"} {
		c, _ := New(provider, "fixture-model", "key")
		tr, err := c.Preview(u)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"## Sinks", "## Logging", "injection_protection", "field_requirement", "TestXSS", "internal/parse", "expected_status"} {
			if strings.Contains(string(tr.Request), bad) {
				t.Fatalf("unrelated material: %s", bad)
			}
		}
		tr.HTTPStatus = 200
		tr.Response = xssAnswer(u, provider, "protected")
		if a := c.Replay(u, tr); a.FindingStatus != "needs_evidence" {
			t.Fatal("raw path borrowed protection")
		}
		for _, role := range []string{"render_source", "render_binding", "render_context", "extra_required"} {
			v := u
			v.Completeness = &analysis.Completeness{}
			*v.Completeness = *u.Completeness
			v.Completeness.Evidence = map[string][]analysis.Evidence{}
			for k, e := range u.Completeness.Evidence {
				if k != role {
					v.Completeness.Evidence[k] = e
				}
			}
			v.Completeness.Required = append(append([]string{}, u.Completeness.Required...), role)
			analysispacks.Attach(&v)
			trace, e := c.Preview(v)
			if e != nil {
				t.Fatal(e)
			}
			trace.HTTPStatus = 200
			trace.Response = xssAnswer(v, provider, "raw")
			if a := c.Replay(v, trace); a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) == 0 {
				t.Fatalf("missing role %s bypassed gate: %+v", role, a)
			}
		}
		for _, kind := range []string{"stored", "cross_tier"} {
			v := u
			x := *u.XSS
			v.XSS = &x
			x.Type = kind
			x.OriginResolved = false
			analysispacks.Attach(&v)
			trace, e := c.Preview(v)
			if e != nil {
				t.Fatal(e)
			}
			trace.HTTPStatus = 200
			trace.Response = xssAnswer(v, provider, "raw")
			if a := c.Replay(v, trace); a.FindingStatus != "needs_evidence" {
				t.Fatalf("unresolved %s origin accepted", kind)
			}
		}
		for _, mode := range []string{"unknown", "not_applicable"} {
			tr.Response = xssAnswer(u, provider, mode)
			if a := c.Replay(u, tr); a.Status != "completed" || a.FindingStatus != "needs_evidence" {
				t.Fatalf("mode %s: %+v", mode, a)
			}
		}
	}
}

func TestXSSDataOnlyNotAssessed(t *testing.T) {
	r := sqlFixture(t, "app.js", `const express=require('express');const app=express();app.get('/data',(req,res)=>res.json({value:req.query.q}));`)
	calls := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
	defer s.Close()
	found := false
	for _, u := range r.Uses {
		if u.Kind == "xss_data_candidate" {
			found = true
			if u.Components != nil {
				t.Fatal("data acquired rendering selection")
			}
			for _, p := range []string{"openai", "jev"} {
				c, _ := New(p, "fixture-model", "key")
				c.endpoint = s.URL
				c.http = s.Client()
				if a := c.Assess(context.Background(), u); a.Status != "not_run" {
					t.Fatalf("data assessed %+v", a)
				}
			}
		}
	}
	if !found || calls != 0 {
		t.Fatalf("data coverage=%v calls=%d", found, calls)
	}
}

func TestXSSComponentReplay(t *testing.T) {
	_, u := parsedXSS(t, map[string]string{"client.js": `fetch('/item',{method:'POST'}).then(r=>r.json()).then(r=>{document.body.innerHTML=r.name})`})
	for _, provider := range []string{"openai", "jev"} {
		c, _ := New(provider, "fixture-model", "key")
		tr, err := c.Preview(u)
		if err != nil {
			t.Fatal(err)
		}
		tr.HTTPStatus = 200
		tr.Response = xssAnswer(u, provider, "raw")
		if a := c.Replay(u, tr); a.Status != "completed" || a.RequestDigest == "" {
			t.Fatal("exact replay failed")
		}
		for _, text := range []string{"analysis_guidelines", "method", "POST", "html_text", "fixture-model", "version", "encoding_adequacy"} {
			changed := tr
			raw := string(tr.Request)
			if !strings.Contains(raw, text) {
				t.Fatalf("mutation absent: %s", text)
			}
			changed.Request = []byte(strings.Replace(raw, text, text+" changed", 1))
			if a := c.Replay(u, changed); a.Status != "failed" {
				t.Fatalf("changed %s replayed", text)
			}
		}
		old := tr
		old.QuestionVersion = "xss-use-v1"
		if c.Replay(u, old).Status != "failed" {
			t.Fatal("old protocol replayed")
		}
		v := u
		x := *u.XSS
		v.XSS = &x
		x.ResponseMethod = "GET"
		analysispacks.Attach(&v)
		if c.Replay(v, tr).Status != "failed" {
			t.Fatal("changed method replayed")
		}
		v = u
		v.Sink.Text += " changed"
		if c.Replay(v, tr).Status != "failed" {
			t.Fatal("changed evidence replayed")
		}
		v = u
		v.Components = cloneComponents(u.Components)
		v.Components.Components[0].Digest = "changed-content-without-version-bump"
		if c.Replay(v, tr).Status != "failed" {
			t.Fatal("changed material replayed")
		}
	}
}

func TestXSSComponentFailures(t *testing.T) {
	_, u := parsedXSS(t, map[string]string{"client.js": `document.body.innerHTML=location.hash`})
	for _, provider := range []string{"openai", "jev"} {
		calls := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++ }))
		defer s.Close()
		c, _ := New(provider, "fixture-model", "key")
		c.endpoint = s.URL
		c.http = s.Client()
		for _, change := range []func(*analysis.CandidateUse){
			func(v *analysis.CandidateUse) { v.Components = nil },
			func(v *analysis.CandidateUse) {
				v.Components = cloneComponents(v.Components)
				v.Components.Failure = "unsupported material"
			},
			func(v *analysis.CandidateUse) {
				v.Components = cloneComponents(v.Components)
				v.Components.Components = append(v.Components.Components, v.Components.Components...)
			},
			func(v *analysis.CandidateUse) { v.APIModel = nil },
			func(v *analysis.CandidateUse) { v.Sink.Text = strings.Repeat("x", 100<<10) },
		} {
			v := u
			change(&v)
			a := c.Assess(context.Background(), v)
			if a.Status != "failed" && a.Status != "not_run" {
				t.Fatalf("failure hidden %+v", a)
			}
		}
		if calls != 0 {
			t.Fatalf("bounded failure made %d calls", calls)
		}
	}
}
