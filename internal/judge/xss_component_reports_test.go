package judge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
	"github.com/zazzcode/zazzles/internal/report"
	"reflect"
	"strings"
	"testing"
)

func TestXSSComponentReportParity(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		r, err := pipeline.Analyze(fixtureRoot(language+"/browser-events"), "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 6 || len(r.Uses) != 4 {
			t.Fatalf("coverage count drift: %d/%d", len(r.Entries), len(r.Uses))
		}
		statuses := map[string]int{}
		contexts := map[string]bool{}
		c, _ := New("openai", "fixture-model", "key")
		for i := range r.Uses {
			u := &r.Uses[i]
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("event selection %+v", u.Components)
			}
			contexts[u.InvocationContextID] = true
			mode := "raw"
			if u.XSS.Protection == "encoded" {
				mode = "protected"
			}
			if u.XSS.Protection == "unknown" {
				mode = "protected"
			}
			tr, err := c.Preview(*u)
			if err != nil {
				t.Fatal(err)
			}
			tr.HTTPStatus = 200
			tr.Response = xssAnswer(*u, "openai", mode)
			u.Assessment = c.Replay(*u, tr)
			statuses[u.Assessment.FindingStatus]++
		}
		if len(contexts) != 4 || statuses["confirmed_vulnerability"] != 2 || statuses["protected_for_claim"] != 1 || statuses["needs_evidence"] != 1 {
			t.Fatalf("event outcomes %v contexts %d", statuses, len(contexts))
		}
		report.Enrich(r)
		var html bytes.Buffer
		if err := report.HTML(&html, r); err != nil {
			t.Fatal(err)
		}
		sarif := report.SARIF(r)
		run := sarif["runs"].([]any)[0].(map[string]any)
		represented := 0
		for _, item := range run["results"].([]any) {
			f := item.(map[string]any)["properties"].(map[string]any)["scan.finding"].(analysis.Finding)
			represented += 1 + len(f.GroupedUseIDs)
		}
		if represented != 4 {
			t.Fatal("SARIF use count drift")
		}
		invocation := run["invocations"].([]any)[0].(map[string]any)
		props := invocation["properties"].(map[string]any)
		if len(props["scan.entries"].([]analysis.EntryPoint)) != 6 {
			t.Fatal("SARIF lost zero-use registrations")
		}
		data, _ := json.Marshal(r)
		var decoded analysis.AnalysisReport
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatal(err)
		}
		if len(decoded.Entries) != 6 || len(decoded.Findings) != 4 {
			t.Fatal("canonical source/assessment/coverage drift")
		}
		for i, u := range r.Uses {
			v := decoded.Uses[i]
			wantAnswer, _ := json.Marshal(u.Assessment)
			gotAnswer, _ := json.Marshal(v.Assessment)
			if u.Sink != v.Sink || !reflect.DeepEqual(u.XSS, v.XSS) || !bytes.Equal(wantAnswer, gotAnswer) || !reflect.DeepEqual(u.Components, v.Components) {
				t.Fatalf("source/assessment/provenance changed at %d", i)
			}
		}
		for _, e := range r.Entries {
			if !strings.Contains(html.String(), fmt.Sprint(e.Location.Span.StartLine)) {
				t.Fatal("HTML lost coverage location")
			}
		}
		var shown []int
		for i, f := range r.Findings {
			if f.GroupedInto == "" {
				shown = append(shown, i)
			}
		}
		for k, raw := range run["results"].([]any) {
			i := shown[k]
			p := raw.(map[string]any)["properties"].(map[string]any)
			f := p["scan.finding"].(analysis.Finding)
			if f.Status != r.Findings[i].Status || p["scan.useId"] != r.Uses[i].ID {
				t.Fatal("SARIF status/source association drift")
			}
		}
	}
}

func TestXSSCrossTierComponentParity(t *testing.T) {
	for _, method := range []string{"GET", "POST"} {
		cases := []xssCase{{method, map[string]string{
			"server.js": `const express=require('express');const app=express();app.get('/item',(req,res)=>res.json({name:req.query.q}));app.post('/item',(req,res)=>res.json({name:String(req.body.q).replace(/[^\w-]+/g,'')}));`,
			"client.js": `fetch('/item',{method:'` + method + `'}).then(r=>r.json()).then(r=>{document.body.innerHTML=r.name})`,
		}, "raw", "html_text", "confirmed_vulnerability"}}
		if method == "POST" {
			cases[0].protection = "sanitized"
			cases[0].status = "protected_for_claim"
		}
		xssPipeline(t, cases)
	}
}

func TestXSSComponentInventory(t *testing.T) {
	for _, fixture := range []string{"javascript/xss-fetch", "javascript/browser-events", "typescript/browser-events", "python/routes", "python/dynamic-vulnpy"} {
		r, err := pipeline.Analyze(fixtureRoot(fixture), "")
		if err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, u := range r.Uses {
			if u.Kind != "xss_candidate" {
				continue
			}
			found++
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("%s %s missing registered selection: %+v", fixture, u.ID, u.Components)
			}
			for _, provider := range []string{"openai", "jev"} {
				c, _ := New(provider, "fixture-model", "key")
				tr, err := c.Preview(u)
				if err != nil {
					t.Fatalf("%s %s: %v", fixture, u.ID, err)
				}
				t.Logf("%s %s body=%d", fixture, provider, tr.RequestBytes)
			}
		}
		if found == 0 {
			t.Fatalf("%s missing real rendering fixtures", fixture)
		}
	}
}
