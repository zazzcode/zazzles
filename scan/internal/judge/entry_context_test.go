package judge

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEntryContextReplayMismatch(t *testing.T) {
	c, _ := New("openai", "fixture-model", "fixture-token")
	u := xssClaim("raw")
	u.EntryID = "entry"
	u.InvocationContextID = "invocation"
	u.EntryKind = "browser"
	u.EntryFacts = &analysis.EntryPoint{ID: "entry", Kind: "browser", InstanceID: "page", Browser: &analysis.BrowserEntryMetadata{Category: "script"}, Location: u.Sink}
	u.InvocationFacts = &analysis.InvocationContext{ID: "invocation", EntryID: "entry", DispatchBindingID: "binding", Inputs: []analysis.InputBinding{{Role: "browser.location", Parameter: "location.hash", Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{u.Sink}}}}}
	u.DispatchFacts = &analysis.DispatchBinding{ID: "binding", EntryID: "entry", CallableID: "callable", Resolution: "resolved", Mechanism: "source_slice"}
	trace, err := c.Preview(u)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}
	answers := []map[string]any{}
	for _, q := range questionsFor(u) {
		answers = append(answers, map[string]any{"name": q.name, "type": "choice", "choice": values[q.name]})
	}
	trace.HTTPStatus = 200
	trace.Response, _ = json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
	if got := c.Replay(u, trace); got.Status != "completed" {
		t.Fatalf("identical request rejected: %+v", got)
	}
	for _, tc := range []struct {
		name   string
		change func(*analysis.CandidateUse)
	}{
		{"context identity", func(v *analysis.CandidateUse) { v.InvocationContextID = "other" }},
		{"context binding", func(v *analysis.CandidateUse) {
			ctx := *v.InvocationFacts
			ctx.Inputs = append([]analysis.InputBinding{}, ctx.Inputs...)
			ctx.Inputs[0].Role = "browser.message"
			v.InvocationFacts = &ctx
		}},
		{"entry metadata", func(v *analysis.CandidateUse) {
			e := *v.EntryFacts
			e.Browser = &analysis.BrowserEntryMetadata{Category: "event"}
			v.EntryFacts = &e
		}},
		{"dispatch resolution", func(v *analysis.CandidateUse) { b := *v.DispatchFacts; b.Resolution = "partial"; v.DispatchFacts = &b }},
		{"required role", func(v *analysis.CandidateUse) {
			completeness := *v.Completeness
			completeness.Required = append(append([]string{}, completeness.Required...), "new_role")
			v.Completeness = &completeness
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := u
			tc.change(&v)
			if got := c.Replay(v, trace); got.Status != "failed" {
				t.Fatalf("changed invocation replayed: %+v", got)
			}
		})
	}
	// A single-occurrence instance ID is not in the request (D-2), so a
	// change to it alone leaves the request, and its replay, unchanged.
	v := u
	e := *v.EntryFacts
	e.InstanceID = "other-page"
	v.EntryFacts = &e
	if got := c.Replay(v, trace); got.Status != "completed" {
		t.Fatalf("instance-only change rejected an identical request: %+v", got)
	}
}

func TestAccountCreationInvocationBindingPolicy(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"model.ts":  `import {Model,DataTypes} from 'sequelize';export class Account extends Model{};Account.init({handle:{type:DataTypes.STRING,validate:{notEmpty:true}}},{sequelize:db})`,
		"server.ts": `import express from 'express';import * as rest from 'finale-rest';import {Account} from './model';const api=express();function acceptable(value){return typeof value==='string'&&value.trim().length>0}api.post('/accounts',(req,res,next)=>{if(!acceptable(req.body.handle)){return res.status(400).send('bad')}next()});rest.resource({model:Account,endpoints:['/accounts','/accounts/:id']})`,
	}
	for name, source := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pipeline.AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "account", Method: "POST", Path: "/accounts", Kind: "account_creation", Fields: []string{"handle"}, Validation: "nonempty handle", Protection: "reject before persistence"}})
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New("openai", "fixture-model", "fixture-token")
	checked := 0
	for _, u := range r.Uses {
		if u.Kind != "account_creation_candidate" {
			continue
		}
		checked++
		if len(u.Dependencies) != 0 || len(u.Completeness.Evidence["invocation_binding"]) == 0 {
			t.Fatal("account creation lost adapter binding evidence")
		}
		trace, err := c.Preview(u)
		if err != nil {
			t.Fatal(err)
		}
		answers := []map[string]any{}
		for _, q := range questionsFor(u) {
			answers = append(answers, map[string]any{"name": q.name, "type": "choice", "choice": "sufficient"})
		}
		trace.HTTPStatus = 200
		trace.Response, _ = json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
		got := c.Replay(u, trace)
		if got.Status != "completed" || got.FindingStatus != "protected_for_claim" {
			t.Fatalf("new entry roles changed complete protected outcome: %+v", got)
		}
	}
	if checked == 0 {
		t.Fatal("account creation candidate missing")
	}
}

func TestBrowserInvocationKeepsRequestBounded(t *testing.T) {
	root := t.TempDir()
	source := "/*" + strings.Repeat("unrelated-module-context ", 4000) + "*/\ndocument.body.innerHTML=location.hash;"
	if err := os.WriteFile(filepath.Join(root, "browser.js"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := pipeline.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	c, _ := New("openai", "fixture-model", "fixture-token")
	if len(r.Uses) == 0 {
		t.Fatal("browser candidate lost")
	}
	for _, u := range r.Uses {
		trace, err := c.Preview(u)
		if err != nil {
			t.Fatal(err)
		}
		if len(trace.Request) > 64<<10 || strings.Contains(string(trace.Request), "unrelated-module-context") {
			t.Fatal("common entry projection uploaded entire unrelated module")
		}
	}
}
