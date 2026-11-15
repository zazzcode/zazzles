package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/internal/analysis"
	"strings"
	"testing"
)

func TestCommonEntryExistingConsumers(t *testing.T) {
	for _, tc := range []struct{ name, file, source string }{
		{"javascript HTTP", "app.js", `import express from 'express';const app=express();app.get('/x',(req,res)=>res.send(req.query.q));`},
		{"typescript HTTP", "app.ts", `import express from 'express';const app=express();app.get('/x',(req,res)=>res.send(req.query.q));`},
		{"Python HTTP", "app.py", "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/x')\ndef view():\n    return request.args.get('q')\n"},
		{"browser", "browser.js", `document.body.innerHTML=location.hash`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, tc.file, tc.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) == 0 || len(r.Registrations) == 0 || len(r.InvocationContexts) == 0 {
				t.Fatalf("missing common entry records: %+v", r)
			}
			if len(r.Uses) == 0 {
				t.Fatal("lost existing candidate")
			}
			for _, u := range r.Uses {
				if u.EntryID == "" || u.InvocationContextID == "" {
					t.Fatalf("unassociated candidate: %+v", u)
				}
			}
		})
	}
}

func testBrowserEntries(r *analysis.AnalysisReport) []analysis.EntryPoint {
	out := []analysis.EntryPoint{}
	for _, e := range r.Entries {
		if e.Kind == "browser" {
			out = append(out, e)
		}
	}
	return out
}

func testEntryPath(r *analysis.AnalysisReport, id string) string {
	for _, e := range r.Entries {
		if e.ID == id && e.HTTP != nil {
			return e.HTTP.Path
		}
	}
	return ""
}

func TestDispatchContextIsolation(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function guard(req,res,next){if(!verify(req.query.q)){return res.end()}next()}function shared(req,res){db.query('SELECT '+req.query.q)}app.get('/same',guard,shared);app.get('/same',shared);`)
	checks := []analysis.Check{{ID: "query", Method: "GET", Path: "/same", Kind: "sql_query", Fields: []string{"q"}, Validation: "Only source-backed requirements", Protection: "Input cannot change SQL structure"}}
	r, err := AnalyzeWithChecks(root, "", checks)
	if err != nil {
		t.Fatal(err)
	}
	var uses []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			uses = append(uses, u)
		}
	}
	if len(uses) != 2 {
		t.Fatalf("expected both registrations of shared sink, got %d", len(uses))
	}
	if uses[0].EntryID == uses[1].EntryID || uses[0].InvocationContextID == uses[1].InvocationContextID || uses[0].ID == uses[1].ID {
		t.Fatal("registrations merged their context or candidate identity")
	}
	if uses[0].DispatchFacts.CallableID != uses[1].DispatchFacts.CallableID {
		t.Fatal("same implementation acquired two callable identities")
	}
	guarded := 0
	for _, u := range uses {
		hasGuard := false
		for _, e := range u.Context {
			if e.Kind == "invoked_callable" && strings.Contains(e.Text, "verify(") {
				hasGuard = true
			}
		}
		if hasGuard {
			guarded++
			if len(u.Completeness.Blockers) == 0 {
				t.Fatal("unresolved applicable guard was treated as complete")
			}
		}
		for _, c := range u.InvocationFacts.Controls {
			if c.InvocationContextID != u.InvocationContextID {
				t.Fatal("borrowed control from sibling invocation")
			}
		}
	}
	if guarded != 1 {
		t.Fatalf("guard contaminated contexts: guarded=%d", guarded)
	}
	// A separate unresolved target stays visible without inventing a candidate or
	// changing the known unsafe witness in its own invocation scope.
	e := r.Entries[0]
	b := r.DispatchBindings[0]
	b.ID += "/unknown"
	b.CallableID = ""
	b.Resolution = "unresolved"
	b.Gaps = []analysis.Gap{{Kind: "dynamic_dispatch", At: e.Location.Span}}
	r.DispatchBindings = append(r.DispatchBindings, b)
	if err := r.Catalog().Validate(); err != nil {
		t.Fatal(err)
	}
	if len(r.Uses) != len(uses) {
		t.Fatal("unknown dispatch fabricated or erased use")
	}
}

func TestCheckContextsAndLimitsStayPerRegistration(t *testing.T) {
	for _, kind := range []string{"sql_query", "account_creation"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function g1(value){return g2(value)}function g2(value){return g3(value)}function g3(value){return g4(value)}function g4(value){return g5(value)}function g5(value){return g6(value)}function g6(value){return value}function guard(req,res,next){g1(req.query.q);next()}function shared(req,res){db.query('SELECT '+req.query.q)}app.get('/same',guard,shared);app.get('/same',shared);`)
			r, err := AnalyzeWithChecks(root, "", []analysis.Check{{ID: "check", Method: "GET", Path: "/same", Kind: kind, Fields: []string{"q"}, Validation: "source-backed", Protection: "data separation"}})
			if err != nil {
				t.Fatal(err)
			}
			uses := []analysis.CandidateUse{}
			for _, u := range r.Uses {
				if u.Kind != "input_validation_candidate" {
					uses = append(uses, u)
				}
			}
			if len(uses) != 2 {
				t.Fatalf("same-path %s exposures lost: %d", kind, len(uses))
			}
			limited := 0
			for _, u := range uses {
				hasLimit := false
				for _, g := range u.Completeness.Blockers {
					hasLimit = hasLimit || g.Kind == "helper_context_limit"
				}
				if hasLimit {
					limited++
				}
			}
			if limited != 1 {
				t.Fatalf("sibling inherited context limit: %d entries", limited)
			}
		})
	}
	t.Run("missing sink per entry", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "app.js", `import express from 'express';const app=express();function shared(req,res){res.end()}app.get('/same',shared);app.get('/same',shared);`)
		r, err := AnalyzeWithChecks(root, "", []analysis.Check{{ID: "check", Method: "GET", Path: "/same", Kind: "sql_query", Fields: []string{"q"}, Validation: "source-backed", Protection: "data separation"}})
		if err != nil {
			t.Fatal(err)
		}
		missing := 0
		ids := map[string]bool{}
		for _, u := range r.Uses {
			if u.Kind == "sql_sink_missing" {
				missing++
				ids[u.EntryID] = true
			}
		}
		if missing != 2 || len(ids) != 2 {
			t.Fatal("missing-sink checks combined exposures")
		}
	})
}

func TestOrderedHTTPForwardingContext(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function acceptable(q){return typeof q==='string'}app.get('/x',(req,res,next)=>{if(!acceptable(req.query.q)){return res.end()}next()});app.get('/x',(req,res)=>{db.query('SELECT '+req.query.q)});app.get('/x',(req,res,next)=>{later(req);next()});`)
	r, err := AnalyzeWithChecks(root, "", []analysis.Check{{ID: "query", Method: "GET", Path: "/x", Kind: "sql_query", Fields: []string{"q"}, Validation: "source-backed", Protection: "data separation"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind != "sql_query_candidate" {
			continue
		}
		prior, later := false, false
		for _, e := range u.Context {
			if e.Kind == "invoked_callable" {
				prior = prior || strings.Contains(e.Text, "acceptable(req.query.q)")
				later = later || strings.Contains(e.Text, "later(req)")
			}
		}
		if !prior || later {
			t.Fatal("source order lost supported forwarding guard or borrowed later guard")
		}
		return
	}
	t.Fatal("query candidate missing")
}

func TestCandidateIdentityDistinguishesHelperWitnesses(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.js", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function execute(value){db.query('SELECT '+value)}app.get('/x',(req,res)=>{execute(req.query.a);execute(req.query.b)});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	count := 0
	for _, u := range r.Uses {
		if u.Kind != "sql_query_candidate" {
			continue
		}
		count++
		if ids[u.ID] {
			t.Fatal("different call/input witnesses share candidate ID")
		}
		ids[u.ID] = true
	}
	if count != 2 {
		t.Fatalf("lost helper witness: %d", count)
	}
	first, _ := json.Marshal(r)
	again, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(again)
	if !bytes.Equal(first, second) {
		t.Fatal("same source snapshot emitted nondeterministic report")
	}
}

func TestHTTPAllPredecessorApplicability(t *testing.T) {
	for _, next := range []bool{true, false} {
		t.Run(fmt.Sprint(next), func(t *testing.T) {
			root := t.TempDir()
			body := `res.end()`
			if next {
				body = `if(!acceptable(req.query.q)){return res.end()}next()`
			}
			writeSource(t, root, "app.js", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function acceptable(q){return typeof q==='string'}app.all('/x',(req,res,next)=>{`+body+`});app.get('/x',(req,res)=>db.query('SELECT '+req.query.q));`)
			r, err := AnalyzeWithChecks(root, "", []analysis.Check{{ID: "query", Method: "GET", Path: "/x", Kind: "sql_query", Fields: []string{"q"}, Validation: "source-backed", Protection: "data separation"}})
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				guard, gap := false, false
				for _, e := range u.Context {
					guard = guard || (e.Kind == "invoked_callable" && strings.Contains(e.Text, "acceptable(req.query.q)"))
				}
				for _, g := range u.Completeness.Blockers {
					gap = gap || g.Kind == "prior_dispatch_unresolved"
				}
				if guard != next || gap == next {
					t.Fatalf("ALL applicability guard=%v gap=%v next=%v", guard, gap, next)
				}
				return
			}
			t.Fatal("missing query")
		})
	}
}

func TestMountedHTTPPredecessorUsesSourcePath(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.js", `const express=require('express');const app=express();const router=require('./router');app.use('/api',router);`)
	writeSource(t, root, "router.js", `const express=require('express');const {Sequelize}=require('sequelize');const db=new Sequelize('sqlite::memory:');const router=express.Router();module.exports=router;function acceptable(q){return typeof q==='string'}router.get('/x',(req,res,next)=>{if(!acceptable(req.query.q)){return res.end()}next()});router.get('/x',(req,res)=>db.query('SELECT '+req.query.q));`)
	r, err := AnalyzeWithChecks(root, "app.js", []analysis.Check{{ID: "query", Method: "GET", Path: "/api/x", Kind: "sql_query", Fields: []string{"q"}, Validation: "source-backed", Protection: "data separation"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind != "sql_query_candidate" {
			continue
		}
		found := false
		for _, e := range u.Context {
			found = found || (e.Kind == "invoked_callable" && strings.Contains(e.Text, "acceptable(req.query.q)"))
		}
		if !found {
			t.Fatal("mount path comparison omitted forwarding predecessor")
		}
		if u.EntryFacts.HTTP.SourcePath != "/x" || u.EntryFacts.HTTP.Mount != "/api" {
			t.Fatal("raw and effective mount metadata conflated")
		}
		return
	}
	t.Fatal("missing query")
}

func TestSharedExpressChain(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `
const express=require('express');
const {exec}=require('child_process');
const {Sequelize}=require('sequelize');
const db=new Sequelize('sqlite::memory:');
const app=express();
function mw(req,res,next){db.query('SELECT '+req.query.q);next()}
function final(req,res){exec('echo '+req.query.q);res.end()}
app.post('/x',mw,final);
app.post('/unknown',mystery,final);
`)
	r, err := Analyze(root, "server.js")
	if err != nil {
		t.Fatal(err)
	}
	var sql, cmd []analysis.CandidateUse
	entries := map[string]bool{}
	for _, u := range r.Uses {
		entries[u.EntryID] = true
		switch u.Kind {
		case "sql_query_candidate":
			sql = append(sql, u)
		case "command_execution_candidate":
			cmd = append(cmd, u)
		}
	}
	if len(sql) != 1 {
		t.Fatalf("middleware SQL uses=%d want 1: %+v", len(sql), sql)
	}
	// /x final + /unknown final both run exec.
	if len(cmd) != 2 {
		t.Fatalf("final command uses=%d want 2", len(cmd))
	}
	var xCmd *analysis.CandidateUse
	for i := range cmd {
		for _, e := range r.Entries {
			if e.ID == cmd[i].EntryID && e.HTTP != nil && e.HTTP.Path == "/x" {
				xCmd = &cmd[i]
			}
		}
	}
	if xCmd == nil {
		t.Fatal("missing command on /x final")
	}
	if sql[0].EntryID == xCmd.EntryID || sql[0].InvocationContextID == xCmd.InvocationContextID || sql[0].ID == xCmd.ID {
		t.Fatal("chain and final share identity")
	}
	if !entries[sql[0].EntryID] || !entries[xCmd.EntryID] {
		t.Fatal("missing entries for chain/final uses")
	}
	// Two entries for /x (final + chain sibling); mystery middleware invents no chain entry.
	xEntries := 0
	for _, e := range r.Entries {
		if e.HTTP != nil && e.HTTP.Path == "/x" {
			xEntries++
		}
	}
	if xEntries != 2 {
		t.Fatalf("/x entries=%d want 2 (final+chain)", xEntries)
	}
	unknownEntries := 0
	for _, e := range r.Entries {
		if e.HTTP != nil && e.HTTP.Path == "/unknown" {
			unknownEntries++
		}
	}
	if unknownEntries != 1 {
		t.Fatalf("/unknown entries=%d want 1 (final only; mystery unresolved)", unknownEntries)
	}
}
