package langjs

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"testing"
)

func TestTransparentWrapperDispatch(t *testing.T) {
	for _, ext := range []string{"js", "ts"} {
		for _, tt := range []struct {
			name, wrapper, importText, tail string
			transparent                     bool
		}{
			{"local arrow", `const wrap = fn => (req,res,next) => { void Promise.resolve(fn(req,res,next)).catch(next) }`, "", "", true},
			{"try forwarding", `function wrap(fn){return function(req,res,next){try{return fn(req,res,next)}catch(err){next(err)}}}`, "", "", true},
			{"try mutation", `function wrap(fn){return function(req,res,next){try{req.body={};return fn(req,res,next)}catch(err){next(err)}}}`, "", "", false},
			{"local function", `function wrap(fn) { return function(req,res,next) { return fn(req,res,next).catch(next) } }`, "", "", true},
			{"imported arrow", `export const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next)`, "import {wrap} from './wrapper';", "", true},
			{"namespace imported", `export const wrap = fn => (req,res,next) => Promise.resolve(fn(req,res,next)).catch(next)`, "import * as tools from './wrapper';", "", true},
			{"typed factory", `const wrap = (fn: (req:any,res:any,next:any)=>Promise<any>|any) => (req:any,res:any,next:any) => { void Promise.resolve(fn(req,res,next)).catch(next) }`, "", "", true},
			{"async outer", `const wrap=async fn=>(req,res,next)=>fn(req,res,next)`, "", "", false},
			{"recursive inner", `const wrap=fn=>function fn(req,res,next){return fn(req,res,next)}`, "", "", false},
			{"mutation", `const wrap=fn=>(req,res,next)=>{req.body={};return fn(req,res,next)}`, "", "", false},
			{"double call", `const wrap=fn=>(req,res,next)=>{fn(req,res,next);return fn(req,res,next)}`, "", "", false},
			{"reorder", `const wrap=fn=>(req,res,next)=>fn(res,req,next)`, "", "", false},
			{"reassigned", `let wrap=fn=>(req,res,next)=>fn(req,res,next)`, "", "wrap=other;", false},
			{"imported reassigned", `export let wrap=fn=>(req,res,next)=>fn(req,res,next);wrap=other;`, "import {wrap} from './wrapper';", "", false},
			{"mutated Promise resolve", `Promise.resolve=other;const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)`, "", "", false},
			{"shadowed Promise", `const Promise={resolve:x=>x};const wrap=fn=>(req,res,next)=>Promise.resolve(fn(req,res,next)).catch(next)`, "", "", false},
		} {
			if ext == "js" && tt.name == "typed factory" {
				continue
			}
			t.Run(ext+"/"+tt.name, func(t *testing.T) {
				root := t.TempDir()
				definition := tt.wrapper
				name := "wrap"
				if tt.importText != "" {
					writeSource(t, root, "wrapper."+ext, definition)
					definition = tt.importText
				}
				if tt.name == "namespace imported" {
					name = "tools.wrap"
				}
				source := `import express from 'express';import fs from 'fs';import {exec} from 'child_process';import * as MarsDB from 'marsdb';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');const users=new MarsDB.Collection('users');` + definition + tt.tail + `
    app.post('/x',` + name + `((req,res,next)=>{ fs.readFile(req.query.file,()=>{});exec(req.query.command);fetch(req.query.destination);db.query('SELECT '+req.query.id);users.find({name:req.body.name});console.log(req.body.password);res.send(req.query.html) }));`
				writeSource(t, root, "server."+ext, source)
				report, err := Analyze(root, "")
				if err != nil {
					t.Fatal(err)
				}
				counts := map[string]int{}
				for _, u := range report.Uses {
					counts[u.Kind]++
					if !tt.transparent {
						continue
					}
					found := false
					for _, e := range u.Context {
						found = found || e.Kind == "wrapper_definition"
					}
					if u.Kind != "input_validation_candidate" && !found {
						t.Errorf("%s lost wrapper definition", u.Kind)
					}
					gaps := append([]analysis.Gap{}, u.Gaps...)
					if u.Completeness != nil {
						gaps = append(gaps, u.Completeness.Blockers...)
					}
					for _, g := range gaps {
						if g.Kind == "unresolved_wrapper" || g.Kind == "unresolved_handler" {
							t.Errorf("transparent %s retained %s", u.Kind, g.Kind)
						}
					}
				}
				if tt.transparent {
					for _, kind := range []string{"sql_query_candidate", "nosql_query_candidate", "path_traversal_candidate", "command_execution_candidate", "ssrf_candidate", "log_sink_candidate", "xss_candidate"} {
						if counts[kind] == 0 {
							t.Errorf("missing %s: %v", kind, counts)
						}
					}
				} else {
					blocked := false
					for _, e := range report.Entries {
						for _, g := range e.Gaps {
							if g.Kind == "unresolved_wrapper" || g.Kind == "unresolved_handler" || g.Kind == "unresolved_factory" {
								blocked = true
							}
						}
					}
					if !blocked && len(report.Uses) > 0 {
						t.Errorf("unproven wrapper resolved: %v", counts)
					}
				}
			})
		}
	}
}

func TestWrappedMutableInnerKeepsDispatchUnresolved(t *testing.T) {
	for _, inner := range []string{
		`let inner=(req,res,next)=>res.send(req.query.x);inner=other;app.get('/x',wrap(inner))`,
		`const factory=async()=>(req,res,next)=>res.send(req.query.x);app.get('/x',wrap(factory()))`,
		`let factory=()=>((req,res,next)=>res.send(req.query.x));factory=other;app.get('/x',wrap(factory()))`,
	} {
		root := t.TempDir()
		writeSource(t, root, "server.ts", `import express from 'express';const app=express();const wrap=fn=>(req,res,next)=>fn(req,res,next);`+inner)
		r, e := Analyze(root, "")
		if e != nil {
			t.Fatal(e)
		}
		blocked := false
		for _, entry := range r.Entries {
			for _, gap := range entry.Gaps {
				if gap.Kind == "unresolved_handler" || gap.Kind == "unresolved_factory" {
					blocked = true
				}
			}
		}
		if !blocked && len(r.Uses) > 0 {
			t.Fatal("mutable inner handler promoted to resolved dispatch")
		}
	}
}

func TestWrappedStableNamedInnerResolves(t *testing.T) {
	for _, inner := range []string{
		`const inner=(req,res,next)=>res.send(req.query.x);app.get('/x',wrap(inner))`,
		`const factory=()=>(req,res,next)=>res.send(req.query.x);app.get('/x',wrap(factory()))`,
	} {
		root := t.TempDir()
		writeSource(t, root, "server.ts", `import express from 'express';const app=express();const wrap=fn=>(req,res,next)=>fn(req,res,next);`+inner)
		r, e := Analyze(root, "")
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, u := range r.Uses {
			if u.Kind == "xss_candidate" {
				found = true
				for _, g := range u.Gaps {
					if g.Kind == "unresolved_handler" || g.Kind == "unresolved_wrapper" {
						t.Fatal("stable named inner unresolved")
					}
				}
			}
		}
		if !found {
			t.Fatalf("stable named inner lost: %s entries=%+v", inner, r.Entries)
		}
	}
}
