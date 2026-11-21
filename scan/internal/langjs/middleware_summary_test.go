package langjs

import (
	"strings"
	"testing"
)

func TestMiddlewareSummaryRequiresClosedForwardingGrammar(t *testing.T) {
	for _, tt := range []struct {
		name, body string
		summary    bool
	}{
		{"headers and next", `res.setHeader('x-test','yes');next()`, true},
		{"next only", `next()`, true},
		{"request write", `req.body.name='fixed';next()`, false},
		{"request mutation helper", `change(req.body);next()`, false},
		{"authorization", `if(!req.user)return res.status(401).end();next()`, false},
		{"dynamic header", `res.setHeader('x-user',req.body.name);next()`, false},
		{"next error", `next(new Error('blocked'))`, false},
		{"double next", `next();next()`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", `import express from 'express';import * as MarsDB from 'marsdb';const app=express();const users=new MarsDB.Collection('users');app.use((req,res,next)=>{`+tt.body+`});app.post('/x',(req,res)=>{users.find({name:req.body.name})});`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range report.Uses {
				if u.Kind != "nosql_query_candidate" {
					continue
				}
				for _, e := range u.Context {
					if e.Kind == "middleware_summary" {
						found = true
						if tt.name == "headers and next" && !strings.Contains(e.ModelText, `res.setHeader('x-test','yes')`) {
							t.Fatal("header names or values lost")
						}
						if e.Text == e.ModelText || e.ModelText == "" {
							t.Fatal("summary lost source provenance")
						}
					}
				}
			}
			if found != tt.summary {
				t.Fatalf("summary=%v want %v", found, tt.summary)
			}
		})
	}
}

func TestReassignedMiddlewareNeverSummarized(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import * as MarsDB from 'marsdb';const app=express();const users=new MarsDB.Collection('users');let headers=(req,res,next)=>{next()};headers=(req,res,next)=>{req.body.name='safe';next()};app.use(headers);app.post('/x',(req,res)=>{users.find({name:req.body.name})});`)
	r, e := Analyze(root, "")
	if e != nil {
		t.Fatal(e)
	}
	for _, u := range r.Uses {
		for _, e := range u.Context {
			if e.Kind == "middleware_summary" {
				t.Fatal("reassigned middleware was summarized")
			}
		}
	}
}

func TestStableNamedMiddlewareSummary(t *testing.T) {
	for _, imported := range []bool{false, true} {
		root := t.TempDir()
		decl := `function headers(req,res,next){res.setHeader('Content-Type','text/plain');next()}`
		if imported {
			writeSource(t, root, "headers.ts", "export "+decl)
			decl = `import {headers} from './headers';`
		}
		writeSource(t, root, "server.ts", `import express from 'express';import * as MarsDB from 'marsdb';const app=express();const users=new MarsDB.Collection('users');`+decl+`app.use(headers);app.post('/x',(req,res)=>{users.find({name:req.body.name})});`)
		r, e := Analyze(root, "")
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, u := range r.Uses {
			for _, e := range u.Context {
				if e.Kind == "middleware_summary" {
					found = true
					if !strings.Contains(e.ModelText, "Content-Type") || !strings.Contains(e.ModelText, "text/plain") {
						t.Fatal("lost header meaning")
					}
				}
			}
		}
		if !found {
			t.Fatal("stable named middleware not summarized")
		}
	}
}
