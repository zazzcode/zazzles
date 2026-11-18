package parse

import (
	"strings"
	"testing"
)

func TestBrowserFetchMethodIsolation(t *testing.T) {
	for _, tt := range []struct {
		name, options, method string
		resolved              bool
	}{
		{"default", "", "GET", true}, {"undefined options", ", undefined", "GET", true}, {"empty", ", {}", "GET", true},
		{"post", ", {method:'post'}", "POST", true},
		{"get", ", {method:'GET'}", "GET", true},
		{"dynamic", ", {method:verb}", "", false},
		{"alias", ", opts", "", false},
		{"spread", ", {...opts, method:'POST'}", "", false},
		{"overwrite", ", {method:'POST', method:'GET'}", "", false},
		{"computed", ", {['method']:'POST'}", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `import express from 'express';const app=express();app.get('/item',(req,res)=>res.json({name:req.query.get}));app.post('/item',(req,res)=>res.json({name:String(req.body.post).replace(/[^\w-]+/g,'')}));`)
			writeSource(t, root, "client.js", `fetch('/item'`+tt.options+`).then(r=>r.json()).then(r=>{document.getElementById('out').innerHTML=r.name;});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range xssUses(r) {
				if u.XSS.Type != "cross_tier" {
					continue
				}
				found = true
				if u.XSS.ResponseMethod != tt.method || u.XSS.OriginResolved != tt.resolved {
					t.Fatalf("want %q resolved=%v, got %+v", tt.method, tt.resolved, u.XSS)
				}
				if tt.resolved {
					wantProtection, wantSource := "raw", "req.query.get"
					if tt.method == "POST" {
						wantProtection, wantSource = "sanitized", "req.body.post"
					}
					if u.XSS.Protection != wantProtection || len(u.Dependencies) == 0 || !strings.Contains(u.Dependencies[0].Source.Text, wantSource) {
						t.Fatalf("wrong origin/protection: %+v %+v", u.XSS, u.Dependencies)
					}
					if len(u.XSS.RelatedEntries) != 1 {
						t.Fatalf("origins: %+v", u.XSS)
					}
					for _, e := range r.Entries {
						if e.ID == u.XSS.RelatedEntries[0] && e.HTTP.Method != tt.method {
							t.Fatalf("borrowed method: %+v", e)
						}
					}
				} else {
					if len(u.XSS.RelatedEntries) != 0 {
						t.Fatal("guessed origin")
					}
					hit := false
					for _, g := range u.Gaps {
						hit = hit || g.Kind == "response_method_unresolved"
					}
					if !hit {
						t.Fatal("missing method gap")
					}
				}
			}
			if !found {
				t.Fatal("no independent rendering record")
			}
		})
	}
}

func TestBrowserFetchRequestObjectRetainsGap(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express=require('express');const app=express();app.get('/item',(req,res)=>res.json({name:req.query.q}));`)
	writeSource(t, root, "client.js", `fetch(new Request('/item',{method:'POST'})).then(r=>r.json()).then(r=>{document.body.innerHTML=r.name})`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := xssUses(r)
	if len(uses) != 1 || uses[0].XSS.OriginResolved || uses[0].XSS.ResponseMethod != "" || len(uses[0].XSS.RelatedEntries) != 0 {
		t.Fatalf("Request object borrowed producer: %+v", uses)
	}
	hit := false
	for _, g := range uses[0].Gaps {
		hit = hit || g.Kind == "response_method_unresolved"
	}
	if !hit {
		t.Fatal("missing method provenance gap")
	}
}
