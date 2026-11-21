package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func TestMongooseQueryProtectionControls(t *testing.T) {
	for _, tc := range []struct {
		name, guard, want string
		protected         bool
	}{
		{"operator object accepted", "", "confirmed_vulnerability", false},
		{"scalar-only selector", "if(typeof req.body.password!=='string'){return res.status(400).send('bad')}", "protected_for_claim", true},
		{"scalar guard cannot accept unsupported vulnerable answer", "if(typeof req.body.password!=='string'){return res.status(400).send('bad')}", "needs_evidence", false},
		{"unknown guard cannot inherit protected answer", "unknownGuard(req.body.password);", "needs_evidence", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			src := `const express=require('express');const validator=require('validator');const mongoose=require('mongoose');const User=mongoose.model('User',new mongoose.Schema({username:String,password:String}));const app=express();app.use(express.json());app.post('/login',(req,res)=>{if(validator.isEmail(req.body.username)){` + tc.guard + `User.find({username:req.body.username,password:req.body.password},(err,users)=>res.json(users));}});`
			if e := os.WriteFile(filepath.Join(root, "server.js"), []byte(src), 0600); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"dependencies":{"mongoose":"4.2.4"}}`), 0600); e != nil {
				t.Fatal(e)
			}
			r, e := pipeline.Analyze(root, "")
			if e != nil {
				t.Fatal(e)
			}
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Questions []struct {
						Name string `json:"name"`
					} `json:"questions"`
				}
				if e := json.NewDecoder(req.Body).Decode(&body); e != nil {
					t.Error(e)
					return
				}
				values := map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}
				if tc.protected {
					values["protection"] = "sufficient"
					values["injection_protection"] = "protected"
					values["all_paths_protected"] = "yes"
				}
				answers := []map[string]string{}
				for _, q := range body.Questions {
					answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": values[q.Name]})
				}
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
			}))
			defer stub.Close()
			c, e := New("openai", "fixture-model", "synthetic-test-key")
			if e != nil {
				t.Fatal(e)
			}
			c.endpoint = stub.URL
			c.http = stub.Client()
			checked := 0
			for _, u := range r.Uses {
				if u.Kind != "nosql_query_candidate" {
					continue
				}
				checked++
				a, tr := c.AssessTrace(context.Background(), u)
				if a.Status != "completed" || a.FindingStatus != tc.want {
					t.Fatalf("want%s got%+v", tc.want, a)
				}
				if c.Replay(u, tr).FindingStatus != tc.want {
					t.Fatal("exact replay changed policy")
				}
			}
			if checked != 1 {
				t.Fatalf("queries=%d", checked)
			}
		})
	}
}

func TestSQLHexConstraintContradiction(t *testing.T) {
	for _, tc := range []struct{ name, expr, want string }{
		{"hex only", `hash(req.body.email)`, "needs_evidence"},
		{"raw sibling", `req.body.raw ? req.body.email : hash(req.body.email)`, "confirmed_vulnerability"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source := `import express from 'express';import crypto from 'node:crypto';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const hash=(data:string)=>crypto.createHash('md5').update(data).digest('hex');const app=express();app.use(express.json());app.post('/lookup',(req,res)=>{db.query("SELECT * FROM Users WHERE email='"+` + tc.expr + `+"'")});`
			if e := os.WriteFile(filepath.Join(root, "server.ts"), []byte(source), 0600); e != nil {
				t.Fatal(e)
			}
			r, e := pipeline.Analyze(root, "")
			if e != nil {
				t.Fatal(e)
			}
			checked := 0
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				checked++
				a := analysis.Assessment{Status: "completed", Answers: map[string]string{"injection_protection": "vulnerable", "protection": "insufficient"}}
				applyPolicy(u, &a)
				if a.FindingStatus != tc.want {
					t.Fatalf("want%s got%+v", tc.want, a)
				}
				if tc.name == "hex only" && (len(a.BlockingGaps) == 0 || a.BlockingGaps[0].Kind != "injection_constraint_review") {
					t.Fatal("contradiction is not explicit")
				}
			}
			if checked != 1 {
				t.Fatalf("queries=%d", checked)
			}
		})
	}
}
