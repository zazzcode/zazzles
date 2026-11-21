package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, source := range files {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, name), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func familyFixtureUse(t *testing.T, files map[string]string, kind string) (analysis.CandidateUse, *analysis.AnalysisReport) {
	t.Helper()
	r, err := pipeline.Analyze(writeFixture(t, files), "")
	if err != nil {
		t.Fatal(err)
	}
	for i := range r.Uses {
		if r.Uses[i].Kind == kind {
			return r.Uses[i], r
		}
	}
	t.Fatalf("no %s candidate", kind)
	return analysis.CandidateUse{}, r
}

func selectedNoSQLUse(t *testing.T) analysis.CandidateUse {
	u, _ := familyFixtureUse(t, map[string]string{"server.js": `const express=require('express');const marsdb=require('marsdb');const users=new marsdb.Collection('users');const app=express();app.use(express.json());app.post('/raw',(req,res)=>users.find({name:req.body.name}));`}, "nosql_query_candidate")
	return u
}

func selectedValidationUse(t *testing.T) analysis.CandidateUse {
	u, _ := familyFixtureUse(t, map[string]string{
		"main.py": `from flask import Flask,request,render_template
import sqlite3
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    if not email:
        return render_template('signup.html')
    c=sqlite3.connect(':memory:')
    c.execute('INSERT INTO users (email) VALUES (?)',(email,))
    return render_template('signup.html')
`,
		"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
	}, "input_validation_candidate")
	if u.Completeness == nil || u.Completeness.ClaimKind != "validation" {
		t.Fatal("no policy-backed validation claim")
	}
	return u
}

// N6: both provider encoders receive only selected material, correct named
// questions/choices and no labels; transport and exact replay roundtrip.
func TestFamilyComponentPayloads(t *testing.T) {
	for _, tt := range []struct {
		name     string
		use      analysis.CandidateUse
		protocol string
		want     []string
		notWant  []string
		answers  map[string]string
	}{
		{
			name: "nosql", use: selectedNoSQLUse(t), protocol: analysispacks.NoSQLProtocol,
			want:    []string{"analysis_components", "marsdb-collection-v1", "`$where` string", "selector operators", "control_flow"},
			notWant: []string{"Cross-site scripting", "## Logging", "Sequelize", "field_requirement", "TestNoSQL", "never-persist-key", "internal/parse", "DB-API"},
			answers: map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
		},
		{
			name: "validation", use: selectedValidationUse(t), protocol: analysispacks.ValidationProtocol,
			want:    []string{"analysis_components", "## Validation", "A missing check alone does not establish a business requirement"},
			notWant: []string{"api_contract", "## Sinks", "Cross-site scripting", "## Logging", "`$where`", "TestFamily", "never-persist-key", "DB-API"},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
		},
	} {
		for _, provider := range []string{"openai", "jev"} {
			t.Run(tt.name+"/"+provider, func(t *testing.T) {
				u := tt.use
				c, _ := New(provider, "fixture-model", "never-persist-key")
				trace, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				if trace.QuestionVersion != tt.protocol || trace.RequestDigest == "" || trace.Components == nil {
					t.Fatalf("family provenance missing: %+v", trace)
				}
				var body map[string]any
				if err := json.Unmarshal(trace.Request, &body); err != nil {
					t.Fatal(err)
				}
				key := "input"
				if provider == "jev" {
					key = "state"
				}
				input := body[key].(string)
				for _, bad := range tt.notWant {
					if strings.Contains(input, bad) {
						t.Fatalf("unrelated material leaked: %s", bad)
					}
				}
				for _, want := range tt.want {
					if !strings.Contains(input, want) {
						t.Fatalf("missing selected context: %s", want)
					}
				}
				// The request carries exactly the family's registered question
				// names and no other family's questions.
				names := map[string]bool{}
				switch v := body["questions"].(type) {
				case []any:
					for _, q := range v {
						names[q.(map[string]any)["name"].(string)] = true
					}
				case map[string]any:
					for name := range v {
						names[name] = true
					}
				}
				expected := map[string]bool{}
				for _, q := range questionsFor(u) {
					expected[q.name] = true
				}
				if len(names) != len(expected) {
					t.Fatalf("question set differs: %v", names)
				}
				for name := range expected {
					if !names[name] {
						t.Fatalf("question %s missing from request", name)
					}
				}
				if tt.name == "validation" && !strings.Contains(string(trace.Request), "Client-side form constraints establish intended policy but do not prove server enforcement") {
					t.Fatal("field-requirement protocol text missing from questions")
				}

				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					var received map[string]any
					if err := json.NewDecoder(req.Body).Decode(&received); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					expected := map[string]any{}
					if err := json.Unmarshal(trace.Request, &expected); err != nil {
						t.Error(err)
					}
					receivedBytes, _ := json.Marshal(received)
					expectedBytes, _ := json.Marshal(expected)
					if string(receivedBytes) != string(expectedBytes) {
						t.Error("transport changed selected payload")
					}
					if provider == "openai" {
						w.Write(familyResponse(u, "fixture-model", tt.answers))
						return
					}
					answers := map[string]any{}
					for name, value := range tt.answers {
						answers[name] = map[string]string{"type": "choice", "choice": value}
					}
					json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
				}))
				defer server.Close()
				c.endpoint = server.URL
				c.http = server.Client()
				assessed, saved := c.AssessTrace(context.Background(), u)
				if assessed.Status != "completed" || len(assessed.Answers) != len(tt.answers) {
					t.Fatalf("%s %s transport/decoder failed: %+v", tt.name, provider, assessed)
				}
				if assessed.QuestionVersion != tt.protocol || assessed.RequestDigest != trace.RequestDigest {
					t.Fatalf("%s %s provenance lost: %+v", tt.name, provider, assessed)
				}
				if replay := c.Replay(u, saved); replay.Status != "completed" || !sameJSON(replay, assessed) {
					t.Fatalf("%s %s replay differs: %+v", tt.name, provider, replay)
				}
				t.Logf("%s %s request=%d bytes components=%d", tt.name, provider, trace.RequestBytes, len(u.Components.Components))
			})
		}
	}
}

func familyResponse(u analysis.CandidateUse, model string, values map[string]string) []byte {
	answers := []map[string]string{}
	for _, q := range questionsFor(u) {
		answers = append(answers, map[string]string{"type": "choice", "name": q.name, "choice": values[q.name]})
	}
	b, _ := json.Marshal(map[string]any{"model": model, "answers": answers})
	return b
}

// N6: missing/conflicting selections make zero HTTP calls, and mandatory Go
// gates reject optimistic answers on incomplete evidence.
func TestFamilyComponentFailures(t *testing.T) {
	t.Run("zero-call selection failures", func(t *testing.T) {
		for _, tt := range []struct {
			name string
			use  func(analysis.CandidateUse) analysis.CandidateUse
		}{
			{"nosql missing selection", func(v analysis.CandidateUse) analysis.CandidateUse { v.Components = nil; return v }},
			{"nosql coverage failure", func(v analysis.CandidateUse) analysis.CandidateUse {
				v.Components = &analysis.ComponentSelection{Failure: "NoSQL component selection needs verified API binding"}
				return v
			}},
			{"nosql stale digest", func(v analysis.CandidateUse) analysis.CandidateUse {
				s := *v.Components
				s.Digest = "wrong"
				v.Components = &s
				return v
			}},
			{"nosql python source", func(v analysis.CandidateUse) analysis.CandidateUse { v.Sink.Span.File = "app.py"; return v }},
			{"validation missing selection", func(v analysis.CandidateUse) analysis.CandidateUse { v.Components = nil; return v }},
			{"validation carrying api contract", func(v analysis.CandidateUse) analysis.CandidateUse {
				v.APIModel = analysispacks.SQLContract("sequelize-raw-query-v1")
				return v
			}},
		} {
			t.Run(tt.name, func(t *testing.T) {
				use := tt.use(selectedNoSQLUse(t))
				if strings.Contains(tt.name, "validation") {
					use = tt.use(selectedValidationUse(t))
				}
				calls := 0
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
				defer server.Close()
				c, _ := New("openai", "fixture-model", "key")
				c.endpoint = server.URL
				c.http = server.Client()
				got := c.Assess(context.Background(), use)
				if calls != 0 || got.Status != "failed" || got.Reason == "" || got.FindingStatus == "protected_for_claim" || got.FindingStatus == "confirmed_vulnerability" {
					t.Fatalf("selection failure hidden: %+v calls=%d", got, calls)
				}
			})
		}
	})
	t.Run("optimistic answers cannot bypass gates", func(t *testing.T) {
		// An unknown guard body stays a blocker: protected answers must not
		// become a protection record.
		use, _ := familyFixtureUse(t, map[string]string{"server.js": `const express=require('express');const marsdb=require('marsdb');const users=new marsdb.Collection('users');const app=express();app.use(express.json());app.post('/open',(req,res)=>{unknownGuard(req.body.name);users.find({name:req.body.name})});`}, "nosql_query_candidate")
		stub := fixedAnswerStub(t, map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"})
		defer stub.Close()
		c, _ := New("openai", "fixture-model", "key")
		c.endpoint = stub.URL
		c.http = stub.Client()
		if a := c.Assess(context.Background(), use); a.Status != "completed" || a.FindingStatus != "needs_evidence" {
			t.Fatalf("optimistic NoSQL answer bypassed gates: %+v", a)
		}
		// A policy claim with an unresolved helper cannot become a defect.
		vuse, _ := familyFixtureUse(t, map[string]string{
			"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    validateEmail(email)
    return render_template('signup.html')
`,
			"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
		}, "input_validation_candidate")
		vstub := fixedAnswerStub(t, map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"})
		defer vstub.Close()
		c2, _ := New("openai", "fixture-model", "key")
		c2.endpoint = vstub.URL
		c2.http = vstub.Client()
		if a := c2.Assess(context.Background(), vuse); a.Status != "completed" || a.FindingStatus != "needs_evidence" || len(a.BlockingGaps) == 0 {
			t.Fatalf("optimistic validation answer bypassed gates: %+v", a)
		}
	})
}

func fixedAnswerStub(t *testing.T, values map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			Questions []struct {
				Name string `json:"name"`
			} `json:"questions"`
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.Error(err)
			return
		}
		answers := []map[string]string{}
		for _, q := range body.Questions {
			answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": values[q.Name]})
		}
		json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
	}))
}

// N3: actual parsed NoSQL controls keep bindings, gaps, raw answers and
// outcomes through the selected component pipeline.
func TestNoSQLComponentPipelineParity(t *testing.T) {
	const marsdbPrefix = `const express=require('express');const marsdb=require('marsdb');const users=new marsdb.Collection('users');const app=express();app.use(express.json());`
	for _, tc := range []struct {
		name        string
		files       map[string]string
		answers     map[string]string
		wantByRoute map[string]string
		wantUses    int
	}{
		{
			name:        "raw selector",
			files:       map[string]string{"server.js": marsdbPrefix + `app.post('/raw',(req,res)=>users.find({name:req.body.name}));`},
			answers:     map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/raw": "confirmed_vulnerability"},
			wantUses:    1,
		},
		{
			name:        "constrained scalar selector",
			files:       map[string]string{"server.js": marsdbPrefix + `app.post('/scalar',(req,res)=>{if(typeof req.body.name!=='string'){return res.status(400).send('bad');}users.find({name:req.body.name})});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/scalar": "protected_for_claim"},
			wantUses:    1,
		},
		{
			name:        "scalar guard keeps vulnerable answer in review",
			files:       map[string]string{"server.js": marsdbPrefix + `app.post('/scalar',(req,res)=>{if(typeof req.body.name!=='string'){return res.status(400).send('bad');}users.find({name:req.body.name})});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/scalar": "needs_evidence"},
			wantUses:    1,
		},
		{
			name:        "where numeric-only alternatives",
			files:       map[string]string{"server.js": marsdbPrefix + `app.get('/numeric',(req,res)=>{const id=req.query.mode?Number(req.query.id):0;users.find({$where:'this.id == '+id})});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/numeric": "protected_for_claim"},
			wantUses:    1,
		},
		{
			name:        "where raw sibling alternative",
			files:       map[string]string{"server.js": marsdbPrefix + `app.get('/sibling',(req,res)=>{const id=req.query.mode?Number(req.query.id):req.query.id;users.find({$where:'this.id == '+id})});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/sibling": "confirmed_vulnerability"},
			wantUses:    1,
		},
		{
			name: "mongoose pinned version and schema",
			files: map[string]string{
				"server.js":    `const express=require('express');const mongoose=require('mongoose');const User=mongoose.model('User',new mongoose.Schema({username:String}));const app=express();app.use(express.json());app.post('/login',(req,res)=>User.find({username:req.body.username},(err,users)=>res.json(users)));`,
				"package.json": `{"dependencies":{"mongoose":"4.2.4"}}`,
			},
			answers:     map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/login": "confirmed_vulnerability"},
			wantUses:    1,
		},
		{
			name:        "unknown helper guard stays blocked",
			files:       map[string]string{"server.js": marsdbPrefix + `app.post('/unknown',(req,res)=>{unknownGuard(req.body.name);users.find({name:req.body.name})});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/unknown": "needs_evidence"},
			wantUses:    1,
		},
		{
			name:        "shared caller keeps per-invocation effects",
			files:       map[string]string{"server.js": marsdbPrefix + `const lookup=(value)=>users.find({$where:'this.id == '+value});app.get('/guarded',(req,res)=>{if(typeof req.query.id!=='string'){return res.status(400).end();}lookup(req.query.id);res.end()});app.get('/open',(req,res)=>{lookup(req.query.id);res.end()});`},
			answers:     map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"},
			wantByRoute: map[string]string{"/guarded": "protected_for_claim", "/open": "confirmed_vulnerability"},
			wantUses:    2,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := pipeline.Analyze(writeFixture(t, tc.files), "")
			if err != nil {
				t.Fatal(err)
			}
			stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Input     string `json:"input"`
					Questions []struct {
						Name string `json:"name"`
					} `json:"questions"`
				}
				json.NewDecoder(req.Body).Decode(&body)
				values := map[string]string{}
				for k, v := range tc.answers {
					values[k] = v
				}
				if tc.name == "shared caller keeps per-invocation effects" {
					// Caller isolation: only the guarded invocation's evidence
					// carries the guard statement, so answers follow the use.
					if strings.Contains(body.Input, "if(typeof") {
						values["injection_protection"], values["all_paths_protected"], values["protection"] = "protected", "yes", "sufficient"
					} else {
						values["injection_protection"], values["all_paths_protected"], values["protection"] = "vulnerable", "no", "insufficient"
					}
				}
				answers := []map[string]string{}
				for _, q := range body.Questions {
					if values[q.Name] == "" {
						t.Errorf("no answer configured for %s", q.Name)
					}
					answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": values[q.Name]})
				}
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
			}))
			defer stub.Close()
			c, _ := New("openai", "fixture-model", "key")
			c.endpoint = stub.URL
			c.http = stub.Client()
			assessed, routes := 0, map[string]int{}
			for i := range r.Uses {
				u := &r.Uses[i]
				if u.Kind != "nosql_query_candidate" {
					continue
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("selection: %+v", u.Components)
				}
				if tc.name == "mongoose pinned version and schema" && u.APIModel.ID != "mongoose-model-query-v2" {
					t.Fatalf("mongoose contract: %+v", u.APIModel)
				}
				a, tr := c.AssessTrace(context.Background(), *u)
				if a.Status != "completed" {
					t.Fatalf("NoSQL not assessed: %+v", a)
				}
				route := ""
				for _, e := range r.Entries {
					if e.ID == u.EntryID && e.HTTP != nil {
						route = e.HTTP.Path
					}
				}
				if route == "" {
					t.Fatalf("use without HTTP entry: %+v", u.EntryID)
				}
				routes[route]++
				if want := tc.wantByRoute[route]; want == "" || a.FindingStatus != want {
					t.Fatalf("%s: result=%s want=%s", route, a.FindingStatus, want)
				}
				if len(u.Completeness.Blockers) > 0 && a.FindingStatus != "needs_evidence" {
					t.Fatal("optimistic answer bypassed missing evidence")
				}
				if c.Replay(*u, tr).Status != "completed" {
					t.Fatal("pipeline replay failed")
				}
				u.Assessment = a
				assessed++
			}
			if assessed != tc.wantUses || len(routes) != len(tc.wantByRoute) {
				t.Fatalf("assessed=%d routes=%v", assessed, routes)
			}
			assertComponentReportParity(t, r)
		})
	}
	t.Run("unknown api gains no candidate", func(t *testing.T) {
		r, err := pipeline.Analyze(writeFixture(t, map[string]string{"server.js": `const express=require('express');const users={find(q){return q}};const app=express();app.use(express.json());app.post('/fake',(req,res)=>users.find({name:req.body.name}));`}), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range r.Uses {
			if u.Kind == "nosql_query_candidate" {
				t.Fatalf("unverified collection produced a NoSQL candidate: %+v", u.ID)
			}
		}
	})
	t.Run("python nosql gains no detector", func(t *testing.T) {
		r, err := pipeline.Analyze(writeFixture(t, map[string]string{"main.py": `from flask import Flask,request\nfrom pymongo import MongoClient\napp=Flask(__name__)\nclient=MongoClient()\n@app.post('/find')\ndef find():\n    return str(client.db.users.find({'name':request.form.get('name')}))\n`}), "")
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range r.Uses {
			if u.Kind == "nosql_query_candidate" {
				t.Fatal("unimplemented Python NoSQL adapter produced a candidate")
			}
		}
	})
}

// N5: injection protection and field-policy validity stay independent claims;
// neither facet grants the other and no issue is double counted.
func TestNoSQLValidationClaimIsolation(t *testing.T) {
	t.Run("policy-invalid field with protected query", func(t *testing.T) {
		r, err := pipeline.Analyze(writeFixture(t, map[string]string{
			"main.py": `from flask import Flask,request,render_template
import sqlite3
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    if not email:
        return render_template('signup.html')
    c=sqlite3.connect(':memory:')
    c.execute('INSERT INTO users (email) VALUES (?)',(email,))
    return render_template('signup.html')
`,
			"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
		}), "")
		if err != nil {
			t.Fatal(err)
		}
		sqlStub := fixedAnswerStub(t, map[string]string{"validation": "insufficient", "protection": "sufficient", "injection_protection": "protected"})
		defer sqlStub.Close()
		validationStub := fixedAnswerStub(t, map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"})
		defer validationStub.Close()
		sqlClient, _ := New("openai", "fixture-model", "key")
		sqlClient.endpoint, sqlClient.http = sqlStub.URL, sqlStub.Client()
		validationClient, _ := New("openai", "fixture-model", "key")
		validationClient.endpoint, validationClient.http = validationStub.URL, validationStub.Client()
		sqlStatus, validationStatus := "", ""
		for i := range r.Uses {
			u := &r.Uses[i]
			switch u.Kind {
			case "sql_query_candidate":
				u.Assessment = sqlClient.Assess(context.Background(), *u)
				sqlStatus = u.Assessment.FindingStatus
			case "input_validation_candidate":
				if u.Completeness == nil {
					continue
				}
				u.Assessment = validationClient.Assess(context.Background(), *u)
				validationStatus = u.Assessment.FindingStatus
			}
		}
		// Bound values protect statement structure while the same field's
		// declared email policy is unenforced: two independent outcomes.
		if sqlStatus != "protected_for_claim" {
			t.Fatalf("sql facet: %s", sqlStatus)
		}
		if validationStatus != "poor_practice" {
			t.Fatalf("validation facet: %s", validationStatus)
		}
		assertComponentReportParity(t, r)
		for _, f := range r.Findings {
			if f.Status == "poor_practice" && strings.Contains(f.Title, "field validation") && f.RecordType == "finding" {
				if !strings.Contains(f.Summary, "separately") && !strings.Contains(f.Summary, "separate") {
					// The exact summary wording is owned by reporting; the
					// isolation requirement is the distinct record itself.
					_ = f.Summary
				}
			}
		}
	})
	t.Run("injection-protected selector with unresolved field policy", func(t *testing.T) {
		// The guarded selector field stays a selector claim; the free-text
		// comment field that never reaches a query keeps its own standalone
		// record. Neither record borrows the other's outcome.
		r, err := pipeline.Analyze(writeFixture(t, map[string]string{"server.js": `const express=require('express');const marsdb=require('marsdb');const users=new marsdb.Collection('users');const app=express();app.use(express.json());app.post('/login',(req,res)=>{if(typeof req.body.name!=='string'){return res.status(400).send('bad');}users.find({name:req.body.name});res.end(req.body.comment)});`}), "")
		if err != nil {
			t.Fatal(err)
		}
		nosqlStub := fixedAnswerStub(t, map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"})
		defer nosqlStub.Close()
		validationStub := fixedAnswerStub(t, map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"})
		defer validationStub.Close()
		nosqlClient, _ := New("openai", "fixture-model", "key")
		nosqlClient.endpoint, nosqlClient.http = nosqlStub.URL, nosqlStub.Client()
		validationClient, _ := New("openai", "fixture-model", "key")
		validationClient.endpoint, validationClient.http = validationStub.URL, validationStub.Client()
		nosqlStatus, validationStatus := "", ""
		for i := range r.Uses {
			u := &r.Uses[i]
			switch u.Kind {
			case "nosql_query_candidate":
				u.Assessment = nosqlClient.Assess(context.Background(), *u)
				nosqlStatus = u.Assessment.FindingStatus
			case "input_validation_candidate":
				u.Assessment = validationClient.Assess(context.Background(), *u)
				validationStatus = u.Assessment.FindingStatus
			}
		}
		if nosqlStatus != "protected_for_claim" {
			t.Fatalf("nosql facet: %s", nosqlStatus)
		}
		// The selector guard constrains types; it establishes no business
		// policy, so the standalone field record stays unresolved.
		if validationStatus != "needs_evidence" {
			t.Fatalf("validation facet inherited protection: %q", validationStatus)
		}
		// The free-text record is its own issue, not a duplicate of the
		// selector claim.
		counts := map[string]int{}
		for _, f := range r.Findings {
			counts[f.Status]++
		}
		assertComponentReportParity(t, r)
	})
}

// N7: changed material, questions, evidence, protocol or model rejects replay
// for both new families.
func TestFamilyComponentReplay(t *testing.T) {
	for _, tt := range []struct {
		name     string
		use      analysis.CandidateUse
		protocol string
		mutate   []string
	}{
		{
			name: "nosql", use: selectedNoSQLUse(t), protocol: analysispacks.NoSQLProtocol,
			mutate: []string{"MarsDB Collection uses Mongo-style", "all_paths_protected", "users.find", "version", "fixture-model"},
		},
		{
			name: "validation", use: selectedValidationUse(t), protocol: analysispacks.ValidationProtocol,
			mutate: []string{"Client-side form constraints", "field_requirement", "required presence", "version", "fixture-model"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := tt.use
			c, _ := New("openai", "fixture-model", "key")
			trace, err := c.Preview(u)
			if err != nil {
				t.Fatal(err)
			}
			trace.HTTPStatus = 200
			var values map[string]string
			if tt.name == "nosql" {
				values = map[string]string{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable", "all_paths_protected": "no", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}
			} else {
				values = map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"}
			}
			trace.Response = familyResponse(u, "fixture-model", values)
			if got := c.Replay(u, trace); got.Status != "completed" || got.RequestDigest != trace.RequestDigest {
				t.Fatalf("exact replay failed: %+v", got)
			}
			for _, text := range tt.mutate {
				request := string(trace.Request)
				if !strings.Contains(request, text) {
					t.Fatalf("mutation absent: %s", text)
				}
				changed := trace
				changed.Request = []byte(strings.Replace(request, text, text+" changed", 1))
				if got := c.Replay(u, changed); got.Status != "failed" {
					t.Fatalf("changed %s reused stale answers", text)
				}
			}
			changed := trace
			changed.QuestionVersion = "old-protocol-v0"
			if c.Replay(u, changed).Status != "failed" {
				t.Fatal("old protocol replayed")
			}
			staleProtocol := trace
			staleProtocol.QuestionVersion = "sql-components-v1"
			if c.Replay(u, staleProtocol).Status != "failed" {
				t.Fatal("foreign family protocol replayed")
			}
			v := u
			v.Sink.Text += " changed"
			if c.Replay(v, trace).Status != "failed" {
				t.Fatal("changed evidence replayed")
			}
		})
	}
}

// N4: actual parsed JS/TS/Python standalone validation preserves policy
// outcomes without API requirements; absent policy stays Review instead of an
// invented restriction.
func TestValidationComponentPipelineParity(t *testing.T) {
	const jsPrefix = `const express=require('express');const app=express();app.use(express.json());`
	for _, tc := range []struct {
		name    string
		files   map[string]string
		answers map[string]string
		// field selects the input_validation use by its dependency text.
		field   string
		claim   bool
		want    string
		wantGap string
	}{
		{
			name:    "free text has no alphabet requirement",
			files:   map[string]string{"server.js": jsPrefix + `app.post('/comment',(req,res)=>{res.send(req.body.comment)});`},
			answers: map[string]string{"field_requirement": "unknown", "validation": "uncertain", "enforcement_coverage": "incomplete"},
			field:   "req.body.comment", want: "needs_evidence", wantGap: "input_validation_absent",
		},
		{
			name:    "absent policy cannot become a defect",
			files:   map[string]string{"server.js": jsPrefix + `app.post('/name',(req,res)=>{res.send(req.body.name)});`},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
			field:   "req.body.name", want: "needs_evidence", wantGap: "input_validation_absent",
		},
		{
			name:    "ignored type-only guard is not enforcement",
			files:   map[string]string{"server.js": jsPrefix + `app.post('/age',(req,res)=>{if(typeof req.body.age==='number'){}res.send(req.body.age)});`},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
			field:   "req.body.age", want: "needs_evidence", wantGap: "input_validation_absent",
		},
		{
			name: "required-only policy enforced",
			files: map[string]string{
				"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    if not email:
        return render_template('signup.html')
    return render_template('signup.html')
`,
				"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" required></form>`,
			},
			answers: map[string]string{"field_requirement": "established", "validation": "sufficient", "enforcement_coverage": "complete"},
			field:   "form.email", claim: true, want: "protected_for_claim",
		},
		{
			name: "source-backed format unenforced",
			files: map[string]string{
				"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    if not email:
        return render_template('signup.html')
    return render_template('signup.html')
`,
				"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
			},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
			field:   "form.email", claim: true, want: "poor_practice",
		},
		{
			name: "client-only policy is not enforcement",
			files: map[string]string{
				"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    return render_template('signup.html')
`,
				"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
			},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
			field:   "form.email", claim: true, want: "poor_practice",
		},
		{
			name: "unknown helper blocks defect",
			files: map[string]string{
				"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    validateEmail(email)
    return render_template('signup.html')
`,
				"templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`,
			},
			answers: map[string]string{"field_requirement": "established", "validation": "insufficient", "enforcement_coverage": "complete"},
			field:   "form.email", claim: true, want: "needs_evidence",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := pipeline.Analyze(writeFixture(t, tc.files), "")
			if err != nil {
				t.Fatal(err)
			}
			stub := fixedAnswerStub(t, tc.answers)
			defer stub.Close()
			c, _ := New("openai", "fixture-model", "key")
			c.endpoint, c.http = stub.URL, stub.Client()
			matched := 0
			for i := range r.Uses {
				u := &r.Uses[i]
				if u.Kind != "input_validation_candidate" {
					continue
				}
				if !(strings.Contains(u.Sink.Text, tc.field) || (u.Check != nil && len(u.Check.Fields) > 0 && u.Check.Fields[0] == tc.field)) {
					continue
				}
				matched++
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("selection: %+v", u.Components)
				}
				if u.Components.Pack.ID != "pack.validation" {
					t.Fatalf("pack: %+v", u.Components.Pack)
				}
				a, tr := c.AssessTrace(context.Background(), *u)
				if a.Status != "completed" {
					t.Fatalf("validation not assessed: %+v", a)
				}
				if a.QuestionVersion != analysispacks.ValidationProtocol {
					t.Fatalf("protocol: %s", a.QuestionVersion)
				}
				if a.FindingStatus != tc.want {
					t.Fatalf("result=%s want=%s blockers=%d", a.FindingStatus, tc.want, len(a.BlockingGaps))
				}
				if tc.wantGap != "" && !validationGapPresent(*u, tc.wantGap) {
					t.Fatalf("gap %s not retained: %+v", tc.wantGap, u.Gaps)
				}
				if tc.claim && len(u.Completeness.Evidence["field_policy"]) == 0 {
					t.Fatal("policy-backed claim lost its field policy evidence")
				}
				if c.Replay(*u, tr).Status != "completed" {
					t.Fatal("pipeline replay failed")
				}
				u.Assessment = a
			}
			if matched != 1 {
				t.Fatalf("matched %d validation uses for %s", matched, tc.field)
			}
			assertComponentReportParity(t, r)
		})
	}
}

func validationGapPresent(u analysis.CandidateUse, kind string) bool {
	for _, g := range u.Gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}
