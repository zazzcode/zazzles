package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
	reportpkg "github.com/zazzcode/zazzles/internal/report"
)

func TestEquivalenceSignatureSoundness(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	u := selectedSQLUse(t)
	v := u
	v.ID = "another-candidate"
	v.EntryID = "another-entry"
	v.InvocationContextID = "another-context"
	a, err := c.EquivalenceSignature(u)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.EquivalenceSignature(v)
	if err != nil || a != b {
		t.Fatalf("identity split: %v", err)
	}
	facts := *u.InputFacts
	facts.Controls = append([]analysis.Evidence{}, facts.Controls...)
	facts.Controls = append(facts.Controls, u.Sink)
	v.InputFacts = &facts
	b, err = c.EquivalenceSignature(v)
	if err != nil || a == b {
		t.Fatalf("input stage merged: %v", err)
	}
}

func TestScheduleDeduplicationAccounting(t *testing.T) {
	r := sqlFixture(t, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){db.query('SELECT '+req.query.id)}
app.get('/one',shared);app.get('/two',shared);app.get('/three',shared);app.get('/four',shared);app.get('/five',shared);`)
	var uses []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			uses = append(uses, u)
		}
	}
	if len(uses) != 5 {
		t.Fatalf("uses=%d", len(uses))
	}
	c, calls := commandStub(t, "openai", commandAnswers{"validation": "uncertain", "protection": "insufficient", "injection_protection": "vulnerable"})
	r.Uses = uses

	if err := c.SetLimits(Limits{}); err != nil {
		t.Fatal(err)
	}
	traces := map[string]DecisionTrace{}
	failed := c.AssessScheduled(context.Background(), r, ScheduleOptions{Limit: 1, SaveTrace: func(id string, trace DecisionTrace) error { traces[id] = trace; return nil }})
	if failed || calls.Load() != 1 {
		for _, u := range r.Uses {
			t.Logf("%s: %+v", u.ID, u.Assessment)
		}
		t.Fatalf("failed=%v calls=%d", failed, calls.Load())
	}
	if c.limiter.attempts != 1 || c.limiter.input != 11 {
		t.Fatalf("single-counted usage: %+v", c.limiter)
	}
	reportpkg.Enrich(r)
	if len(r.Findings) != 5 {
		t.Fatalf("findings=%d", len(r.Findings))
	}
	var html bytes.Buffer
	reportpkg.HTML(&html, r)
	sarif, _ := json.Marshal(reportpkg.SARIF(r))
	if strings.Count(html.String(), "Assessment derived from equivalent entry context") < 4 || !strings.Contains(string(sarif), "Assessment derived from equivalent entry context") {
		t.Fatal("missing exported provenance")
	}

	for i, u := range r.Uses {
		if u.Assessment.Status != "completed" {
			t.Fatal(u.Assessment)
		}
		if i > 0 && (u.Assessment.DeduplicatedFrom != r.Uses[0].ID || u.Assessment.Usage != nil) {
			t.Fatal("missing derivation", u.Assessment)
		}
		if got := c.Replay(u, traces[u.ID]); got.Status != "completed" || got.RequestDigest != u.Assessment.RequestDigest {
			t.Fatal("replay failed", got)
		}
	}
}

func TestEquivalentContextsKeepSecurityDifferences(t *testing.T) {
	c, _ := New("openai", "fixture-model", "offline")
	u := selectedSQLUse(t)
	before, _ := c.Preview(u)
	base, err := c.EquivalenceSignature(u)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*analysis.CandidateUse)
	}{
		{"input control", func(v *analysis.CandidateUse) {
			f := *v.InputFacts
			f.Controls = append(append([]analysis.Evidence{}, f.Controls...), v.Sink)
			v.InputFacts = &f
		}},
		{"source expression", func(v *analysis.CandidateUse) {
			v.Dependencies = append([]analysis.Dependency{}, v.Dependencies...)
			v.Dependencies[0].Source.Text = "req.params.id"
			f := *v.InputFacts
			f.Values = append([]analysis.InputValueFact{}, f.Values...)
			f.Values[0].Source = v.Dependencies[0].Source
			v.InputFacts = &f
		}},
		{"blocking gap", func(v *analysis.CandidateUse) {
			f := *v.Completeness
			f.Blockers = append(append([]analysis.Gap{}, f.Blockers...), analysis.Gap{Kind: "unknown_guard", Detail: "unresolved route-specific middleware"})
			v.Completeness = &f
		}},
		{"framework", func(v *analysis.CandidateUse) { f := *v.InputFacts; f.Framework = "fastify"; v.InputFacts = &f }},
		{"declared requirement", func(v *analysis.CandidateUse) { f := *v.Check; f.Validation = "must be an integer"; v.Check = &f }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := u
			tc.mutate(&v)
			sig, err := c.EquivalenceSignature(v)
			if err != nil || sig == base {
				t.Fatalf("difference merged or invalid: %v", err)
			}
		})
	}
	after, _ := c.Preview(u)
	if !bytes.Equal(before.Request, after.Request) || before.RequestDigest != after.RequestDigest {
		t.Fatal("signature mutated exact request")
	}
}

func TestParsedRouteControlsSplitSignatures(t *testing.T) {
	for _, tc := range []struct{ name, file, source, kind string }{
		{"middleware", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){db.query('SELECT '+req.query.id)};function auth(req,res,next){if(!req.query.token)return res.sendStatus(403);next()};app.get('/one',shared);app.get('/two',auth,shared);`, "sql_query_candidate"},

		{"route metadata branch", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){let id=req.query.id;if(req.path==='/one')id=Number(id);db.query('SELECT '+id)};app.get('/one',shared);app.get('/two',shared);`, "sql_query_candidate"},
		{"destructured route metadata", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){const {path:routePath}=req;let id=req.query.id;if(routePath==='/one')id=Number(id);db.query('SELECT '+id)};app.get('/one',shared);app.get('/two',shared);`, "sql_query_candidate"},
		{"unsupported request property", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){let id=req.query.id;if(req.customMetadata==='/one')id=Number(id);db.query('SELECT '+id)};app.get('/one',shared);app.get('/two',shared);`, "sql_query_candidate"},
		{"dollar request identifier", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared($req,res){let id=$req.query.id;if($req.customMetadata==='/one')id=Number(id);db.query('SELECT '+id)};app.get('/one',shared);app.get('/two',shared);`, "sql_query_candidate"},
		{"whole route object", "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');function shared(req,res){let id=req.query.id;if(JSON.stringify(req.route).includes('/one'))id=Number(id);db.query('SELECT '+id)};app.get('/one',shared);app.get('/two',shared);`, "sql_query_candidate"},
		{"Flask route rule", "app.py", `from flask import Flask,request
import sqlite3
app=Flask(__name__)
@app.get('/one')
@app.get('/two')
def shared():
    value=request.args.get('id')
    if str(request.url_rule)=='/one':
        value=int(value)
    return sqlite3.connect(':memory:').execute('SELECT '+str(value))
`, "sql_query_candidate"},
		{"converter", "app.py", `from flask import Flask,request
import sqlite3
app=Flask(__name__)
@app.get('/one/<int:id>')
@app.get('/two/<path:id>')
def shared(id):
    return sqlite3.connect(':memory:').execute('SELECT '+str(id))
`, "sql_query_candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sqlFixture(t, tc.file, tc.source)
			c, _ := New("openai", "fixture-model", "offline")
			signatures := map[string]bool{}
			count := 0
			for _, u := range r.Uses {
				if u.Kind != tc.kind {
					continue
				}
				count++
				s, err := c.EquivalenceSignature(u)
				if err != nil {
					t.Fatal(err)
				}
				signatures[s] = true
			}
			if count < 2 || len(signatures) < 2 {
				t.Fatalf("uses=%d signatures=%d", count, len(signatures))
			}
		})
	}
}

func BenchmarkEquivalenceSignature(b *testing.B) {
	// Reuse a small valid parsed fixture through the same helper as unit tests.
	root := b.TempDir()
	writeErr := os.WriteFile(filepath.Join(root, "server.ts"), []byte(`import express from 'express';import {Sequelize} from 'sequelize';const app=express();const db=new Sequelize('sqlite::memory:');app.get('/sql',(req,res)=>db.query('SELECT '+req.query.id));`), 0600)
	if writeErr != nil {
		b.Fatal(writeErr)
	}
	r, err := pipeline.Analyze(root, "server.ts")
	if err != nil {
		b.Fatal(err)
	}
	var u analysis.CandidateUse
	for _, v := range r.Uses {
		if v.Kind == "sql_query_candidate" {
			u = v
			break
		}
	}
	c, _ := New("openai", "fixture-model", "offline")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := c.EquivalenceSignature(u); err != nil {
			b.Fatal(err)
		}
	}
}

func TestRouteLiteralNormalizationPreservesPolicyArguments(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"app.get('/one',shared)", "app.get('<route>',shared)"},
		{"app.get('/one',acl('/one'),shared)", "app.get('/one',acl('/one'),shared)"},
		{"app.get(route,acl('/one'),shared)", "app.get(route,acl('/one'),shared)"},
		{"app.get('/one',acl(\"/one\"),shared)", "app.get('/one',acl(\"/one\"),shared)"},
		{"app.get('/<int:id>',shared)", "app.get('/<int:id>',shared)"},
	} {
		if got := normalizeRouteLiteral(tc.in, "/one", "/one"); got != tc.want {
			t.Fatalf("%s -> %s, want %s", tc.in, got, tc.want)
		}
	}
}

func TestSchedulePriorityAndObservationSlots(t *testing.T) {
	xss := xssClaim("raw")
	xss.ID = "xss"
	logging := logClaim()
	logging.ID = "logging"
	validation := selectedValidationUse(t)
	validation.ID = "validation"
	r := &analysis.AnalysisReport{Uses: []analysis.CandidateUse{
		{ID: "outbound", Kind: "outbound_http_candidate"},
		{ID: "data", Kind: "xss_data_candidate"}, validation, xss, logging,
	}}
	c, calls := commandStub(t, "openai", commandAnswers{
		"output_context": "html_text", "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable",
		"data_class": "credential", "content_exposure": "yes", "redaction": "no", "log_exposure": "vulnerable",
	})
	if !c.AssessScheduled(context.Background(), r, ScheduleOptions{Limit: 2}) {
		t.Fatal("unassessed observations must retain incomplete status")
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
	for _, u := range r.Uses {
		switch u.ID {
		case "xss", "logging":
			if u.Assessment.Status != "completed" {
				t.Fatalf("priority sink %s: %+v", u.ID, u.Assessment)
			}
		case "validation":
			if u.Assessment.Reason != "judge request limit reached" {
				t.Fatal(u.Assessment)
			}
		default:
			if u.Assessment.Status != "not_run" || strings.Contains(u.Assessment.Reason, "limit") {
				t.Fatal(u.Assessment)
			}
		}
	}
}
