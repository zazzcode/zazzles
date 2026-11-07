package judge

import (
	"context"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeInputJudgment(t *testing.T) {
	for _, framework := range []string{"express", "fastify", "hapi"} {
		for _, scenario := range []string{"path", "body", "schema", "unknown_hook"} {
			if framework != "fastify" && (scenario == "schema" || scenario == "unknown_hook") {
				continue
			}
			t.Run(framework+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				source := `const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));`
				input := "request.params.id"
				if scenario == "body" {
					input = "request.body.id"
				}
				opts := ""
				if scenario == "schema" {
					opts = `{schema:{params:{type:'object',properties:{id:{type:'string'}}}}},`
				}
				switch framework {
				case "express":
					source += `const express=require('express');const app=express();app.use(express.json());app.get('/items/:id',(request,reply)=>Todo.findById(` + input + `,(err,todo)=>reply.send(todo)));`
				case "fastify":
					source += `const fastify=require('fastify');const app=fastify();`
					if scenario == "unknown_hook" {
						source += `app.addHook('preHandler',unknown);`
					}
					source += `app.post('/items/:id',` + opts + `(request,reply)=>Todo.findById(` + input + `,(err,todo)=>reply.send(todo)));`
				case "hapi":
					if scenario == "body" {
						input = "request.payload.id"
					}
					source += `const Hapi=require('@hapi/hapi');const app=Hapi.server();app.route({method:'POST',path:'/items/{id}',handler:(request,h)=>Todo.findById(` + input + `,(err,todo)=>h.response(todo))});`
				}
				for name, text := range map[string]string{"server.js": source, "package.json": `{"dependencies":{"mongoose":"4.2.4"}}`} {
					if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0600); err != nil {
						t.Fatal(err)
					}
				}
				r, err := parse.Analyze(root, "")
				if err != nil {
					t.Fatal(err)
				}
				var u analysis.CandidateUse
				for _, v := range r.Uses {
					if v.Kind == "nosql_query_candidate" {
						u = v
					}
				}
				if u.InputFacts == nil || u.APIModel.ID != "mongoose-find-by-id-objectid-v1" {
					t.Fatal("missing common facts/contract")
				}
				answers := map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}
				want := "protected_for_claim"
				if scenario == "body" {
					answers["injection_protection"] = "vulnerable"
					answers["all_paths_protected"] = "no"
					want = "confirmed_vulnerability"
				}
				if scenario == "unknown_hook" {
					want = "needs_evidence"
				}
				stub := fixedAnswerStub(t, answers)
				defer stub.Close()
				c, _ := New("openai", "fixture-model", "key")
				c.UseEndpoint(stub.URL, stub.Client())
				a, tr := c.AssessTrace(context.Background(), u)
				if a.FindingStatus != want {
					t.Fatalf("want %s got %+v", want, a)
				}
				if a.Status == "completed" && c.Replay(u, tr).FindingStatus != want {
					t.Fatal("replay drift")
				}
				p, err := c.Preview(u)
				if err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(string(p.Request), "source.node-input-v1") || !strings.Contains(string(p.Request), "initial_type") {
					t.Fatal("selected source/type interpretation missing")
				}
				changed := u
				copyFacts := *u.InputFacts
				changed.InputFacts = &copyFacts
				copyFacts.Acquisition = "message"
				if c.Replay(changed, tr).Status == "completed" {
					t.Fatal("changed acquisition facts reused old response")
				}
			})
		}
	}
}

func TestNodeOptionsAreNotValueControls(t *testing.T) {
	root := t.TempDir()
	for name, text := range map[string]string{"package.json": `{"dependencies":{"mongoose":"4.2.4"}}`, "server.js": `const fastify=require('fastify');const app=fastify();const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));app.post('/x',{logLevel:'info'},(request,reply)=>Todo.findById(request.body.id));`} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := parse.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind != "nosql_query_candidate" {
			continue
		}
		answers := map[string]string{"validation": "uncertain", "protection": "sufficient", "injection_protection": "protected", "all_paths_protected": "yes", "source_coverage": "yes", "library_coverage": "yes", "guard_coverage": "yes", "path_coverage": "yes"}
		stub := fixedAnswerStub(t, answers)
		defer stub.Close()
		c, _ := New("openai", "fixture-model", "key")
		c.UseEndpoint(stub.URL, stub.Client())
		a := c.Assess(context.Background(), u)
		if a.FindingStatus != "needs_evidence" {
			t.Fatalf("non-enforcing options permitted protection: %+v", a)
		}
		return
	}
	t.Fatal("query candidate absent")
}
