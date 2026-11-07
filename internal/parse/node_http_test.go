package parse

import (
	"strings"
	"testing"
)

func TestNodeHTTPInputs(t *testing.T) {
	for _, framework := range []string{"express", "fastify", "hapi"} {
		for _, body := range []bool{false, true} {
			t.Run(framework+map[bool]string{false: "/path", true: "/body"}[body], func(t *testing.T) {
				root := t.TempDir()
				setup, route, path, input := "", "", "/items/:id", "request.params.id"
				if body {
					input = "request.body.id"
				}
				switch framework {
				case "express":
					setup = `const express=require('express');const app=express();app.use(express.json());`
					route = `app.post('` + path + `',(request,reply)=>Todo.findById(` + input + `,(err,todo)=>reply.send(todo)));`
				case "fastify":
					setup = `const fastify=require('fastify');const app=fastify();`
					route = `app.post('` + path + `',(request,reply)=>Todo.findById(` + input + `,(err,todo)=>reply.send(todo)));`
				case "hapi":
					path = "/items/{id}"
					if body {
						input = "request.payload.id"
					}
					setup = `const Hapi=require('@hapi/hapi');const app=Hapi.server();`
					route = `app.route({method:'POST',path:'` + path + `',handler:(request,h)=>Todo.findById(` + input + `,(err,todo)=>h.response(todo))});`
				}
				writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4"}}`)
				writeSource(t, root, "server.js", `const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));`+setup+route)
				r, err := Analyze(root, "")
				if err != nil {
					t.Fatal(err)
				}
				u := kindUse(t, r, "nosql_query_candidate")
				if u.InputFacts == nil {
					t.Fatal("no shared input facts")
				}
				if err := u.InputFacts.Validate(u.Dependencies); err != nil {
					t.Fatal(err)
				}
				if u.APIModel == nil || u.APIModel.ID != "mongoose-find-by-id-objectid-v1" {
					t.Fatalf("not generic sink: %+v", u.APIModel)
				}
				if strings.Contains(u.APIModel.Semantics, "Express") || strings.Contains(u.APIModel.Semantics, "URL") {
					t.Fatal("sink contract depends on transport")
				}
				f := u.InputFacts
				if f.Framework != framework || f.Acquisition != "http" {
					t.Fatalf("source adapter=%+v", f)
				}
				if len(f.Values) != 1 {
					t.Fatalf("values=%+v", f.Values)
				}
				v := f.Values[0]
				if body {
					if v.Origin != "http.body" || v.SinkType != "unknown" {
						t.Fatalf("body inherited scalar guarantee: %+v", v)
					}
				} else if v.Origin != "http.path" || v.InitialType != "string" || v.SinkType != "string" {
					t.Fatalf("path source types=%+v gaps=%+v", v, f.Gaps)
				}
				if len(u.Completeness.Blockers) > 0 {
					t.Fatalf("unexpected blockers: %+v", u.Completeness.Blockers)
				}
			})
		}
	}
}
func TestNodeHTTPHookFacts(t *testing.T) {
	for _, tc := range []struct {
		name, setup, options string
		blocked              bool
	}{
		{"supplied hook", `app.addHook('preHandler',(request,reply,done)=>{request.params.id=request.body.id;done()});`, "", false},
		{"schema is evidence", "", `schema:{params:{type:'object',properties:{id:{type:'string'}}}}`, false},
		{"unavailable nested helper", `app.addHook('preHandler',(request,reply,done)=>{unknownGuard(request.params.id);done()});`, "", true},
		{"unavailable schema", "", `schema:{params:unknownSchema}`, true},
		{"unknown hook", `app.addHook('preHandler',external);`, "", true},
		{"plugin scope", `app.register(external);`, "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4"}}`)
			writeSource(t, root, "server.js", `const fastify=require('fastify');const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));const app=fastify();`+tc.setup+`app.get('/items/:id',{`+tc.options+`},(request,reply)=>Todo.findById(request.params.id,(err,todo)=>reply.send(todo)));`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			if u.InputFacts == nil || u.InputFacts.Values[0].SinkType != "unknown" {
				t.Fatal("hook/schema inherited raw string guarantee")
			}
			if (len(u.Completeness.Blockers) > 0) != tc.blocked {
				t.Fatalf("blockers=%+v", u.Completeness.Blockers)
			}
			if len(u.InputFacts.Controls) == 0 {
				t.Fatal("control source omitted")
			}
		})
	}
}

func TestNodeNoGETBodySource(t *testing.T) {
	for _, framework := range []string{"hapi", "fastify"} {
		t.Run(framework, func(t *testing.T) {
			root := t.TempDir()
			setup := `const fastify=require('fastify');const app=fastify();app.get('/x',(request,reply)=>Todo.findById(request.body.id));`
			if framework == "hapi" {
				setup = `const Hapi=require('@hapi/hapi');const app=Hapi.server();app.route({method:'GET',path:'/x',handler:(request,h)=>Todo.findById(request.payload.id)});`
			}
			writeSource(t, root, "server.js", `const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));`+setup)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range r.Uses {
				if u.Kind == "nosql_query_candidate" {
					t.Fatal("GET payload invented an external input")
				}
			}
		})
	}
}
func TestNodeHookRegistrationOrder(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const fastify=require('fastify');const app=fastify();const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));function validate(request,reply,done){if(typeof request.params.id!=='string')return reply.send('bad');done()};function overwrite(request,reply,done){request.params.id=request.body.id;done()};app.addHook('preHandler',overwrite);app.addHook('preHandler',validate);app.get('/x/:id',(request,reply)=>Todo.findById(request.params.id));`)
	writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4"}}`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u := kindUse(t, r, "nosql_query_candidate")
	stages := u.InputFacts.Stages
	if len(stages) != 2 || !strings.Contains(stages[0].Evidence.Text, "request.params.id=request.body.id") || !strings.Contains(stages[1].Evidence.Text, "typeof") {
		t.Fatalf("stage order follows declarations rather than registrations: %+v", stages)
	}
}

func TestNodeLateHooksRemainUncertain(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const fastify=require('fastify');const app=fastify();const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));app.get('/x/:id',(request,reply)=>Todo.findById(request.params.id));app.addHook('preHandler',(request,reply,done)=>{request.params.id=request.body.id;done()});`)
	writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4"}}`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u := kindUse(t, r, "nosql_query_candidate")
	if len(u.Completeness.Blockers) == 0 || u.InputFacts.ScalarInputs() {
		t.Fatal("late hook borrowed a complete acquisition path")
	}
}

func TestNodeRegistrationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, setup, route string
		want               int
	}{
		{"Fastify full route methods", `const fastify=require('fastify');const app=fastify();`, `app.route({method:['GET','POST'],url:'/x/:id',handler});`, 2},
		{"conflicting Fastify aliases", `const fastify=require('fastify');const app=fastify();`, `app.route({method:'GET',url:'/x/:id',path:'/other/:id',handler});`, 0},
		{"Hapi url is not path", `const Hapi=require('@hapi/hapi');const app=Hapi.server();`, `app.route({method:'GET',url:'/x/{id}',handler});`, 0},
		{"mutated registration callable", `const fastify=require('fastify');const app=fastify();app.get=unknown;`, `app.get('/x/:id',handler);`, 0},
		{"fake framework", `const app={get(){}};`, `app.get('/x/:id',handler);`, 0},
		{"deferred registration", `const fastify=require('fastify');const app=fastify();`, `function later(){app.get('/x/:id',handler)}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", tc.setup+`function handler(request,reply){reply.send('ok')};`+tc.route)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != tc.want {
				t.Fatalf("entries=%d want %d", len(r.Entries), tc.want)
			}
		})
	}
}
