package parse

import "testing"

func TestMongoosePathIDFacts(t *testing.T) {
	for _, tc := range []struct {
		name, input, before, middleware, schema, version string
		want                                             bool
	}{
		{name: "named URL parameter", input: "req.params.id", want: true},
		{name: "body can carry operators", input: "req.body.id"},
		{name: "query can carry operators", input: "req.query.id"},
		{name: "parsed URL JSON", input: "JSON.parse(req.params.id)"},
		{name: "request field overwritten", input: "req.params.id", before: "req.params.id=req.body.id;"},
		{name: "params alias", input: "req.params.id", before: "const p=req.params;p.id=req.body.id;"},
		{name: "request escapes", input: "req.params.id", before: "configure(req);"},
		{name: "request method may mutate params", input: "req.params.id", before: "req.refreshParams();"},
		{name: "middleware mutation", input: "req.params.id", middleware: "app.use((req,res,next)=>{req.params.id=req.body.id;next()});"},
		{name: "unknown middleware", input: "req.params.id", middleware: "app.use(unknown);"},
		{name: "parameter callback", input: "req.params.id", middleware: "app.param('id',(req,res,next,id)=>{req.params.id=JSON.parse(id);next()});"},
		{name: "custom string ID", input: "req.params.id", schema: "{_id:String,content:String}"},
		{name: "schema options", input: "req.params.id", schema: "{content:String},{_id:false}"},
		{name: "different version", input: "req.params.id", version: "4.2.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			if tc.schema == "" {
				tc.schema = "{content:String}"
			}
			if tc.version == "" {
				tc.version = "4.2.4"
			}
			writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"`+tc.version+`"}}`)
			writeSource(t, root, "server.js", `const express=require('express');const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema(`+tc.schema+`));const app=express();app.use(express.json());`+tc.middleware+`app.post('/update/:id',(req,res)=>{`+tc.before+`Todo.findById(`+tc.input+`,(err,todo)=>res.json(todo));});`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			got := u.APIModel != nil && u.APIModel.ID == "mongoose-path-id-objectid-v1"
			if got != tc.want {
				t.Fatalf("path ID contract=%v want %v; facts=%+v blockers=%+v", got, tc.want, u.Completeness.ModelFacts, u.Completeness.Blockers)
			}
			if tc.want && len(u.Completeness.Evidence["selector_path_string"]) == 0 {
				t.Fatal("missing source-backed path string evidence")
			}
		})
	}
}
