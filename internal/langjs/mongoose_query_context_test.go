package langjs

import (
	"strings"
	"testing"
)

func TestMongooseQuerySchemaContext(t *testing.T) {
	for _, tc := range []struct {
		name, wire, model string
		wantSchema        bool
	}{
		{"explicit side effect registration", `require('./models');`, `const mongoose=require('mongoose');const Schema=mongoose.Schema;var User=new Schema({username:String,password:String});mongoose.model('User',User);User=mongoose.model('User');`, true},
		{"unrelated schema is not borrowed", ``, `const mongoose=require('mongoose');mongoose.model('User',new mongoose.Schema({password:String}));`, false},
		{"named import cannot borrow namespace constructor", `require('./models');`, `const mongoose=require('mongoose');import {unknown as other} from 'mongoose';mongoose.model('User',new other.Schema({password:String}));`, false},
		{"fake schema constructor", `require('./models');`, `const mongoose=require('mongoose');const Schema=external;mongoose.model('User',new Schema({password:String}));`, false},
		{"schema reassigned before registration", `require('./models');`, `const mongoose=require('mongoose');let schema=new mongoose.Schema({password:String});schema=unknown;mongoose.model('User',schema);`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "models.js", tc.model)
			writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4"}}`)
			writeSource(t, root, "server.js", tc.wire+`const express=require('express');const mongoose=require('mongoose');const User=mongoose.model('User');const app=express();app.use(express.json());app.post('/lookup',(req,res)=>{User.find({password:req.body.password},(error,users)=>res.json(users))});`)
			r, e := Analyze(root, "server.js")
			if e != nil {
				t.Fatal(e)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			if (len(u.Completeness.Evidence["model_schema"]) > 0) != tc.wantSchema {
				t.Fatalf("schema=%+v want%v", u.Completeness.Evidence["model_schema"], tc.wantSchema)
			}
			if tc.wantSchema {
				if u.APIModel.ID != "mongoose-model-query-v2" || !strings.Contains(u.APIModel.Semantics, "$ne") {
					t.Fatal("pinned query casting contract absent")
				}
				for _, role := range []string{"model_schema_registration", "model_module_binding", "model_dependency_version"} {
					if len(u.Completeness.Evidence[role]) == 0 {
						t.Errorf("source role missing %s", role)
					}
				}
			}
		})
	}
}

func TestMongooseCustomSchemaBehaviorRemainsBlocked(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "models.js", `const mongoose=require('mongoose');const schema=new mongoose.Schema({password:String});schema.pre('find',unknownQueryGuard);mongoose.model('User',schema);`)
	writeSource(t, root, "server.js", `require('./models');const express=require('express');const mongoose=require('mongoose');const User=mongoose.model('User');const app=express();app.use(express.json());app.post('/lookup',(req,res)=>User.find({password:req.body.password}));`)
	r, e := Analyze(root, "server.js")
	if e != nil {
		t.Fatal(e)
	}
	u := kindUse(t, r, "nosql_query_candidate")
	if !gapKind(u.Completeness.Blockers, "mongoose_schema_behavior_unresolved") {
		t.Fatalf("custom query hook is not complete: %+v", u.Completeness)
	}
}

func TestMongooseSchemaMutationRemainsBlocked(t *testing.T) {
	for _, hook := range []string{"schema.options=external;", "configure(schema);", "mongoose.plugin(external);"} {
		t.Run(hook, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express=require('express');const mongoose=require('mongoose');const schema=new mongoose.Schema({password:String});`+hook+`const User=mongoose.model('User',schema);const app=express();app.use(express.json());app.post('/lookup',(req,res)=>User.find({password:req.body.password}));`)
			r, e := Analyze(root, "")
			if e != nil {
				t.Fatal(e)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			if len(u.Completeness.Evidence["model_schema"]) > 0 && !gapKind(u.Completeness.Blockers, "mongoose_schema_behavior_unresolved") {
				t.Fatalf("unmodeled schema behavior not blocked: %+v", u.Completeness)
			}
		})
	}
}
