package parse

import (
	"strings"
	"testing"
)

func TestExpressQueryAdapterCompleteness(t *testing.T) {
	for _, tc := range []struct {
		name, setup, predicate, guard string
		blocked                       bool
	}{
		{"default adapters and unrelated email predicate", "", "validator.isEmail(req.body.username)", "", false},
		{"scalar password guard", "", "validator.isEmail(req.body.username)", "if(typeof req.body.password!=='string'){return res.status(400).send('bad')}", false},
		{"unknown password helper", "", "validator.isEmail(req.body.username)", "unknownGuard(req.body.password);", true},
		{"fake validator", "validator={isEmail(value){return value}};", "validator.isEmail(req.body.username)", "", true},
		{"mutated validator method", "validator.isEmail=external;", "validator.isEmail(req.body.username)", "", true},
		{"custom session store", "sessionOptions.store=customStore;", "validator.isEmail(req.body.username)", "", true},
		{"custom method getter", "methodOverride=customOverride;", "validator.isEmail(req.body.username)", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			source := `const express=require('express');const bodyParser=require('body-parser');let session=require('express-session');let methodOverride=require('method-override');const upload=require('express-fileupload');let validator=require('validator');const mongoose=require('mongoose');const User=mongoose.model('User',new mongoose.Schema({username:String,password:String}));const app=express();const sessionOptions={secret:'fixture-only',cookie:{path:'/'}};` + tc.setup + `app.use(methodOverride());app.use(session({secret:'fixture-only',cookie:{path:'/'}}));app.use(bodyParser.json());app.use(bodyParser.urlencoded({extended:false}));app.use(upload());app.post('/login',(req,res)=>{if(` + tc.predicate + `){` + tc.guard + `User.find({username:req.body.username,password:req.body.password},(err,users)=>res.json(users));}else{return res.status(400).send('bad')}});`
			if tc.name == "custom session store" {
				source = strings.Replace(source, "app.use(session({secret:'fixture-only',cookie:{path:'/'}}))", "app.use(session(sessionOptions))", 1)
			}
			writeSource(t, root, "server.js", source)
			writeSource(t, root, "package.json", `{"dependencies":{"mongoose":"4.2.4","validator":"13.5.2","express-session":"1.17.2","method-override":"3.0.0","express-fileupload":"0.0.5"}}`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			if u.APIModel == nil || u.APIModel.Library != "mongoose" {
				t.Fatal("model query binding missing")
			}
			if (len(u.Completeness.Blockers) > 0) != tc.blocked {
				t.Fatalf("blocked=%v want %v: %+v", len(u.Completeness.Blockers) > 0, tc.blocked, u.Completeness.Blockers)
			}
			if !tc.blocked {
				facts := strings.Join(u.Completeness.ModelFacts, "\n")
				if !strings.Contains(facts, "validator_is_email") || !strings.Contains(facts, "express_transport_adapters") {
					t.Fatalf("predicate contract absent: %s", facts)
				}
				if len(u.Completeness.Evidence["middleware_adapter_binding"]) < 3 {
					t.Fatal("adapter source witnesses missing")
				}
			}
		})
	}
}
