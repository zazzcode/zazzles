package langjs

import "testing"

func TestMountedCommonJSRoutesRetainValidationAndNoSQLResults(t *testing.T) {
	for _, entry := range []string{"app.js", ""} {
		t.Run("entry="+entry, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const app=express();const users=require('./users');app.use('/users',users)")
			writeSource(t, root, "users.js", "const express=require('express');const mongoose=require('mongoose');const User=mongoose.model('User');const router=express.Router();module.exports=router;router.post('/login',(req,res)=>{User.find({password:req.body.password},function(err,users){res.json(users)})});router.post('/',(req,res)=>{const role=req.body.role;res.json({role})})")
			r, err := Analyze(root, entry)
			if err != nil {
				t.Fatal(err)
			}
			paths := map[string]string{}
			for _, e := range r.Entries {
				if e.HTTPRoute().PathPattern == "/login" {
					t.Fatal("mounted router also reported as an unmounted root")
				}
				paths[e.HTTPRoute().ID] = e.HTTPRoute().PathPattern
			}
			nosql, validation := false, false
			for _, use := range r.Uses {
				if use.Kind == "nosql_query_candidate" && paths[use.EntryID] == "/users/login" {
					nosql = use.APIModel != nil && use.APIModel.Library == "mongoose"
				}
				validation = validation || (use.Kind == "input_validation_candidate" && paths[use.EntryID] == "/users")
			}
			if !nosql || !validation {
				t.Fatalf("missing NoSQL=%v validation=%v", nosql, validation)
			}
		})
	}
}
