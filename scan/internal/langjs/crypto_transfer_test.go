package langjs

import (
	"strings"
	"testing"
)

func TestNativeHashHexTransfer(t *testing.T) {
	for _, tc := range []struct {
		name, prefix, expression string
		known                    bool
	}{
		{"helper hex", "", "hash(req.body.password)", true},
		{"hex", "", "crypto.createHash('md5').update(req.body.password).digest('hex')", true},
		{"utf8", "", "crypto.createHash('sha256').update(req.body.password,'utf8').digest('hex')", true},
		{"raw sibling", "", "req.body.raw ? req.body.password : crypto.createHash('md5').update(req.body.password).digest('hex')", true},
		{"unknown encoding", "", "crypto.createHash('md5').update(req.body.password).digest(req.body.encoding)", false},
		{"binary encoding", "", "crypto.createHash('md5').update(req.body.password).digest('latin1')", false},
		{"mutated import", "crypto.createHash=external;", "crypto.createHash('md5').update(req.body.password).digest('hex')", false},
		{"fake import", "", "fake.createHash('md5').update(req.body.password).digest('hex')", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", `import express from 'express';import crypto from 'node:crypto';import {Sequelize} from 'sequelize';const sequelize=new Sequelize('sqlite::memory:');const hash=(data:string)=>crypto.createHash('md5').update(data).digest('hex');const app=express();app.use(express.json());`+tc.prefix+`app.post('/login',(req,res)=>{const password=`+tc.expression+`;sequelize.query("SELECT * FROM Users WHERE password='"+password+"'")});`)
			writeSource(t, root, "db.ts", `import { Sequelize } from 'sequelize';export const sequelize=new Sequelize('sqlite::memory:');`)
			r, e := Analyze(root, "")
			if e != nil {
				t.Fatal(e)
			}
			u := kindUse(t, r, "sql_query_candidate")
			found := false
			for _, d := range u.Dependencies {
				for _, e := range d.Transfers {
					if e.Kind == "native_hash_hex" {
						found = true
					}
				}
			}
			if found != tc.known {
				t.Fatalf("hex transfer=%v want%v", found, tc.known)
			}
			if u.APIModel == nil || u.APIModel.Library != "sequelize" {
				t.Fatal("SQL library binding absent")
			}
			if tc.name == "hex" || tc.name == "helper hex" {
				if len(u.Completeness.Evidence["sql_all_inputs_hex"]) == 0 {
					t.Fatal("all hex review evidence missing")
				}
			}
			if tc.name == "raw sibling" {
				if len(u.Completeness.Evidence["sql_all_inputs_hex"]) != 0 {
					t.Fatal("raw branch inherited sibling hex constraint")
				}
			}
			if tc.known && !strings.Contains(strings.Join(u.Completeness.ModelFacts, "\n"), "native_hash_hex: ") {
				t.Fatal("hex contract missing")
			}
			if tc.name == "hex" || tc.name == "utf8" {
				for _, g := range u.Completeness.Blockers {
					if g.Kind == "unknown_transfer" || g.Kind == "unknown_value" {
						t.Fatalf("native hash not modeled: %+v", g)
					}
				}
			}
		})
	}
}
