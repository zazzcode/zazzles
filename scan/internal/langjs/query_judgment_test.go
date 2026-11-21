package langjs

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func TestConditionalQueryOutputConstraints(t *testing.T) {
	for _, tt := range []struct {
		name, prefix, value string
		allNumeric          bool
	}{
		{"numeric and constant", "", "req.query.mode ? Number(req.query.id) : 0", true},
		{"raw sibling", "", "req.query.mode ? Number(req.query.id) : req.query.id", false},
		{"nested numeric", "", "req.query.mode ? (req.query.other ? Number(req.query.id) : 1) : 0", true},
		{"nested raw", "", "req.query.mode ? (req.query.other ? Number(req.query.id) : req.query.id) : 0", false},
		{"shadowed conversion", "const Number=(v)=>v;", "req.query.mode ? Number(req.query.id) : 0", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", `import express from 'express';import * as MarsDB from 'marsdb';const api=express();const records=new MarsDB.Collection('x');`+tt.prefix+`api.get('/input',(req,res)=>{const id=`+tt.value+`;records.find({$where:'this.id == '+id})});`)
			r, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			u := kindUse(t, r, "nosql_query_candidate")
			facts := strings.Join(u.Completeness.ModelFacts, "\n")
			if got := strings.Contains(facts, "numeric_output_expression: "); got != tt.allNumeric {
				t.Fatalf("all numeric = %v, want %v; facts:\n%s", got, tt.allNumeric, facts)
			}
		})
	}
}

func TestAutomaticCollectionProvenance(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "data.ts", `import * as MarsDB from 'marsdb';export const records=new MarsDB.Collection('records')`)
	writeSource(t, root, "server.ts", `import express from 'express';import * as store from './data';const api=express();api.get('/lookup',(req,res)=>store.records.find({$where:'this.id == '+req.query.id}));`)
	r, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	u := kindUse(t, r, "nosql_query_candidate")
	if u.Completeness == nil || len(u.Completeness.Evidence["sink_binding"]) == 0 {
		ps, err := newParsers()
		if err != nil {
			t.Fatal(err)
		}
		set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"data.ts": true, "server.ts": true}}
		defer set.close()
		m, err := set.load("data.ts")
		if err != nil {
			t.Fatal(err)
		}
		v := topVariable(m, "records")
		if v == nil {
			t.Fatalf("no top variable: %s", m.tree.RootNode().ToSexp())
		}
		t.Fatalf("binding missing imports=%+v ctor=%s", m.imports, v.ToSexp())
	}
}

func TestAutomaticQueryEvidenceControls(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		binding      bool
		wantBlock    string
	}{
		{"raw SQL", `import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');api.post('/input',(req,res)=>db.query('SELECT * FROM x WHERE value = '+req.body.value));`, true, ""},
		{"bound SQL", `import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');api.post('/input',(req,res)=>db.query('SELECT * FROM x WHERE value = $v',{bind:{v:req.body.value}}));`, true, ""},
		{"fake query", `const db={query(v){return v}};api.post('/input',(req,res)=>db.query('SELECT '+req.body.value));`, false, ""},
		{"unknown guard", `import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');api.post('/input',(req,res)=>{externalValidate(req.body.value);db.query('SELECT '+req.body.value)});`, true, "input_helper_unresolved"},
		{"numeric NoSQL", `import * as MarsDB from 'marsdb';const records=new MarsDB.Collection('x');api.get('/input',(req,res)=>{const id=Number(req.query.id);records.find({$where:'this.id == '+id})});`, true, ""},
		{"shadowed receiver", `import * as store from './data';api.get('/input',(req,res)=>{const store={records:{find(x){return x}}};store.records.find({$where:'this.id == '+req.query.id})});`, false, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "data.ts", `import * as MarsDB from 'marsdb';export const records=new MarsDB.Collection('x');`)
			writeSource(t, root, "server.ts", `import express from 'express';const api=express();`+tt.source)
			r, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			var use *analysis.CandidateUse
			for i := range r.Uses {
				if r.Uses[i].Completeness != nil {
					use = &r.Uses[i]
					break
				}
			}
			if use == nil {
				t.Fatal("no query completeness")
			}
			c := use.Completeness
			if (len(c.Evidence["sink_binding"]) > 0) != tt.binding {
				t.Fatalf("binding=%+v", c.Evidence["sink_binding"])
			}
			if tt.wantBlock != "" && !gapKind(c.Blockers, tt.wantBlock) {
				t.Fatalf("missing blocker %s: %+v", tt.wantBlock, c.Blockers)
			}
			if tt.binding && tt.wantBlock == "" && len(c.Blockers) > 0 {
				t.Fatalf("unexpected blockers %+v", c.Blockers)
			}
			if tt.name == "bound SQL" && gapKind(use.Gaps, "query_text_interpolated") {
				t.Fatal("bound data called interpolated query")
			}
		})
	}
}
