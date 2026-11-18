package langjs

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestCheckedRouteContext(t *testing.T) {
	for _, variant := range []struct {
		name, guard, model string
		unknown            bool
	}{
		{"vulnerable", `if(req.body.repeat!==undefined){if(req.body.handle.length===0){res.status(400).send('bad')}}next()`, `handle:{type:DataTypes.STRING}`, false},
		{"protected", `if(!acceptable(req.body.handle)){return res.status(400).send('bad')}next()`, `handle:{type:DataTypes.STRING,validate:{notEmpty:true}}`, false},
		{"unknown", `unknownGuard(req);next()`, `handle:{type:DataTypes.STRING}`, true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "model.ts", `import {Model,DataTypes} from 'sequelize';export class Account extends Model{};Account.init({`+variant.model+`},{sequelize:db})`)
			writeSource(t, root, "middleware.ts", `export const audit=()=> (req,res,next)=>next()`)
			writeSource(t, root, "server.ts", `import express from 'express';import * as rest from 'finale-rest';import {Account} from './model';import * as audit from './middleware';const api=express();function acceptable(value){return typeof value==='string'&&value.trim().length>0}api.post('/accounts',(req,res,next)=>{`+variant.guard+`});api.post('/accounts',audit.audit());const tables=[{name:'Account',model:Account}];for(const {name,model} of tables){rest.resource({model,endpoints:[`+"`/api/${name}s`"+`, '/unused']})}rest.resource({model:Account,endpoints:['/accounts','/accounts/:id']})`)
			check := analysis.Check{ID: "account", Method: "POST", Path: "/accounts", Kind: "account_creation", Fields: []string{"handle"}, Validation: "handle must be a nonempty string", Protection: "reject invalid handles before persistence"}
			report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{check})
			if err != nil {
				t.Fatal(err)
			}
			use := kindUse(t, report, "account_creation_candidate")
			if len(use.Completeness.Evidence["model_constraints"]) == 0 || len(use.Completeness.Evidence["persistence_mapping"]) == 0 || len(use.ControlEdges) == 0 {
				t.Fatalf("incomplete route/model/control context: %+v", use.Completeness)
			}
			found := false
			for _, g := range use.Completeness.Blockers {
				if g.Kind == "input_helper_unresolved" {
					found = true
				}
			}
			if found != variant.unknown {
				t.Fatalf("unknown guard blocker=%v want %v", found, variant.unknown)
			}
			encoded, _ := json.Marshal(use.Context)
			if variant.name == "protected" && (!strings.Contains(string(encoded), "acceptable") || !strings.Contains(string(encoded), "notEmpty")) {
				t.Fatal("custom guard/model protection omitted")
			}
		})
	}
}

func TestSQLClaimBindingAndUnrelatedGaps(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const api=express();api.post('/session',(req,res)=>{db.query(`+"`SELECT '${req.body.handle}'`"+`,{model:UnknownResult})})`)
	check := analysis.Check{ID: "sql", Method: "POST", Path: "/session", Kind: "sql_query", Fields: []string{"handle"}, Validation: "valid handle", Protection: "handle cannot change SQL syntax"}
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{check})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 {
		t.Fatalf("uses=%d", len(report.Uses))
	}
	c := report.Uses[0].Completeness
	binding, _ := json.Marshal(c.Evidence["sink_binding"])
	if !strings.Contains(string(binding), "import {Sequelize} from 'sequelize'") || !strings.Contains(string(binding), "db=new Sequelize") {
		t.Fatal("verified library import/receiver assignment omitted from judge evidence")
	}
	if len(c.Evidence["sink_binding"]) == 0 || len(c.Blockers) != 0 || len(c.Coverage) == 0 {
		t.Fatalf("claim completeness=%+v", c)
	}
}

func TestUnknownMiddlewareBlocksCheckedClaim(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';const api=express();api.use(unknownGuard());api.post('/x',(req,res)=>db.query(req.body.handle))`)
	c := analysis.Check{ID: "x", Method: "POST", Path: "/x", Kind: "sql_query", Fields: []string{"handle"}}
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{c})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 || len(report.Uses[0].Completeness.Blockers) == 0 {
		t.Fatal("unknown applicable guard was ignored")
	}
}

func TestMethodSpecificChecks(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';const api=express();api.get('/same',(req,res)=>db.query(req.query.handle));api.post('/same',(req,res)=>db.query(req.body.handle))`)
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "post", Method: "POST", Path: "/same", Kind: "sql_query", Fields: []string{"handle"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 || !strings.Contains(report.Uses[0].Sink.Text, "req.body") {
		t.Fatalf("method filtering failed: %+v", report.Uses)
	}
}

func TestRelevantHelperBounds(t *testing.T) {
	for _, tt := range []struct {
		name, call string
		limited    bool
	}{{"unrelated bookkeeping", "bookkeeping()", false}, {"checked-input chain", "level1(req.body.handle)", true}} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "model.ts", `export class Account{};`)
			writeSource(t, root, "server.ts", `import express from 'express';import * as rest from 'finale-rest';import {Account} from './model';const api=express();function bookkeeping(){level1('constant')}function level1(v){level2(v)}function level2(v){level3(v)}function level3(v){level4(v)}function level4(v){return v}api.post('/accounts',(req,res,next)=>{`+tt.call+`;next()});rest.resource({model:Account,endpoints:['/accounts','/accounts/:id']})`)
			c := analysis.Check{ID: "bounded", Method: "POST", Path: "/accounts", Kind: "account_creation", Fields: []string{"handle"}}
			report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{c})
			if err != nil {
				t.Fatal(err)
			}
			use := kindUse(t, report, "account_creation_candidate")
			limited := false
			for _, g := range use.Completeness.Blockers {
				if g.Kind == "helper_context_limit" {
					limited = true
				}
			}
			if limited != tt.limited {
				t.Fatalf("helper limit=%v want=%v", limited, tt.limited)
			}
		})
	}
}

func TestCheckedEvidenceGolden(t *testing.T) {
	const root = "testdata/string-flow"
	c := analysis.Check{ID: "login-input", Method: "POST", Path: "/login", Kind: "sql_query", Fields: []string{"email"}, Validation: "email must be a valid string", Protection: "separate data from SQL structure"}
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{c})
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	const file = root + "/checked-analysis.json"
	if *update {
		if err := os.WriteFile(file, data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, want) {
		t.Fatalf("checked evidence differs; use -update and review diff")
	}
}

func TestShadowedValidationHelperRemainsUnknown(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "model.ts", `export class Account{}`)
	writeSource(t, root, "server.ts", `import express from 'express';import * as rest from 'finale-rest';import {Account} from './model';const api=express();function validate(v){return true}api.post('/accounts',(req,res,next)=>{const validate=unknown;validate(req);next()});rest.resource({model:Account,endpoints:['/accounts','/accounts/:id']})`)
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "account", Method: "POST", Path: "/accounts", Kind: "account_creation", Fields: []string{"handle"}}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range report.Uses[0].Completeness.Blockers {
		if g.Kind == "input_helper_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatal("shadowed helper was resolved to an unrelated definition")
	}
}

func TestUnreturnedSequelizeDoesNotBindSink(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';function make(){const unused=new Sequelize('sqlite::memory:');return fake}const db=make();const api=express();api.post('/x',(req,res)=>db.query(req.body.handle))`)
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "x", Method: "POST", Path: "/x", Kind: "sql_query", Fields: []string{"handle"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 || len(report.Uses[0].Completeness.Evidence["sink_binding"]) != 0 {
		t.Fatal("unreturned constructor was used as binding proof")
	}
}

func TestWildcardMiddlewareCannotBeSilentlyIgnored(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';const api=express();api.use('*',guard());api.post('/x',(req,res)=>db.query(req.body.handle))`)
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "x", Method: "POST", Path: "/x", Kind: "sql_query", Fields: []string{"handle"}}})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, g := range report.Uses[0].Completeness.Blockers {
		if g.Kind == "middleware_mount_unresolved" {
			found = true
		}
	}
	if !found {
		t.Fatal("unknown wildcard guard applicability was ignored")
	}
}

func TestConciseSQLHandlerHasCompleteLocalControl(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const api=express();api.post('/x',(req,res)=>db.query('SELECT $handle',{bind:{handle:req.body.handle}}))`)
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{{ID: "x", Method: "POST", Path: "/x", Kind: "sql_query", Fields: []string{"handle"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 || len(report.Uses[0].Completeness.Blockers) != 0 {
		t.Fatalf("implicit-return handler acquired a false control gap: %+v", report.Uses)
	}
}

func TestHelperSQLDiscovery(t *testing.T) {
	corpus := filepath.Join("..", "..", ".zazz", "evaluation", "transfer-corpus")
	sql := analysis.Check{ID: "query-structure", Method: "POST", Path: "/session", Kind: "sql_query", Fields: []string{"handle"}, Validation: "nonempty", Protection: "request input must not change SQL structure"}
	t.Run("case09 same-file", func(t *testing.T) {
		use := oneSQL(t, checkedDir(t, filepath.Join(corpus, "case09")))
		if use.Sink.Span.File != "server.ts" || !strings.Contains(use.Sink.Text, "SELECT") {
			t.Fatalf("sink=%+v", use.Sink)
		}
		assertParameter(t, use, "server.ts", "value")
		if len(use.Completeness.Evidence["input_source"]) == 0 {
			t.Fatal("request field did not reach the helper sink")
		}
	})
	t.Run("case10 imported", func(t *testing.T) {
		use := oneSQL(t, checkedDir(t, filepath.Join(corpus, "case10")))
		if use.Sink.Span.File != "store.ts" || !strings.Contains(use.Sink.Text, "SELECT") {
			t.Fatalf("sink=%+v", use.Sink)
		}
		assertParameter(t, use, "store.ts", "value")
		if !evidenceKind(use.Context, "helper_call") {
			t.Fatal("imported call site missing")
		}
	})
	t.Run("case12 bound import", func(t *testing.T) {
		use := oneSQL(t, checkedDir(t, filepath.Join(corpus, "case12")))
		if use.Sink.Span.File != "store.ts" || !strings.Contains(use.Sink.Text, "bind") {
			t.Fatalf("sink=%+v", use.Sink)
		}
		assertParameter(t, use, "store.ts", "value")
		binding, _ := json.Marshal(use.Completeness.Evidence["sink_binding"])
		if !strings.Contains(string(binding), "Sequelize") {
			t.Fatalf("binding=%s", binding)
		}
	})
	t.Run("returned operand", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function sqlFor(value){return `SELECT '${value}'`}api.post('/session',(req,res)=>database.query(sqlFor(req.body.handle)))")
		use := oneSQL(t, mustChecked(t, root, sql))
		if !strings.Contains(use.Sink.Text, "database.query") {
			t.Fatalf("sink=%+v", use.Sink)
		}
		assertParameter(t, use, "server.ts", "value")
		if !transferKind(use, "return_value", "SELECT") {
			t.Fatalf("return witness missing: %+v", use.Dependencies)
		}
	})
	t.Run("missing sink", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function lookup(value){return String(value)}api.post('/session',(req,res)=>res.send(lookup(req.body.handle)))")
		report := mustChecked(t, root, sql)
		use := kindUse(t, report, "sql_sink_missing")
		if !gapKind(use.Completeness.Blockers, "sql_sink_missing") {
			t.Fatalf("uses=%+v", report.Uses)
		}
	})
	t.Run("recursion stops", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function loop(value){return loop(value)}api.post('/session',(req,res)=>database.query(loop(req.body.handle)))")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Uses) != 1 || !gapKind(report.Uses[0].Gaps, "recursive_helper") {
			t.Fatalf("uses=%+v entries=%+v", report.Uses, report.Entries)
		}
	})
	t.Run("three nested helpers", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function d2(v){return database.query(`SELECT '${v}'`)}function d1(v){return d2(v)}function d0(v){return d1(v)}api.post('/session',(req,res)=>d0(req.body.handle))")
		use := oneSQL(t, mustChecked(t, root, sql))
		assertParameter(t, use, "server.ts", "v")
	})
	t.Run("fourth helper is a limit", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function d3(v){return database.query(`SELECT '${v}'`)}function d2(v){return d3(v)}function d1(v){return d2(v)}function d0(v){return d1(v)}api.post('/session',(req,res)=>d0(req.body.handle))")
		report := mustChecked(t, root, sql)
		use := kindUse(t, report, "sql_sink_missing")
		if !gapKind(use.Completeness.Blockers, "sql_sink_missing") || !gapKind(use.Completeness.Blockers, "helper_call_limit") {
			t.Fatalf("blockers=%+v", use.Completeness.Blockers)
		}
	})
}

func checkedDir(t *testing.T, dir string) *analysis.AnalysisReport {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "checks.json"))
	if err != nil {
		t.Fatal(err)
	}
	var checks []analysis.Check
	if err := json.Unmarshal(raw, &checks); err != nil {
		t.Fatal(err)
	}
	report, err := AnalyzeWithChecks(dir, "server.ts", checks)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func mustChecked(t *testing.T, root string, check analysis.Check) *analysis.AnalysisReport {
	t.Helper()
	report, err := AnalyzeWithChecks(root, "server.ts", []analysis.Check{check})
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func oneSQL(t *testing.T, report *analysis.AnalysisReport) analysis.CandidateUse {
	t.Helper()
	if len(report.Uses) != 1 || report.Uses[0].Kind != "sql_query_candidate" {
		t.Fatalf("uses=%+v", report.Uses)
	}
	return report.Uses[0]
}

func assertParameter(t *testing.T, use analysis.CandidateUse, file, name string) {
	t.Helper()
	source, param := false, false
	for _, d := range use.Dependencies {
		if d.Source.Kind == "input_source" && strings.HasSuffix(d.Source.Text, ".body.handle") {
			source = true
		}
		for _, e := range d.Transfers {
			if e.Kind == "parameter_binding" && e.Text == name && e.Span.File == file {
				param = true
			}
		}
	}
	if !source || !param {
		t.Fatalf("dependencies=%+v", use.Dependencies)
	}
}

func transferKind(use analysis.CandidateUse, kind, text string) bool {
	for _, d := range use.Dependencies {
		for _, e := range d.Transfers {
			if e.Kind == kind && strings.Contains(e.Text, text) {
				return true
			}
		}
	}
	return false
}

func evidenceKind(items []analysis.Evidence, kind string) bool {
	for _, e := range items {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestQueryShapeAndValidation(t *testing.T) {
	sql := analysis.Check{ID: "query-structure", Method: "POST", Path: "/session", Kind: "sql_query", Fields: []string{"handle"}, Validation: "nonempty", Protection: "request input must not change query structure"}
	t.Run("nosql where string", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();api.get('/rest/track-order/:id',(req,res)=>{const id=utils.trunc(req.params.id,60);db.ordersCollection.find({$where:`this.orderId === '${id}'`})})")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		use := kindUse(t, report, "nosql_query_candidate")
		if !strings.Contains(use.Sink.Text, "$where") || !gapKind(use.Gaps, "query_text_interpolated") {
			t.Fatalf("nosql=%+v", use)
		}
	})
	t.Run("nosql update document", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();api.patch('/rest/products/reviews',(req,res)=>{db.reviewsCollection.update({_id:req.body.id},{$set:{message:req.body.message}},{multi:true})})")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		use := kindUse(t, report, "nosql_query_candidate")
		if !gapKind(use.Gaps, "query_document_unvalidated") || !gapKind(use.Gaps, "input_validation_absent") {
			t.Fatalf("update=%+v", use.Gaps)
		}
	})
	t.Run("array find is not a query", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();api.post('/api/login',(req,res)=>{const query=`SELECT '${req.body.username}'`;console.log(query);users.find((u)=>u.username===req.body.username)})")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		for _, use := range report.Uses {
			if use.Kind == "sql_query_candidate" || use.Kind == "nosql_query_candidate" {
				t.Fatalf("log or array find became a query sink: %+v", use.Sink)
			}
		}
		if kindUse(t, report, "input_validation_candidate").Kind == "" {
			t.Fatal("login inputs were not reported")
		}
	})
	t.Run("bound query keeps validation separate", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const api=express();api.post('/session',(req,res)=>db.query('SELECT $handle',{bind:{handle:req.body.handle}}))")
		report := mustChecked(t, root, sql)
		use := kindUse(t, report, "sql_query_candidate")
		if gapKind(use.Gaps, "query_text_interpolated") || !gapKind(use.Gaps, "input_validation_absent") {
			t.Fatalf("bound=%+v", use.Gaps)
		}
		if len(use.Completeness.Blockers) != 0 {
			t.Fatalf("validation gap blocked the bound query claim: %+v", use.Completeness.Blockers)
		}
	})
	t.Run("interpolated query records both deficiencies", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const api=express();api.post('/session',(req,res)=>db.query(`SELECT '${req.body.handle}'`))")
		use := kindUse(t, mustChecked(t, root, sql), "sql_query_candidate")
		if !gapKind(use.Gaps, "query_text_interpolated") || !gapKind(use.Gaps, "input_validation_absent") {
			t.Fatalf("interpolated=%+v", use.Gaps)
		}
	})
	t.Run("string check does not protect an interpolated query", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();function guard(req,res,next){if(typeof req.body.handle!=='string')return res.status(400).end();next()}api.use(guard);api.post('/session',(req,res)=>db.query(`SELECT '${req.body.handle}'`))")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		use := kindUse(t, report, "sql_query_candidate")
		if !gapKind(use.Gaps, "query_text_interpolated") || !gapKind(use.Gaps, "validation_insufficient_for_sink") || gapKind(use.Gaps, "input_validation_absent") {
			t.Fatalf("string middleware=%+v", use.Gaps)
		}
	})
	t.Run("free text must be bound at the sink", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const api=express();api.post('/session',(req,res)=>db.reviewsCollection.update({_id:1},{$set:{message:req.body.comment}}))")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		use := kindUse(t, report, "nosql_query_candidate")
		if !gapKind(use.Gaps, "query_document_unvalidated") || !gapKind(use.Gaps, "sink_must_bind_free_text") {
			t.Fatalf("comment=%+v", use.Gaps)
		}
	})
	t.Run("bound free text does not demand an allow-list", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const api=express();api.post('/session',(req,res)=>db.query('SELECT $comment',{bind:{comment:req.body.comment}}))")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		use := kindUse(t, report, "sql_query_candidate")
		if gapKind(use.Gaps, "query_text_interpolated") || gapKind(use.Gaps, "sink_must_bind_free_text") || !gapKind(use.Gaps, "validation_free_text_bound") {
			t.Fatalf("bound comment=%+v", use.Gaps)
		}
	})
}

func kindUse(t *testing.T, report *analysis.AnalysisReport, kind string) analysis.CandidateUse {
	t.Helper()
	for _, use := range report.Uses {
		if use.Kind == kind {
			return use
		}
	}
	t.Fatalf("missing %s in %+v", kind, report.Uses)
	return analysis.CandidateUse{}
}

func gapKind(gaps []analysis.Gap, kind string) bool {
	for _, g := range gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

func TestEntrySelectors(t *testing.T) {
	for _, tc := range []struct{ name, file, source string }{
		{"http", "app.ts", `import express from 'express';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const a=express();const b=express();function handler(req,res){db.query('SELECT '+req.query.email)}a.get('/same',handler);b.get('/same',handler);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, tc.file, tc.source)
			c := analysis.Check{ID: "typed", Selector: &analysis.EntrySelector{Kind: "http", Method: "GET", Path: "/same", RegistrationFile: tc.file}, Kind: "sql_query", Fields: []string{"email", "query.email"}, Validation: "explicit field policy", Protection: "data only"}
			r, err := AnalyzeWithChecks(root, tc.file, []analysis.Check{c})
			if err != nil {
				t.Fatal(err)
			}
			if len(r.CheckMatches) == 0 {
				t.Fatal("no context selection metadata")
			}
			seen := map[string]bool{}
			for _, u := range r.Uses {
				if u.Check != nil && u.Check.ID == "typed" {
					if u.Check.Selector == nil || u.InvocationContextID == "" || seen[u.InvocationContextID] {
						t.Fatal("lost/duplicated contextual requirement")
					}
					seen[u.InvocationContextID] = true
				}
			}
			if len(seen) != len(r.CheckMatches) {
				t.Fatalf("uses=%d matched contexts=%d gaps=%+v", len(seen), len(r.CheckMatches), r.Gaps)
			}
			if tc.name == "http" && len(seen) != 2 {
				t.Fatal("same callable lost separate app contexts")
			}
			second := c
			second.ID = "second-policy"
			both, err := AnalyzeWithChecks(root, tc.file, []analysis.Check{c, second})
			if err != nil {
				t.Fatal(err)
			}
			if len(both.CheckMatches) != 2*len(r.CheckMatches) {
				t.Fatal("second check replaced first requirement")
			}
			for _, match := range both.CheckMatches {
				if match.UseCount != 1 {
					t.Fatalf("context requirement not evaluated independently: %+v", match)
				}
			}
			c.Selector.Path = "/absent"
			r, err = AnalyzeWithChecks(root, tc.file, []analysis.Check{c})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, g := range r.Gaps {
				found = found || g.Kind == "check_selector_missing"
			}
			if !found || len(r.CheckMatches) != 0 {
				t.Fatal("zero matches hidden")
			}
		})
	}
	t.Run("browser zero operation", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "browser.js", `document.body.innerHTML=location.hash`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		var e analysis.EntryPoint
		for _, entry := range r.Entries {
			if entry.Kind == "browser" {
				e = entry
			}
		}
		c := analysis.Check{ID: "browser-check", Selector: &analysis.EntrySelector{Kind: "browser", Category: e.Browser.Category, Name: e.Name}, Kind: "sql_query"}
		r, err = AnalyzeWithChecks(root, "", []analysis.Check{c})
		if err != nil {
			t.Fatal(err)
		}
		if len(r.CheckMatches) != 1 || r.CheckMatches[0].UseCount != 0 {
			t.Fatalf("missing zero-use context metadata: %+v", r.CheckMatches)
		}
		found := false
		for _, g := range r.Gaps {
			found = found || g.Kind == "check_operation_missing"
		}
		if !found {
			t.Fatal("missing operation gap hidden")
		}
	})
}

func TestEntrySelectorsContextIsolation(t *testing.T) {
	for _, kind := range []string{"graphql", "grpc", "browser"} {
		t.Run(kind, func(t *testing.T) {
			e := analysis.EntryPoint{ID: "entry", Kind: kind, Name: "Component", GraphQL: nil}
			sel := analysis.EntrySelector{Kind: kind}
			switch kind {
			case "graphql":
				e.GraphQL = &analysis.GraphQLEntryMetadata{Type: "Query", Field: "search"}
				sel.Type = "Query"
				sel.Field = "search"
			case "grpc":
				e.GRPC = &analysis.GRPCEntryMetadata{Service: "Search", Method: "Find"}
				sel.Service = "Search"
				sel.Method = "Find"
			case "browser":
				e.Browser = &analysis.BrowserEntryMetadata{Category: "component"}
				sel.Category = "component"
				sel.Name = "Component"
			}
			r := &analysis.AnalysisReport{Entries: []analysis.EntryPoint{e}, InvocationContexts: []analysis.InvocationContext{{ID: "a", EntryID: e.ID}, {ID: "b", EntryID: e.ID}}}
			for _, id := range []string{"a", "b"} {
				gaps := []analysis.Gap{}
				if id == "b" {
					gaps = append(gaps, analysis.Gap{Kind: "unknown_guard"})
				}
				r.Uses = append(r.Uses, analysis.CandidateUse{ID: id, EntryID: e.ID, InvocationContextID: id, Kind: "sql_query_candidate", Dependencies: []analysis.Dependency{{Source: analysis.Evidence{Text: "args.email"}}}, Completeness: &analysis.Completeness{Required: []string{"input_source"}, Evidence: map[string][]analysis.Evidence{}, Blockers: gaps}})
			}
			s := &moduleSet{}
			s.buildChecks(r, []analysis.Check{{ID: "typed", Selector: &sel, Kind: "sql_query", Fields: []string{"args.email"}}})
			if len(r.Uses) != 2 {
				t.Fatal("not every context evaluated")
			}
			for _, u := range r.Uses {
				if len(u.Completeness.Evidence["input_source"]) != 1 {
					t.Fatal("source role lost")
				}
				if (len(u.Completeness.Blockers) > 0) != (u.InvocationContextID == "b") {
					t.Fatal("guard crossed contexts")
				}
			}
		})
	}
}
