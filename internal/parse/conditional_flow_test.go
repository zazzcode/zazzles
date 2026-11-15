package parse

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

var conditionalControlGaps = []string{"unsupported_control_flow", "branch_exit", "unknown_control_effect"}

func conditionalReport(t *testing.T, name, src string) *analysis.AnalysisReport {
	t.Helper()
	root := t.TempDir()
	writeSource(t, root, name, src)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// conditionalHandler wraps body in an Express GET handler for JavaScript or TypeScript.
func conditionalHandler(lang, prelude, body string) (string, string) {
	if lang == "ts" {
		return "server.ts", "import express from 'express';const app=express();" + prelude + "app.get('/x',(req,res)=>{" + body + "});"
	}
	return "server.js", "const express=require('express');const app=express();" + prelude + "app.get('/x',(req,res)=>{" + body + "});"
}

func usesOfKind(r *analysis.AnalysisReport, kind string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sink.Span.StartByte < out[j].Sink.Span.StartByte })
	return out
}

func contextTexts(u analysis.CandidateUse, kind string) []string {
	var out []string
	for _, e := range u.Context {
		if e.Kind == kind {
			out = append(out, e.Text)
		}
	}
	return out
}

// depBranches maps each dependency source text to the branch preconditions on its transfers.
func depBranches(u analysis.CandidateUse) map[string][]string {
	out := map[string][]string{}
	for _, d := range u.Dependencies {
		var kinds []string
		for _, e := range d.Transfers {
			if e.Kind == branchTruePrecondition || e.Kind == branchFalsePrecondition {
				kinds = append(kinds, e.Kind+" "+e.Text)
			}
		}
		out[d.Source.Text] = append(out[d.Source.Text], strings.Join(kinds, ";"))
	}
	return out
}

func requireNoControlGaps(t *testing.T, u analysis.CandidateUse) {
	t.Helper()
	for _, g := range u.Gaps {
		for _, kind := range conditionalControlGaps {
			if g.Kind == kind {
				t.Fatalf("modeled if left a %s gap: %+v", kind, g)
			}
		}
	}
}

func sameTexts(got []string, want ...string) bool {
	return strings.Join(got, "|") == strings.Join(want, "|")
}

func TestConditionalPolarityAndFallthrough(t *testing.T) {
	for _, lang := range []string{"js", "ts"} {
		t.Run(lang, func(t *testing.T) {
			sql := func(t *testing.T, body string) []analysis.CandidateUse {
				t.Helper()
				name, src := conditionalHandler(lang, "", body)
				return usesOfKind(conditionalReport(t, name, src), "sql_query_candidate")
			}
			t.Run("consequence exits", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(!ok(v)){return res.sendStatus(400)}db.query('S '+v)")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchFalsePrecondition), "(!ok(v))") || len(contextTexts(uses[0], branchTruePrecondition)) != 0 {
					t.Fatalf("uses %+v", uses)
				}
				requireNoControlGaps(t, uses[0])
			})
			t.Run("alternative exits", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(ok(v)){res.set('X','1')}else{throw new Error('bad')}db.query('S '+v)")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(ok(v))") || len(contextTexts(uses[0], branchFalsePrecondition)) != 0 {
					t.Fatalf("uses %+v", uses)
				}
				requireNoControlGaps(t, uses[0])
			})
			t.Run("absent else keeps both values under their tests", func(t *testing.T) {
				uses := sql(t, "let v=req.query.q;if(req.query.a){v=req.query.b}db.query('S '+v)")
				if len(uses) != 1 {
					t.Fatalf("uses %+v", uses)
				}
				got := depBranches(uses[0])
				if !sameTexts(got["req.query.q"], branchFalsePrecondition+" (req.query.a)") || !sameTexts(got["req.query.b"], branchTruePrecondition+" (req.query.a)") {
					t.Fatalf("dependency branches %v", got)
				}
				if len(contextTexts(uses[0], branchTruePrecondition))+len(contextTexts(uses[0], branchFalsePrecondition)) != 0 {
					t.Fatalf("a join of two continuing arms kept an arm precondition: %+v", uses[0].Context)
				}
				requireNoControlGaps(t, uses[0])
			})
			t.Run("unchanged value is not tagged", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;let w='x';if(req.query.a){w='y'}db.query('S '+v+w)")
				if len(uses) != 1 || !sameTexts(depBranches(uses[0])["req.query.q"], "") {
					t.Fatalf("uses %+v", uses)
				}
			})
			t.Run("else-if chain", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(a(v)){return res.end()}else if(b(v)){return res.end()}db.query('S '+v)")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchFalsePrecondition), "(a(v))", "(b(v))") {
					t.Fatalf("uses %+v", uses)
				}
				requireNoControlGaps(t, uses[0])
			})
			t.Run("else-if chain with a continuing middle arm", func(t *testing.T) {
				uses := sql(t, "let v=req.query.q;if(a(v)){return res.end()}else if(b(v)){v='safe'}else{return res.end()}db.query('S '+v)")
				if len(uses) != 0 {
					t.Fatalf("only the constant arm continues; uses %+v", uses)
				}
			})
			t.Run("both arms exit", func(t *testing.T) {
				for _, body := range []string{
					"const v=req.query.q;if(c(v)){return res.end()}else{throw new Error('x')}db.query('S '+v)",
					"const v=req.query.q;if(c(v)){process.exit(1)}else{return res.end()}db.query('S '+v)",
					"const v=req.query.q;if(c(v)){if(d(v)){return res.end()}else{return res.end()}}else{return}db.query('S '+v)",
				} {
					if uses := sql(t, body); len(uses) != 0 {
						t.Fatalf("%s: unreachable sink discovered: %+v", body, uses)
					}
				}
			})
			t.Run("shadowed process.exit does not exit", func(t *testing.T) {
				uses := sql(t, "const process={exit(){}};const v=req.query.q;if(c(v)){process.exit(1)}else{return res.end()}db.query('S '+v)")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(c(v))") {
					t.Fatalf("uses %+v", uses)
				}
			})
			t.Run("process.exit arm leaves the join", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(!ok(v)){process.exit(1)}db.query('S '+v)")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchFalsePrecondition), "(!ok(v))") {
					t.Fatalf("uses %+v", uses)
				}
			})
			t.Run("nested early guards", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(a(v)){if(!b(v)){return res.end()}db.query('S '+v)}")
				if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(a(v))") || !sameTexts(contextTexts(uses[0], branchFalsePrecondition), "(!b(v))") {
					t.Fatalf("uses %+v", uses)
				}
			})
			t.Run("sinks in sibling arms keep their own polarity", func(t *testing.T) {
				uses := sql(t, "if(c()){db.query('A '+req.query.a)}else{db.query('B '+req.query.b)}")
				if len(uses) != 2 {
					t.Fatalf("uses %+v", uses)
				}
				if !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(c())") || len(contextTexts(uses[0], branchFalsePrecondition)) != 0 {
					t.Fatalf("consequence sink context %+v", uses[0].Context)
				}
				if !sameTexts(contextTexts(uses[1], branchFalsePrecondition), "(c())") || len(contextTexts(uses[1], branchTruePrecondition)) != 0 {
					t.Fatalf("alternative sink context %+v", uses[1].Context)
				}
			})
			t.Run("an arm-only guard is not lent to the join", func(t *testing.T) {
				uses := sql(t, "const v=req.query.q;if(c()){if(!ok(v)){return res.end()}}else{res.set('X','1')}db.query('S '+v)")
				if len(uses) != 1 || len(contextTexts(uses[0], branchFalsePrecondition))+len(contextTexts(uses[0], branchTruePrecondition)) != 0 {
					t.Fatalf("uses %+v", uses)
				}
			})
			t.Run("binding evidence of an arm survives the join", func(t *testing.T) {
				name, src := conditionalHandler(lang, "function h(x){return x.trim()}", "let v=req.query.q;if(c()){v=h(v)}db.query('S '+v)")
				uses := usesOfKind(conditionalReport(t, name, src), "sql_query_candidate")
				if len(uses) != 1 || len(contextTexts(uses[0], "helper_definition")) == 0 {
					t.Fatalf("uses %+v", uses)
				}
			})
		})
	}
}

func TestConditionalValueIsolation(t *testing.T) {
	sql := func(t *testing.T, prelude, body string) []analysis.CandidateUse {
		t.Helper()
		name, src := conditionalHandler("js", prelude, body)
		return usesOfKind(conditionalReport(t, name, src), "sql_query_candidate")
	}
	sources := func(u analysis.CandidateUse) string {
		var out []string
		for _, d := range u.Dependencies {
			out = append(out, d.Source.Text)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	t.Run("block-scoped shadow does not leak", func(t *testing.T) {
		uses := sql(t, "", "let v='s';if(c()){const v=req.query.a;db.query('A '+v)}db.query('B '+v)")
		if len(uses) != 1 || sources(uses[0]) != "req.query.a" || !strings.HasPrefix(uses[0].Sink.Text, "db.query('A ") {
			t.Fatalf("uses %+v", uses)
		}
	})
	t.Run("block-scoped declaration is not visible after the if", func(t *testing.T) {
		for _, u := range sql(t, "", "if(c()){const w=req.query.a}else{let w=req.query.b}db.query('B '+w)") {
			if len(u.Dependencies) != 0 {
				t.Fatalf("block-scoped binding leaked: %+v", u.Dependencies)
			}
		}
	})
	t.Run("var keeps function scope", func(t *testing.T) {
		uses := sql(t, "", "if(c()){var w=req.query.a}db.query('B '+w)")
		if len(uses) != 1 || !sameTexts(depBranches(uses[0])["req.query.a"], branchTruePrecondition+" (c())") {
			t.Fatalf("uses %+v", uses)
		}
	})
	t.Run("raw and safe sibling values", func(t *testing.T) {
		uses := sql(t, "", "let v;if(c()){v=req.query.raw}else{v='constant'}db.query('S '+v)")
		if len(uses) != 1 || !sameTexts(depBranches(uses[0])["req.query.raw"], branchTruePrecondition+" (c())") {
			t.Fatalf("uses %+v", uses)
		}
	})
	t.Run("object-field writes match straight-line sources", func(t *testing.T) {
		for _, pair := range [][2]string{
			{"const o={k:'s'};if(c()){o.x=req.query.a}db.query('S '+o.x)", "const o={k:'s'};o.x=req.query.a;db.query('S '+o.x)"},
			{"const o={k:'s'};if(c()){o.x=req.query.a}else{o.y=req.query.b}db.query('S '+o.x)", "const o={k:'s'};o.x=req.query.a;o.y=req.query.b;db.query('S '+o.x)"},
			{"const o={n:{k:'s'}};if(c()){o.n.x=req.query.a}else{o.n.y=req.query.b}db.query('S '+o.n.y)", "const o={n:{k:'s'}};o.n.x=req.query.a;o.n.y=req.query.b;db.query('S '+o.n.y)"},
		} {
			branch, straight := sql(t, "", pair[0]), sql(t, "", pair[1])
			if len(branch) != len(straight) || len(branch) != 1 || sources(branch[0]) != sources(straight[0]) {
				t.Fatalf("%s: branch %+v straight %+v", pair[0], branch, straight)
			}
		}
	})
	t.Run("helper with a neutral non-exiting branch is precise", func(t *testing.T) {
		uses := sql(t, "function pick(x){let r='d';if(typeof x==='string'){r=x}return r}", "db.query('S '+pick(req.query.q))")
		if len(uses) != 1 || !sameTexts(depBranches(uses[0])["req.query.q"], branchTruePrecondition+" (typeof x==='string')") || gapKind(uses[0].Gaps, "unknown_transfer") {
			t.Fatalf("uses %+v", uses)
		}
	})
	for _, helper := range []string{
		"function pick(x){if(!/^[a-z]+$/.test(x)){return ''}return x}",
		"function pick(x){let r='d';if(/^[a-z]+$/.test(x)){r=x}return r}",
		"function pick(x){if(x.includes('%00')){return x.substring(0,1)}return x}",
	} {
		t.Run("helper keeps the may-dependency policy: "+helper, func(t *testing.T) {
			uses := sql(t, helper, "db.query('S '+pick(req.query.q))")
			if len(uses) != 1 || !gapKind(uses[0].Gaps, "unknown_transfer") {
				t.Fatalf("uses %+v", uses)
			}
		})
	}
	for _, body := range []string{
		"if(c()){req={query:{q:'x'}}}db.query('S '+req.query.q)",
		"if(c()){({req}=other())}db.query('S '+req.query.q)",
		"if(c()){let res=1}db.query('S '+req.query.q)",
	} {
		t.Run("request/response rebinding keeps the fallback and the feasible source: "+body, func(t *testing.T) {
			uses := sql(t, "", body)
			if len(uses) != 1 || !gapKind(uses[0].Gaps, "unsupported_control_flow") || len(uses[0].Dependencies) == 0 {
				t.Fatalf("uses %+v", uses)
			}
		})
	}
	for _, write := range []string{"req.session.user=req.query.u", "delete req.query.x", "counter.n++", "state.list+=req.query.u"} {
		t.Run("unmodeled heap write keeps its gap: "+write, func(t *testing.T) {
			uses := sql(t, "", "if(c()){"+write+"}db.query('S '+req.query.q)")
			if len(uses) != 1 || !gapKind(uses[0].Gaps, "unsupported_write") {
				t.Fatalf("uses %+v", uses)
			}
		})
	}
	for _, body := range []string{
		"for(const x of list()){db.query('S '+req.query.q)}",
		// Case bodies are not traversed (a recorded limit); the gap reaches later code.
		"let v=req.query.q;switch(req.query.m){case 'a':v=req.query.b}db.query('S '+v)",
		"try{db.query('S '+req.query.q)}finally{res.end()}",
		"while(c()){db.query('S '+req.query.q)}",
	} {
		t.Run("unsupported statement keeps its gap: "+body, func(t *testing.T) {
			uses := sql(t, "", body)
			if len(uses) != 1 || !gapKind(uses[0].Gaps, "unsupported_control_flow") {
				t.Fatalf("uses %+v", uses)
			}
		})
	}
	t.Run("deterministic", func(t *testing.T) {
		body := "let v=req.query.q;const o={a:1};if(c()){v=req.query.b;o.x=v}else if(d()){o.y=req.query.c}else{return}db.query('S '+v+o.x+o.y)"
		a, b := sql(t, "", body), sql(t, "", body)
		if len(a) != 1 || len(b) != 1 || a[0].ID != b[0].ID || depBranchesString(a[0]) != depBranchesString(b[0]) {
			t.Fatalf("nondeterministic: %+v %+v", a, b)
		}
	})
}

func depBranchesString(u analysis.CandidateUse) string {
	var out []string
	for k, v := range depBranches(u) {
		out = append(out, k+"="+strings.Join(v, "/"))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestConditionalSharedFamilies(t *testing.T) {
	t.Run("command allowlist on one arm only", func(t *testing.T) {
		uses := analyzeCommandUses(t, "server.js", jsCommandPrelude+`
app.get('/allow',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/unsafe',(req,res)=>{const cmd=req.query.c;if(!cmd){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/arms',(req,res)=>{const cmd=req.query.c;if(req.query.m){if(!ALLOWED.has(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});}else{exec(cmd,()=>{});}res.send('x');});
`)
		requireGuards(t, "/allow", uses["/allow"][0], "terminating_guard: if(!ALLOWED.has(cmd))")
		if commandProtection(uses["/allow"][0]) != "guarded" {
			t.Fatalf("/allow protection %s", commandProtection(uses["/allow"][0]))
		}
		if p := commandProtection(uses["/unsafe"][0]); p == "guarded" {
			t.Fatalf("/unsafe was credited a guard")
		}
		arms := uses["/arms"]
		sort.Slice(arms, func(i, j int) bool { return arms[i].Sink.Span.StartByte < arms[j].Sink.Span.StartByte })
		if len(arms) != 2 {
			t.Fatalf("/arms uses %d", len(arms))
		}
		requireGuards(t, "/arms consequence", arms[0], "terminating_guard: if(!ALLOWED.has(cmd))")
		requireGuards(t, "/arms alternative", arms[1])
		if !sameTexts(contextTexts(arms[1], branchFalsePrecondition), "(req.query.m)") {
			t.Fatalf("alternative context %+v", arms[1].Context)
		}
		for _, u := range append(append(arms, uses["/allow"]...), uses["/unsafe"]...) {
			requireNoControlGaps(t, u)
		}
	})
	t.Run("path allowlist on one arm only", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `
const express=require('express');const fs=require('fs');const path=require('path');const app=express();
const ROOT=path.resolve(__dirname,'uploads');const ALLOWED=new Set(['a.txt','b.txt']);
app.get('/guarded',(req,res)=>{const f=req.query.f;if(req.query.m){if(!ALLOWED.has(f)){return res.sendStatus(400);}res.send(fs.readFileSync(path.join(ROOT,f)));}else{res.send('x');}});
app.get('/sibling',(req,res)=>{const f=req.query.f;if(req.query.m){if(!ALLOWED.has(f)){return res.sendStatus(400);}}res.send(fs.readFileSync(path.join(ROOT,f)));});
`)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		uses := pathUses(r)
		if got := guardKinds(uses["/guarded"]); len(got) != 1 || got[0] != analysis.PathGuardAllowlist {
			t.Fatalf("/guarded guards %v", got)
		}
		if got := guardKinds(uses["/sibling"]); len(got) != 0 {
			t.Fatalf("/sibling credited a guard from one arm: %v", got)
		}
	})
	t.Run("SSRF in sibling arms", func(t *testing.T) {
		r := conditionalReport(t, "server.ts", "import express from 'express';import axios from 'axios';const app=express();app.get('/x',async (req,res)=>{if(req.query.m){await axios.get(req.query.a as string)}else{await axios.get('https://example.test/')}res.send('ok')});")
		uses := usesOfKind(r, "ssrf_candidate")
		if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(req.query.m)") {
			t.Fatalf("ssrf uses %+v", uses)
		}
		requireNoControlGaps(t, uses[0])
	})
	t.Run("NoSQL typeof guard stays a selector witness", func(t *testing.T) {
		r := conditionalReport(t, "server.js", "const express=require('express');const app=express();const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));app.post('/x',(req,res)=>{if(typeof req.body.id!=='string'){return res.sendStatus(400)}Todo.findById(req.body.id).then(t=>res.json(t))});")
		uses := usesOfKind(r, "nosql_query_candidate")
		if len(uses) != 1 || uses[0].Completeness == nil || len(uses[0].Completeness.Evidence["selector_type_guard"]) != 1 {
			t.Fatalf("nosql uses %+v", uses)
		}
	})
	t.Run("logging in one arm", func(t *testing.T) {
		r := conditionalReport(t, "server.ts", "import express from 'express';import {createLogger} from 'winston';const logger=createLogger({});const app=express();app.get('/x',(req,res)=>{if(req.query.debug){logger.info(req.query.token)}res.end()})")
		uses := logUses(r)
		if len(uses) != 1 || !sameTexts(contextTexts(uses[0], branchTruePrecondition), "(req.query.debug)") {
			t.Fatalf("log uses %+v", uses)
		}
		requireNoControlGaps(t, uses[0])
	})
	t.Run("XSS encoder on one arm only", func(t *testing.T) {
		r := conditionalReport(t, "app.js", "const express=require('express');const escapeHtml=require('escape-html');const app=express();app.get('/x',(req,res)=>{const q=req.query.q;if(req.query.safe){res.send('<p>'+escapeHtml(q)+'</p>')}else{res.send('<p>'+q+'</p>')}})")
		if got := summarize(xssUses(r)); !sameTexts(got, "reflected/html_text/raw", "reflected/html_text/sanitized") {
			t.Fatalf("xss %v", got)
		}
	})
	t.Run("response content type differs across arms", func(t *testing.T) {
		r := conditionalReport(t, "app.js", "const express=require('express');const app=express();app.get('/x',(req,res)=>{if(req.query.html){res.type('html')}else{res.set('X','1')}res.send(req.query.q)})")
		found := false
		for _, u := range xssUses(r) {
			for _, g := range u.Gaps {
				found = found || (g.Kind == "unknown_control_effect" && strings.Contains(g.Detail, "content type"))
			}
		}
		if !found {
			t.Fatalf("content-type ambiguity hidden: %+v", xssUses(r))
		}
	})
}

// Independent QA regressions: a precondition must keep its polarity and never
// outlive the path it was recorded on.
func TestConditionalPreconditionsDoNotLeak(t *testing.T) {
	sql := func(t *testing.T, body string) []analysis.CandidateUse {
		t.Helper()
		name, src := conditionalHandler("js", "", body)
		return usesOfKind(conditionalReport(t, name, src), "sql_query_candidate")
	}
	for _, body := range []string{
		"for(const x of req.query.l){if(!isAdmin(req)){return res.sendStatus(403)}}db.query('S '+req.query.q)",
		"try{if(!isAdmin(req)){return res.sendStatus(403)}}catch(e){}db.query('S '+req.query.q)",
		"while(more()){if(!isAdmin(req)){return res.sendStatus(403)}break}db.query('S '+req.query.q)",
		"try{if(!isAdmin(req)){throw new Error('x')}}catch(e){db.query('S '+req.query.q)}",
	} {
		t.Run(body, func(t *testing.T) {
			uses := sql(t, body)
			if len(uses) != 1 || len(contextTexts(uses[0], branchFalsePrecondition))+len(contextTexts(uses[0], branchTruePrecondition)) != 0 {
				t.Fatalf("a precondition leaked out of an unmodeled body: %+v", uses)
			}
		})
	}
	t.Run("NoSQL typeof witness needs the excluding polarity", func(t *testing.T) {
		prelude := "const express=require('express');const app=express();const mongoose=require('mongoose');const Todo=mongoose.model('Todo',new mongoose.Schema({content:String}));"
		for body, want := range map[string]int{
			"if(typeof req.body.id!=='string'){return res.sendStatus(400)}Todo.findById(req.body.id).then(t=>res.json(t))":        1,
			"if(typeof req.body.id==='string'){Todo.findById(req.body.id).then(t=>res.json(t))}else{res.sendStatus(400)}":         1,
			"if(typeof req.body.id!=='string'){return Todo.findById(req.body.id).then(t=>res.json(t))}res.sendStatus(400)":        0,
			"if(typeof req.body.id==='string'){res.sendStatus(400)}else{Todo.findById(req.body.id).then(t=>res.json(t))}":         0,
			"if(typeof req.body.id!=='string'||x()){return res.sendStatus(400)}Todo.findById(req.body.id).then(t=>res.json(t))": 0,
		} {
			r := conditionalReport(t, "server.js", prelude+"app.post('/x',(req,res)=>{"+body+"});")
			uses := usesOfKind(r, "nosql_query_candidate")
			if len(uses) != 1 || len(uses[0].Completeness.Evidence["selector_type_guard"]) != want {
				t.Fatalf("%s: want %d selector witnesses, uses %+v", body, want, uses)
			}
		}
	})
}

func TestConditionalInvocationPromotionKeepsPolarity(t *testing.T) {
	resolver := func(t *testing.T, body string) (analysis.CandidateUse, analysis.InvocationContext) {
		t.Helper()
		r := conditionalReport(t, "app.js", "import {ApolloServer} from '@apollo/server';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');const typeDefs=`type Query { search(email: String): String }`;new ApolloServer({typeDefs,resolvers:{Query:{search:(parent,args,context)=>{"+body+"}}}});")
		uses := usesOfKind(r, "sql_query_candidate")
		if len(uses) != 1 {
			t.Fatalf("uses %+v", uses)
		}
		for _, ctx := range r.InvocationContexts {
			if ctx.ID == uses[0].InvocationContextID {
				return uses[0], ctx
			}
		}
		t.Fatal("no invocation")
		return analysis.CandidateUse{}, analysis.InvocationContext{}
	}
	controls := func(ctx analysis.InvocationContext) []string {
		var out []string
		for _, c := range ctx.Controls {
			if c.Evidence.Kind != "invoked_callable" {
				out = append(out, c.Evidence.Kind+" "+c.Evidence.Text)
			}
		}
		return out
	}
	_, ctx := resolver(t, "if(!allowed(args.email)){throw new Error('no')}return db.query('SELECT '+args.email)")
	if !sameTexts(controls(ctx), conditionalFalseTest+" (!allowed(args.email))") {
		t.Fatalf("early guard controls %v", controls(ctx))
	}
	for _, body := range []string{
		"if(context.user){return 'x'}else{return db.query('SELECT '+args.email)}",
		"if(context.admin){return db.query('SELECT '+args.email)}return 'x'",
		"for(const r of context.roles){if(!context.user){throw new Error('x')}}return db.query('SELECT '+args.email)",
	} {
		if _, ctx := resolver(t, body); len(controls(ctx)) != 0 {
			t.Fatalf("%s: arm-only test promoted to invocation control: %v", body, controls(ctx))
		}
	}
}
