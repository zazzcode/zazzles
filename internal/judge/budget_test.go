package judge

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func withRequestLimit(t *testing.T, limit int) {
	t.Helper()
	previous := requestLimit
	requestLimit = limit
	t.Cleanup(func() { requestLimit = previous })
}

// offlineClient answers every request with a 500 from a local stub, so an
// assessment that fits is attempted (and fails) without leaving the machine.
func offlineClient(t *testing.T) *Client {
	t.Helper()
	c, err := New("openai", "fixture-model", "key")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > int64(requestLimit) {
			t.Error("an over-limit request reached the transport")
		}
		w.WriteHeader(400) // a non-retried failure; these tests only inspect requests
	}))
	t.Cleanup(server.Close)
	c.UseEndpoint(server.URL, server.Client())
	return c
}

// budgetFixture has context in another file (helpers), registrations and a
// sink whose dependency and binding evidence the budget must keep.
func budgetFixture(t *testing.T) analysis.CandidateUse {
	var helpers strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&helpers, "export function check%d(v){ const parts=String(v).split(','); let total=0; for (const p of parts) { total += p.length * %d } return total > 3 }\n", i, i)
	}
	var calls, mounts strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&calls, "check%d(req.query.other);", i)
		fmt.Fprintf(&mounts, "app.use((req,res,next)=>{res.setHeader('x-h%d','1');next()});", i)
	}
	u, _ := familyFixtureUse(t, map[string]string{
		"lib/checks.ts": helpers.String(),
		"server.ts": `import express from 'express';import * as MarsDB from 'marsdb';import {check0,check1,check2,check3,check4,check5} from './lib/checks';const app=express();const users=new MarsDB.Collection('users');` + mounts.String() +
			`app.post('/raw',(req,res)=>{` + calls.String() + `users.find({name:req.body.name});res.send('ok')});`,
	}, "nosql_query_candidate")
	return u
}

func TestRequestBudgetUnderLimitAlwaysCompact(t *testing.T) {
	c := offlineClient(t)
	for name, u := range map[string]analysis.CandidateUse{"nosql": selectedNoSQLUse(t), "sql": selectedSQLUse(t), "budget fixture": budgetFixture(t)} {
		full, err := c.payloadForm(u, true)
		if err != nil {
			t.Fatal(err)
		}
		got, omitted, err := c.budgetedPayload(u)
		if err != nil || len(omitted) != 0 || string(got) != string(full) {
			t.Fatalf("%s: request under the limit changed (omitted=%v err=%v)", name, omitted, err)
		}
	}
}

func TestRequestBudgetShedsContextByRole(t *testing.T) {
	c := offlineClient(t)
	u := budgetFixture(t)
	compact, err := c.payloadForm(u, true)
	if err != nil {
		t.Fatal(err)
	}
	withRequestLimit(t, len(compact)-200)
	payload, omitted, err := c.budgetedPayload(u)
	if err != nil {
		t.Fatal(err)
	}
	if len(omitted) == 0 || len(payload) > requestLimit {
		t.Fatalf("budget did not fit: %d bytes, %d omitted", len(payload), len(omitted))
	}
	again, omittedAgain, _ := c.budgetedPayload(u)
	if string(again) != string(payload) || !reflect.DeepEqual(omitted, omittedAgain) {
		t.Fatal("budget is not deterministic")
	}
	reduced, _ := budgetUse(u, func(r analysis.CandidateUse) bool {
		p, err := c.payloadForm(r, true)
		return err == nil && len(p) <= requestLimit
	})
	if !reflect.DeepEqual(reduced.Sink, u.Sink) || !reflect.DeepEqual(reduced.Dependencies, u.Dependencies) || !reflect.DeepEqual(reduced.ControlEdges, u.ControlEdges) {
		t.Fatal("sink, dependency or control evidence was shed")
	}
	for _, role := range u.Completeness.Required {
		if !reflect.DeepEqual(reduced.Completeness.Evidence[role], u.Completeness.Evidence[role]) {
			t.Fatalf("required role %s was shed", role)
		}
	}
	// Lossless items go first, then other-file context, then same-file context;
	// the request names every omission.
	seenLossy, seenSame := false, false
	for _, o := range omitted {
		if o.Lossless {
			if seenLossy {
				t.Fatal("lossless omission after a lossy one")
			}
			continue
		}
		seenLossy = true
		if o.Span.File == u.Sink.Span.File {
			seenSame = true
		} else if seenSame {
			t.Fatalf("other-file context %s shed after same-file context", o.Span.File)
		}
	}
	var gap *analysis.Gap
	for i, g := range reduced.Completeness.Coverage {
		if g.Kind == "evidence_omitted_for_size" {
			gap = &reduced.Completeness.Coverage[i]
		}
	}
	if gap == nil || !strings.HasPrefix(gap.Detail, fmt.Sprintf("%d context evidence item(s)", len(omitted))) {
		t.Fatalf("omission gap missing or miscounted: %+v", gap)
	}
	for _, o := range omitted {
		if !strings.Contains(gap.Detail, fmt.Sprintf("%s:%d-%d", o.Span.File, o.Span.StartLine, o.Span.EndLine)) {
			t.Fatalf("omitted span %+v not named in the request: %s", o.Span, gap.Detail)
		}
	}
	if !strings.Contains(string(payload), "evidence_omitted_for_size") {
		t.Fatal("omission gap is not in the request")
	}
	a := c.Assess(context.Background(), u)
	if a.Status != "failed" || len(a.EvidenceOmissions) == 0 {
		// The stub refuses the call, so the exchange fails; the omissions are still recorded.
		t.Fatalf("assessment omission record: status=%s omissions=%d", a.Status, len(a.EvidenceOmissions))
	}
}

func TestRequestBudgetFloor(t *testing.T) {
	c := offlineClient(t)
	u := budgetFixture(t)
	withRequestLimit(t, 4096)
	a := c.Assess(context.Background(), u)
	if a.Status != "not_run" || !strings.HasPrefix(a.Reason, evidenceTooLarge+":") || a.FindingStatus != "needs_evidence" || a.Protection != "uncertain" {
		t.Fatalf("floor outcome: %+v", a)
	}
	if !strings.Contains(a.Reason, "Bytes by section: ") || !strings.Contains(a.Reason, "source_excerpts") {
		t.Fatalf("floor reason lacks section sizes: %s", a.Reason)
	}
	trace, _ := c.Preview(u)
	if len(trace.EvidenceOmissions) == 0 || !reflect.DeepEqual(trace.EvidenceOmissions, a.EvidenceOmissions) {
		t.Fatal("trace and assessment omission records differ")
	}
}

// Each way a request can grow, in each family and language, either fits with an
// omission gap or reaches the floor with a reason; none is skipped silently.
func TestRequestBudgetSyntheticShapes(t *testing.T) {
	type family struct{ kind, header, sink string }
	js := map[string]family{
		"sql":        {"sql_query_candidate", `import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');`, `db.query('SELECT * FROM x WHERE v = '+v);`},
		"nosql":      {"nosql_query_candidate", `import * as MarsDB from 'marsdb';const users=new MarsDB.Collection('users');`, `users.find({$where:'this.v == '+v});`},
		"command":    {"command_execution_candidate", `import { exec } from 'child_process';`, `exec('ls '+v);`},
		"path":       {"path_traversal_candidate", `import fs from 'fs';`, `fs.readFile('/srv/'+v,()=>{});`},
		"xss":        {"xss_candidate", ``, `res.send('<p>'+v+'</p>');return;`},
		"validation": {"input_validation_candidate", ``, `const size=String(v).length;`},
	}
	py := map[string]family{
		"sql":        {"sql_query_candidate", "import sqlite3\n", "    sqlite3.connect(':memory:').execute('SELECT * FROM x WHERE v = ' + v)\n"},
		"command":    {"command_execution_candidate", "import os\n", "    os.system('ls ' + v)\n"},
		"path":       {"path_traversal_candidate", "", "    open('/srv/' + v).read()\n"},
		"xss":        {"xss_candidate", "", "    return '<p>' + v + '</p>'\n"},
		"validation": {"input_validation_candidate", "", "    size = len(str(v))\n"},
	}
	repeat := func(n int, format string) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, format, i, i)
		}
		return b.String()
	}
	jsShapes := map[string]func(f family) map[string]string{
		"large handler": func(f family) map[string]string {
			return map[string]string{"server.ts": `import express from 'express';` + f.header + `const app=express();app.post('/x',(req,res)=>{const v=req.query.v;` + repeat(120, "const local%d = %d * 2;") + f.sink + `res.send('ok')});`}
		},
		"many middleware": func(f family) map[string]string {
			return map[string]string{"server.ts": `import express from 'express';` + f.header + `const app=express();` + repeat(40, "app.use((req,res,next)=>{res.setHeader('x-h%d','%d');next()});") + `app.post('/x',(req,res)=>{const v=req.query.v;` + f.sink + `res.send('ok')});`}
		},
		"repeated gaps": func(f family) map[string]string {
			return map[string]string{"server.ts": `import express from 'express';` + f.header + `const app=express();app.post('/x',(req,res)=>{const v=req.query.v;` + repeat(40, "if (req.query.f%d) { res.status(400 + %d) }") + f.sink + `res.send('ok')});`}
		},
		"helper chain": func(f family) map[string]string {
			files := map[string]string{}
			imports := ""
			calls := ""
			for i := 0; i < 40; i++ {
				files[fmt.Sprintf("lib/h%d.ts", i)] = fmt.Sprintf("export function h%d(x){ const parts=String(x).split(','); let n=0; for (const p of parts) { n += p.length * %d; if (n > 100) { n = n %% 7 } } return n }\n", i, i)
				imports += fmt.Sprintf("import { h%d } from './lib/h%d';", i, i)
				calls += fmt.Sprintf("h%d(req.query.o);", i)
			}
			files["server.ts"] = `import express from 'express';` + f.header + imports + `const app=express();app.post('/x',(req,res)=>{const v=req.query.v;` + calls + f.sink + `res.send('ok')});`
			return files
		},
	}
	pyShapes := map[string]func(f family) map[string]string{
		"large handler": func(f family) map[string]string {
			return map[string]string{"app.py": "from flask import Flask, request\n" + f.header + "app = Flask(__name__)\n@app.route('/x')\ndef x():\n    v = request.args.get('v')\n" + repeat(120, "    local%d = %d * 2\n") + f.sink + "    return 'ok'\n"}
		},
		"repeated gaps": func(f family) map[string]string {
			return map[string]string{"app.py": "from flask import Flask, request\n" + f.header + "app = Flask(__name__)\n@app.route('/x')\ndef x():\n    v = request.args.get('v')\n" + repeat(40, "    if request.args.get('f%d'):\n        print(%d)\n") + f.sink + "    return 'ok'\n"}
		},
		"helper chain": func(f family) map[string]string {
			files := map[string]string{}
			body := "from flask import Flask, request\n" + f.header
			calls := ""
			for i := 0; i < 40; i++ {
				files[fmt.Sprintf("h%d.py", i)] = fmt.Sprintf("def h%d(x):\n    n = 0\n    for p in str(x).split(','):\n        n += len(p) * %d\n        if n > 100:\n            n = n %% 7\n    return n\n", i, i)
				body += fmt.Sprintf("from h%d import h%d\n", i, i)
				calls += fmt.Sprintf("    h%d(request.args.get('o'))\n", i)
			}
			files["app.py"] = body + "app = Flask(__name__)\n@app.route('/x')\ndef x():\n    v = request.args.get('v')\n" + calls + f.sink + "    return 'ok'\n"
			return files
		},
	}
	check := func(t *testing.T, files map[string]string, kind string) {
		u, _ := familyFixtureUse(t, files, kind)
		c := offlineClient(t)
		compact, err := c.payloadForm(u, true)
		if err != nil {
			t.Skipf("no request for this shape: %v", err)
		}
		withRequestLimit(t, len(compact)*3/4)
		a := c.Assess(context.Background(), u)
		payload, omitted, _ := c.budgetedPayload(u)
		switch {
		case len(payload) <= requestLimit:
			if len(omitted) == 0 || !strings.Contains(string(payload), "evidence_omitted_for_size") || len(a.EvidenceOmissions) != len(omitted) {
				t.Fatalf("fits without a visible omission record (omitted=%d)", len(omitted))
			}
		case strings.HasPrefix(a.Reason, evidenceTooLarge+":"):
		default:
			t.Fatalf("over the limit without a floor reason: %+v", a)
		}
	}
	for shape, build := range jsShapes {
		for name, f := range js {
			t.Run("js/"+name+"/"+shape, func(t *testing.T) { check(t, build(f), f.kind) })
		}
	}
	for shape, build := range pyShapes {
		for name, f := range py {
			t.Run("python/"+name+"/"+shape, func(t *testing.T) { check(t, build(f), f.kind) })
		}
	}
}
