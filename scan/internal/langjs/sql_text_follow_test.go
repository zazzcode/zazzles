package langjs

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Specification 21 follow-up: SQL text built by a join, returned by a helper,
// imported from another file, a statement prepared apart from the call that binds
// the value, and a tagged template.

func followFiles(pre, body string) map[string]string {
	return map[string]string{"server.js": "const express=require('express');const app=express();\n" + pre + "\napp.get('/x', async (req, res) => {\n" + body + "\n})\n"}
}

func followRecords(t *testing.T, pre, body string) []analysis.CandidateUse {
	t.Helper()
	return sqlTextAnalyze(t, followFiles(pre, body))
}

// expectOne asserts exactly one sql-text-v1 record with only the given slot.
func expectOne(t *testing.T, uses []analysis.CandidateUse, slot string) analysis.CandidateUse {
	t.Helper()
	if len(uses) != 1 {
		t.Fatalf("records %d, want 1: %+v", len(uses), sinks(uses))
	}
	u := uses[0]
	if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
		t.Fatalf("contract %v", u.APIModel)
	}
	if slots := slotsOf(u); len(slots) != 1 || slots[slot] == 0 {
		t.Fatalf("slots %v, want only %s", slots, slot)
	}
	return u
}

func sinks(uses []analysis.CandidateUse) []string {
	var out []string
	for _, u := range uses {
		out = append(out, u.Sink.Text)
	}
	return out
}

// sinkCovered reports the judge's requirement: the sink lies inside one context
// evidence of an allowed kind with the same file string.
func sinkCovered(u analysis.CandidateUse) bool { return sqlTextCovered(u.Context, u.Sink.Span) }

func contextOf(u analysis.CandidateUse, kind string) []analysis.Evidence {
	var out []analysis.Evidence
	for _, e := range u.Context {
		if e.Kind == kind {
			out = append(out, e)
		}
	}
	return out
}

func TestSQLTextFollowJoin(t *testing.T) {
	for name, tc := range map[string]struct {
		pre, body, slot string
	}{
		"literal list, text":      {"", `await db.run(["SELECT * FROM users", "WHERE name = '" + req.query.name + "'"].join(" "))`, "sql_text"},
		"separator in a name":     {"const SEP = ' '", `await db.run(["SELECT * FROM users", "WHERE id = " + req.query.id].join(SEP))`, "sql_text"},
		"element a request value": {"", `await db.run(["SELECT * FROM users WHERE id =", req.query.id].join(" "))`, "sql_text"},
		"list in a name, push":    {"", "const parts = ['SELECT * FROM users']\nparts.push('WHERE id = ' + req.query.id)\nawait db.run(parts.join(' '))", "sql_text"},
		"concat":                  {"", `await db.run("SELECT * FROM users WHERE id = ".concat(req.query.id))`, "sql_text"},
		"bound twin":              {"", `await db.run(["SELECT * FROM users", "WHERE name = ?"].join(" "), [req.query.name])`, "sql_parameters"},
		"bound twin, push":        {"", "const parts = ['SELECT * FROM users']\nparts.push('WHERE id = ?')\nawait db.run(parts.join(' '), [req.query.id])", "sql_parameters"},
	} {
		t.Run(name, func(t *testing.T) {
			u := expectOne(t, followRecords(t, tc.pre, tc.body), tc.slot)
			if !sinkCovered(u) {
				t.Errorf("sink not covered by context")
			}
		})
	}
	for name, body := range map[string]string{
		"no request data":     `await db.run(["SELECT * FROM users", "WHERE id = 1"].join(" "))`,
		"prose":               `res.send(["Select a file", "from the list", req.query.n].join(" "))`,
		"list is a parameter": "function f(parts) { return db.run(parts.join(' ')) }\nawait f(['SELECT * FROM users WHERE id = ', req.query.id])",
		"list from a call":    `await db.run(mystery().join(" ") + req.query.id)`,
		"concat on a list":    `await db.run(["a"].concat(["SELECT * FROM users WHERE id = "]).join(" ") + req.query.id)`,
	} {
		t.Run("none: "+name, func(t *testing.T) {
			if uses := followRecords(t, "", body); len(uses) != 0 {
				t.Fatalf("records %d, want none: %v", len(uses), sinks(uses))
			}
		})
	}
}

func TestSQLTextFollowHelper(t *testing.T) {
	const build = "function build(id) { return 'SELECT * FROM users WHERE id = ' + id }"
	t.Run("text", func(t *testing.T) {
		u := expectOne(t, followRecords(t, build, `await db.run(build(req.query.id))`), "sql_text")
		if !sinkCovered(u) {
			t.Errorf("sink not covered")
		}
	})
	t.Run("arrow, expression body", func(t *testing.T) {
		expectOne(t, followRecords(t, "const build = (id) => `SELECT * FROM users WHERE id = ${id}`", `await db.run(build(req.query.id))`), "sql_text")
	})
	t.Run("bound twin", func(t *testing.T) {
		expectOne(t, followRecords(t, "function sqlFor() { return 'SELECT * FROM users WHERE id = ?' }", `await db.run(sqlFor(), [req.query.id])`), "sql_parameters")
	})
	t.Run("two returns, SQL second", func(t *testing.T) {
		pre := "function build(id) { if (!id) { return 'nothing to say' }\n return 'SELECT * FROM users WHERE id = ' + id }"
		expectOne(t, followRecords(t, pre, `await db.run(build(req.query.id))`), "sql_text")
	})
	t.Run("two returns, SQL first", func(t *testing.T) {
		pre := "function build(id) { if (id) { return 'SELECT * FROM users WHERE id = ' + id }\n return 'nothing to say' }"
		expectOne(t, followRecords(t, pre, `await db.run(build(req.query.id))`), "sql_text")
	})
	t.Run("method of an object literal", func(t *testing.T) {
		pre := "const Q = { byId(id) { return 'SELECT * FROM users WHERE id = ' + id } }"
		expectOne(t, followRecords(t, pre, `await db.run(Q.byId(req.query.id))`), "sql_text")
	})
	t.Run("module constant used by the helper", func(t *testing.T) {
		pre := "const BASE = 'SELECT * FROM users WHERE id = '\nfunction build(id) { return BASE + id }"
		u := expectOne(t, followRecords(t, pre, `await db.run(build(req.query.id))`), "sql_text")
		if u.Completeness.Evidence[parse.SQLTextPlacementKind] == nil {
			t.Errorf("the placement of the hole is missing")
		}
	})
	t.Run("a parameter is not the module name of the same spelling", func(t *testing.T) {
		pre := "const base = 'SELECT * FROM users WHERE id = '\nfunction build(base) { return base }"
		if uses := followRecords(t, pre, `await db.run(build(req.query.id))`); len(uses) != 0 {
			t.Fatalf("records %d, want none", len(uses))
		}
	})
	for name, tc := range map[string]struct{ pre, body string }{
		"no request data":   {build, `await db.run(build(1))`},
		"prose helper":      {"function say(n) { return 'Select a file from the list ' + n }", `res.send(say(req.query.n))`},
		"helper not SQL":    {"function key(id) { return 'user:' + id }", `await db.run(key(req.query.id))`},
		"helper not found":  {"", `await db.run(missing(req.query.id))`},
		"helper, no return": {"function build(id) { console.log(id) }", `await db.run(build(req.query.id))`},
		// One helper level: a helper that returns another helper's text is a hole.
		"depth limit": {"function inner(id) { return 'SELECT * FROM users WHERE id = ' + id }\nfunction outer(id) { return inner(id) }", `await db.run(outer(req.query.id))`},
	} {
		t.Run("none: "+name, func(t *testing.T) {
			// db.run is not a driver: a call is recorded only when SQL text is read.
			for _, u := range followRecords(t, tc.pre, tc.body) {
				t.Fatalf("record %v, want none", u.Sink.Text)
			}
		})
	}
}

// holds reports a context evidence of an allowed kind, in file, that contains text.
func holds(u analysis.CandidateUse, file, text string) bool {
	for _, e := range u.Context {
		if sqlTextEvidenceKinds[e.Kind] && e.Span.File == file && strings.Contains(e.Text, text) {
			return true
		}
	}
	return false
}

func TestSQLTextFollowDefinitionEvidence(t *testing.T) {
	pad := strings.Repeat("// padding line to keep the file larger than the whole-file limit of an excerpt\n", 300)
	t.Run("helper, same file, outside the excerpt", func(t *testing.T) {
		files := map[string]string{"server.js": "const express=require('express');const app=express();\nfunction build(id) { return 'SELECT * FROM users WHERE id = ' + id }\n" + pad +
			"app.get('/x', async (req, res) => {\n  await db.run(build(req.query.id))\n})\n" + pad}
		u := expectOne(t, sqlTextAnalyze(t, files), "sql_text")
		if !holds(u, "server.js", "function build") || !sinkCovered(u) {
			t.Fatalf("the helper's definition and the sink must be held: %+v", u.Context)
		}
	})
	t.Run("helper, other file", func(t *testing.T) {
		files := map[string]string{
			"server.js":  "const express=require('express');const app=express();\nconst { build } = require('./queries')\napp.get('/x', async (req, res) => {\n  await db.run(build(req.query.id))\n})\n",
			"queries.js": "function build(id) {\n  return 'SELECT * FROM users WHERE id = ' + id\n}\nmodule.exports = { build }\n",
		}
		u := expectOne(t, sqlTextAnalyze(t, files), "sql_text")
		if !holds(u, "queries.js", "function build") || !sinkCovered(u) {
			t.Fatalf("the helper's definition and the sink must be held: %+v", u.Context)
		}
	})
	t.Run("constant, same file, outside the excerpt: referenced_definition", func(t *testing.T) {
		files := map[string]string{"server.js": "const express=require('express');const app=express();\nconst BASE = 'SELECT * FROM users WHERE id = '\n" + pad +
			"app.get('/x', async (req, res) => {\n  await db.run(BASE + req.query.id)\n})\n" + pad}
		u := expectOne(t, sqlTextAnalyze(t, files), "sql_text")
		defs := contextOf(u, "referenced_definition")
		if len(defs) != 1 || !strings.Contains(defs[0].Text, "const BASE") || defs[0].Span.File != u.Sink.Span.File {
			t.Fatalf("referenced_definition %+v", defs)
		}
		if !sinkCovered(u) {
			t.Errorf("sink not covered")
		}
	})
	t.Run("constant, other file: an excerpt of that file", func(t *testing.T) {
		files := map[string]string{
			"server.js": "const express=require('express');const app=express();\nconst { SQL } = require('./q')\napp.get('/x', async (req, res) => {\n  await db.run(SQL + req.query.id)\n})\n",
			"q.js":      "module.exports = { SQL: 'SELECT * FROM users WHERE id = ' }\n",
		}
		u := expectOne(t, sqlTextAnalyze(t, files), "sql_text")
		var found bool
		for _, e := range contextOf(u, "source_excerpt") {
			found = found || e.Span.File == "q.js" && strings.Contains(e.Text, "SELECT")
		}
		if !found {
			t.Fatalf("no source_excerpt of q.js: %+v", u.Context)
		}
	})
}

func TestSQLTextFollowOtherModule(t *testing.T) {
	handler := "const express=require('express');const app=express();\n%s\napp.get('/x', async (req, res) => {\n%s\n})\n"
	mk := func(imp, body string) string {
		return strings.Replace(strings.Replace(handler, "%s", imp, 1), "%s", body, 1)
	}
	for name, tc := range map[string]struct {
		files map[string]string
		slot  string
	}{
		"destructured require, constant": {map[string]string{
			"server.js": mk("const { SQL } = require('./q')", "await db.run(SQL + req.query.id)"),
			"q.js":      "module.exports = { SQL: 'SELECT * FROM users WHERE id = ' }",
		}, "sql_text"},
		"exports assignment": {map[string]string{
			"server.js": mk("const { SQL } = require('./q')", "await db.run(SQL + req.query.id)"),
			"q.js":      "exports.SQL = 'SELECT * FROM users WHERE id = '",
		}, "sql_text"},
		"require member": {map[string]string{
			"server.js":  mk("", "await db.run(require('./queries').byName + req.query.id)"),
			"queries.js": "module.exports = { byName: 'SELECT * FROM users WHERE name = ' }",
		}, "sql_text"},
		"namespace object": {map[string]string{
			"server.js":  mk("const queries = require('./queries')", "await db.run(queries.byName + req.query.id)"),
			"queries.js": "module.exports = { byName: 'SELECT * FROM users WHERE name = ' }",
		}, "sql_text"},
		"esm named import": {map[string]string{
			"server.js": "import express from 'express'\nimport { q } from './q'\nconst app = express()\napp.get('/x', async (req, res) => {\n  await db.run(q + req.query.id)\n})\n",
			"q.js":      "export const q = 'SELECT * FROM users WHERE id = '",
		}, "sql_text"},
		"esm namespace": {map[string]string{
			"server.js": "import express from 'express'\nimport * as Q from './q'\nconst app = express()\napp.get('/x', async (req, res) => {\n  await db.run(Q.byId + req.query.id)\n})\n",
			"q.js":      "export const byId = 'SELECT * FROM users WHERE id = '",
		}, "sql_text"},
		"imported text, bound twin": {map[string]string{
			"server.js": mk("const { SQL } = require('./q')", "await db.run(SQL, [req.query.id])"),
			"q.js":      "module.exports = { SQL: 'SELECT * FROM users WHERE id = ?' }",
		}, "sql_parameters"},
		"object constant in the same file": {map[string]string{
			"server.js": mk("const Q = { byId: 'SELECT * FROM users WHERE id = ' }", "await db.run(Q.byId + req.query.id)"),
		}, "sql_text"},
	} {
		t.Run(name, func(t *testing.T) {
			u := expectOne(t, sqlTextAnalyze(t, tc.files), tc.slot)
			if !sinkCovered(u) {
				t.Errorf("sink not covered")
			}
			if len(tc.files) > 1 && name != "object constant in the same file" {
				var other string
				for f := range tc.files {
					if f != "server.js" && f != "package.json" {
						other = f
					}
				}
				found := false
				for _, e := range u.Context {
					if sqlTextEvidenceKinds[e.Kind] && e.Span.File == other && strings.Contains(e.Text, "SELECT") {
						found = true
					}
				}
				if !found {
					t.Errorf("no context evidence holds the definition in %s", other)
				}
			}
		})
	}
	for name, files := range map[string]map[string]string{
		"imported text, no request data": {
			"server.js": mk("const { SQL } = require('./q')", "await db.run(SQL + 1)"),
			"q.js":      "module.exports = { SQL: 'SELECT * FROM users WHERE id = ' }",
		},
		"imported prose": {
			"server.js": mk("const { SAY } = require('./q')", "res.send(SAY + req.query.id)"),
			"q.js":      "module.exports = { SAY: 'Select a file from the list ' }",
		},
		"export not found": {
			"server.js": mk("const { SQL } = require('./q')", "await db.run(SQL + req.query.id)"),
			"q.js":      "module.exports = { OTHER: 'SELECT * FROM users WHERE id = ' }",
		},
		"import cycle": {
			"server.js": mk("const { A } = require('./a')", "await db.run(A + req.query.id)"),
			"a.js":      "const { B } = require('./b')\nexports.A = B",
			"b.js":      "const { A } = require('./a')\nexports.B = A",
		},
	} {
		t.Run("none: "+name, func(t *testing.T) {
			if uses := sqlTextAnalyze(t, files); len(uses) != 0 {
				t.Fatalf("records %d, want none: %v", len(uses), sinks(uses))
			}
		})
	}
}

func TestSQLTextFollowPrepared(t *testing.T) {
	t.Run("one record, value in a separate call", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "const st = db.prepare('SELECT * FROM users WHERE id = ?')\nconst r = st.get(req.query.id)\nres.json(r)"), "sql_parameters")
		if !strings.HasPrefix(u.Sink.Text, "st.get(") {
			t.Errorf("sink %q", u.Sink.Text)
		}
		c := u.Completeness
		if b := c.Evidence["sink_binding"]; len(b) != 1 || b[0].Text != "st.get" {
			t.Errorf("sink_binding %+v", b)
		}
		if q := c.Evidence["query_text"]; len(q) != 1 || !strings.Contains(q[0].Text, "SELECT * FROM users WHERE id = ?") {
			t.Errorf("query_text must be the text argument of the preparing call: %+v", q)
		}
		if c.Evidence[parse.SQLTextPlacementKind] != nil {
			t.Errorf("a text with no hole has no placement")
		}
		if !sinkCovered(u) {
			t.Errorf("sink not covered")
		}
	})
	t.Run("later calls on the statement add dependencies", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "const st = db.prepare('SELECT * FROM users WHERE id = ? AND n = ?')\nst.get(req.query.a)\nst.all(req.query.b)"), "sql_parameters")
		if len(u.Dependencies) != 2 {
			t.Errorf("dependencies %d, want 2: %+v", len(u.Dependencies), u.Dependencies)
		}
		if u.Sink.Text != "st.get(req.query.a)" {
			t.Errorf("sink is the first call that carries data: %q", u.Sink.Text)
		}
	})
	t.Run("two statements, two records", func(t *testing.T) {
		uses := followRecords(t, "", "const a = db.prepare('SELECT * FROM users WHERE id = ?')\nconst b = db.prepare('DELETE FROM users WHERE id = ?')\na.get(req.query.a)\nb.run(req.query.b)")
		if len(uses) != 2 {
			t.Fatalf("records %d, want 2", len(uses))
		}
	})
	t.Run("assigned later", func(t *testing.T) {
		expectOne(t, followRecords(t, "", "let st\nst = db.prepare('SELECT * FROM users WHERE id = ?')\nst.run(req.query.id)"), "sql_parameters")
	})
	t.Run("module-level literal statement", func(t *testing.T) {
		expectOne(t, followRecords(t, "const st = db.prepare('SELECT * FROM users WHERE id = ?')", "st.get(req.query.id)"), "sql_parameters")
	})
	t.Run("a text case at the preparing call is the only record", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "const st = db.prepare('SELECT * FROM users WHERE id = ' + req.query.id)\nst.run(req.query.x)"), "sql_text")
		if !strings.HasPrefix(u.Sink.Text, "db.prepare(") {
			t.Errorf("sink %q", u.Sink.Text)
		}
	})
	t.Run("a contract records the preparing call", func(t *testing.T) {
		files := followFiles("const Database = require('better-sqlite3')\nconst better = new Database('b.db')", "const st = better.prepare('SELECT * FROM users WHERE id = ?')\nst.get(req.query.id)")
		files["package.json"] = `{"dependencies":{"express":"4.19.0","better-sqlite3":"9.0.0"}}`
		for _, u := range sqlTextAnalyze(t, files) {
			t.Errorf("record %s (%v), a contract owns this statement", u.Sink.Text, u.APIModel)
		}
	})
	for name, tc := range map[string]struct{ pre, body string }{
		"no request data":         {"", "const st = db.prepare('SELECT * FROM users WHERE id = ?')\nst.get(1)"},
		"prepared text is prose":  {"", "const st = db.prepare('Select a file from the list')\nst.get(req.query.id)"},
		"module-level, a hole":    {"const T = mystery()\nconst st = db.prepare('SELECT * FROM ' + T + ' WHERE id = ?')", "st.get(req.query.id)"},
		"receiver not prepared":   {"", "const st = makeStatement()\nst.get(req.query.id)"},
		"receiver is a parameter": {"", "function run(st) { return st.get(req.query.id) }\nrun(db.prepare('SELECT * FROM users WHERE id = ?'))"},
	} {
		t.Run("none: "+name, func(t *testing.T) {
			for _, u := range followRecords(t, tc.pre, tc.body) {
				t.Fatalf("record %s, want none", u.Sink.Text)
			}
		})
	}
}

func TestSQLTextFollowTaggedTemplate(t *testing.T) {
	check := func(t *testing.T, u analysis.CandidateUse, tag string) {
		t.Helper()
		c := u.Completeness
		if c == nil {
			t.Fatal("no completeness")
		}
		if marks := c.Evidence["template_tag"]; len(marks) != 1 || marks[0].Text != tag || marks[0].Kind != "template_tag" {
			t.Errorf("template_tag %+v, want %s", marks, tag)
		}
		if !sinkCovered(u) {
			t.Errorf("sink not covered")
		}
		if gapKind(u.Gaps, "query_text_interpolated") {
			t.Errorf("the scanner does not say a tagged template interpolates")
		}
	}
	t.Run("tag", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "await sql`SELECT * FROM users WHERE id = ${req.query.id}`"), "sql_text")
		check(t, u, "sql")
		if !strings.HasPrefix(u.Sink.Text, "sql`SELECT") {
			t.Errorf("sink %q is the tagged template", u.Sink.Text)
		}
		if b := u.Completeness.Evidence["sink_binding"]; len(b) != 1 || b[0].Text != "sql" {
			t.Errorf("sink_binding is the tag: %+v", b)
		}
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(p) != 1 || p[0].ModelText != "{1}: outside quotes" {
			t.Errorf("placement %+v", p)
		}
	})
	t.Run("member tag", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "await db.sql`SELECT * FROM users WHERE name = '${req.query.n}'`"), "sql_text")
		check(t, u, "db.sql")
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(p) != 1 || p[0].ModelText != "{1}: inside a single-quoted literal" {
			t.Errorf("placement %+v", p)
		}
	})
	t.Run("as the text argument of a call, one record at the call", func(t *testing.T) {
		u := expectOne(t, followRecords(t, "", "await db.run(sql`SELECT * FROM users WHERE id = ${req.query.id}`)"), "sql_text")
		check(t, u, "sql")
		if !strings.HasPrefix(u.Sink.Text, "db.run(") {
			t.Errorf("sink %q", u.Sink.Text)
		}
		if b := u.Completeness.Evidence["sink_binding"]; len(b) != 1 || b[0].Text != "db.run" {
			t.Errorf("sink_binding %+v", b)
		}
	})
	t.Run("tag function defined in the source", func(t *testing.T) {
		pad := strings.Repeat("// padding line to keep the file larger than the whole-file limit of an excerpt\n", 300)
		files := map[string]string{"server.js": "const express=require('express');const app=express();\nfunction sql(strings, ...v) { return strings.join('?') }\n" + pad +
			"app.get('/x', async (req, res) => {\n  await db.run(sql`SELECT * FROM users WHERE id = ${req.query.id}`)\n})\n" + pad}
		u := expectOne(t, sqlTextAnalyze(t, files), "sql_text")
		check(t, u, "sql")
		if !holds(u, "server.js", "function sql(") {
			t.Fatalf("the tag function's definition is held by no context evidence: %+v", u.Context)
		}
	})
	t.Run("a call of the template and a plain call are different", func(t *testing.T) {
		// A tagged template inside another call's helper-free argument list of a
		// non-SQL call is still recorded at that call: the judge sorts it.
		uses := followRecords(t, "", "logger.info(sql`SELECT * FROM users WHERE id = ${req.query.id}`)")
		if len(uses) != 1 || !strings.HasPrefix(uses[0].Sink.Text, "logger.info(") {
			t.Fatalf("records %v", sinks(uses))
		}
	})
	for name, body := range map[string]string{
		"no request data": "await sql`SELECT * FROM users WHERE id = ${1}`",
		"not SQL":         "await tag`hello ${req.query.id}`",
		"prose":           "await tag`Select a file from the list ${req.query.id}`",
	} {
		t.Run("none: "+name, func(t *testing.T) {
			if uses := followRecords(t, "", body); len(uses) != 0 {
				t.Fatalf("records %v, want none", sinks(uses))
			}
		})
	}
}

// Item 7: the placement of each hole in the statement text.
func TestSQLTextPlacementEvidence(t *testing.T) {
	for name, tc := range map[string]struct{ body, want string }{
		"outside quotes":       {`await db.run("SELECT * FROM users WHERE id = " + req.query.id)`, "{1}: outside quotes"},
		"inside single quotes": {`await db.run("SELECT * FROM users WHERE n = '" + req.query.n + "'")`, "{1}: inside a single-quoted literal"},
		"template":             {"await db.run(`SELECT * FROM users WHERE n = '${req.query.n}' AND id = ${req.query.id}`)", "{1}: inside a single-quoted literal\n{2}: outside quotes"},
		"join":                 {`await db.run(["SELECT * FROM users WHERE n = '", req.query.n, "'"].join(""))`, "{1}: inside a single-quoted literal"},
	} {
		t.Run(name, func(t *testing.T) {
			u := sqlTextAnalyze(t, sqlTextHandler(tc.body))[0]
			p := u.Completeness.Evidence[parse.SQLTextPlacementKind]
			if len(p) != 1 || p[0].ModelText != tc.want || p[0].Kind != parse.SQLTextPlacementKind {
				t.Fatalf("placement %+v, want %q", p, tc.want)
			}
		})
	}
	t.Run("bound case with a hole in the text", func(t *testing.T) {
		u := sqlTextAnalyze(t, sqlTextHandler("await db.run('SELECT * FROM ' + table + ' WHERE id = ?', [req.query.id])"))[0]
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(p) != 1 || p[0].ModelText != "{1}: outside quotes" {
			t.Fatalf("placement %+v", p)
		}
	})
	t.Run("text with no hole", func(t *testing.T) {
		u := sqlTextAnalyze(t, sqlTextHandler("await db.run('SELECT * FROM users WHERE id = ?', [req.query.id])"))[0]
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; p != nil {
			t.Fatalf("placement %+v, want none", p)
		}
	})
	t.Run("a contract-less query record that becomes a text record", func(t *testing.T) {
		u := sqlTextAnalyze(t, sqlTextHandler(`db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows))`))[0]
		if p := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(p) != 1 || p[0].ModelText != "{1}: inside a single-quoted literal" {
			t.Fatalf("placement %+v", p)
		}
	})
}

// The fixture application holds every form once, injectable, bound and with
// nothing to record.
func TestSQLTextFollowFixture(t *testing.T) {
	uses := sqlTextRecords(t, "testdata/sql-text/follow")
	got := map[string]string{}
	for _, u := range uses {
		got[u.Sink.Text] = strings.Join(sortedSlots(u), ",")
	}
	want := map[string]string{
		"db.run(['SELECT * FROM users', \"WHERE name = '\" + req.query.name + \"'\"].join(' '))": "sql_text",
		"db.run(['SELECT * FROM users', 'WHERE name = ?'].join(' '), [req.query.name])":          "sql_parameters",
		"db.run(build(req.query.id))":                                       "sql_text",
		"db.run(byIdBound(), [req.query.id])":                               "sql_parameters",
		"db.run(byId(req.query.id))":                                        "sql_text",
		"db.run(BY_NAME + req.query.name + \"'\")":                          "sql_text",
		"st.get(req.query.id)":                                              "sql_parameters",
		"prepared.get(req.query.id)":                                        "sql_parameters",
		"sql`SELECT * FROM users WHERE id = ${req.query.id}`":               "sql_text",
		"db.run(sql`SELECT * FROM users WHERE name = '${req.query.name}'`)": "sql_text",
	}
	for sink, slots := range want {
		if got[sink] != slots {
			t.Errorf("%s: slots %q, want %q", sink, got[sink], slots)
		}
	}
	if len(got) != len(want) {
		t.Errorf("records %d, want %d: %v", len(got), len(want), got)
	}
}

func sortedSlots(u analysis.CandidateUse) []string {
	var out []string
	for s := range slotsOf(u) {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
