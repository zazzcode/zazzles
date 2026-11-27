package langjs

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Specification 21: a call that passes SQL statement text is recorded whatever the
// driver, with the contract sql-text-v1.

func sqlTextAnalyze(t *testing.T, files map[string]string) []analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	if _, ok := files["package.json"]; !ok {
		files["package.json"] = `{"dependencies":{"express":"4.19.0"}}`
	}
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	return sqlTextRecords(t, root)
}

func sqlTextRecords(t *testing.T, root string) []analysis.CandidateUse {
	t.Helper()
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []analysis.CandidateUse
	seen := map[string]bool{}
	for _, u := range r.Uses {
		if u.Kind != "sql_query_candidate" && u.Kind != "nosql_query_candidate" {
			continue
		}
		key := u.EntryID + "|" + u.Sink.Span.File + "|" + u.Sink.Text
		if seen[key] {
			t.Errorf("two records for one call in one entry: %s", u.Sink.Text)
		}
		seen[key] = true
		out = append(out, u)
	}
	return out
}

func sqlTextHandler(body string) map[string]string {
	return map[string]string{"server.js": "const express=require('express');const app=express();\napp.get('/x', async (req, res) => {\n" + body + "\n})\n"}
}

func slotsOf(u analysis.CandidateUse) map[string]int {
	out := map[string]int{}
	for _, d := range u.Dependencies {
		out[d.SinkSlot]++
	}
	return out
}

func sqlTextByCallee(uses []analysis.CandidateUse, callee string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range uses {
		if strings.HasPrefix(u.Sink.Text, callee+"(") {
			out = append(out, u)
		}
	}
	return out
}

// TestSQLTextRecordDriverForms: every driver form gives exactly one SQL record,
// with the contract the call has, or sql-text-v1 and the text slot when no
// contract records it, and its bound twin the same record with the parameter slot.
func TestSQLTextRecordDriverForms(t *testing.T) {
	type form struct {
		callee, contract string
		boundSlot        string
	}
	forms := []form{
		{"pool.query", analysispacks.SQLTextContract, "sql_parameters"},
		{"conn.query", analysispacks.SQLTextContract, "sql_parameters"},
		{"legacy.query", analysispacks.SQLTextContract, "sql_parameters"},
		{"p.request().query", analysispacks.SQLTextContract, ""}, // the bound twin passes the value to input(), not to query()
		{"conn.execute", analysispacks.SQLTextContract, "sql_parameters"},
		{"lite.all", analysispacks.SQLTextContract, "sql_parameters"},
		{"better.prepare", "better-sqlite3-v1", ""},
		{"knex.raw", analysispacks.SQLTextContract, "sql_parameters"},
		{"sequelize.query", "sequelize-raw-query-v1", "sql_options"},
		{"sql.unsafe", analysispacks.SQLTextContract, "sql_parameters"},
	}
	for _, tc := range []struct {
		dir  string
		text bool
	}{{"text", true}, {"bound", false}} {
		uses := sqlTextRecords(t, filepath.Join("testdata", "sql-text", tc.dir))
		for _, f := range forms {
			got := sqlTextByCallee(uses, f.callee)
			wantSlot := "sql_text"
			if !tc.text {
				wantSlot = f.boundSlot
			}
			if wantSlot == "" {
				// A contract record for better-sqlite3's bound twin carries no value
				// (the value goes to .all()), and mssql's goes to input().
				if len(got) != 0 {
					t.Errorf("%s/%s: %d records, want none", tc.dir, f.callee, len(got))
				}
				continue
			}
			if len(got) != 1 {
				t.Errorf("%s/%s: %d records, want 1", tc.dir, f.callee, len(got))
				continue
			}
			u := got[0]
			if u.APIModel == nil || u.APIModel.ID != f.contract {
				t.Errorf("%s/%s: contract %v, want %s", tc.dir, f.callee, u.APIModel, f.contract)
			}
			slots := slotsOf(u)
			if len(slots) != 1 || slots[wantSlot] == 0 {
				t.Errorf("%s/%s: slots %v, want only %s", tc.dir, f.callee, slots, wantSlot)
			}
		}
	}
}

func TestSQLTextRecordShape(t *testing.T) {
	uses := sqlTextAnalyze(t, sqlTextHandler(`const r = await db.run("SELECT * FROM users WHERE name = '" + req.query.name + "'")
res.json(r)`))
	if len(uses) != 1 {
		t.Fatalf("records %d, want 1", len(uses))
	}
	u := uses[0]
	if u.Kind != "sql_query_candidate" || u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
		t.Fatalf("record %+v", u)
	}
	if slots := slotsOf(u); len(slots) != 1 || slots[analysispacks.SQLTextSlot] != 1 {
		t.Errorf("slots %v", slots)
	}
	c := u.Completeness
	if c == nil {
		t.Fatal("no completeness")
	}
	if binding := c.Evidence["sink_binding"]; len(binding) != 1 || binding[0].Text != "db.run" {
		t.Errorf("sink_binding must be the callee only: %+v", binding)
	}
	if text := c.Evidence["query_text"]; len(text) != 1 || !strings.HasPrefix(text[0].Text, `"SELECT`) {
		t.Errorf("query_text must be the text argument: %+v", text)
	}
	if len(c.Blockers) != 0 {
		t.Errorf("blockers: %+v", c.Blockers)
	}
	var excerpts int
	for _, e := range u.Context {
		if e.Kind == "source_excerpt" {
			excerpts++
			sp := u.Sink.Span
			if e.Span.File != sp.File || e.Span.StartByte > sp.StartByte || e.Span.EndByte < sp.EndByte {
				t.Errorf("excerpt %+v does not contain the sink %+v", e.Span, sp)
			}
			if !strings.Contains(e.Text, "db.run(") {
				t.Errorf("excerpt text lacks the call")
			}
		}
	}
	if excerpts != 1 {
		t.Errorf("source_excerpt evidence %d, want 1", excerpts)
	}
}

func TestSQLTextRecordForms(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		slot string
	}{
		"template literal":             {"await db.run(`SELECT * FROM users WHERE name = '${req.query.name}'`)", "sql_text"},
		"text in a variable":           {"let q = 'SELECT * FROM users'\nq += \" WHERE name = '\" + req.query.name + \"'\"\nawait db.run(q)", "sql_text"},
		"keyword form":                 {"await db.run(\"DELETE FROM users WHERE id = \" + req.body.id)", "sql_text"},
		"escaped newline in the text":  {"await db.run('SELECT *\\nFROM users WHERE id = ' + req.body.id)", "sql_text"},
		"bound value in an array":      {"await db.run('SELECT * FROM users WHERE name = ?', [req.query.name])", "sql_parameters"},
		"bound value, options object":  {"await db.run('SELECT * FROM users WHERE name = :n', { n: req.query.name })", "sql_parameters"},
		"text and value, both request": {"await db.run('SELECT * FROM users WHERE name = ' + req.query.a, [req.query.b])", "sql_text"},
	} {
		t.Run(name, func(t *testing.T) {
			uses := sqlTextAnalyze(t, sqlTextHandler(tc.body))
			if len(uses) != 1 {
				t.Fatalf("records %d, want 1", len(uses))
			}
			u := uses[0]
			if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
				t.Fatalf("contract %v", u.APIModel)
			}
			if slotsOf(u)[tc.slot] == 0 {
				t.Errorf("slots %v, want %s", slotsOf(u), tc.slot)
			}
			if tc.slot == "sql_parameters" && slotsOf(u)["sql_text"] != 0 {
				t.Errorf("the bound case has no text dependency: %v", slotsOf(u))
			}
		})
	}
	t.Run("both slots", func(t *testing.T) {
		u := sqlTextAnalyze(t, sqlTextHandler("await db.run('SELECT * FROM users WHERE name = ' + req.query.a, [req.query.b])"))[0]
		if slotsOf(u)["sql_text"] != 1 || slotsOf(u)["sql_parameters"] != 1 {
			t.Errorf("slots %v", slotsOf(u))
		}
	})
}

// A call with SQL text and no request, stored or session value is not recorded;
// neither is prose that merely starts like a statement.
func TestSQLTextRecordNothing(t *testing.T) {
	for name, body := range map[string]string{
		"constant text":           "await db.run('SELECT * FROM users WHERE id = 1')",
		"constant text, constant": "const id = 1\nawait db.run('SELECT * FROM users WHERE id = ' + id)",
		"prose, log":              "console.log('Select a file from the list ' + req.query.name)",
		"prose, response":         "res.send('Update your settings ' + req.query.name)",
		"prose, delete":           "res.send('Delete from the list ' + req.query.name)",
		"request value only":      "await db.run(req.query.name)",
		"url":                     "await db.run('https://example.com/select?from=' + req.query.name)",
	} {
		t.Run(name, func(t *testing.T) {
			if uses := sqlTextAnalyze(t, sqlTextHandler(body)); len(uses) != 0 {
				t.Fatalf("records %d, want none: %+v", len(uses), uses[0].Sink.Text)
			}
		})
	}
}

// A log or print call that takes SQL text with request data IS recorded: the
// scanner never decides what the call does, the judge's operation question sorts
// it out (a log call is not_database_operation).
func TestSQLTextRecordLogCallIsRecorded(t *testing.T) {
	uses := sqlTextAnalyze(t, sqlTextHandler(`logger.info("SELECT * FROM users WHERE name = '" + req.query.name + "'")`))
	if len(uses) != 1 || uses[0].APIModel == nil || uses[0].APIModel.ID != analysispacks.SQLTextContract {
		t.Fatalf("a log call with SQL text and request data must be recorded: %+v", uses)
	}
}

func TestSQLTextRecordBlockersAndJudgedLimits(t *testing.T) {
	const sink = `await db.run("SELECT * FROM users WHERE name = '" + req.query.name + "'")`
	t.Run("unrelated loop is a judged limit", func(t *testing.T) {
		uses := sqlTextAnalyze(t, sqlTextHandler("for (const x of list) { console.log(x) }\n"+sink))
		if len(uses) != 1 {
			t.Fatalf("records %d", len(uses))
		}
		c := uses[0].Completeness
		if len(c.Blockers) != 0 {
			t.Errorf("blockers: %+v", c.Blockers)
		}
		if len(c.Judged) == 0 {
			t.Errorf("a flow-wide limit is expected as judged")
		}
		for _, g := range c.Judged {
			if !gapKind(c.Coverage, g.Kind) {
				t.Errorf("judged limit %s is not in the coverage the model reads", g.Kind)
			}
		}
	})
	t.Run("unresolved value in the text is a blocker", func(t *testing.T) {
		uses := sqlTextAnalyze(t, sqlTextHandler(`await db.run("SELECT * FROM users WHERE name = '" + mystery(req.query.name) + "'")`))
		if len(uses) != 1 {
			t.Fatalf("records %d", len(uses))
		}
		if len(uses[0].Completeness.Blockers) == 0 {
			t.Errorf("an unresolved call on the value in the text must block: %+v", uses[0].Completeness)
		}
	})
}

// A dependency whose evidence lies in another file gets a source_excerpt of that
// file only when no context evidence of an allowed kind covers it; here the helper
// definition does, so the record carries the one excerpt of the sink's file.
func TestSQLTextRecordExcerptOfAnotherFile(t *testing.T) {
	files := sqlTextHandler(`await db.run("SELECT * FROM users WHERE name = '" + norm(req.query.name) + "'")`)
	files["server.js"] = "const { norm } = require('./helpers')\n" + files["server.js"]
	files["helpers.js"] = "function norm(v) {\n  return v\n}\nmodule.exports = { norm }\n" + strings.Repeat("// padding line to keep the helper file large\n", 400)
	uses := sqlTextAnalyze(t, files)
	if len(uses) != 1 {
		t.Fatalf("records %d", len(uses))
	}
	u := uses[0]
	excerpts := 0
	for _, e := range u.Context {
		if e.Kind == "source_excerpt" {
			excerpts++
		}
	}
	if excerpts != 1 {
		t.Errorf("source_excerpt evidence %d, want 1", excerpts)
	}
	for _, d := range u.Dependencies {
		for _, e := range append([]analysis.Evidence{d.Source}, d.Transfers...) {
			if e.Span.File != u.Sink.Span.File && !sqlTextCovered(u.Context, e.Span) {
				t.Errorf("evidence in %s is covered by no context evidence", e.Span.File)
			}
		}
	}
}

// A file larger than the whole-file limit is excerpted as a window around the call.
func TestSQLTextRecordExcerptWindow(t *testing.T) {
	pad := strings.Repeat("// padding line to make the file larger than the whole-file limit\n", 400)
	files := map[string]string{"server.js": "const express=require('express');const app=express();\n" + pad +
		"app.get('/x', async (req, res) => {\n  await db.run(\"SELECT * FROM users WHERE name = '\" + req.query.name + \"'\")\n})\n" + pad}
	u := sqlTextAnalyze(t, files)[0]
	for _, e := range u.Context {
		if e.Kind != "source_excerpt" {
			continue
		}
		sp := u.Sink.Span
		if e.Span.File != sp.File || e.Span.StartByte > sp.StartByte || e.Span.EndByte < sp.EndByte {
			t.Fatalf("excerpt %+v does not contain the sink %+v", e.Span, sp)
		}
		if len(e.Text) >= len(files["server.js"]) {
			t.Fatalf("the excerpt is the whole large file")
		}
		return
	}
	t.Fatal("no source_excerpt")
}

// D-1: the record of a method named query that no contract binds becomes a text
// record when its text argument is SQL statement text, and stays as it was when
// it is not.
func TestSQLTextRecordContractlessQuery(t *testing.T) {
	t.Run("sql text", func(t *testing.T) {
		uses := sqlTextAnalyze(t, sqlTextHandler(`db.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows))`))
		if len(uses) != 1 {
			t.Fatalf("records %d", len(uses))
		}
		u := uses[0]
		if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract {
			t.Fatalf("contract %v", u.APIModel)
		}
		if gapKind(u.Completeness.Blockers, "sink_binding_unverified") || gapKind(u.Gaps, "sink_binding_unverified") {
			t.Errorf("the text record has no sink_binding_unverified")
		}
		if b := u.Completeness.Evidence["sink_binding"]; len(b) != 1 || b[0].Text != "db.query" {
			t.Errorf("sink_binding %+v", b)
		}
		if len(u.Completeness.Blockers) != 0 {
			t.Errorf("blockers %+v", u.Completeness.Blockers)
		}
		if slotsOf(u)["sql_text"] != 1 || len(slotsOf(u)) != 1 {
			t.Errorf("slots %v", slotsOf(u))
		}
	})
	t.Run("bound twin", func(t *testing.T) {
		u := sqlTextAnalyze(t, sqlTextHandler(`db.query("SELECT * FROM users WHERE name = ?", [req.query.name], (err, rows) => res.json(rows))`))[0]
		if u.APIModel == nil || u.APIModel.ID != analysispacks.SQLTextContract || len(slotsOf(u)) != 1 || slotsOf(u)["sql_parameters"] != 1 {
			t.Errorf("record %v slots %v", u.APIModel, slotsOf(u))
		}
	})
	for name, body := range map[string]string{
		"key, not sql":      "cache.query(req.query.key)",
		"prose argument":    "cache.query('Select a file from the list ' + req.query.key)",
		"unresolved helper": "db.query(buildText(req.query.key))",
	} {
		t.Run("stays: "+name, func(t *testing.T) {
			uses := sqlTextAnalyze(t, sqlTextHandler(body))
			if len(uses) != 1 {
				t.Fatalf("records %d", len(uses))
			}
			u := uses[0]
			if u.APIModel != nil {
				t.Errorf("contract %v, want none", u.APIModel)
			}
			if !gapKind(u.Completeness.Blockers, "sink_binding_unverified") {
				t.Errorf("sink_binding_unverified blocker missing: %+v", u.Completeness.Blockers)
			}
			if slotsOf(u)["sql_text"] == 0 {
				t.Errorf("slots %v", slotsOf(u))
			}
			for _, e := range u.Context {
				if e.Kind == "source_excerpt" {
					t.Errorf("an unchanged record has no source_excerpt")
				}
			}
		})
	}
}
