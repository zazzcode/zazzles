package langpy

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"testing"
)

func TestEntrySelectors(t *testing.T) {
	for _, tc := range []struct{ name, file, source string }{
		{"python", "app.py", "from flask import Flask, request\nimport sqlite3\napp=Flask(__name__)\n@app.route('/same')\ndef view():\n    db=sqlite3.connect('test.db')\n    return db.execute('SELECT '+request.args.get('email')).fetchall()\n"},
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
}
