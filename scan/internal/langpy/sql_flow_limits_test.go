package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func pyGapKinds(gaps []analysis.Gap) map[string]int {
	out := map[string]int{}
	for _, g := range gaps {
		out[g.Kind]++
	}
	return out
}

func pySQLRecords(t *testing.T, body string) []analysis.CandidateUse {
	t.Helper()
	const head = "from flask import Flask,request\nimport sqlite3\napp=Flask(__name__)\n@app.get('/')\ndef entry():\n    c=sqlite3.connect('d')\n    cur=c.cursor()\n"
	r, err := Analyze(pythonFixture(t, map[string]string{"main.py": head + body}), "")
	if err != nil {
		t.Fatal(err)
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			out = append(out, u)
		}
	}
	return out
}

// TestPythonSQLFlowWideLimits: a loop elsewhere in the entry flow is a judged
// limit of a SQL record, not a blocker. A request value assigned or changed in
// a loop body does not carry the loop's gap (it is on the flow only), so such
// a record also holds the loop as a judged limit and has no blocker.
func TestPythonSQLFlowWideLimits(t *testing.T) {
	const injectable = `cur.execute("select * from u where n = '%s'" % name)`
	for name, body := range map[string]string{
		"unrelated loop, injectable query": "    name=request.args.get('name')\n    for i in range(3):\n        print(i)\n    " + injectable + "\n    return 'ok'\n",
		"value changed in the loop":        "    name=request.args.get('name')\n    for i in range(3):\n        name=name+'x'\n    " + injectable + "\n    return 'ok'\n",
		"value assigned in the loop":       "    while x:\n        name=request.args.get('name')\n    " + injectable + "\n    return 'ok'\n",
		"query inside the loop":            "    for i in range(3):\n        name=request.args.get('name')\n        " + injectable + "\n    return 'ok'\n",
		"bound query, unrelated loop":      "    for i in range(3):\n        print(i)\n    cur.execute('select * from u where n = ?', (request.args.get('name'),))\n    return 'ok'\n",
	} {
		t.Run(name, func(t *testing.T) {
			uses := pySQLRecords(t, body)
			if len(uses) != 1 {
				t.Fatalf("records %d, want 1", len(uses))
			}
			c := uses[0].Completeness
			if len(c.Blockers) != 0 {
				t.Errorf("blockers: %v", pyGapKinds(c.Blockers))
			}
			if pyGapKinds(c.Judged)["python_loop_unresolved"] != 1 {
				t.Errorf("judged limits: %v", pyGapKinds(c.Judged))
			}
			if pyGapKinds(c.Coverage)["python_loop_unresolved"] != 1 {
				t.Errorf("the judged limit is not in the coverage the model reads: %v", pyGapKinds(c.Coverage))
			}
		})
	}
	t.Run("no loop, no judged limit", func(t *testing.T) {
		uses := pySQLRecords(t, "    name=request.args.get('name')\n    "+injectable+"\n    return 'ok'\n")
		if len(uses) != 1 || len(uses[0].Completeness.Judged) != 0 || len(uses[0].Completeness.Blockers) != 0 {
			t.Fatalf("%d records", len(uses))
		}
	})
	t.Run("value limit stays a blocker", func(t *testing.T) {
		uses := pySQLRecords(t, "    name=request.args.get('name')+undefined_name\n    "+injectable+"\n    return 'ok'\n")
		if len(uses) != 1 || len(uses[0].Completeness.Blockers) == 0 {
			t.Fatalf("%d records", len(uses))
		}
	})
}
