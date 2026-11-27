package langpy

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// sqlTextAnalyze analyzes a fixture directory and returns its SQL records by the
// line of the call.
func sqlTextAnalyze(t *testing.T, root string) map[int][]analysis.CandidateUse {
	t.Helper()
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	out := map[int][]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			out[u.Sink.Span.StartLine] = append(out[u.Sink.Span.StartLine], u)
		}
	}
	return out
}

func sqlTextSlots(u analysis.CandidateUse) []string {
	seen := map[string]bool{}
	for _, d := range u.Dependencies {
		seen[d.SinkSlot] = true
	}
	var out []string
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sqlTextModelID(u analysis.CandidateUse) string {
	if u.APIModel == nil {
		return ""
	}
	return u.APIModel.ID
}

// sqlTextWant is the expected record of one call: the contract id and the slots
// its dependencies carry.
type sqlTextWant struct {
	model string
	slot  string
}

func checkSQLTextRecords(t *testing.T, got map[int][]analysis.CandidateUse, want map[int]sqlTextWant) {
	t.Helper()
	for line, w := range want {
		uses := got[line]
		if len(uses) != 1 {
			t.Errorf("line %d: %d records, want exactly 1", line, len(uses))
			continue
		}
		if id := sqlTextModelID(uses[0]); id != w.model {
			t.Errorf("line %d: contract %q, want %q", line, id, w.model)
		}
		if s := sqlTextSlots(uses[0]); len(s) != 1 || s[0] != w.slot {
			t.Errorf("line %d: slots %v, want [%s]", line, s, w.slot)
		}
	}
	for line, uses := range got {
		if _, ok := want[line]; !ok {
			t.Errorf("line %d: unexpected %d record(s) (%s)", line, len(uses), sqlTextModelID(uses[0]))
		}
	}
}

// TestPythonSQLTextDriverForms: every driver form that no contract records is
// one sql-text-v1 record, text case in slot sql_text and its bound twin in slot
// sql_parameters; a contract-recorded call keeps its contract and gains no second
// record. The forms are in testdata/sql-text/swap and swap-safe.
func TestPythonSQLTextDriverForms(t *testing.T) {
	const text = analysispacks.SQLTextContract
	root := filepath.Join("testdata", "sql-text")
	checkSQLTextRecords(t, sqlTextAnalyze(t, filepath.Join(root, "swap")), map[int]sqlTextWant{
		26: {"python-sqlite3-dbapi-v1", "sql_text"}, 34: {"python-psycopg2-dbapi-v1", "sql_text"},
		42: {"python-pymysql-dbapi-v1", "sql_text"}, 50: {"python-mysql.connector-dbapi-v1", "sql_text"},
		58: {text, "sql_text"}, 66: {text, "sql_text"}, 74: {text, "sql_text"}, 82: {text, "sql_text"},
		89: {text, "sql_text"},
	})
	checkSQLTextRecords(t, sqlTextAnalyze(t, filepath.Join(root, "swap-safe")), map[int]sqlTextWant{
		26: {"python-sqlite3-dbapi-v1", "sql_parameters"}, 34: {"python-psycopg2-dbapi-v1", "sql_parameters"},
		42: {"python-pymysql-dbapi-v1", "sql_parameters"}, 50: {"python-mysql.connector-dbapi-v1", "sql_parameters"},
		58: {text, "sql_parameters"}, 66: {text, "sql_parameters"}, 74: {text, "sql_parameters"}, 82: {text, "sql_parameters"},
		89: {text, "sql_parameters"},
	})
}

// TestPythonSQLTextForms: forms of the text argument and of the call, in
// testdata/sql-text/extra. The log and print calls take SQL text with request
// data and ARE recorded: the judge's operation question sorts a log line from a
// database call, the recorder does not name logging functions.
func TestPythonSQLTextForms(t *testing.T) {
	const text = analysispacks.SQLTextContract
	got := sqlTextAnalyze(t, filepath.Join("testdata", "sql-text", "extra"))
	checkSQLTextRecords(t, got, map[int]sqlTextWant{
		15: {text, "sql_text"}, // f-string
		21: {text, "sql_text"}, // % operator
		29: {text, "sql_text"}, // module constant with .format in a nested function
		36: {text, "sql_text"}, // keyword argument text
		43: {text, "sql_text"}, // variable built with +=
		48: {text, "sql_text"}, // log call, recorded
		49: {text, "sql_text"}, // print call, recorded
		60: {text, "sql_parameters"},
		67: {text, "sql_parameters"}, // text in a variable, bound value in a keyword argument
		73: {text, "sql_text"},       // keyword text on a contract driver: no contract record, one text record
		74: {"python-sqlite3-dbapi-v1", "sql_parameters"},
		81: {text, "sql_text"}, 82: {text, "sql_text"}, 83: {text, "sql_text"}, 84: {text, "sql_text"},
	})
	// No request data and no SQL text statements: /nodeps (line 55) and the
	// non-statements at the end of /stmts (lines 85, 86).
	for _, line := range []int{55, 85, 86} {
		if len(got[line]) != 0 {
			t.Errorf("line %d: recorded", line)
		}
	}
}

func sqlTextSingle(t *testing.T, files map[string]string) analysis.CandidateUse {
	t.Helper()
	got := sqlTextAnalyze(t, pythonFixture(t, files))
	var all []analysis.CandidateUse
	for _, uses := range got {
		all = append(all, uses...)
	}
	if len(all) != 1 {
		t.Fatalf("%d records, want 1", len(all))
	}
	return all[0]
}

const sqlTextHead = "from flask import Flask, request\nimport duckdb\napp = Flask(__name__)\n@app.get('/')\ndef entry():\n    db = duckdb.connect()\n"

func TestPythonSQLTextNoRecord(t *testing.T) {
	for name, body := range map[string]string{
		"SQL text, no request data": "    db.execute(\"SELECT * FROM users WHERE name = 'a'\")\n    return 'ok'\n",
		"prose, not SQL":            "    print('Select a file from the list ' + request.args.get('n'))\n    print('Update your settings, ' + request.args.get('n'))\n    return 'ok'\n",
		"request data, no text":     "    db.execute(request.args.get('n'))\n    return 'ok'\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := sqlTextAnalyze(t, pythonFixture(t, map[string]string{"main.py": sqlTextHead + body})); len(got) != 0 {
				t.Fatalf("recorded: %v", got)
			}
		})
	}
}

// TestPythonSQLTextBlockersAndJudged: an unresolved value in the text is a
// blocker; a limit elsewhere in the entry flow is a judged limit, never a blocker.
func TestPythonSQLTextBlockersAndJudged(t *testing.T) {
	const call = "    db.execute(\"SELECT * FROM users WHERE name = '\" + request.args.get('n') + \"'\")\n    return 'ok'\n"
	t.Run("unrelated loop is a judged limit", func(t *testing.T) {
		u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + "    for i in range(3):\n        print(i)\n" + call})
		c := u.Completeness
		if len(c.Blockers) != 0 || pyGapKinds(c.Judged)["python_loop_unresolved"] != 1 {
			t.Fatalf("blockers %v judged %v", pyGapKinds(c.Blockers), pyGapKinds(c.Judged))
		}
	})
	t.Run("unresolved value in the text is a blocker", func(t *testing.T) {
		u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + "    n = request.args.get('n') + undefined_name\n    db.execute(\"SELECT * FROM users WHERE name = '\" + n + \"'\")\n    return 'ok'\n"})
		if len(u.Completeness.Blockers) == 0 {
			t.Fatal("no blocker")
		}
	})
	t.Run("clean call has neither", func(t *testing.T) {
		u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + call})
		if len(u.Completeness.Blockers) != 0 || len(u.Completeness.Judged) != 0 {
			t.Fatalf("blockers %v judged %v", pyGapKinds(u.Completeness.Blockers), pyGapKinds(u.Completeness.Judged))
		}
	})
}

// TestPythonSQLTextEvidence: the sink binding is the callee only, the query text
// is the text argument, and a source_excerpt of the sink's file holds the sink.
// The source of every dependency is held by some evidence the judge sends.
func TestPythonSQLTextEvidence(t *testing.T) {
	u := sqlTextSingle(t, map[string]string{
		"main.py":   "from flask import Flask\nimport duckdb\nfrom helper import name_arg\napp = Flask(__name__)\n@app.get('/')\ndef entry():\n    db = duckdb.connect()\n    db.execute(\"SELECT * FROM users WHERE name = '\" + name_arg() + \"'\")\n    return 'ok'\n",
		"helper.py": "from flask import request\n\n\ndef name_arg():\n    return request.args.get('n')\n",
	})
	if sqlTextModelID(u) != analysispacks.SQLTextContract {
		t.Fatalf("contract %q", sqlTextModelID(u))
	}
	c := u.Completeness
	if b := c.Evidence["sink_binding"]; len(b) != 1 || b[0].Text != "db.execute" {
		t.Errorf("sink_binding %v", b)
	}
	if q := c.Evidence["query_text"]; len(q) != 1 || q[0].Text != "\"SELECT * FROM users WHERE name = '\" + name_arg() + \"'\"" {
		t.Errorf("query_text %v", q)
	}
	allowed := map[string]bool{"handler": true, "invoked_callable": true, "helper_definition": true, "selected_callable": true, "validation_schema": true, "validation_control": true, "condition_helper": true, "referenced_definition": true, parse.SQLTextSourceExcerptKind: true}
	covers := func(sp analysis.Span) bool {
		for _, e := range u.Context {
			if allowed[e.Kind] && e.Span.File == sp.File && e.Span.StartByte <= sp.StartByte && e.Span.EndByte >= sp.EndByte {
				return true
			}
		}
		return false
	}
	if !covers(u.Sink.Span) {
		t.Errorf("no sent evidence holds the sink %v", u.Sink.Span)
	}
	excerpt := false
	for _, e := range u.Context {
		excerpt = excerpt || (e.Kind == parse.SQLTextSourceExcerptKind && e.Span.File == u.Sink.Span.File && e.Span.StartByte <= u.Sink.Span.StartByte && e.Span.EndByte >= u.Sink.Span.EndByte)
	}
	if !excerpt {
		t.Error("no source_excerpt holds the sink")
	}
	// The source of the dependency is in helper.py and is held by the helper's
	// definition, so no second excerpt is needed; the judge still gets it.
	for _, d := range u.Dependencies {
		if !covers(d.Source.Span) {
			t.Errorf("no sent evidence holds the dependency source %v", d.Source.Span)
		}
	}
}

// TestPythonSQLTextWrapperShape: a call that only wraps the statement text is
// known by its shape, a single string argument, and by no name. The call that
// takes the wrapper is the record, once; a wrapper passed to a plain function
// keeps the record itself.
func TestPythonSQLTextWrapperShape(t *testing.T) {
	const q = "\"SELECT * FROM users WHERE name = '\" + request.args.get('n') + \"'\""
	for name, c := range map[string]struct{ body, sink string }{
		"wrapper with a name no list holds": {"    return str(db.execute(statement_of(" + q + ")).fetchall())\n", "db.execute(statement_of("},
		"wrapper reached by attribute":      {"    return str(db.execute(duckdb.anything(" + q + ")).fetchall())\n", "db.execute(duckdb.anything("},
		"wrapper around a variable":         {"    q = " + q + "\n    return str(db.execute(wrap(q)).fetchall())\n", "db.execute(wrap(q))"},
		"wrapper with bound values":         {"    return str(db.execute(wrap(\"SELECT * FROM users WHERE name = ?\"), [request.args.get('n')]).fetchall())\n", "db.execute(wrap("},
		"plain function around the call":    {"    return str(db.sql(" + q + "))\n", "db.sql("},
		"result passed to a method":         {"    rows = []\n    rows.append(db.execute(" + q + "))\n    return 'ok'\n", "rows.append(db.execute("},
	} {
		t.Run(name, func(t *testing.T) {
			u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + c.body})
			if sqlTextModelID(u) != analysispacks.SQLTextContract {
				t.Fatalf("contract %q", sqlTextModelID(u))
			}
			if len(u.Sink.Text) < len(c.sink) || u.Sink.Text[:len(c.sink)] != c.sink {
				t.Fatalf("record at %q, want the call starting %q", u.Sink.Text, c.sink)
			}
		})
	}
}

// sqlTextFollowCases are the forms the text hook follows beyond one expression:
// a join, a list built by append, a helper, a constant of another module. Each is
// a body that goes after sqlTextHead; text is the injectable form and bound its
// twin with the request value passed apart from the statement.
var sqlTextFollowCases = map[string]struct {
	files        map[string]string
	text, bound  string
	sink         string
	definitionIn string
}{
	"join of a list": {
		text:  "    return str(db.execute(\" \".join([\"SELECT * FROM users WHERE name = '\", request.args.get('n'), \"'\"])).fetchall())\n",
		bound: "    return str(db.execute(\" \".join([\"SELECT * FROM users\", \"WHERE name = ?\"]), [request.args.get('n')]).fetchall())\n",
	},
	"join of a tuple with a separator variable": {
		text:  "    sep = ' '\n    return str(db.execute(sep.join((\"SELECT * FROM users WHERE\", \"name = '\" + request.args.get('n') + \"'\"))).fetchall())\n",
		bound: "    sep = ' '\n    return str(db.execute(sep.join((\"SELECT * FROM users WHERE\", \"name = ?\")), [request.args.get('n')]).fetchall())\n",
	},
	"join of a list built by append": {
		text:  "    parts = ['SELECT * FROM users WHERE name =']\n    parts.append(\"'\" + request.args.get('n') + \"'\")\n    return str(db.execute(' '.join(parts)).fetchall())\n",
		bound: "    parts = ['SELECT * FROM users']\n    parts.append('WHERE name = ?')\n    return str(db.execute(' '.join(parts), [request.args.get('n')]).fetchall())\n",
	},
	"helper of the same file": {
		text:  "    def build(n):\n        return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n    return str(db.execute(build(request.args.get('n'))).fetchall())\n",
		bound: "    def build():\n        return \"SELECT * FROM users WHERE name = ?\"\n    return str(db.execute(build(), [request.args.get('n')]).fetchall())\n",
	},
	"helper with two returns, one SQL": {
		text:  "    def build(n):\n        if not n:\n            return 'Select a name from the list'\n        return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n    return str(db.execute(build(request.args.get('n'))).fetchall())\n",
		bound: "    def build(n):\n        if not n:\n            return 'Select a name from the list'\n        return 'SELECT * FROM users WHERE name = ?'\n    return str(db.execute(build(1), [request.args.get('n')]).fetchall())\n",
	},
	"helper of another file": {
		files: map[string]string{"helper.py": "def build(n):\n    return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n\n\ndef bound():\n    return 'SELECT * FROM users WHERE name = ?'\n"},
		text:  "    return str(db.execute(build(request.args.get('n'))).fetchall())\n",
		bound: "    return str(db.execute(bound(), [request.args.get('n')]).fetchall())\n", definitionIn: "helper.py",
	},
	"constant of another file": {
		files: map[string]string{"q.py": "SQL = \"SELECT * FROM users WHERE name = '{}'\"\nBOUND = 'SELECT * FROM users WHERE name = ?'\n"},
		text:  "    return str(db.execute(SQL.format(request.args.get('n'))).fetchall())\n",
		bound: "    return str(db.execute(BOUND, [request.args.get('n')]).fetchall())\n", definitionIn: "q.py",
	},
	"constant of a module reached by attribute": {
		files: map[string]string{"q.py": "SQL = \"SELECT * FROM users WHERE name = '\"\nBOUND = 'SELECT * FROM users WHERE name = ?'\n"},
		text:  "    return str(db.execute(q.SQL + request.args.get('n') + \"'\").fetchall())\n",
		bound: "    return str(db.execute(q.BOUND, [request.args.get('n')]).fetchall())\n", definitionIn: "q.py",
	},
	"class attribute of another file": {
		files: map[string]string{"q.py": "class Queries:\n    BY_NAME = \"SELECT * FROM users WHERE name = '{}'\"\n    BOUND = 'SELECT * FROM users WHERE name = ?'\n"},
		text:  "    return str(db.execute(Queries.BY_NAME.format(request.args.get('n'))).fetchall())\n",
		bound: "    return str(db.execute(Queries.BOUND, [request.args.get('n')]).fetchall())\n", definitionIn: "q.py",
	},
	"method of a class of the same file": {
		files: map[string]string{"main.py": "from flask import Flask, request\nimport duckdb\napp = Flask(__name__)\n\n\nclass Repo:\n    @staticmethod\n    def build(n):\n        return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n\n\n@app.get('/')\ndef entry():\n    db = duckdb.connect()\n    return str(db.execute(Repo.build(request.args.get('n'))).fetchall())\n"},
	},
}

func sqlTextFollowFiles(c struct {
	files        map[string]string
	text, bound  string
	sink         string
	definitionIn string
}, body string) map[string]string {
	files := map[string]string{}
	for k, v := range c.files {
		files[k] = v
	}
	if _, own := files["main.py"]; !own {
		head := sqlTextHead
		switch {
		case c.definitionIn == "helper.py":
			head = "from helper import build, bound\n" + head
		case c.definitionIn == "q.py" && strings.Contains(c.files["q.py"], "class "):
			head = "from q import Queries\n" + head
		case c.definitionIn == "q.py" && strings.Contains(body, "q."):
			head = "import q\n" + head
		case c.definitionIn == "q.py":
			head = "from q import SQL, BOUND\n" + head
		}
		files["main.py"] = head + body
	}
	return files
}

// TestPythonSQLTextFollow: a join, a helper and a constant of another module each
// give exactly one record, text in slot sql_text and its bound twin in slot
// sql_parameters. The statement text a helper or a constant holds reaches the
// judge as context evidence of the definition.
func TestPythonSQLTextFollow(t *testing.T) {
	for name, c := range sqlTextFollowCases {
		t.Run(name, func(t *testing.T) {
			if c.text == "" {
				u := sqlTextSingle(t, c.files)
				if sqlTextModelID(u) != analysispacks.SQLTextContract || sqlTextSlots(u)[0] != "sql_text" {
					t.Fatalf("contract %q slots %v", sqlTextModelID(u), sqlTextSlots(u))
				}
				return
			}
			u := sqlTextSingle(t, sqlTextFollowFiles(c, c.text))
			if sqlTextModelID(u) != analysispacks.SQLTextContract || len(sqlTextSlots(u)) != 1 || sqlTextSlots(u)[0] != "sql_text" {
				t.Fatalf("text: contract %q slots %v", sqlTextModelID(u), sqlTextSlots(u))
			}
			if c.definitionIn != "" {
				held := false
				for _, e := range u.Context {
					switch e.Kind {
					case "helper_definition", "referenced_definition", parse.SQLTextSourceExcerptKind:
						held = held || (e.Span.File == c.definitionIn && strings.Contains(e.Text, "SELECT"))
					}
				}
				if !held {
					t.Errorf("no context evidence holds the definition in %s", c.definitionIn)
				}
			}
			b := sqlTextSingle(t, sqlTextFollowFiles(c, c.bound))
			if sqlTextModelID(b) != analysispacks.SQLTextContract || len(sqlTextSlots(b)) != 1 || sqlTextSlots(b)[0] != "sql_parameters" {
				t.Fatalf("bound: contract %q slots %v", sqlTextModelID(b), sqlTextSlots(b))
			}
		})
	}
}

// TestPythonSQLTextFollowNoRecord: the followed forms give nothing without request
// data, for prose, and past the helper depth.
func TestPythonSQLTextFollowNoRecord(t *testing.T) {
	for name, body := range map[string]string{
		"join, no request data":   "    return str(db.execute(' '.join(['SELECT * FROM users', \"WHERE name = 'a'\"])).fetchall())\n",
		"join of prose":           "    print(' '.join(['Select a file from the list', request.args.get('n')]))\n    return 'ok'\n",
		"helper, no request data": "    def build():\n        return \"SELECT * FROM users WHERE name = 'a'\"\n    return str(db.execute(build()).fetchall())\n",
		"helper of prose":         "    def build(n):\n        return 'Select a file from the list ' + n\n    print(build(request.args.get('n')))\n    return 'ok'\n",
		"two helper levels":       "    def inner(n):\n        return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n\n    def outer(n):\n        return inner(n, 1)\n    return str(db.execute(outer(request.args.get('n'))).fetchall())\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := sqlTextAnalyze(t, pythonFixture(t, map[string]string{"main.py": sqlTextHead + body})); len(got) != 0 {
				t.Fatalf("recorded: %v", got)
			}
		})
	}
}

// TestPythonSQLTextPlacement: the statement_shape evidence says where each hole
// sits in the text; a text with no hole has none.
func TestPythonSQLTextPlacement(t *testing.T) {
	for name, c := range map[string]struct{ body, model string }{
		"outside quotes":   {"    return str(db.execute(\"SELECT * FROM users WHERE id = \" + request.args.get('n')).fetchall())\n", "{1}: outside quotes"},
		"inside quotes":    {"    return str(db.execute(\"SELECT * FROM users WHERE name = '\" + request.args.get('n') + \"'\").fetchall())\n", "{1}: inside a single-quoted literal"},
		"through a join":   {"    return str(db.execute(' '.join(['SELECT * FROM users WHERE id =', request.args.get('n')])).fetchall())\n", "{1}: outside quotes"},
		"through a helper": {"    def b(n):\n        return \"SELECT * FROM users WHERE name = '\" + n + \"'\"\n    return str(db.execute(b(request.args.get('n'))).fetchall())\n", "{1}: inside a single-quoted literal"},
	} {
		t.Run(name, func(t *testing.T) {
			u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + c.body})
			e := u.Completeness.Evidence[parse.SQLTextPlacementKind]
			if len(e) != 1 || e[0].ModelText != c.model {
				t.Fatalf("placement %v, want %q", e, c.model)
			}
		})
	}
	for name, body := range map[string]string{
		"bound twin with a placeholder": "    return str(db.execute('SELECT * FROM users WHERE name = ?', [request.args.get('n')]).fetchall())\n",
		"percent formatting":            "    return str(db.execute(\"SELECT * FROM users WHERE name = '%s'\" % request.args.get('n')).fetchall())\n",
	} {
		t.Run(name, func(t *testing.T) {
			u := sqlTextSingle(t, map[string]string{"main.py": sqlTextHead + body})
			if e := u.Completeness.Evidence[parse.SQLTextPlacementKind]; len(e) != 0 {
				t.Fatalf("placement %v", e)
			}
		})
	}
}
