package langpy

import (
	"bytes"
	"encoding/json"
	"github.com/zazzcode/zazzles/internal/analysis"
	"testing"
)

func TestPythonEvidence(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask, request, jsonify, render_template, render_template_string
from markupsafe import escape, Markup
import sqlite3, logging, requests
app = Flask(__name__)
@app.route('/unsafe/<name>')
def unsafe(name):
    connection = sqlite3.connect('test.db')
    cursor = connection.cursor()
    q = "select * from people where name = '%s'" % name
    cursor.execute(q)
    cursor.execute('select * from people where name = ?', (name,))
    logging.error(request.headers.get('Authorization'))
    logging.info(len(request.args.get('password')))
    requests.get(request.args.get('url'))
    return '<p>' + name + '</p>'
@app.get('/json')
def json_control():
    return jsonify(data=request.args.get('name'))
@app.get('/escaped')
def escaped():
    return render_template('view.html', name=request.args.get('name'))
@app.get('/dynamic')
def dynamic():
    name = request.args.get('name')
    return render_template_string(f'<p>{name}</p>')
@app.get('/branch')
def branch():
    name = request.args.get('name')
    if request.args.get('escape'):
        content = escape(name)
    else:
        content = name
    return content
@app.get('/unknown')
def unknown():
    return custom_mask(request.args.get('name'))
`, "templates/view.html": `<p>{{ name }}</p><p>{{ name | safe }}</p><script>{{ name }}</script>`})
	r, err := Analyze(root, "app.py")
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string][]analysis.CandidateUse{}
	for _, u := range r.Uses {
		for _, e := range r.Entries {
			if u.EntryID == e.HTTPRoute().ID {
				byPath[e.HTTPRoute().PathPattern] = append(byPath[e.HTTPRoute().PathPattern], u)
			}
		}
	}
	sql := 0
	logs := 0
	out := 0
	for _, u := range byPath["/unsafe/<name>"] {
		switch u.Kind {
		case "sql_query_candidate":
			sql++
			if u.APIModel == nil || len(u.Dependencies) == 0 {
				t.Error("SQL binding/dependencies missing")
			}
		case "log_sink_candidate":
			logs++
		case "outbound_http_candidate", "ssrf_candidate":
			// A request-derived destination is an SSRF claim, still one outbound destination.
			out++
		}
	}
	if sql != 2 || logs != 2 || out != 1 {
		t.Errorf("sink counts SQL=%d logs=%d outbound=%d", sql, logs, out)
	}
	if len(pythonXSSOnly(byPath["/json"])) != 0 {
		t.Error("JSON falsely emitted as HTML")
	}
	want := []string{"encoded", "raw", "unknown"}
	var got []string
	for _, u := range byPath["/escaped"] {
		if u.XSS != nil {
			got = append(got, u.XSS.Protection)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("template outputs %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("template %d = %s want %s", i, got[i], want[i])
		}
	}
	for _, p := range []string{"/dynamic", "/branch"} {
		claims := pythonXSSOnly(byPath[p])
		if len(claims) != 1 || claims[0].XSS.Protection != "raw" {
			t.Errorf("unsafe %s: %#v", p, byPath[p])
		}
	}
	unknown := pythonXSSOnly(byPath["/unknown"])
	if len(unknown) != 1 || unknown[0].XSS.Protection != "unknown" {
		t.Error("unknown helper became safe/raw")
	}
}

func TestPythonExceptionAndHelperFlows(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask, request
from helpers import connect, html
app=Flask(__name__)
@app.get('/exception')
def exception():
    x=request.args.get('name')
    try:
        raise ValueError()
    except ValueError:
        return x + ' failed'
@app.get('/helper')
def helper():
    c=connect()
    cursor=c.cursor()
    cursor.execute('select * from people where name = ?', (request.args.get('name'),))
    return html(request.args.get('name'))
`, "helpers.py": `import sqlite3
from markupsafe import escape
def connect():
    c=sqlite3.connect(':memory:')
    return c
def html(name):
    return escape(name)
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, encoded, sql := 0, 0, 0
	for _, u := range r.Uses {
		if u.XSS != nil {
			if u.XSS.Protection == "raw" {
				raw++
			}
			if u.XSS.Protection == "encoded" {
				encoded++
			}
		}
		if u.Kind == "sql_query_candidate" {
			sql++
		}
	}
	if raw != 1 || encoded != 1 || sql != 1 {
		t.Fatalf("raw=%d encoded=%d SQL=%d uses=%#v", raw, encoded, sql, r.Uses)
	}
}

func pythonXSSOnly(uses []analysis.CandidateUse) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range uses {
		if u.XSS != nil {
			out = append(out, u)
		}
	}
	return out
}

func TestPythonBindingControls(t *testing.T) {
	for _, tt := range []struct {
		name, prefix, body string
		want               string
	}{
		{"plain escape", "", "return escape(request.args.get('name'))", "encoded"},
		{"shadowed encoder", "def escape(x):\n    return x\n", "return escape(request.args.get('name'))", "raw"},
		{"parameter shadow", "", "escape = custom\n    return escape(request.args.get('name'))", "unknown"},
		{"raw wrapper", "", "return Markup(request.args.get('name'))", "raw"},
		{"escaped sibling unknown", "", "name=request.args.get('name')\n    if request.args.get('mode'):\n        content=escape(name)\n    else:\n        content=custom(name)\n    return content", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"app.py": "from flask import Flask,request\nfrom markupsafe import escape,Markup\napp=Flask(__name__)\n" + tt.prefix + "@app.get('/input')\ndef input():\n    " + tt.body + "\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := pythonXSSOnly(r.Uses)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want {
				t.Fatalf("got %#v want %s", uses, tt.want)
			}
		})
	}
}

func TestPythonLoggingControls(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask,request
import logging
app=Flask(__name__)
@app.get('/logs')
def logs():
    password=request.form.get('password')
    email=request.form.get('email')
    print(password)
    logging.info(email)
    logging.warning(request.headers.get('Authorization'))
    print(len(password))
    logging.info('admin@example.org')
    logging.info(request.args.get('ordinary'))
    return 'ok'
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	logs := 0
	for _, u := range r.Uses {
		if u.Kind != "log_sink_candidate" {
			continue
		}
		logs++
		for _, g := range u.Gaps {
			counts[g.Kind]++
		}
	}
	if logs != 5 || counts["log_sensitive_field_hint"] != 3 || counts["log_non_content_only"] != 1 || counts["log_protocol_credential"] != 1 {
		t.Fatalf("logs=%d facts=%v", logs, counts)
	}
}

func TestPythonImportedSQLSinkAndDeterminism(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask,request
from store import lookup
app=Flask(__name__)
@app.get('/people')
def people():
    lookup(request.args.get('name'))
    return 'ok'
`, "store.py": `import sqlite3
def lookup(name):
    c=sqlite3.connect(':memory:')
    c.execute('select * from people where name = ' + name)
`})
	first, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("Python evidence is nondeterministic")
	}
	sql := kindUse(t, first, "sql_query_candidate")
	if sql.Sink.Span.File != "store.py" || sql.Completeness.Evidence["invoked_callable"][0].Span.File != "app.py" {
		t.Error("helper/handler snapshots confused")
	}
}

func TestPythonOutboundOperandRoles(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request
import requests,httpx
app=Flask(__name__)
@app.post('/')
def index():
    requests.post('https://fixed.example', data=request.json)
    requests.request('GET',request.args.get('url'))
    httpx.get(url=request.args.get('url2'))
    return 'ok'
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, u := range r.Uses {
		switch u.Kind {
		case "outbound_http_candidate":
			t.Fatalf("a request destination stayed an observation, or a body-only call was recorded: %s", u.Sink.Text)
		case "ssrf_candidate":
			count++
			for _, d := range u.Dependencies {
				if d.SinkSlot != "destination" || d.Source.Text == "request.json" {
					t.Fatalf("non-destination dependency on the SSRF claim: %+v", d)
				}
			}
		}
	}
	if count != 2 {
		t.Fatalf("destinations=%d", count)
	}
}

func TestPythonFormPolicyIsNotEnforcement(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request,render_template
import sqlite3
app=Flask(__name__)
@app.route('/signup',methods=['POST'])
def signup():
    email=request.form.get('email')
    c=sqlite3.connect(':memory:')
    c.execute('INSERT INTO users (email) VALUES (?)',(email,))
    return render_template('signup.html')
`, "templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`})
	r, err := Analyze(root, "a.py")
	if err != nil {
		t.Fatal(err)
	}
	u := kindUse(t, r, "sql_query_candidate")
	found := false
	for _, e := range u.Context {
		found = found || e.Kind == "form_field_requirement"
	}
	if !found || u.Check == nil {
		t.Fatal("source-backed form policy missing")
	}
	if !gapKind(u.Gaps, "input_validation_absent") {
		t.Fatal("browser form mistaken for server validation")
	}
}

func TestPythonMethodFeasibility(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request
import sqlite3
app=Flask(__name__)
@app.route('/input',methods=['GET','POST'])
def input():
    if request.method == 'POST':
        c=sqlite3.connect(':memory:')
        c.execute('select ' + request.form.get('value'))
    return 'ok'
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	methods := map[string]string{}
	for _, e := range r.Entries {
		methods[e.HTTPRoute().ID] = e.HTTPRoute().Method
	}
	count := 0
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			count++
			if methods[u.EntryID] != "POST" {
				t.Error("POST-only SQL attributed to GET")
			}
		}
	}
	if count != 1 {
		t.Fatalf("SQL count %d", count)
	}
}

func TestPythonGuardPrecisionAndKeywordHelper(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request
import sqlite3
app=Flask(__name__)
def echo(value: str):
    return value
@app.get('/guard')
def guard():
    name=request.args.get('name')
    externalValidate(name)
    c=sqlite3.connect(':memory:')
    c.execute('select ' + name)
    return name
@app.get('/unrelated')
def unrelated():
    name=request.args.get('name')
    externalValidate(request.args.get('other'))
    c=sqlite3.connect(':memory:')
    c.execute('select ' + name)
    return echo(value=name)
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, e := range r.Entries {
		paths[e.HTTPRoute().ID] = e.HTTPRoute().PathPattern
	}
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			blocked := gapKind(u.Completeness.Blockers, "input_helper_unresolved")
			if blocked != (paths[u.EntryID] == "/guard") {
				t.Errorf("guard blocker on %s = %v", paths[u.EntryID], blocked)
			}
		}
		if u.XSS != nil && paths[u.EntryID] == "/unrelated" && u.XSS.Protection != "raw" {
			t.Error("keyword helper lost raw value")
		}
	}
}

func TestPythonTryTerminationAndFinally(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request
app=Flask(__name__)
@app.get('/dead')
def dead():
    name=request.args.get('name')
    try:
        return 'ok'
    except ValueError:
        return 'fallback'
    return name
@app.get('/finally')
def override():
    name=request.args.get('name')
    try:
        return name
    finally:
        return 'overridden'
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range pythonXSSOnly(r.Uses) {
		if u.XSS.Protection != "unknown" || !gapKind(u.Gaps, "python_finally_unresolved") {
			t.Fatal("unreachable/overridden return became raw rendering claim")
		}
	}
}
