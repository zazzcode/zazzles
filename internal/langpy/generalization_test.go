package langpy

import (
	"strings"
	"testing"
)

func TestPythonGeneralizationBranches(t *testing.T) {
	for _, tt := range []struct{ name, body, want string }{
		{"raw plus unknown fallback", "return name or external_value", "raw"},
		{"dictionary raw sibling", "if mode:\n        obj={'value':escape(name)}\n    else:\n        obj={'value':name}\n    return obj['value']", "raw"},
		{"dictionary unknown sibling", "if mode:\n        obj={'value':escape(name)}\n    else:\n        obj={'value':external_value}\n    return obj['value']", "unknown"},
		{"unknown output alternative", "return escape(name) if mode else external_value", "unknown"},
		{"both dictionary values escaped", "if mode:\n        obj={'value':escape(name)}\n    else:\n        obj={'value':escape(name)}\n    return obj['value']", "encoded"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"main.py": "from flask import Flask,request\nfrom markupsafe import escape\napp=Flask(__name__)\n@app.get('/')\ndef entry():\n    name=request.args.get('name')\n    mode=request.args.get('mode')\n    " + tt.body + "\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := pythonXSSOnly(r.Uses)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want {
				t.Fatalf("rendering count=%d want %s; actual=%v", len(uses), tt.want, func() string {
					if len(uses) > 0 {
						return uses[0].XSS.Protection
					}
					return "missing"
				}())
			}
		})
	}
}

func TestPythonPackageImports(t *testing.T) {
	root := pythonFixture(t, map[string]string{"web/__init__.py": "", "web/helpers.py": "def echo(value):\n    return value\n", "web/main.py": `from flask import Flask,request
from . import helpers
app=Flask(__name__)
@app.get('/')
def index():
    return helpers.echo(request.args.get('name'))
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := pythonXSSOnly(r.Uses)
	if len(uses) != 1 || uses[0].XSS.Protection != "raw" {
		t.Fatal("relative package helper failed to resolve raw return")
	}
}

func TestPythonValidationPolicyClaims(t *testing.T) {
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request,render_template
import sqlite3
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    note=request.form.get('note')
    c=sqlite3.connect(':memory:')
    c.execute('INSERT INTO users (email) VALUES (?)',(email,))
    return render_template('signup.html')
`, "templates/signup.html": `<form method="POST" action="{{ url_for('signup') }}"><input name="email" type="email" required><input name="note"></form>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	claims, legacy := 0, 0
	for _, u := range r.Uses {
		if u.Kind != "input_validation_candidate" {
			continue
		}
		if u.Completeness != nil {
			claims++
			if !strings.Contains(u.Check.Validation, "email format") {
				t.Fatal("missing exact format policy")
			}
			if u.Check.Fields[0] != "form.email" || len(u.Completeness.Evidence["field_policy"]) != 1 {
				t.Fatal("borrowed field policy")
			}
		} else {
			legacy++
		}
	}
	if claims != 1 || legacy != 1 {
		t.Fatalf("claims=%d legacy=%d", claims, legacy)
	}
}

func TestPythonDBAPIBindings(t *testing.T) {
	for _, driver := range []string{"sqlite3", "psycopg", "psycopg2", "pymysql", "mysql.connector"} {
		t.Run(driver, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"main.py": "from flask import Flask,request\nimport " + driver + "\napp=Flask(__name__)\n@app.get('/')\ndef entry():\n    c=" + driver + ".connect('demo')\n    cur=c.cursor()\n    cur.execute('select * from users where name = %s',(request.args.get('name'),))\n    cur.execute(\"select * from users where name = '%s'\" % request.args.get('name'))\n    return 'ok'\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				count++
				if u.APIModel == nil || u.APIModel.Library != driver {
					t.Fatal("driver provenance lost")
				}
				want := "sql_parameters"
				if gapKind(u.Gaps, "query_text_interpolated") {
					want = "sql_text"
				}
				if u.Dependencies[0].SinkSlot != want {
					t.Fatalf("wrong SQL operand: %+v", u.Dependencies)
				}
			}
			if count != 2 {
				t.Fatalf("SQL uses=%d", count)
			}
		})
	}
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request
import psycopg
app=Flask(__name__)
@app.get('/')
def entry():
    psycopg = fake
    c=psycopg.connect('demo')
    c.cursor().execute(request.args.get('name'))
    return 'ok'
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			t.Fatal("shadowed driver became verified SQL")
		}
	}
}
func TestPythonRequestAlias(t *testing.T) {
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request
app=Flask(__name__)
@app.get('/')
def entry():
    r=request
    return r.args.get('name')
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u := pythonXSSOnly(r.Uses)
	if len(u) != 1 || u[0].XSS.Protection != "raw" {
		t.Fatal("request alias lost")
	}
}
func TestPythonUnknownHelperParameters(t *testing.T) {
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request
app=Flask(__name__)
def helper(*args):
    return args[0]
@app.get('/')
def entry():
    return helper(request.args.get('name'))
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u := pythonXSSOnly(r.Uses)
	if len(u) != 1 || u[0].XSS.Protection != "unknown" || !gapKind(u[0].Gaps, "python_parameter_unresolved") {
		t.Fatal("unsupported helper lost source or uncertainty")
	}
}

func TestPythonJinjaConstantTemplateRepair(t *testing.T) {
	for _, tt := range []struct{ option, want string }{{"", "raw"}, {",autoescape=True", "encoded"}, {",autoescape=False", "raw"}, {",autoescape=configuration", "unknown"}} {
		t.Run(tt.option, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"main.py": "from flask import Flask,request\nfrom jinja2 import Template\napp=Flask(__name__)\n@app.get('/')\ndef entry():\n    return Template('<p>{{ name }}</p>'" + tt.option + ").render(name=request.args.get('name'))\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			u := pythonXSSOnly(r.Uses)
			if len(u) != 1 || u[0].XSS.Protection != tt.want {
				t.Fatalf("want %s got %+v", tt.want, u)
			}
		})
	}
}

func TestPythonTemplateContextContainsAttributeMarkup(t *testing.T) {
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.get('/')
def entry():
    return render_template('view.html',name=request.args.get('name'))
`, "templates/view.html": "<input\n name=\"name\"\n value=\"{{ name }}\">\n"})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u := pythonXSSOnly(r.Uses)
	if len(u) != 1 {
		t.Fatal("missing rendering")
	}
	found := false
	for _, e := range u[0].Completeness.Evidence["render_context"] {
		if e.Kind == "render_markup_context" && strings.Contains(e.Text, "<input") && strings.Contains(e.Text, `value="{{ name }}"`) {
			found = true
		}
	}
	if !found {
		t.Fatal("judge cannot see actual attribute context")
	}
}

func TestPythonAlternativeBindingsCannotBorrowProtection(t *testing.T) {
	a := pythonValue{binding: "db_connection", driver: "sqlite3"}
	b := pythonValue{binding: "db_connection", driver: "psycopg"}
	if joined := pyJoin(a, b, 0); joined.binding != "" || joined.driver != "" || !joined.unknown {
		t.Fatal("alternative drivers borrowed one contract")
	}
	a = pythonValue{binding: "jinja_template", templateEscape: "encoded", constant: true, literal: "<p>{{name}}</p>"}
	b = a
	b.templateEscape = "raw"
	if joined := pyJoin(a, b, 0); joined.templateEscape != "unknown" {
		t.Fatal("alternative template borrowed escaping")
	}
}

func TestPythonMismatchedFormMethodIsNotFieldPolicy(t *testing.T) {
	root := pythonFixture(t, map[string]string{"main.py": `from flask import Flask,request,render_template
app=Flask(__name__)
@app.post('/signup')
def signup():
    email=request.form.get('email')
    return render_template('signup.html')
`, "templates/signup.html": `<form method="GET" action="{{ url_for('signup') }}"><input name="email" type="email" required></form>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range r.Uses {
		if u.Kind == "input_validation_candidate" && u.Completeness != nil {
			t.Fatal("different method borrowed form policy")
		}
	}
}

func TestPythonKeywordPathsAndRegistrationCoverage(t *testing.T) {
	for _, tt := range []struct {
		name, source, gap string
		routes            int
	}{
		{"literal FastAPI keyword", "from fastapi import FastAPI\napp=FastAPI()\n@app.get(path='/keyword')\ndef view():\n    return 'ok'\n", "", 1},
		{"generated FastAPI keyword", "from fastapi import APIRouter\nrouter=APIRouter()\ndef generate(path):\n    @router.get(path=path)\n    def view():\n        return 'ok'\n", "dynamic_path", 0},
		{"verified add_url_rule", "from flask import Flask\napp=Flask(__name__)\ndef view():\n    return 'ok'\napp.add_url_rule('/generated',view_func=view)\n", "python_registration_unresolved", 0},
		{"fake add_url_rule", "app=custom_factory()\napp.add_url_rule('/generated',view_func=view)\n", "", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"main.py": tt.source})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != tt.routes {
				t.Fatalf("routes=%d want %d", len(r.Entries), tt.routes)
			}
			if tt.gap != "" && !gapKind(r.Gaps, tt.gap) {
				t.Fatalf("unsupported registration was silent: %+v", r.Gaps)
			}
			if tt.gap == "" && (gapKind(r.Gaps, "python_registration_unresolved") || gapKind(r.Gaps, "dynamic_path")) {
				t.Fatalf("invented coverage warning: %+v", r.Gaps)
			}
		})
	}
}
