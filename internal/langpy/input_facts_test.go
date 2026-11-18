package langpy

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPythonInputFacts(t *testing.T) {
	for _, fixture := range []string{"routes", "dynamic-vulnpy", "command-injection", "path-traversal", "outbound"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := Analyze("testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			entries := map[string]analysis.EntryPoint{}
			for _, e := range r.Entries {
				entries[e.ID] = e
			}
			for _, u := range r.Uses {
				e := entries[u.EntryID]
				if e.HTTP == nil {
					continue
				}
				count++
				f := u.InputFacts
				if f == nil {
					t.Fatalf("missing shared facts: %s", u.ID)
				}
				if err := f.Validate(u.Dependencies); err != nil {
					t.Fatalf("%s: %v", u.ID, err)
				}
				if f.Framework != e.HTTP.Framework || f.Binding != e.Location || f.Acquisition != "http" {
					t.Fatalf("borrowed registration: %+v", f)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("component selection: %+v", u.Components)
				}
				for _, d := range f.Values {
					if d.SinkType != "unknown" || d.InitialType != "unknown" {
						t.Fatalf("invented type: %+v", d)
					}
				}
				for _, gap := range u.Gaps {
					found := false
					for _, retained := range f.Gaps {
						found = found || gap == retained
					}
					if !found {
						t.Fatalf("lost gap %s", gap.Kind)
					}
				}
			}
			if count == 0 {
				t.Fatal("no HTTP candidates tested")
			}
		})
	}
}

func TestPythonInputOrigins(t *testing.T) {
	for _, tc := range []struct{ name, framework, source, origin string }{
		{"flask query", "flask", "return request.args.get('q')", "http.query"},
		{"flask form", "flask", "return request.form.get('q')", "http.form"},
		{"flask JSON", "flask", "return request.get_json()['q']", "http.body"},
		{"flask values", "flask", "return request.values.get('q')", "http.query_or_form"},
		{"flask headers", "flask", "return request.headers.get('q')", "http.headers"},
		{"flask cookies", "flask", "return request.cookies.get('q')", "http.cookies"},
		{"flask upload", "flask", "return request.files.get('q').filename", "http.upload_filename"},
		{"session", "flask", "return session.get('q')", "session"},
		{"quart query", "quart", "return request.args.get('q')", "http.query"},
		{"bottle query", "bottle", "return request.args.get('q')", "http.query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class := map[string]string{"flask": "Flask", "quart": "Quart", "bottle": "Bottle"}[tc.framework]
			source := "from " + tc.framework + " import " + class + ",request,session\napp=" + class + "(__name__)\n@app.route('/')\ndef view():\n    " + tc.source + "\n"
			if tc.framework == "bottle" {
				source = "from bottle import Bottle,request\napp=Bottle()\ndef view():\n    " + tc.source + "\napp.route('/', callback=view)\n"
			}
			r, err := Analyze(pythonFixture(t, map[string]string{"app.py": source}), "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range r.Uses {
				if u.InputFacts == nil {
					continue
				}
				for _, v := range u.InputFacts.Values {
					if v.Origin == tc.origin {
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("missing origin %s", tc.origin)
			}
		})
	}
}

func TestPythonInputAnnotationAndPathFacts(t *testing.T) {
	for _, tc := range []struct{ name, head, route, param, origin string }{
		{"flask path", "from flask import Flask\napp=Flask(__name__)", "/<q>", "q", "http.path"},
		{"flask converter", "from flask import Flask\napp=Flask(__name__)", "/<int:q>", "q", "http.path"},
		{"fastapi path", "from fastapi import FastAPI\napp=FastAPI()", "/{q}", "q: str", "http.path"},
		{"annotation", "from fastapi import FastAPI\napp=FastAPI()", "/", "q: int", "http.query"},
		{"dependency", "from fastapi import FastAPI,Depends\napp=FastAPI()", "/", "q: int = Depends(external)", "unknown"},
		{"dependency path", "from fastapi import FastAPI,Depends\napp=FastAPI()", "/{q}", "q: int = Depends(external)", "unknown"},
		{"dependency alias", "from fastapi import FastAPI,Depends as inject\napp=FastAPI()", "/", "q = inject(external)", "unknown"},
		{"qualified dependency", "import fastapi as api\napp=api.FastAPI()", "/", "q = api.Depends(external)", "unknown"},
		{"security", "from fastapi import FastAPI,Security\napp=FastAPI()", "/", "q = Security(external)", "unknown"},
		{"security alias path", "from fastapi import FastAPI,Security as secure\napp=FastAPI()", "/{q}", "q = secure(external)", "unknown"},
		{"qualified security", "import fastapi as api\napp=api.FastAPI()", "/", "q = api.Security(external)", "unknown"},
		{"params dependency", "from fastapi import FastAPI\nfrom fastapi.params import Depends\napp=FastAPI()", "/", "q = Depends(external)", "unknown"},
		{"params security", "from fastapi import FastAPI\nimport fastapi.params as params\napp=FastAPI()", "/", "q = params.Security(external)", "unknown"},
		{"annotated dependency", "from typing import Annotated\nfrom fastapi import FastAPI,Depends\napp=FastAPI()", "/", "q: Annotated[int, Depends(external)]", "unknown"},
		{"annotated dependency alias path", "from typing import Annotated as A\nfrom fastapi import FastAPI,Depends as inject\napp=FastAPI()", "/{q}", "q: A[int, inject(external)]", "unknown"},
		{"qualified annotated security", "import typing as t\nimport fastapi as api\napp=api.FastAPI()", "/", "q: t.Annotated[int, api.Security(external)]", "unknown"},
		{"annotated security path", "from typing import Annotated\nfrom fastapi import FastAPI,Security\napp=FastAPI()", "/{q}", "q: Annotated[int, Security(external)]", "unknown"},
		{"plain annotated query", "from typing import Annotated\nfrom fastapi import FastAPI\napp=FastAPI()", "/", "q: Annotated[int, 'metadata']", "http.query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source := tc.head + "\n@app.get('" + tc.route + "')\ndef view(" + tc.param + "):\n    return str(q)\n"
			r, err := Analyze(pythonFixture(t, map[string]string{"app.py": source}), "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range r.Uses {
				if u.InputFacts == nil {
					continue
				}
				for _, v := range u.InputFacts.Values {
					if v.Origin == tc.origin {
						found = true
						if v.InitialType != "unknown" || v.SinkType != "unknown" || u.InputFacts.ScalarInputs() {
							t.Fatal("annotation/converter/transfer acquired unverified type safety")
						}
					}
				}
			}
			if !found {
				t.Fatalf("missing %s origin", tc.origin)
			}
		})
	}
}

// Shared helpers used from multiple routes keep each registration's binding and
// preserve independent raw/protected branches without a global source-safe bit.
func TestPythonInputConditionalInvocations(t *testing.T) {
	source := `from flask import Flask, request
from markupsafe import escape
app=Flask(__name__)
def shared(q):
    if request.args.get('safe'):
        return escape(q)
    return q
@app.get('/a')
def a():
    return shared(request.args.get('q'))
@app.get('/b')
def b():
    return shared(request.form.get('q'))
`
	r, err := Analyze(pythonFixture(t, map[string]string{"app.py": source}), "")
	if err != nil {
		t.Fatal(err)
	}
	invocations := map[string]bool{}
	origins := map[string]bool{}
	for _, u := range r.Uses {
		if u.Kind != "xss_candidate" {
			continue
		}
		invocations[u.InvocationContextID] = true
		if u.InputFacts == nil || u.InputFacts.ScalarInputs() {
			t.Fatal("conditional acquired scalar guarantee")
		}
		if err := u.InputFacts.Validate(u.Dependencies); err != nil {
			t.Fatal(err)
		}
		for _, v := range u.InputFacts.Values {
			if strings.Contains(v.Source.Text, "'q'") || strings.HasSuffix(v.Source.Text, ".args") || strings.HasSuffix(v.Source.Text, ".form") {
				origins[v.Origin] = true
			}
		}
	}
	if len(invocations) != 2 || !origins["http.query"] || !origins["http.form"] {
		t.Fatalf("lost independent invocation/source: %v %v", invocations, origins)
	}
}

func TestPythonInputSourceModuleIsolation(t *testing.T) {
	root := pythonFixture(t, map[string]string{
		"main.py":   "def view(q):\n    return q\n",
		"helper.py": "def read(q):\n    return q\n",
	})
	s, err := newPythonSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m, helper := s.modules["main.py"], s.modules["helper.py"]
	f := pythonFlow{set: s, route: pythonRoute{module: m, fn: m.funcs["view"], route: analysis.Route{PathPattern: "/<q>"}}, invocation: analysis.InvocationContext{ID: "invocation"}}
	// Equal byte offsets in distinct files do not establish a route parameter.
	source := helper.evidence("input_source", helper.funcs["read"].ChildByFieldName("parameters").NamedChild(0))
	f.recordInput(source, "query", "q")
	if got := s.inputs[f.invocation.ID][source].origin; got != "http.query" {
		t.Fatalf("helper borrowed route capture origin: %s", got)
	}
}
