package langpy

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestPythonFrameworkHTMLResponses(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		want         []string
	}{
		{"django default is HTML", "from django.http import HttpResponse\nfrom django.urls import path\ndef view(request):\n    return HttpResponse('<p>' + request.GET['q'] + '</p>')\nurlpatterns = [path('a', view)]\n", []string{"reflected/html_text/raw", "reflected/html_text/raw"}},
		{"django explicit non-HTML", "from django.http import HttpResponse\nfrom django.urls import path\ndef view(request):\n    return HttpResponse(request.GET['q'], content_type='text/plain')\nurlpatterns = [path('a', view)]\n", nil},
		{"aiohttp must state HTML", "from aiohttp import web\nasync def view(request):\n    return web.Response(text=request.rel_url.query.get('q'))\napp = web.Application()\napp.add_routes([web.get('/a', view)])\n", nil},
		{"aiohttp stated HTML", "from aiohttp import web\nasync def view(request):\n    return web.Response(text=request.rel_url.query.get('q'), content_type='text/html')\napp = web.Application()\napp.add_routes([web.get('/a', view)])\n", []string{"reflected/html_text/raw"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := summarize(pythonXSSOnly(analyzeFiles(t, map[string]string{"app.py": tt.source}).Uses))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("want %v got %v", tt.want, got)
			}
		})
	}
}

func TestJinjaEnvironmentAutoescape(t *testing.T) {
	source := func(option string) string {
		return "from pathlib import Path\nfrom flask import Flask, request\nfrom jinja2 import Environment, FileSystemLoader\nenv = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates')" + option + ")\napp = Flask(__name__)\n@app.route('/a')\ndef view():\n    return env.get_template('a.html').render(q=request.args.get('q'))\n"
	}
	for _, tt := range []struct{ name, option, template, want string }{
		{"default environment does not escape", "", "<p>{{ q }}</p>", "raw"},
		{"autoescape escapes", ", autoescape=True", "<p>{{ q }}</p>", "encoded"},
		{"safe filter defeats autoescape", ", autoescape=True", "<p>{{ q | safe }}</p>", "raw"},
		{"computed autoescape is unknown", ", autoescape=select_autoescape()", "<p>{{ q }}</p>", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := pythonXSSOnly(analyzeFiles(t, map[string]string{"app.py": source(tt.option), "templates/a.html": tt.template}).Uses)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want {
				t.Fatalf("want %s got %+v", tt.want, uses)
			}
		})
	}
}

func analyzeFiles(t *testing.T, files map[string]string) *analysis.AnalysisReport {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func summarize(uses []analysis.CandidateUse) []string {
	var out []string
	for _, u := range uses {
		out = append(out, u.XSS.Type+"/"+u.XSS.OutputContext+"/"+u.XSS.Protection)
	}
	sort.Strings(out)
	return out
}
