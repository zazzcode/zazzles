package langpy

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"testing"
)

func TestPythonStoredOrigins(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": `from flask import Flask, request, render_template
import sqlite3
app=Flask(__name__)
@app.post('/write')
def write():
    c=sqlite3.connect(':memory:')
    cur=c.cursor()
    cur.execute('INSERT INTO users (country) VALUES (?)', (request.form['country'],))
    return 'ok'
@app.get('/read')
def read():
    c=sqlite3.connect(':memory:')
    cur=c.cursor()
    cur.execute('SELECT * FROM users WHERE id = ?', (1,))
    user=cur.fetchone()
    return render_template('view.html', user=user)
`, "templates/view.html": `<p>{{ user.country | safe }}</p><p>{{ user.country }}</p><p>{{ user.email | safe }}</p>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := pythonXSSOnly(r.Uses)
	if len(uses) != 3 {
		t.Fatalf("outputs %d", len(uses))
	}
	for i, expect := range []struct {
		p        string
		resolved bool
	}{{"raw", true}, {"encoded", true}, {"raw", false}} {
		x := uses[i].XSS
		if x.Type != "stored" || x.Protection != expect.p || x.OriginResolved != expect.resolved {
			t.Fatalf("output %d: %#v", i, x)
		}
	}
	if len(uses[0].XSS.RelatedEntries) != 1 || uses[0].Dependencies[0].StorageKey != "python-sql:users.country" {
		t.Error("stored writer/field identity missing")
	}
}

func TestPythonResponseContexts(t *testing.T) {
	for _, tt := range []struct{ name, expr, protection, context string }{
		{"escaped text", `f'<p>{escape(name)}</p>'`, "encoded", "html_text"},
		{"escaped script", `f'<script>{escape(name)}</script>'`, "unknown", "script"},
		{"concat script", `'<script>' + escape(name) + '</script>'`, "unknown", "script"},
		{"escaped URL", `f'<a href="{escape(name)}">go</a>'`, "unknown", "url"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"a.py": "from flask import Flask,request\nfrom markupsafe import escape\napp=Flask(__name__)\n@app.get('/')\ndef index():\n    name=request.args.get('name')\n    return " + tt.expr + "\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := pythonXSSOnly(r.Uses)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection || uses[0].XSS.OutputContext != tt.context {
				t.Fatalf("uses %#v expected %s/%s", uses, tt.protection, tt.context)
			}
		})
	}
}

func TestPythonContentVersusControlAndInlineTemplates(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request,render_template_string
app=Flask(__name__)
@app.get('/constant')
def constant():
    return '<p>yes</p>' if request.args.get('mode') else '<p>no</p>'
@app.get('/inline')
def inline():
    return render_template_string('<p>{{ name }}</p><script>{{ name }}</script>{% autoescape false %}{{ name }}{% endautoescape %}', name=request.args.get('name'))
@app.get('/boolean')
def boolean():
    return str(not request.args.get('name'))
`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	raw, unknown, encoded := 0, 0, 0
	for _, u := range pythonXSSOnly(r.Uses) {
		switch u.XSS.Protection {
		case "raw":
			raw++
		case "encoded":
			encoded++
		case "unknown":
			unknown++
		}
	}
	if raw != 1 || unknown != 1 || encoded != 2 {
		t.Fatalf("raw=%d unknown=%d encoded=%d", raw, unknown, encoded)
	}
}

func TestPythonTemplateBrowserBridge(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,render_template
app=Flask(__name__)
@app.get('/')
def index():
    return render_template('view.html')
`, "templates/view.html": `<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
<script>
$(document).ready(function(){
 $('.item').each(function(){
  var item=$(this);
  item.find('form').submit(function(event){
   var comment=item.find('input').val();
   item.find('ul').append('<li>'+comment+'</li>');
  });
 });
});
</script>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var client []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.EntryKind == "browser" {
			client = append(client, u)
		}
	}
	if len(client) != 1 || client[0].XSS.Protection != "raw" || client[0].Sink.Span.File != "templates/view.html" || client[0].Sink.Span.StartLine != 8 {
		t.Fatalf("browser uses %#v", client)
	}
}

func TestJQueryVersusNativeAppend(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		want         bool
	}{
		{"jQuery HTML", `import $ from 'jquery';$('#output').append(location.hash);`, true},
		{"native text", `const el=document.querySelector('#output');el.append(location.hash);`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pythonFixture(t, map[string]string{"browser.js": tt.source})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if got := len(pythonXSSOnly(r.Uses)) > 0; got != tt.want {
				t.Fatalf("HTML claim=%v want %v", got, tt.want)
			}
		})
	}
}

func TestPythonTrustedHTMLDoesNotEscape(t *testing.T) {
	root := pythonFixture(t, map[string]string{"a.py": `from flask import Flask,request,render_template
from markupsafe import escape,Markup
app=Flask(__name__)
@app.get('/')
def index():
    name=request.args.get('name')
    return render_template('view.html',name=name,raw=Markup(name),safe=Markup(escape(name)),ineffective=escape(Markup(name)))
`, "templates/view.html": `{{ name | safe | escape }}
{{ name | safe | forceescape }}
{{ raw }}
{{ safe }}
{{ ineffective }}`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := pythonXSSOnly(r.Uses)
	want := []string{"raw", "encoded", "raw", "encoded", "raw"}
	if len(uses) != len(want) {
		t.Fatalf("outputs %d", len(uses))
	}
	for i, p := range want {
		if uses[i].XSS.Protection != p {
			t.Errorf("output %d got %s want %s", i, uses[i].XSS.Protection, p)
		}
	}
}
