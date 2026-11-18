package langpy

import (
	"testing"
)

// TestPythonContainerWrite checks that a module-stable local list stores the
// appended value, and that an aliased list keeps today's unresolved behavior.
func TestPythonContainerWrite(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.py", `from flask import Flask, request
app = Flask(__name__)


@app.route('/a')
def a():
    out = []
    out.append(request.args.get('q'))
    return "".join(out)


@app.route('/b')
def b():
    alias = []
    other = alias
    alias.append(request.args.get('q'))
    return "".join(other)
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	stored, aliased := false, false
	for _, u := range r.Uses {
		if u.Sink.Span.StartLine == 9 && len(u.Dependencies) > 0 {
			stored = true
		}
		if u.Sink.Span.StartLine == 17 && len(u.Dependencies) > 0 {
			aliased = true
		}
	}
	if !stored {
		t.Errorf("appended request value did not reach the returned join: %+v", r.Uses)
	}
	if aliased {
		t.Errorf("aliased list was typed: the alias carried the appended value")
	}
}
