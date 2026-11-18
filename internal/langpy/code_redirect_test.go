package langpy

import (
	"testing"
)

func TestCodeRedirectPython(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.py", `from flask import Flask, request, redirect
import ast
app=Flask(__name__)
@app.route('/code')
def code():
    eval(request.args.get('q'))
    exec(request.args.get('q'))
    compile(request.args.get('q'), '<input>', 'exec')
    ast.literal_eval(request.args.get('data'))
    return redirect(request.args.get('next'))
@app.route('/keyword')
def keyword():
    compile(filename='<input>',source=request.args.get('q'),mode='exec')
    return redirect(location=request.args.get('next'))
@app.route('/shadow')
def shadow():
    eval=lambda x:x
    eval(request.args.get('q'))
    return redirect('/fixed')
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		kind string
		n    int
	}{{"code_execution_candidate", 4}, {"open_redirect_candidate", 2}} {
		uses := usesOf(r, row.kind, "")
		if len(uses) != row.n {
			t.Errorf("%s got %d want %d", row.kind, len(uses), row.n)
		}
		for _, u := range uses {
			if u.Code != nil {
				if err := u.Code.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Error(err)
				}
			}
			if u.Completeness == nil || len(u.Completeness.Blockers) > 0 {
				t.Errorf("%s completeness %+v", u.Sink.Text, u.Completeness)
			}
		}
	}
}
