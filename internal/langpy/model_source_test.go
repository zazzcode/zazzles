package langpy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestModelSourcePreservesExecutableStrings(t *testing.T) {
	for _, statement := range []string{`f"{passthrough('FIRST_RUNTIME', request.args.get('q'))}"`, `b"FIRST_RUNTIME"`} {
		root := t.TempDir()
		source := "from flask import Flask,request\napp=Flask(__name__)\ndef passthrough(marker,value):\n    return value\n@app.get('/')\ndef handler():\n    " + statement + "\n    return '<p>'+request.args.get('q')\n"
		if err := os.WriteFile(filepath.Join(root, "server.py"), []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		r, err := Analyze(root, "server.py")
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, u := range r.Uses {
			for _, e := range u.Context {
				if e.Kind == "invoked_callable" && strings.Contains(e.Text, "def handler") {
					found = true
					if e.ModelText != "" && !strings.Contains(e.ModelText, "FIRST_RUNTIME") {
						t.Fatal("non-docstring runtime expression was masked")
					}
				}
			}
		}
		if !found {
			t.Fatal("handler source missing")
		}
	}
}
