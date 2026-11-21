package langpy

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"testing"
)

func TestCommonEntryExistingConsumers(t *testing.T) {
	for _, tc := range []struct{ name, file, source string }{
		{"Python HTTP", "app.py", "from flask import Flask, request\napp = Flask(__name__)\n@app.route('/x')\ndef view():\n    return request.args.get('q')\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, tc.file, tc.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) == 0 || len(r.Registrations) == 0 || len(r.InvocationContexts) == 0 {
				t.Fatalf("missing common entry records: %+v", r)
			}
			if len(r.Uses) == 0 {
				t.Fatal("lost existing candidate")
			}
			for _, u := range r.Uses {
				if u.EntryID == "" || u.InvocationContextID == "" {
					t.Fatalf("unassociated candidate: %+v", u)
				}
			}
		})
	}
}
