package langpy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDynamicPythonVulnPyTraces(t *testing.T) {
	root := "testdata/dynamic-vulnpy"
	if _, err := os.Stat(root); err != nil {
		t.Fatal(err)
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, framework := range []string{"flask", "fastapi"} {
		for _, stem := range []string{"sqli/sqlite3-execute", "sqli/sqlite3-executemany", "sqli/sqlite3-executescript", "xss/raw"} {
			methods := []string{"GET"}
			if framework == "flask" {
				methods = append(methods, "POST")
			}
			for _, method := range methods {
				var ids []string
				for _, e := range report.Entries {
					if e.HTTP != nil && e.HTTP.Framework == framework && e.HTTP.Method == method && (e.HTTP.Path == "/vulnpy/"+stem || e.HTTP.Path == "/vulnpy/"+stem+"/") {
						ids = append(ids, e.ID)
					}
				}
				if len(ids) != 1 {
					t.Errorf("%s %s %s: entries %v", framework, method, stem, ids)
					continue
				}
				witnessed := false
				for _, u := range report.Uses {
					if u.EntryID != ids[0] {
						continue
					}
					if stem == "xss/raw" {
						witnessed = witnessed || u.Kind == "xss_candidate" && len(u.Dependencies) > 0
					} else {
						witnessed = witnessed || u.Kind == "sql_query_candidate" && len(u.Dependencies) > 0 && filepath.Base(u.Sink.Span.File) == "sqli.py"
					}
				}
				if !witnessed {
					t.Errorf("%s %s %s: missing value-to-sink witness", framework, method, stem)
				}
			}
		}
	}
}

func TestDynamicHTTPBoundsPython(t *testing.T) {
	for _, tc := range []struct{ name, file, append string }{
		{"registry-mutation", "src/vulnpy/trigger/__init__.py", `TRIGGER_MAP['sqli'] = ['external']`},
		{"member-mutation", "src/vulnpy/trigger/sqli.py", `do_sqlite3_execute = unknown`},
		{"shadowed-lookup", "src/vulnpy/flask/blueprint.py", `get_trigger = unknown`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			err := filepath.WalkDir("testdata/dynamic-vulnpy", func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				rel, err := filepath.Rel("testdata/dynamic-vulnpy", path)
				if err != nil {
					return err
				}
				dest := filepath.Join(root, rel)
				if entry.IsDir() {
					return os.MkdirAll(dest, 0700)
				}
				b, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				if filepath.ToSlash(rel) == tc.file {
					b = append(b, []byte("\n"+tc.append+"\n")...)
				}
				return os.WriteFile(dest, b, 0600)
			})
			if err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range r.Uses {
				for _, e := range r.Entries {
					if e.ID == u.EntryID && e.HTTP != nil && e.HTTP.Framework == "flask" && e.HTTP.Path == "/vulnpy/sqli/sqlite3-execute/" && u.Kind == "sql_query_candidate" {
						t.Fatal("mutated source acquired fabricated SQL callback")
					}
				}
			}
		})
	}
}

func TestDynamicPythonVulnPyWitnesses(t *testing.T) {
	r, err := Analyze("testdata/dynamic-vulnpy", "")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	frameworks := map[string]string{}
	methods := map[string]string{}
	for _, e := range r.Entries {
		if e.HTTP != nil {
			entries[e.ID] = e.HTTP.Path
			frameworks[e.ID] = e.HTTP.Framework
			methods[e.ID] = e.HTTP.Method
		}
	}
	sqlCount, xssCount := 0, 0
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" && strings.Contains(entries[u.EntryID], "/vulnpy/") {
			sqlCount++
			if u.Completeness == nil || len(u.Completeness.Blockers) > 0 {
				t.Fatalf("incomplete SQL witness: %+v", u.Completeness)
			}
			transfers := map[string]bool{}
			sources := map[int]bool{}
			for _, d := range u.Dependencies {
				if d.SinkSlot != "sql_text" {
					t.Errorf("constant bound operand borrowed request SQL: %s", d.SinkSlot)
				}
				sources[d.Source.Span.StartLine] = true
				for _, e := range d.Transfers {
					transfers[e.Kind] = true
				}
			}
			for _, kind := range []string{"argument_to_parameter", "closure_capture"} {
				if !transfers[kind] {
					t.Errorf("%s missing %s: %v", entries[u.EntryID], kind, transfers)
				}
			}
			cursor := false
			selection := false
			for _, e := range u.Context {
				cursor = cursor || e.Kind == "sink_binding" && strings.Contains(e.Text, ".cursor(")
				selection = selection || e.Kind == "selection_definition"
			}
			if !cursor || !selection {
				t.Errorf("%s cursor/selection witnesses missing", entries[u.EntryID])
			}
			if frameworks[u.EntryID] == "flask" {
				line := 14
				if methods[u.EntryID] == "POST" {
					line = 15
				}
				if !sources[11] || !sources[line] || len(sources) != 2 {
					t.Errorf("Flask precedence/alternatives lost: %v", sources)
				}
			}
		}
		if u.XSS != nil && frameworks[u.EntryID] != "" && strings.Contains(entries[u.EntryID], "/vulnpy/") {
			xssCount++
			if !strings.Contains(entries[u.EntryID], "/xss/raw") || u.XSS.Protection != "raw" {
				t.Errorf("fabricated/wrong XSS branch: %s %+v", entries[u.EntryID], u.XSS)
			}
		}
	}
	if sqlCount != 9 || xssCount != 3 {
		t.Fatalf("SQL/XSS route witnesses=%d/%d", sqlCount, xssCount)
	}
	for _, reg := range r.Registrations {
		if !strings.Contains(entries[reg.EntryID], "/sqli/sqlite3-") {
			continue
		}
		kinds := map[string]bool{}
		for _, e := range reg.DerivedFrom {
			kinds[e.Kind] = true
		}
		for _, kind := range []string{"generation_loop", "registry_module", "registry_member", "factory_call", "mount_binding"} {
			if !kinds[kind] {
				t.Errorf("%s lacks %s provenance: %v", entries[reg.EntryID], kind, kinds)
			}
		}
	}
	for _, ctx := range r.InvocationContexts {
		if !strings.Contains(entries[ctx.EntryID], "/sqli/sqlite3-") {
			continue
		}
		constants := map[string]string{}
		for _, b := range ctx.Closures {
			if b.Constant != nil {
				constants[b.Parameter] = *b.Constant
			}
		}
		if constants["name"] != "sqli" || !strings.HasPrefix(constants["trigger"], "sqlite3-") {
			t.Errorf("closure constants=%v", constants)
		}
	}
}

func TestDynamicHTTPContextIsolationPython(t *testing.T) {
	r, err := Analyze("testdata/dynamic-vulnpy/independent-controls", "")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, e := range r.Entries {
		paths[e.ID] = e.HTTP.Path
	}
	outcomes := map[string]string{}
	slots := map[string]string{}
	for _, u := range r.Uses {
		if u.XSS != nil {
			outcomes[paths[u.EntryID]] = u.XSS.Protection
		}
		if u.Kind == "sql_query_candidate" {
			for _, d := range u.Dependencies {
				slots[paths[u.EntryID]] = d.SinkSlot
			}
		}
	}
	for path, want := range map[string]string{"/control/raw": "raw", "/control/encoded": "encoded", "/control/unknown": "unknown"} {
		if outcomes[path] != want {
			t.Errorf("%s=%s want %s", path, outcomes[path], want)
		}
	}
	if slots["/control/sql-bound"] != "sql_parameters" || slots["/control/sql-raw"] != "sql_text" {
		t.Fatalf("SQL slots=%v", slots)
	}
}

func TestDynamicHTTPBoundsPythonLimitAndDeterminism(t *testing.T) {
	root := t.TempDir()
	var source strings.Builder
	source.WriteString("from fastapi import FastAPI\napp=FastAPI()\ndef register(path):\n    @app.get(path)\n    def handler():\n        return 'constant'\npaths=[")
	for i := 0; i < 130; i++ {
		fmt.Fprintf(&source, "'/r%d',", i)
	}
	source.WriteString("]\nfor path in paths:\n    register(path)\n")
	if err := os.WriteFile(filepath.Join(root, "routes.py"), []byte(source.String()), 0600); err != nil {
		t.Fatal(err)
	}
	var previous []byte
	for i := 0; i < 2; i++ {
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Entries) != 128 {
			t.Fatalf("bounded entries=%d", len(r.Entries))
		}
		found := false
		for _, g := range r.Gaps {
			found = found || strings.Contains(g.Detail, "remainder unexpanded")
		}
		if !found {
			t.Fatal("Python limit remainder hidden")
		}
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(previous, data) {
			t.Fatal("repeated Python expansion changed")
		}
		previous = data
	}
}

func TestDynamicHTTPBoundsPythonUnresolvedCallback(t *testing.T) {
	root := t.TempDir()
	source := `from flask import Flask,request
import sqlite3
app=Flask(__name__)
def register(path):
    @app.get(path)
    def view():
        @unknown_wrapper
        def callback(cursor):
            cursor.execute('SELECT '+request.args.get('q'))
        connection=sqlite3.connect(':memory:')
        callback(connection.cursor())
register('/unresolved')
`
	if err := os.WriteFile(filepath.Join(root, "routes.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Entries) != 1 {
		t.Fatalf("lost zero-use registration: %d", len(r.Entries))
	}
	if len(r.Uses) != 0 {
		t.Fatalf("unknown callback created uses: %d", len(r.Uses))
	}
	found := false
	for _, g := range r.Entries[0].Gaps {
		found = found || g.Kind == "python_callback_unresolved"
	}
	if !found {
		t.Fatal("unresolved callback gap hidden")
	}
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" {
			t.Fatal("unknown wrapper fabricated a callback/cursor binding")
		}
	}
}

func TestDynamicHTTPContextIsolationPythonRepeatedPath(t *testing.T) {
	root := t.TempDir()
	source := `from flask import Flask,request
from markupsafe import escape
app=Flask(__name__)
def register(path,encoded):
    @app.get(path)
    def handler():
        value=request.args.get('q')
        if encoded == 'yes':
            return '<p>'+escape(value)+'</p>'
        return '<p>'+value+'</p>'
register('/shared','no')
register('/shared','yes')
`
	if err := os.WriteFile(filepath.Join(root, "routes.py"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	contexts := map[string]bool{}
	for _, u := range r.Uses {
		if u.XSS != nil {
			counts[u.XSS.Protection]++
			contexts[u.InvocationContextID] = true
		}
	}
	if counts["raw"] != 1 || counts["encoded"] != 1 || len(contexts) != 2 {
		t.Fatalf("repeated-path contexts borrowed controls: %v / %d", counts, len(contexts))
	}
}
