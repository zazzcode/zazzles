package parse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestAnalysisGolden(t *testing.T) {
	const root = "testdata/string-flow"
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	got, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	const file = root + "/analysis.json"
	if *update {
		if err := os.WriteFile(file, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("analysis report differs from golden; use -update and review diff\n%s", got)
	}
	if len(report.Uses) != 1 || len(report.Uses[0].Dependencies) != 1 {
		t.Fatalf("uses = %+v", report.Uses)
	}
	d := report.Uses[0].Dependencies[0]
	if d.Source.Text != "req.body.email" || len(d.Transfers) == 0 {
		t.Fatalf("dependency = %+v", d)
	}
	for _, e := range append(d.Transfers, d.Source) {
		data, err := os.ReadFile(filepath.Join(root, e.Span.File))
		if err != nil {
			t.Fatal(err)
		}
		if string(data[e.Span.StartByte:e.Span.EndByte]) != e.Text {
			t.Fatalf("bad source span: %+v", e)
		}
	}
	second, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := json.MarshalIndent(second, "", "  ")
	if !bytes.Equal(got[:len(got)-1], again) {
		t.Fatal("offline evidence is nondeterministic")
	}
}

func TestLocalDependencies(t *testing.T) {
	tests := []struct {
		name, body string
		uses       int
		gap        string
	}{
		{"direct interpolation", "db.query(`SELECT '${req.body.email}'`)", 1, ""},
		{"local assignment", "const v=req.query.q; db.query('SELECT '+v)", 1, ""},
		{"reassignment", "let v=req.query.q; v='constant'; db.query(v)", 0, ""},
		{"parameter binding remains candidate", "const v=req.body.email; db.query('SELECT ?', {replacements:[v]})", 1, ""},
		{"method receiver dependency", "db.query(req.query.q.trim())", 1, "unknown_transfer"},
		{"unknown sanitizer not trusted", "const v=custom(req.query.q); db.query(v)", 1, "unknown_transfer"},
		{"modeled guard leaves no control-flow gap", "const v=req.query.q; if (!valid(v)) {return}; db.query(v)", 1, ""},
		{"ignored validator", "const v=req.query.q; valid(v); db.query(v)", 1, ""},
		{"request reassigned", "req={body:{email:'literal'}};db.query(req.body.email)", 0, ""},
		{"destructuring", "const {email}=req.body;db.query(email)", 1, ""},
		{"outbound under try", "const v=req.query.url;try {const response=await axios.get(v);res.json(response.data)} catch(e) {}", 1, "external_response_unresolved"},
		{"opaque source stays uncertain", "const v=opaque();db.query(v)", 1, "unknown_call_result"},
		{"literal outbound boundary", "fetch('https://example.test')", 1, "external_response_unresolved"},
		{"no fabricated SQL sink", "const query=`SELECT '${req.body.email}'`;console.log(query)", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			src := "import express from 'express';const app=express();app.post('/x',async (req,res)=>{" + tt.body + "})"
			writeSource(t, root, "server.ts", src)
			report, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			sinks := 0
			var u analysis.CandidateUse
			for _, use := range report.Uses {
				if use.Kind == "input_validation_candidate" || use.Kind == "log_sink_candidate" {
					continue
				}
				sinks++
				u = use
			}
			if sinks != tt.uses {
				t.Fatalf("uses=%d want %d; entries=%+v", sinks, tt.uses, report.Entries)
			}
			if tt.uses > 0 {
				if u.Assessment.Status != "not_run" {
					t.Fatal("offline assessment was not not_run")
				}
				if tt.gap != "" {
					found := false
					for _, g := range u.Gaps {
						if g.Kind == tt.gap {
							found = true
						}
					}
					if !found {
						t.Fatalf("missing %s: %+v", tt.gap, u.Gaps)
					}
				}
			}
		})
	}
}

func TestEntrySelectionAndReceiver(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import * as express from 'express';const app=express();app.post('/x',(req,res)=>db.query(req.body.x));request(app).post('/client');function fake(app){app.get('/shadow',(req,res)=>db.query(req.body.x))}`)
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Entries) != 2 || len(report.Uses) != 1 {
		t.Fatalf("entries=%+v uses=%+v", report.Entries, report.Uses)
	}
	if len(report.Entries[1].Gaps) != 1 || report.Entries[1].Gaps[0].Kind != "ambiguous_receiver" {
		t.Fatal("shadowed receiver was accepted")
	}
	for _, entry := range []string{"../outside.ts", "/tmp/outside.ts", "missing.ts"} {
		if _, err := Analyze(root, entry); err == nil {
			t.Errorf("accepted entry %s", entry)
		}
	}
}

func TestConfiguredReceiverParameter(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';const app=express();function configure(app){app.post('/x',(req,res)=>db.query(req.body.x))}configure(app)`)
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 {
		t.Fatalf("not resolved: %+v", report.Entries)
	}
}

func TestUnknownHandlerAndParseError(t *testing.T) {
	for _, src := range []string{`import express from 'express';const app=express();app.get('/x',missing)`, `const = (`} {
		root := t.TempDir()
		writeSource(t, root, "server.ts", src)
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Uses) != 0 {
			t.Fatal("fabricated use")
		}
		if len(report.Gaps) == 0 && (len(report.Entries) == 0 || len(report.Entries[0].Gaps) == 0) {
			t.Fatal("missing uncertainty")
		}
	}
}

func writeSource(t *testing.T, root, name, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte(strings.TrimSpace(text)), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestHandlerImportShadowing(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "handler.ts", `export function handler(req,res){db.query(req.body.x)}`)
	writeSource(t, root, "server.ts", `import express from 'express';import {handler} from './handler';const app=express();function configure(){const handler=unrelated;app.post('/x',handler)}`)
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 0 || len(report.Entries) != 1 || report.Handler(report.Entries[0].ID) != nil {
		t.Fatalf("shadowed import resolved: %+v", report)
	}
}

func TestDependencyLimit(t *testing.T) {
	root := t.TempDir()
	// Identical paths are merged, so the limit needs distinct request sources.
	body := "let v=req.query.q;"
	for i := 0; i < 70; i++ {
		body += fmt.Sprintf("v=v+req.query.p%d;", i)
	}
	body += "db.query(v)"
	writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.get('/x',(req,res)=>{"+body+"})")
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	// Inputs beyond the limit are reported as their own input-validation records.
	var query *analysis.CandidateUse
	for i := range report.Uses {
		if report.Uses[i].Kind == "sql_query_candidate" {
			query = &report.Uses[i]
		}
	}
	if query == nil || len(query.Dependencies) > 64 {
		t.Fatal("dependency work was not bounded")
	}
	found := false
	for _, g := range query.Gaps {
		if g.Kind == "dependency_limit" || g.Kind == "gap_limit" {
			found = true
		}
	}
	if !found {
		t.Fatal("dependency limit was hidden")
	}
}

func TestCustomValidationEvidence(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", `import express from 'express';const app=express();function acceptsId(value){return /^[0-9]+$/.test(value)}app.get('/x',(req,res)=>{const id=req.query.id;if(!acceptsId(id)){return};db.query('SELECT '+id)})`)
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Uses) != 1 {
		t.Fatalf("uses=%+v", report.Uses)
	}
	use := report.Uses[0]
	guard, helper := false, false
	for _, e := range use.Context {
		if e.Kind == "branch_false_precondition" && strings.Contains(e.Text, "acceptsId") {
			guard = true
		}
		if e.Kind == "helper_definition" && strings.Contains(e.Text, "[0-9]") {
			helper = true
		}
	}
	if !guard || !helper || use.Assessment.Protection != "" {
		t.Fatalf("missing source-backed guard/helper, or invented protection: %+v", use)
	}
}
