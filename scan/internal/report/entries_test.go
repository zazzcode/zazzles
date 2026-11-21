package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func mixedEntries() *analysis.AnalysisReport {
	return &analysis.AnalysisReport{Entries: []analysis.EntryPoint{
		{ID: "http", Kind: "http", HTTP: &analysis.HTTPEntryMetadata{Method: "POST", Path: "/accounts"}},
		{ID: "browser", Kind: "browser", Name: "Signup", Browser: &analysis.BrowserEntryMetadata{Category: "component", Event: "submit", Target: "form"}},
		{ID: "graphql", Kind: "graphql", GraphQL: &analysis.GraphQLEntryMetadata{Type: "Mutation", Field: "createAccount"}},
		{ID: "grpc", Kind: "grpc", GRPC: &analysis.GRPCEntryMetadata{Package: "accounts", Service: "AccountService", Method: "CreateAccount"}},
		{ID: "unknown", Kind: "future", Name: "unknown-operation", UnknownMetadata: []byte(`{"mode":"custom"}`), Gaps: []analysis.Gap{{Kind: "unknown_dispatch", Detail: "zero-use coverage gap"}}},
	}, Uses: []analysis.CandidateUse{}}
}

func TestEntrySpecificReports(t *testing.T) {
	r := mixedEntries()
	var out bytes.Buffer
	if err := HTML(&out, r); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"POST /accounts", "Signup", "submit", "Mutation.createAccount", "accounts.AccountService/CreateAccount", "unknown-operation", "zero-use coverage gap", "Declaration location"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing entry presentation %q", want)
		}
	}
	if len(r.Findings) != 0 {
		t.Fatal("zero-use entries manufactured findings")
	}
}

func TestEntrySARIFLocations(t *testing.T) {
	r := mixedEntries()
	for _, e := range r.Entries {
		r.Uses = append(r.Uses, analysis.CandidateUse{ID: "use-" + e.ID, EntryID: e.ID, InvocationContextID: "ctx-" + e.ID, Kind: "sql_query_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "sink.ts", StartLine: 19}}, Assessment: analysis.Assessment{Status: "not_run"}})
		r.Registrations = append(r.Registrations, analysis.EntryRegistration{ID: "reg-" + e.ID, EntryID: e.ID, Origin: analysis.Evidence{Span: analysis.Span{File: "registration.ts", StartLine: 2}}, DerivedFrom: []analysis.Evidence{{Kind: "schema", Span: analysis.Span{File: "schema.graphql", StartLine: 3}}}})
		r.DispatchBindings = append(r.DispatchBindings, analysis.DispatchBinding{ID: "binding-" + e.ID, EntryID: e.ID, RegistrationID: "reg-" + e.ID, CallableID: "call-" + e.ID})
		r.Callables = append(r.Callables, analysis.Callable{ID: "call-" + e.ID, Definition: analysis.Evidence{Span: analysis.Span{File: "handler.ts", StartLine: 7}}})
		r.InvocationContexts = append(r.InvocationContexts, analysis.InvocationContext{ID: "ctx-" + e.ID, EntryID: e.ID, DispatchBindingID: "binding-" + e.ID})
	}
	run := SARIF(r)["runs"].([]any)[0].(map[string]any)
	for i, item := range run["results"].([]any) {
		result := item.(map[string]any)
		loc := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
		if loc["artifactLocation"].(map[string]string)["uri"] != "sink.ts" {
			t.Fatal("sink is not primary")
		}
		props := result["properties"].(map[string]any)
		if props["scan.entryKind"] != r.Entries[i].Kind || props["scan.invocationContextId"] != "ctx-"+r.Entries[i].ID {
			t.Fatal("missing canonical associations")
		}
		if _, ok := props["scan.route"]; ok && r.Entries[i].Kind != "http" {
			t.Fatal("manufactured HTTP route")
		}
		if len(result["relatedLocations"].([]any)) != 3 {
			t.Fatalf("related schema/registration/handler missing: %+v", result)
		}
	}
	r.Uses = nil
	run = SARIF(r)["runs"].([]any)[0].(map[string]any)
	if len(run["results"].([]any)) != 0 {
		t.Fatal("zero-use gap manufactured finding")
	}
	inv := run["invocations"].([]any)[0].(map[string]any)
	if len(inv["toolExecutionNotifications"].([]any)) == 0 || inv["properties"] == nil {
		t.Fatal("zero-use invocation coverage hidden")
	}
}

func TestEntryReportStatusParity(t *testing.T) {
	for _, kind := range []string{"http", "browser", "graphql", "grpc", "future", "orphan"} {
		t.Run(kind, func(t *testing.T) {
			r := mixedEntries()
			id := "unknown"
			for _, e := range r.Entries {
				if e.Kind == kind {
					id = e.ID
				}
			}
			if kind == "orphan" {
				id = "legacy-orphan"
			}
			for i, status := range []string{"poor_practice", "needs_evidence", "protected_for_claim"} {
				u := analysis.CandidateUse{ID: fmt.Sprint(i), EntryID: id, Kind: "sql_query_candidate", Assessment: analysis.Assessment{Status: "completed", FindingStatus: status}}
				if i == 0 {
					u.Gaps = []analysis.Gap{{Kind: "query_text_interpolated"}}
					u.Dependencies = requestDependency()
				}
				r.Uses = append(r.Uses, u)
			}
			var html, text bytes.Buffer
			if err := HTML(&html, r); err != nil {
				t.Fatal(err)
			}
			Text(&text, r)
			run := SARIF(r)["runs"].([]any)[0].(map[string]any)
			results := run["results"].([]any)
			for i, want := range []string{"finding", "analysis", "protection"} {
				f := r.Findings[i]
				if f.RecordType != want {
					t.Fatalf("status drift: %+v", f)
				}
				sf := results[i].(map[string]any)["properties"].(map[string]any)["scan.finding"].(analysis.Finding)
				a, _ := json.Marshal(sf)
				b, _ := json.Marshal(f)
				if !bytes.Equal(a, b) {
					t.Fatal("SARIF/JSON finding drift")
				}
			}
			data, _ := json.Marshal(r.Findings)
			for _, f := range r.Findings {
				if !strings.Contains(html.String(), "status-"+f.Status) || !strings.Contains(text.String(), "["+f.Status+"]") || !bytes.Contains(data, []byte(f.Status)) {
					t.Fatalf("format status lost: %s", f.Status)
				}
			}
			if strings.Contains(html.String(), "entry is safe</") {
				t.Fatal("entry-wide safe label")
			}
		})
	}
}

func TestEntrySpecificReportsParsedPipeline(t *testing.T) {
	for _, tc := range []struct{ file, source string }{
		{"app.ts", `import express from 'express';const app=express();app.get('/x',(req,res)=>res.send(req.query.q));app.get('/gap',unknownHandler);`},
		{"app.py", "from flask import Flask, request\napp=Flask(__name__)\n@app.route('/x')\ndef view():\n    return request.args.get('q')\n"},
		{"browser.js", `document.body.innerHTML=location.hash`},
	} {
		t.Run(tc.file, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, tc.file), []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Uses) == 0 {
				t.Fatal("pipeline produced no candidate")
			}
			for _, u := range r.Uses {
				if u.InvocationContextID == "" || (u.Kind == "xss_candidate" && u.Completeness == nil) {
					t.Fatal("candidate lacks contextual claim")
				}
			}
			var html, text bytes.Buffer
			if err := HTML(&html, r); err != nil {
				t.Fatal(err)
			}
			Text(&text, r)
			run := SARIF(r)["runs"].([]any)[0].(map[string]any)
			if len(run["results"].([]any)) != len(r.Uses) {
				t.Fatal("report lost parsed use")
			}
			for _, e := range r.Entries {
				if !strings.Contains(html.String(), e.ID) || !strings.Contains(text.String(), e.ID) {
					t.Fatal("report lost parsed entry")
				}
			}
			before := html.String()
			slices.Reverse(r.Entries)
			html.Reset()
			if err := HTML(&html, r); err != nil {
				t.Fatal(err)
			}
			if before != html.String() {
				t.Fatal("entry order changes report")
			}
		})
	}
}
