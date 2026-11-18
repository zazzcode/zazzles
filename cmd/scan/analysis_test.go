package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestAnalysisModeCompatibility(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := "../../internal/langjs/testdata/string-flow"
	var canonical []byte
	for _, mode := range []string{"--analyze", "--strings"} {
		var out, stderr bytes.Buffer
		if code := run([]string{mode, "--json", "--entry", "server.ts", root}, &out, &stderr); code != exitOK {
			t.Fatalf("%s: code=%d stderr=%s", mode, code, stderr.String())
		}
		var r analysis.AnalysisReport
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatal(err)
		}
		if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Uses) == 0 || len(r.AnalysisGuidelines) != 1 {
			t.Fatalf("missing current analysis metadata: %+v", r)
		}
		if canonical != nil && !bytes.Equal(canonical, out.Bytes()) {
			t.Fatal("compatibility alias changed analysis output")
		}
		canonical = append([]byte{}, out.Bytes()...)
	}
	for _, mode := range []string{"--analyze", "--strings"} {
		var out, stderr bytes.Buffer
		if code := run([]string{mode, "--routes", root}, &out, &stderr); code != exitUsage {
			t.Fatalf("conflicting modes accepted for %s", mode)
		}
	}
}

func TestSavedAnalysisSchemaExports(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":1,"practice":[{"id":"python","version":"2"}],"entries":[],"uses":[],"files":[],"gaps":[]}`,
		`{"schema_version":2,"analysis_guidelines":[{"id":"python","version":"3"}],"entries":[],"uses":[],"files":[],"gaps":[]}`,
	} {
		file := filepath.Join(t.TempDir(), "saved.json")
		if err := os.WriteFile(file, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
		for _, mode := range []string{"--export-html", "--export-sarif"} {
			var out, stderr bytes.Buffer
			if code := run([]string{mode, file}, &out, &stderr); code != exitOK || out.Len() == 0 {
				t.Fatalf("%s: code=%d stderr=%s", mode, code, stderr.String())
			}
			if mode == "--export-sarif" && !json.Valid(out.Bytes()) {
				t.Fatal("invalid SARIF JSON")
			}
		}
		after, err := os.ReadFile(file)
		if err != nil || string(after) != input {
			t.Fatal("export mutated saved evidence")
		}
	}
}

func TestBrowserEventPipeline(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := "../../internal/langjs/testdata/javascript/browser-events"
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--json", root}, &out, &stderr); code != exitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var r analysis.AnalysisReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) != 6 || len(r.Uses) != 4 || len(r.Findings) != 4 {
		t.Fatalf("bad actual event pipeline: %d/%d/%d", len(r.Entries), len(r.Uses), len(r.Findings))
	}
	if err := r.ValidateUses(); err != nil {
		t.Fatal(err)
	}
	saved := filepath.Join(t.TempDir(), "events.json")
	original := append([]byte{}, out.Bytes()...)
	if err := os.WriteFile(saved, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"--export-html", "--export-sarif"} {
		out.Reset()
		stderr.Reset()
		if code := run([]string{mode, saved}, &out, &stderr); code != exitOK {
			t.Fatalf("%s code=%d stderr=%s", mode, code, stderr.String())
		}
		if mode == "--export-sarif" && !json.Valid(out.Bytes()) {
			t.Fatal("invalid event SARIF")
		}
	}
	after, err := os.ReadFile(saved)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("export modified evidence")
	}
}

func TestDynamicPythonVulnPyTraces(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--json", "../../internal/langpy/testdata/dynamic-vulnpy"}, &out, &stderr); code != exitOK {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	var r analysis.AnalysisReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateUses(); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for _, e := range r.Entries {
		if e.HTTP != nil {
			paths[e.ID] = e.HTTP.Path
		}
	}
	count := 0
	for _, f := range r.Findings {
		if strings.HasPrefix(paths[f.EntryID], "/vulnpy/") && f.Status == "poor_practice" {
			count++
		}
	}
	if count != 12 {
		t.Fatalf("generated contextual poor-practice findings=%d want12", count)
	}
}

func TestGraphQLPipelineAndBounds(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			root := "../../internal/langjs/testdata/" + language + "/graphql"
			var out, stderr bytes.Buffer
			if code := run([]string{"--analyze", "--json", "--entry-kind", "graphql", root}, &out, &stderr); code != exitOK {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			var r analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) != 9 {
				t.Fatalf("wrong inventory %d", len(r.Entries))
			}
			if err := r.ValidateUses(); err != nil {
				t.Fatal(err)
			}
			for _, e := range r.Entries {
				if e.HTTP != nil || e.Kind != "graphql" {
					t.Fatal("fake HTTP entry")
				}
			}
			original := append([]byte{}, out.Bytes()...)
			saved := filepath.Join(t.TempDir(), "graphql.json")
			if err := os.WriteFile(saved, original, 0600); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"--export-html", "--export-sarif"} {
				out.Reset()
				stderr.Reset()
				if code := run([]string{mode, saved}, &out, &stderr); code != exitOK {
					t.Fatalf("%s: %s", mode, stderr.String())
				}
				if mode == "--export-html" && (!strings.Contains(out.String(), "Query.raw") || !strings.Contains(out.String(), "Query.absent")) {
					t.Fatal("resolver/zero-use presentation missing")
				}
				if mode == "--export-sarif" && (!json.Valid(out.Bytes()) || strings.Contains(out.String(), `"scan.route"`)) {
					t.Fatal("invalid/fake HTTP SARIF")
				}
			}
			after, err := os.ReadFile(saved)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("saved export changed source evidence")
			}
			out.Reset()
			stderr.Reset()
			if code := run([]string{"--analyze", "--json", "--entry-kind", "graphql", "--entry-id", r.Entries[0].ID, root}, &out, &stderr); code != exitOK {
				t.Fatal(stderr.String())
			}
			var selected analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &selected); err != nil {
				t.Fatal(err)
			}
			if len(selected.Entries) != 1 || selected.Entries[0].ID != r.Entries[0].ID {
				t.Fatal("entry-id filter mismatch")
			}
			out.Reset()
			stderr.Reset()
			if code := run([]string{"--analyze", "--route", "GET /graphql", root}, &out, &stderr); code == exitOK {
				t.Fatal("HTTP-only selector matched GraphQL")
			}
		})
	}
}

func TestGRPCPipeline(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			root := "../../internal/langjs/testdata/" + language + "/grpc"
			var out, stderr bytes.Buffer
			if code := run([]string{"--analyze", "--json", "--entry-kind", "grpc", root}, &out, &stderr); code != exitOK {
				t.Fatalf("code=%d stderr=%s", code, stderr.String())
			}
			var r analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &r); err != nil {
				t.Fatal(err)
			}
			if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) != 11 {
				t.Fatalf("wrong inventory %d", len(r.Entries))
			}
			if err := r.ValidateUses(); err != nil {
				t.Fatal(err)
			}
			for _, e := range r.Entries {
				if e.HTTP != nil || e.Kind != "grpc" {
					t.Fatal("fake HTTP entry")
				}
			}
			original := append([]byte{}, out.Bytes()...)
			saved := filepath.Join(t.TempDir(), "grpc.json")
			if err := os.WriteFile(saved, original, 0600); err != nil {
				t.Fatal(err)
			}
			for _, mode := range []string{"--export-html", "--export-sarif"} {
				out.Reset()
				stderr.Reset()
				if code := run([]string{mode, saved}, &out, &stderr); code != exitOK {
					t.Fatalf("%s: %s", mode, stderr.String())
				}
				if mode == "--export-html" && (!strings.Contains(out.String(), "fixtures.search.SearchService/Raw") || !strings.Contains(out.String(), "fixtures.search.SearchService/Absent")) {
					t.Fatal("resolver/zero-use presentation missing")
				}
				if mode == "--export-sarif" && (!json.Valid(out.Bytes()) || strings.Contains(out.String(), `"scan.route"`)) {
					t.Fatal("invalid/fake HTTP SARIF")
				}
			}
			after, err := os.ReadFile(saved)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("saved export changed source evidence")
			}
			out.Reset()
			stderr.Reset()
			if code := run([]string{"--analyze", "--json", "--entry-kind", "grpc", "--entry-id", r.Entries[0].ID, root}, &out, &stderr); code != exitOK {
				t.Fatal(stderr.String())
			}
			var selected analysis.AnalysisReport
			if err := json.Unmarshal(out.Bytes(), &selected); err != nil {
				t.Fatal(err)
			}
			if len(selected.Entries) != 1 || selected.Entries[0].ID != r.Entries[0].ID {
				t.Fatal("entry-id filter mismatch")
			}
			out.Reset()
			stderr.Reset()
			if code := run([]string{"--analyze", "--route", "GET /grpc", root}, &out, &stderr); code == exitOK {
				t.Fatal("HTTP-only selector matched gRPC")
			}
		})
	}
}
