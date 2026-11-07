package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/report"
)

func TestMixedEntryPipeline(t *testing.T) {
	t.Setenv("SCAN_FINDINGS_DIR", "")
	root := t.TempDir()
	fixtures := []struct {
		source, name  string
		entries, uses int
	}{
		{"javascript/browser-events", "events", 6, 4},
		{"javascript/graphql", "graphql", 9, 7},
		{"javascript/grpc", "", 11, 7},
		{"typescript/dynamic-dispatch", "http", 4, 4},
		{"python/dynamic-vulnpy", "", 38, 31},
	}
	for _, fixture := range fixtures {
		source := filepath.Join("../../internal/parse/testdata", fixture.source)
		err := filepath.WalkDir(source, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			rel, err := filepath.Rel(source, path)
			if err != nil {
				return err
			}
			dest := filepath.Join(root, fixture.name, rel)
			if err := os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, data, 0600)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	var out, stderr bytes.Buffer
	if code := run([]string{"--analyze", "--json", root}, &out, &stderr); code != exitOK {
		t.Fatalf("%d: %s", code, stderr.String())
	}
	var r analysis.AnalysisReport
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.ValidateUses(); err != nil {
		t.Fatal(err)
	}
	entries := map[string]analysis.EntryPoint{}
	for _, e := range r.Entries {
		entries[e.ID] = e
		if e.Kind != "http" && e.HTTP != nil {
			t.Fatal("fabricated HTTP metadata")
		}
	}
	contexts := map[string]analysis.InvocationContext{}
	for _, c := range r.InvocationContexts {
		contexts[c.ID] = c
	}
	for _, fixture := range fixtures {
		ne, nu := 0, 0
		for _, e := range r.Entries {
			if strings.HasPrefix(e.Location.Span.File, fixture.name+"/") || fixture.source == "python/dynamic-vulnpy" && strings.HasSuffix(e.Location.Span.File, ".py") || fixture.source == "javascript/grpc" && e.Kind == "grpc" {
				ne++
			}
		}
		for _, u := range r.Uses {
			if u.Kind == "command_execution_candidate" {
				continue // later family; this inventory freezes the predecessor families
			}
			if strings.HasPrefix(u.Sink.Span.File, fixture.name+"/") || fixture.source == "python/dynamic-vulnpy" && strings.HasSuffix(u.Sink.Span.File, ".py") || fixture.source == "javascript/grpc" && u.EntryKind == "grpc" {
				nu++
			}
		}
		if ne != fixture.entries || nu != fixture.uses {
			t.Errorf("%s: entries/uses %d/%d want %d/%d", fixture.name, ne, nu, fixture.entries, fixture.uses)
		}
	}
	predecessorUses := 0
	for _, u := range r.Uses {
		if u.Kind != "command_execution_candidate" {
			predecessorUses++
		}
	}
	if r.SchemaVersion != analysis.ReportSchemaVersion || len(r.Entries) != 68 || predecessorUses != 53 {
		t.Fatalf("mixed inventory: schema=%d entries=%d uses=%d", r.SchemaVersion, len(r.Entries), predecessorUses)
	}
	for _, u := range r.Uses {
		c, ok := contexts[u.InvocationContextID]
		if !ok || c.EntryID != u.EntryID || entries[u.EntryID].Kind != u.EntryKind {
			t.Fatalf("crossed mixed association: %s", u.ID)
		}
	}
	saved := filepath.Join(t.TempDir(), "mixed.json")
	original := append([]byte{}, out.Bytes()...)
	if err := os.WriteFile(saved, original, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"--export-html", "--export-sarif"} {
		out.Reset()
		stderr.Reset()
		if code := run([]string{mode, saved}, &out, &stderr); code != exitOK {
			t.Fatal(stderr.String())
		}
		if mode == "--export-html" {
			for _, e := range r.Entries {
				if !strings.Contains(out.String(), e.ID) || !strings.Contains(out.String(), report.EntryLabel(e)) {
					t.Fatalf("entry absent from HTML: %s", e.ID)
				}
			}
		} else {
			var sarif struct {
				Runs []struct {
					Results []struct {
						Properties map[string]json.RawMessage `json:"properties"`
					} `json:"results"`
				} `json:"runs"`
			}
			if err := json.Unmarshal(out.Bytes(), &sarif); err != nil {
				t.Fatal(err)
			}
			if len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) != len(r.Findings) {
				t.Fatal("SARIF count drift")
			}
			seen := map[string]bool{}
			for _, result := range sarif.Runs[0].Results {
				var useID, entryID, contextID string
				json.Unmarshal(result.Properties["scan.useId"], &useID)
				json.Unmarshal(result.Properties["scan.entryId"], &entryID)
				json.Unmarshal(result.Properties["scan.invocationContextId"], &contextID)
				if seen[useID] || contexts[contextID].EntryID != entryID {
					t.Fatal("duplicated or crossed SARIF association")
				}
				seen[useID] = true
			}
		}
	}
	after, err := os.ReadFile(saved)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("export changed saved evidence")
	}
}
