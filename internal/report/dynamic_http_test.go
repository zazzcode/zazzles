package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestDynamicHTTPContextIsolation(t *testing.T) {
	for _, fixture := range []string{"javascript/dynamic-dispatch", "typescript/dynamic-dispatch", "python/dynamic-vulnpy/independent-controls"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := pipeline.Analyze(fixtureRoot(fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			saved, html, run := dynamicBundle(t, r)
			statuses := map[string]bool{}
			for _, f := range saved.Findings {
				statuses[f.Status] = true
			}
			if len(statuses) < 3 {
				t.Fatalf("raw/protected/unknown statuses lost: %v", statuses)
			}
			for _, entry := range saved.Entries {
				if !strings.Contains(html, entry.ID) {
					t.Fatal("zero-use/context entry omitted")
				}
			}
			if sarifRecords(run["results"].([]any)) != len(saved.Uses) {
				t.Fatal("SARIF use count mismatch")
			}
		})
	}
}

func TestDynamicPythonVulnPyTraces(t *testing.T) {
	r, err := pipeline.Analyze("../langpy/testdata/dynamic-vulnpy", "")
	if err != nil {
		t.Fatal(err)
	}
	saved, html, run := dynamicBundle(t, r)
	paths := map[string]string{}
	for _, e := range saved.Entries {
		paths[e.ID] = e.HTTP.Path
	}
	findings := map[string]analysis.Finding{}
	for _, f := range saved.Findings {
		findings[f.UseID] = f
	}
	required := 0
	for _, u := range saved.Uses {
		if !strings.HasPrefix(paths[u.EntryID], "/vulnpy/") {
			continue
		}
		if u.Kind != "sql_query_candidate" && !(u.XSS != nil && strings.Contains(paths[u.EntryID], "/xss/raw")) {
			continue
		}
		required++
		if findings[u.ID].Status != "poor_practice" {
			t.Errorf("%s %s status=%s", paths[u.EntryID], u.Kind, findings[u.ID].Status)
		}
		if !strings.Contains(html, paths[u.EntryID]) {
			t.Fatal("generated route label missing")
		}
	}
	if !strings.Contains(html, "HTML-encode the inserted request text") {
		t.Fatal("generated raw responses lack output-specific guidance")
	}
	if required != 12 {
		t.Fatalf("required contextual findings=%d", required)
	}
	if sarifRecords(run["results"].([]any)) != len(saved.Uses) {
		t.Fatal("SARIF dropped uses")
	}
}

func dynamicBundle(t *testing.T, r *analysis.AnalysisReport) (*analysis.AnalysisReport, string, map[string]any) {
	t.Helper()
	dir, err := WriteBundle(t.TempDir(), r)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved analysis.AnalysisReport
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if err := saved.ValidateUses(); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(dir, "findings.html"))
	if err != nil {
		t.Fatal(err)
	}
	run := SARIF(&saved)["runs"].([]any)[0].(map[string]any)
	byUse := map[string]analysis.Finding{}
	for _, f := range saved.Findings {
		byUse[f.UseID] = f
	}
	for _, item := range run["results"].([]any) {
		result := item.(map[string]any)
		props := result["properties"].(map[string]any)
		f := props["scan.finding"].(analysis.Finding)
		if byUse[f.UseID].Status != f.Status || props["scan.entryId"] != f.EntryID || props["scan.invocationContextId"] != f.InvocationContextID {
			t.Fatal("SARIF contextual status parity failed")
		}
		if !strings.Contains(string(html), f.EntryID) {
			t.Fatal("HTML dropped contextual finding")
		}
	}
	return &saved, string(html), run
}
