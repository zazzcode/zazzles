package report

import (
	"encoding/json"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBundlesPreserveFailedAssessmentAndEarlierRuns(t *testing.T) {
	base := t.TempDir()
	r := &analysis.AnalysisReport{SchemaVersion: 1, Root: "sample", Uses: []analysis.CandidateUse{{ID: "use", Kind: "sql_query_candidate", Assessment: analysis.Assessment{Status: "failed", Reason: "offline failure"}}}}
	first, err := WriteBundle(base, r)
	if err != nil {
		t.Fatal(err)
	}
	second, err := WriteBundle(base, r)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("reused output folder")
	}
	for _, dir := range []string{first, second} {
		for _, name := range []string{"findings.json", "findings.sarif", "findings.html"} {
			p := filepath.Join(dir, name)
			info, err := os.Stat(p)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
				t.Fatalf("public artifact: %s mode %o", p, info.Mode().Perm())
			}
			data, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if name == "findings.html" {
				if !strings.Contains(string(data), "Semantic assessment failed") {
					t.Fatal("failure hidden")
				}
			} else {
				var v any
				if err := json.Unmarshal(data, &v); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	data, _ := os.ReadFile(filepath.Join(first, "findings.json"))
	var saved analysis.AnalysisReport
	if err := json.Unmarshal(data, &saved); err != nil || saved.Uses[0].Assessment.Status != "failed" {
		t.Fatal("assessment changed")
	}
}
