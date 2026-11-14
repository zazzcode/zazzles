package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/report"
)

// TestPathPipelineParity parses the real fixtures, assesses every record with
// stubbed answers that are honest for its facts, and verifies that JSON, HTML
// and SARIF agree on record counts, statuses, the filesystem operation, CWE-22
// and the scoped remediation.
func TestPathPipelineParity(t *testing.T) {
	for _, dir := range []string{"typescript/path-traversal", "javascript/path-traversal", "python/path-traversal"} {
		t.Run(dir, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+dir, "")
			if err != nil {
				t.Fatal(err)
			}
			confirmed, protected, poor := 0, 0, 0
			for i := range r.Uses {
				u := &r.Uses[i]
				if u.Kind != "path_traversal_candidate" {
					continue
				}
				answers := honestRaw
				if len(u.Path.Paths) > 0 && u.Path.Paths[0].Protection == "guarded" && len(u.Path.Guards) > 0 {
					switch u.Path.Guards[0].Kind {
					case analysis.PathGuardAllowlist:
						answers = optimisticAllowlist
					case analysis.PathGuardPrefixBoundary, analysis.PathGuardRelative, analysis.PathGuardCommonPath:
						answers = optimisticBoundary
					}
				}
				c, _ := pathStub(t, "openai", answers)
				u.Assessment = c.Assess(context.Background(), *u)
				switch u.Assessment.FindingStatus {
				case "confirmed_vulnerability":
					confirmed++
				case "protected_for_claim":
					protected++
				case "poor_practice":
					poor++
				}
			}
			if confirmed == 0 || protected == 0 {
				t.Fatalf("confirmed %d protected %d: the fixture must exercise both outcomes", confirmed, protected)
			}
			report.Enrich(r)
			var findings []analysis.Finding
			for _, f := range r.Findings {
				for _, id := range f.TypeIDs {
					if id == "path-traversal" {
						findings = append(findings, f)
					}
				}
			}
			uses := pathUsesOf(r)
			if len(findings) != len(uses) {
				t.Fatalf("one record per filesystem use: %d findings for %d uses", len(findings), len(uses))
			}
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var saved analysis.AnalysisReport
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			if got := len(pathUsesOf(&saved)); got != len(uses) {
				t.Fatalf("JSON uses %d want %d", got, len(uses))
			}
			var page bytes.Buffer
			if err := report.HTML(&page, &saved); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(page.String(), "Path Traversal") {
				t.Fatal("HTML lacks the Path Traversal label")
			}
			var sarif struct {
				Runs []struct {
					Results []map[string]any `json:"results"`
					Tool    struct {
						Driver struct {
							Rules []map[string]any `json:"rules"`
						} `json:"driver"`
					} `json:"tool"`
				} `json:"runs"`
			}
			sarifRaw, _ := json.Marshal(report.SARIF(&saved))
			if err := json.Unmarshal(sarifRaw, &sarif); err != nil {
				t.Fatal(err)
			}
			count, failures, passes := 0, 0, 0
			for _, res := range sarif.Runs[0].Results {
				if id, _ := res["ruleId"].(string); strings.HasPrefix(id, "scan/path-traversal") {
					count++
					switch res["kind"] {
					case "fail":
						failures++
					case "pass":
						passes++
					}
				}
			}
			wantFail, wantPass := 0, 0
			for _, f := range findings {
				if f.RecordType == "finding" && f.Status == "confirmed_vulnerability" {
					wantFail++
					operation := ""
					for _, u := range uses {
						if u.ID == f.UseID {
							operation = u.Path.Operation
						}
					}
					if operation == "" || !strings.Contains(f.Summary, "CWE-22") || !strings.Contains(f.Summary, operation) {
						t.Fatalf("confirmed summary lacks the operation or CWE-22: %s", f.Summary)
					}
					if len(f.Recommendations.Actions) == 0 || !strings.Contains(f.Recommendations.Actions[0], "At ") {
						t.Fatalf("remediation is not scoped to the operation: %+v", f.Recommendations)
					}
				}
				if f.RecordType == "finding" && f.Status == "poor_practice" {
					wantFail++ // a construction-practice finding is a finding record, reported as a failing result
				}
				if f.RecordType == "protection" && f.Status == "protected_for_claim" {
					wantPass++
				}
			}
			if count != len(findings) || failures != wantFail || passes != wantPass || wantFail != confirmed+poor || wantPass != protected {
				t.Fatalf("SARIF results %d (fail %d pass %d) vs findings %d (confirmed %d protected %d)", count, failures, passes, len(findings), wantFail, wantPass)
			}
			cwe := false
			for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
				if id, _ := rule["id"].(string); strings.HasPrefix(id, "scan/path-traversal") && strings.Contains(string(mustJSON(rule)), "CWE-22") {
					cwe = true
				}
			}
			if !cwe {
				t.Fatal("SARIF rule lacks CWE-22")
			}
		})
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
