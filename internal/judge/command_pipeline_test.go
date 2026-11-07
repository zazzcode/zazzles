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

// TestCommandPipelineParity parses real HTTP, GraphQL and gRPC fixtures,
// assesses them with stubbed answers and verifies that JSON, HTML and SARIF
// agree on unique record counts, identities and statuses.
func TestCommandPipelineParity(t *testing.T) {
	fixtures := []struct {
		dir       string
		confirmed int
		protected int
		contexts  int // entries in the fixture, including zero-use contexts
	}{
		{"typescript/command-injection", 1, 0, 1},
		{"javascript/command-injection/goof", 1, 0, 1},
		{"python/command-injection", 9, 0, 11},
		{"javascript/command-injection/graphql", 1, 1, 3},
		{"javascript/command-injection/grpc", 1, 0, 2},
	}
	for _, fx := range fixtures {
		t.Run(fx.dir, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+fx.dir, "")
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Entries) != fx.contexts {
				t.Fatalf("entries = %d, want %d (zero-use contexts must stay present)", len(r.Entries), fx.contexts)
			}
			confirmed, protected := 0, 0
			for i := range r.Uses {
				u := &r.Uses[i]
				if u.Kind != "command_execution_candidate" {
					continue
				}
				answers := rawShell
				if strings.Contains(u.Sink.Text, "execFile('/bin/ping'") {
					answers = optimistic
				}
				if u.Command.EffectiveShellMode != "enabled" && answers[("shell_syntax_protection")] == "vulnerable" {
					answers = commandAnswers{"shell_syntax_protection": "not_applicable", "executable_control": "unsafe", "argument_control": "unknown", "protection_coverage": "incomplete"}
				}
				c, _ := commandStub(t, "openai", answers)
				u.Assessment = c.Assess(context.Background(), *u)
				switch u.Assessment.FindingStatus {
				case "confirmed_vulnerability":
					confirmed++
				case "protected_for_claim":
					protected++
				}
			}
			if confirmed < fx.confirmed || protected != fx.protected {
				t.Fatalf("confirmed %d (want >= %d) protected %d (want %d)", confirmed, fx.confirmed, protected, fx.protected)
			}
			report.Enrich(r)
			var findings []analysis.Finding
			for _, f := range r.Findings {
				for _, id := range f.TypeIDs {
					if id == "command-injection" {
						findings = append(findings, f)
					}
				}
			}
			uses := commandUsesOf(r)
			if len(findings) != len(uses) {
				t.Fatalf("one record per process use: %d findings for %d uses", len(findings), len(uses))
			}
			// JSON round trip keeps the records.
			raw, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			var saved analysis.AnalysisReport
			if err := json.Unmarshal(raw, &saved); err != nil {
				t.Fatal(err)
			}
			if got := len(commandUsesOf(&saved)); got != len(uses) {
				t.Fatalf("JSON uses %d want %d", got, len(uses))
			}
			// HTML names every record and the family label.
			var html bytes.Buffer
			if err := report.HTML(&html, &saved); err != nil {
				t.Fatal(err)
			}
			page := html.String()
			if !strings.Contains(page, "Command Injection") {
				t.Fatal("HTML lacks the Command Injection label")
			}
			// SARIF: one result per command record, same statuses and rule family.
			var sarif struct {
				Runs []struct {
					Results []map[string]any `json:"results"`
				} `json:"runs"`
			}
			sarifRaw, _ := json.Marshal(report.SARIF(&saved))
			if err := json.Unmarshal(sarifRaw, &sarif); err != nil {
				t.Fatal(err)
			}
			count, failures := 0, 0
			for _, res := range sarif.Runs[0].Results {
				if strings.HasPrefix(res["ruleId"].(string), "scan/command-") {
					count++
					if res["kind"] == "fail" {
						failures++
					}
				}
			}
			wantFail := 0
			for _, f := range findings {
				if f.RecordType == "finding" && f.Status == "confirmed_vulnerability" {
					wantFail++
				}
			}
			if count != len(findings) || failures != wantFail || wantFail < fx.confirmed {
				t.Fatalf("SARIF results %d (fail %d) vs findings %d (confirmed %d)", count, failures, len(findings), wantFail)
			}
		})
	}
}
