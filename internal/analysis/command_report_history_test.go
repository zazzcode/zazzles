package analysis_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/report"
)

// TestCommandReportHistory verifies that saved schema1-4 reports keep their raw
// answers and gain no invented command facts, records or finding labels on export,
// and that a fresh report's command facts survive a JSON round trip.
func TestCommandReportHistory(t *testing.T) {
	c := modelCatalog()
	historical := analysis.CandidateUse{ID: "old-sql", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "sql_query_candidate", Sink: origin("handler.ts", 20),
		Assessment: analysis.Assessment{Status: "completed", QuestionVersion: "candidate-injection-v1", Answers: map[string]string{"injection_protection": "vulnerable", "protection": "insufficient"}, FindingStatus: "needs_evidence"}}
	for schema := 3; schema <= analysis.ReportSchemaVersion; schema++ { // schemas 1-2 need legacy route identity; report_compatibility_test covers them
		old := analysis.AnalysisReport{SchemaVersion: schema, Root: "missing-source", Entries: c.Entries, Registrations: c.Registrations, DispatchBindings: c.DispatchBindings, Callables: c.Callables, InvocationContexts: c.InvocationContexts, Uses: []analysis.CandidateUse{historical}}
		data, _ := json.Marshal(old)
		original := append([]byte{}, data...)
		var saved analysis.AnalysisReport
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		if saved.Uses[0].Command != nil || saved.SchemaVersion != schema || saved.Uses[0].Assessment.Answers["injection_protection"] != "vulnerable" {
			t.Fatalf("schema %d: historical answer or facts altered", schema)
		}
		var html bytes.Buffer
		if err := report.HTML(&html, &saved); err != nil {
			t.Fatal(err)
		}
		sarif, _ := json.Marshal(report.SARIF(&saved))
		if bytes.Contains(sarif, []byte("scan/command-")) || !bytes.Equal(data, original) {
			t.Fatalf("schema %d: export invented a command record or changed saved bytes", schema)
		}
		for _, f := range saved.Findings {
			for _, id := range f.TypeIDs {
				if id == "command-injection" {
					t.Fatalf("schema %d: invented command-injection finding", schema)
				}
			}
		}
		if strings.Contains(string(data), `"command"`) {
			t.Fatalf("schema %d: command facts appeared in a historical report", schema)
		}
	}
	// A fresh report carries command facts additively and round-trips them.
	facts := &analysis.CommandFacts{Operation: "child_process.exec", ContractID: "node-child-process-shell-v1", Platform: "posix", APIShellMode: "enabled", EffectiveShellMode: "enabled", ArgvShape: "none",
		Operands: []analysis.CommandOperand{{Slot: analysis.CommandSlotShell, Dependencies: []int{0}}}, Paths: []analysis.CommandPath{{Dependency: 0, Operand: analysis.CommandSlotShell, Protection: "raw"}}}
	fresh := analysis.CandidateUse{ID: "new-command", EntryID: c.Entries[0].ID, InvocationContextID: c.InvocationContexts[0].ID, Kind: "command_execution_candidate", Sink: origin("handler.ts", 30), Command: facts,
		Dependencies: []analysis.Dependency{{Source: origin("handler.ts", 28)}}, Context: []analysis.Evidence{origin("handler.ts", 30)}}
	data, _ := json.Marshal(fresh)
	var back analysis.CandidateUse
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if err := back.Command.Validate(len(back.Dependencies), len(back.Context)); err != nil || back.Command.Operation != facts.Operation {
		t.Fatalf("round trip: %v %+v", err, back.Command)
	}
	bad := *facts
	bad.Paths = []analysis.CommandPath{{Dependency: 3, Operand: analysis.CommandSlotShell, Protection: "raw"}}
	if bad.Validate(1, 1) == nil {
		t.Fatal("out-of-range dependency index accepted")
	}
}
