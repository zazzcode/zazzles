package analysispacks

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestSQLTextContractSelection: a sql-text-v1 record is selected and validated
// for every SQL language, with no per-language driver prefix or capability.
func TestSQLTextContractSelection(t *testing.T) {
	model := SQLContract(SQLTextContract)
	if model == nil || model.ID != SQLTextContract || model.Library != SQLTextLibrary || model.Semantics != SQLTextSemantics {
		t.Fatalf("contract: %+v", model)
	}
	if model.Reference != "" {
		t.Errorf("the contract names a reference: %+v", model)
	}
	for _, file := range []string{"app.js", "app.ts", "app.py", "app.php"} {
		use := analysis.CandidateUse{Kind: "sql_query_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}},
			APIModel: SQLContract(SQLTextContract), Completeness: &analysis.Completeness{Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
		Attach(&use)
		if use.Components == nil || use.Components.Failure != "" {
			t.Fatalf("%s: selection: %+v", file, use.Components)
		}
		m, err := ForUse(use)
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if !reflect.DeepEqual(m.Contract, use.APIModel) {
			t.Errorf("%s: material contract differs", file)
		}
		// A tampered contract is still refused.
		bad := use
		tampered := *use.APIModel
		tampered.Semantics += " tampered"
		bad.APIModel = &tampered
		if _, err := Select(bad); err == nil || !strings.Contains(err.Error(), "unsupported or conflicting") {
			t.Errorf("%s: tampered contract: %v", file, err)
		}
	}
	// The record is in the catalog like every other contract.
	if embedded.components["api."+SQLTextContract].ID == "" {
		t.Error("no api component for the contract")
	}
}

func TestSQLTextQuestions(t *testing.T) {
	qs := SQLTextOperationQuestions()
	if len(qs) != 2 || qs[0].Name != "operation" || qs[1].Name != "request_control" {
		t.Fatalf("%+v", qs)
	}
	for _, q := range qs {
		if len(SQLTextOperationChoices(q.Name)) == 0 {
			t.Errorf("no choices for %s", q.Name)
		}
	}
	if len(SQLTextOperationChoices("operation")) != 3 || len(SQLTextOperationChoices("request_control")) != 4 {
		t.Error("choice counts")
	}
	if SQLTextOperationChoices("other") != nil {
		t.Error("choices for an unknown question")
	}
}
