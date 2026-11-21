package analysispacks_test

import (
	"encoding/json"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func TestPythonInputSelection(t *testing.T) {
	r, err := pipeline.Analyze("../langpy/testdata/command-injection", "")
	if err != nil {
		t.Fatal(err)
	}
	var use analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "command_execution_candidate" {
			use = u
			break
		}
	}
	if use.InputFacts == nil {
		t.Fatal("missing Python command input facts")
	}
	selected, err := analysispacks.Select(use)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range selected.Components {
		found = found || c.ID == "source.python-input-v1"
	}
	if !found {
		t.Fatal("Python input component not selected")
	}
	for name, change := range map[string]func(*analysis.CandidateUse){
		"source":            func(u *analysis.CandidateUse) { u.InputFacts.Values[0].Source.SHA256 = "stale" },
		"transfer":          func(u *analysis.CandidateUse) { u.InputFacts.Values[0].Transfers = nil },
		"binding":           func(u *analysis.CandidateUse) { u.InputFacts.Binding.SHA256 = "stale" },
		"framework":         func(u *analysis.CandidateUse) { u.InputFacts.Framework = "express" },
		"acquisition":       func(u *analysis.CandidateUse) { u.InputFacts.Acquisition = "grpc" },
		"missing entry":     func(u *analysis.CandidateUse) { u.EntryFacts = nil },
		"unsupported nosql": func(u *analysis.CandidateUse) { u.Kind = "nosql_query_candidate" },
	} {
		t.Run(name, func(t *testing.T) {
			b, err := json.Marshal(use)
			if err != nil {
				t.Fatal(err)
			}
			var changed analysis.CandidateUse
			if err := json.Unmarshal(b, &changed); err != nil {
				t.Fatal(err)
			}
			change(&changed)
			if _, err := analysispacks.Select(changed); err == nil {
				t.Fatal("accepted invalid acquisition provenance or unsupported language family")
			}
		})
	}
	use.InputFacts = nil
	historical, err := analysispacks.Select(use)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range historical.Components {
		if c.ID == "source.python-input-v1" {
			t.Fatal("historical nil facts gained a new component")
		}
	}
}
