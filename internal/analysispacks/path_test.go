package analysispacks

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func pathUse(file, id string) analysis.CandidateUse {
	return analysis.CandidateUse{Kind: "path_traversal_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}}, APIModel: PathContract(id),
		Completeness: &analysis.Completeness{ClaimKind: "path_traversal", Required: []string{"input_source", "sink_binding"}, Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
}

func TestPathComponentSelection(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	f := FamFamily("path_traversal_candidate")
	if f == nil || !f.RequiresAPI || ProtocolFor("path_traversal_candidate") != "path-components-v1" || !f.PythonHTTPOnly {
		t.Fatalf("family registration: %+v", f)
	}
	if want := []string{"path_traversal", "containment_control", "protection_coverage"}; !reflect.DeepEqual(f.QuestionNames, want) {
		t.Fatalf("question protocol %v", f.QuestionNames)
	}
	for _, tt := range []struct{ file, id, language string }{
		{"server.ts", NodeFSContract, "language.path.javascript"},
		{"server.js", NodeFSContract, "language.path.javascript"},
		{"app.py", PythonOpenContract, "language.path.python"},
		{"app.py", PythonPathlibContract, "language.path.python"},
	} {
		s, err := Select(pathUse(tt.file, tt.id))
		if err != nil {
			t.Fatalf("%s: %v", tt.id, err)
		}
		have := map[string]bool{}
		for _, c := range s.Components {
			have[c.ID] = true
		}
		for _, want := range []string{"pack.path", "claim.path", "evidence.path", "flow.path", tt.language, "entry.http", "api." + tt.id} {
			if !have[want] {
				t.Fatalf("%s selection missing %s: %v", tt.id, want, have)
			}
		}
		if !contains(s.Required, "path_operands") || !contains(s.Required, "input_source") {
			t.Fatalf("%s missing obligations: %v", tt.id, s.Required)
		}
		for other := range have {
			if strings.HasPrefix(other, "language.") && other != tt.language {
				t.Fatalf("unexpected guidance %s", other)
			}
			if strings.HasPrefix(other, "api.") && other != "api."+tt.id {
				t.Fatalf("unexpected contract %s", other)
			}
		}
		use := pathUse(tt.file, tt.id)
		use.Components = s
		m, err := ForUse(use)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Questions) != 3 || m.Contract == nil || m.Contract.ID != tt.id || !strings.HasPrefix(m.Guidelines.ID, "zazzles.path.") {
			t.Fatalf("material: %+v", m)
		}
		if len(m.Choices["containment_control"]) != 5 || len(m.Choices["protection_coverage"]) != 3 {
			t.Fatalf("choices: %v", m.Choices)
		}
	}
	a, _ := Select(pathUse("a.py", PythonOpenContract))
	b, _ := Select(pathUse("a.py", PythonOpenContract))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("selection not deterministic")
	}
}

func TestPathNodeInputSelectionLeavesSharedComponentUnchanged(t *testing.T) {
	use := pathUse("server.ts", NodeFSContract)
	use.InputFacts = &analysis.InputFacts{Version: 1, Acquisition: "http"}
	use.InputFacts.Binding = analysis.Evidence{}
	shared := nodeInputComponent()
	if contains(shared.Applicability, "path_traversal_candidate") || contains(shared.Compatibility, PathProtocol) {
		t.Fatal("path widened the shared node-input component, which would change every existing family's request")
	}
	if p := pathNodeInputComponent(); p.Material != shared.Material || p.ID == shared.ID || !reflect.DeepEqual(p.Applicability, []string{"path_traversal_candidate"}) {
		t.Fatalf("path node-input component: %+v", p)
	}
}

func TestPathComponentFailures(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate func(*analysis.CandidateUse)
		want   string
	}{
		"missing contract":     {func(u *analysis.CandidateUse) { u.APIModel = nil }, "needs verified API binding"},
		"missing binding":      {func(u *analysis.CandidateUse) { u.Completeness.Evidence = map[string][]analysis.Evidence{} }, "needs verified API binding"},
		"conflicting contract": {func(u *analysis.CandidateUse) { m := *u.APIModel; m.Semantics += " tampered"; u.APIModel = &m }, "unsupported or conflicting"},
		"browser entry":        {func(u *analysis.CandidateUse) { u.EntryKind = "client" }, "unsupported Path traversal entry"},
		"unsupported language": {func(u *analysis.CandidateUse) { u.Sink.Span.File = "main.go" }, "unsupported Path traversal source language"},
		"python non-http entry": {func(u *analysis.CandidateUse) {
			u.Sink.Span.File = "x.py"
			u.APIModel = PathContract(PythonOpenContract)
			u.EntryKind = "graphql"
		}, "unsupported Python"},
	} {
		t.Run(name, func(t *testing.T) {
			u := pathUse("server.js", NodeFSContract)
			tt.mutate(&u)
			if _, err := Select(u); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
			Attach(&u)
			if u.Components == nil || u.Components.Failure == "" {
				t.Fatal("failure not recorded")
			}
			if _, err := ForUse(u); err == nil {
				t.Fatal("material produced after failed selection")
			}
		})
	}
	u := pathUse("server.js", NodeFSContract)
	Attach(&u)
	u.Components.Digest = "stale"
	if _, err := ForUse(u); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale selection: %v", err)
	}
	s, _ := Select(pathUse("server.js", NodeFSContract))
	if len(s.Components) > MaxComponents {
		t.Fatalf("components %d", len(s.Components))
	}
	total := 0
	for _, c := range s.Components {
		total += len(embedded.components[c.ID].Material)
	}
	if total > MaxMaterialBytes {
		t.Fatalf("material %d bytes", total)
	}
}

func TestPathBindingsAndOptions(t *testing.T) {
	for _, id := range pathContractIDs {
		c := PathContract(id)
		if c == nil || c.ID != id || !strings.HasPrefix(c.Reference, "https://") || c.Semantics == "" {
			t.Fatalf("contract %s: %+v", id, c)
		}
	}
	if PathContract("unknown") != nil {
		t.Fatal("unknown contract resolved")
	}
	for id, want := range map[string]string{
		NodeFSContract:        "an absolute later segment is appended",
		PythonOpenContract:    "returns the later segment alone when it is absolute",
		PythonPathlibContract: "replaces the base when a later segment is absolute",
	} {
		if !strings.Contains(PathContract(id).Semantics, want) {
			t.Fatalf("%s semantics missing %q", id, want)
		}
	}
}
