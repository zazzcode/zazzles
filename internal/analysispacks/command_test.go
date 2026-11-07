package analysispacks

import (
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func commandUse(file, id string) analysis.CandidateUse {
	return analysis.CandidateUse{Kind: "command_execution_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}}, APIModel: CommandContract(id),
		Completeness: &analysis.Completeness{ClaimKind: "command_execution", Required: []string{"input_source", "sink_binding"}, Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
}

func TestCommandComponentSelection(t *testing.T) {
	if err := Validate(); err != nil {
		t.Fatal(err)
	}
	f := FamFamily("command_execution_candidate")
	if f == nil || !f.RequiresAPI || ProtocolFor("command_execution_candidate") != "command-components-v1" || !f.PythonHTTPOnly {
		t.Fatalf("family registration: %+v", f)
	}
	if want := []string{"shell_syntax_protection", "executable_control", "argument_control", "protection_coverage"}; !reflect.DeepEqual(f.QuestionNames, want) {
		t.Fatalf("question protocol %v", f.QuestionNames)
	}
	for _, tt := range []struct{ file, id, language string }{
		{"server.ts", NodeShellContract, "language.command.javascript"},
		{"server.js", NodeArgvContract, "language.command.javascript"},
		{"app.py", PythonOSContract, "language.command.python"},
		{"app.py", PythonSubprocessID, "language.command.python"},
	} {
		s, err := Select(commandUse(tt.file, tt.id))
		if err != nil {
			t.Fatalf("%s: %v", tt.id, err)
		}
		have := map[string]bool{}
		for _, c := range s.Components {
			have[c.ID] = true
		}
		for _, want := range []string{"pack.command", "claim.command", "evidence.command", "flow.command", tt.language, "entry.http", "api." + tt.id} {
			if !have[want] {
				t.Fatalf("%s selection missing %s: %v", tt.id, want, have)
			}
		}
		for _, role := range []string{"command_operands", "execution_configuration", "control_flow", "input_source"} {
			if !contains(s.Required, role) {
				t.Fatalf("%s missing obligation %s: %v", tt.id, role, s.Required)
			}
		}
		for other := range have {
			if strings.HasPrefix(other, "language.") && other != tt.language {
				t.Fatalf("unexpected guidance %s", other)
			}
		}
		use := commandUse(tt.file, tt.id)
		use.Components = s
		m, err := ForUse(use)
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Questions) != 4 || m.Contract == nil || m.Contract.ID != tt.id || !strings.HasPrefix(m.Guidelines.ID, "zazzles.command.") {
			t.Fatalf("material: %+v", m)
		}
		if len(m.Choices["executable_control"]) != 4 || len(m.Choices["protection_coverage"]) != 3 {
			t.Fatalf("choices: %v", m.Choices)
		}
	}
	a, _ := Select(commandUse("a.py", PythonOSContract))
	b, _ := Select(commandUse("a.py", PythonOSContract))
	if !reflect.DeepEqual(a, b) {
		t.Fatal("selection not deterministic")
	}
}

func TestCommandComponentFailures(t *testing.T) {
	for name, tt := range map[string]struct {
		mutate func(*analysis.CandidateUse)
		want   string
	}{
		"missing contract":     {func(u *analysis.CandidateUse) { u.APIModel = nil }, "needs verified API binding"},
		"missing binding":      {func(u *analysis.CandidateUse) { u.Completeness.Evidence = map[string][]analysis.Evidence{} }, "needs verified API binding"},
		"conflicting contract": {func(u *analysis.CandidateUse) { m := *u.APIModel; m.Semantics += " tampered"; u.APIModel = &m }, "unsupported or conflicting"},
		"browser entry":        {func(u *analysis.CandidateUse) { u.EntryKind = "client" }, "unsupported Command execution entry"},
		"unsupported language": {func(u *analysis.CandidateUse) { u.Sink.Span.File = "main.go" }, "unsupported Command execution source language"},
		"python non-http entry": {func(u *analysis.CandidateUse) {
			u.Sink.Span.File = "x.py"
			u.APIModel = CommandContract(PythonOSContract)
			u.EntryKind = "graphql"
		}, "unsupported Python"},
	} {
		t.Run(name, func(t *testing.T) {
			u := commandUse("server.js", NodeShellContract)
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
	u := commandUse("server.js", NodeShellContract)
	Attach(&u)
	u.Components.Digest = "stale"
	if _, err := ForUse(u); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale selection: %v", err)
	}
	s, _ := Select(commandUse("server.js", NodeShellContract))
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

func TestCommandContractsCiteOfficialSemantics(t *testing.T) {
	for _, id := range commandContractIDs {
		c := CommandContract(id)
		if c == nil || c.ID != id || !strings.HasPrefix(c.Reference, "https://") || c.Semantics == "" {
			t.Fatalf("contract %s: %+v", id, c)
		}
	}
	if CommandContract("unknown") != nil {
		t.Fatal("unknown contract resolved")
	}
	if !strings.Contains(CommandContract(PythonSubprocessID).Semantics, "first item is shell command text") {
		t.Fatal("subprocess POSIX sequence semantics missing")
	}
}
