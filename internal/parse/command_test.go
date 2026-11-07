package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func commandUses(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "command_execution_candidate" {
			out = append(out, u)
		}
	}
	return out
}

func analyzeFixture(t *testing.T, dir string) *analysis.AnalysisReport {
	t.Helper()
	r, err := Analyze(filepath.Join("testdata", dir), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func slotOf(f *analysis.CommandFacts, slot string) *analysis.CommandOperand {
	for i := range f.Operands {
		if f.Operands[i].Slot == slot {
			return &f.Operands[i]
		}
	}
	return nil
}

// validCommandFacts verifies every serialized index and reference.
func validCommandFacts(t *testing.T, u analysis.CandidateUse) {
	t.Helper()
	if err := u.Command.Validate(len(u.Dependencies), len(u.Context)); err != nil {
		t.Fatalf("invalid command facts: %v", err)
	}
	for _, d := range u.Dependencies {
		if d.Source.SHA256 == "" || d.Source.Span.File == "" {
			t.Fatalf("dependency lacks snapshot reference: %+v", d.Source)
		}
	}
}

func TestCommandJSOperands(t *testing.T) {
	t.Run("express ping", func(t *testing.T) {
		r := analyzeFixture(t, "typescript/command-injection")
		uses := commandUses(r)
		if len(uses) != 1 {
			t.Fatalf("command candidates = %d, want 1", len(uses))
		}
		u := uses[0]
		f := u.Command
		if f == nil || f.Operation != "child_process.exec" || f.ContractID != analysispacks.NodeShellContract || f.Platform != "posix" || f.APIShellMode != "enabled" || f.EffectiveShellMode != "enabled" || f.ArgvShape != "none" {
			t.Fatalf("facts: %+v", f)
		}
		validCommandFacts(t, u)
		shell := slotOf(f, analysis.CommandSlotShell)
		if shell == nil || len(shell.Dependencies) != 1 || !shell.Dynamic {
			t.Fatalf("shell operand: %+v", shell)
		}
		dep := u.Dependencies[shell.Dependencies[0]]
		if dep.Source.Text != "req.query.host" || dep.SinkSlot != analysis.CommandSlotShell {
			t.Fatalf("dependency: %+v", dep)
		}
		// cast/assignment and template transfers remain on the path.
		kinds := []string{}
		for _, e := range dep.Transfers {
			kinds = append(kinds, e.Kind)
		}
		if !strings.Contains(strings.Join(kinds, ","), "assignment") {
			t.Fatalf("assignment transfer missing: %v", kinds)
		}
		if u.APIModel == nil || u.APIModel.ID != analysispacks.NodeShellContract {
			t.Fatalf("contract: %+v", u.APIModel)
		}
		if len(u.Completeness.Evidence["sink_binding"]) == 0 || !strings.Contains(u.Completeness.Evidence["sink_binding"][0].Text, "child_process") {
			t.Fatalf("binding evidence: %+v", u.Completeness.Evidence["sink_binding"])
		}
		for _, role := range commandRequiredRoles {
			if len(u.Completeness.Evidence[role]) == 0 {
				t.Fatalf("role %s has no evidence", role)
			}
		}
		if len(u.Completeness.Blockers) != 0 {
			t.Fatalf("unexpected blockers: %+v", u.Completeness.Blockers)
		}
		if u.Components == nil || u.Components.Failure != "" || len(u.Components.Components) == 0 {
			t.Fatalf("component selection: %+v", u.Components)
		}
		if u.Completeness.ClaimKind != "command_execution" {
			t.Fatalf("claim kind %q", u.Completeness.ClaimKind)
		}
	})
	t.Run("goof regex capture", func(t *testing.T) {
		r := analyzeFixture(t, "javascript/command-injection/goof")
		uses := commandUses(r)
		if len(uses) != 1 {
			t.Fatalf("command candidates = %d, want 1", len(uses))
		}
		u := uses[0]
		validCommandFacts(t, u)
		if u.Command.Operation != "child_process.exec" || !strings.HasSuffix(u.Sink.Span.File, "routes/index.js") {
			t.Fatalf("facts: %+v sink %s", u.Command, u.Sink.Span.File)
		}
		dep := u.Dependencies[0]
		if dep.Source.Text != "req.body.content" {
			t.Fatalf("source %q", dep.Source.Text)
		}
		if len(u.Completeness.Blockers) != 0 {
			t.Fatalf("unexpected blockers: %+v", u.Completeness.Blockers)
		}
		if len(u.Completeness.Evidence["transformation"]) == 0 {
			t.Fatal("regex capture transfer evidence missing")
		}
	})
	t.Run("constant call is not a candidate", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {exec}=require('child_process');const app=express();app.get('/p',(req,res)=>{exec('uptime',()=>{});res.send('x')});`)
		r, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		if n := len(commandUses(r)); n != 0 {
			t.Fatalf("constant-only call produced %d candidates", n)
		}
	})
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, text := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func commandRoutes(r *analysis.AnalysisReport) map[string][]analysis.CandidateUse {
	paths := map[string]string{}
	for _, e := range r.Entries {
		paths[e.ID] = e.HTTPRoute().PathPattern
	}
	out := map[string][]analysis.CandidateUse{}
	for _, u := range commandUses(r) {
		out[paths[u.EntryID]] = append(out[paths[u.EntryID]], u)
	}
	return out
}

func TestCommandPythonOperands(t *testing.T) {
	r := analyzeFixture(t, "python/command-injection")
	routes := commandRoutes(r)
	type want struct {
		op, api, effective, argv string
		slots                    []string // slots that carry request dependencies
	}
	for path, w := range map[string]want{
		"/system":         {"os.system", "python-os-shell-v1", "enabled", "none", []string{"shell_command"}},
		"/popen":          {"os.popen", "python-os-shell-v1", "enabled", "none", []string{"shell_command"}},
		"/argv":           {"subprocess.check_output", "python-subprocess-v1", "disabled", "literal_list", []string{"argument:1"}},
		"/shell-string":   {"subprocess.run", "python-subprocess-v1", "enabled", "none", []string{"shell_command"}},
		"/shell-sequence": {"subprocess.call", "python-subprocess-v1", "enabled", "literal_list", []string{"argument:1"}},
		"/keyword":        {"subprocess.Popen", "python-subprocess-v1", "enabled", "none", []string{"shell_command"}},
		"/executable":     {"subprocess.run", "python-subprocess-v1", "disabled", "literal_list", []string{"executable_override"}},
		"/interpreter":    {"subprocess.run", "python-subprocess-v1", "enabled", "literal_list", []string{"shell_command"}},
		"/alias":          {"subprocess.run", "python-subprocess-v1", "enabled", "none", []string{"shell_command"}},
	} {
		t.Run(path, func(t *testing.T) {
			uses := routes[path]
			if len(uses) != 1 {
				t.Fatalf("candidates = %d, want 1", len(uses))
			}
			u := uses[0]
			f := u.Command
			if f == nil || f.Operation != w.op || f.ContractID != w.api || f.EffectiveShellMode != w.effective || f.ArgvShape != w.argv || f.Platform != "posix" {
				t.Fatalf("facts: %+v", f)
			}
			validCommandFacts(t, u)
			got := []string{}
			for _, o := range f.Operands {
				if len(o.Dependencies) > 0 {
					got = append(got, o.Slot)
				}
			}
			if strings.Join(got, ",") != strings.Join(w.slots, ",") {
				t.Fatalf("request-derived slots %v, want %v (operands %+v)", got, w.slots, f.Operands)
			}
			for _, role := range commandRequiredRoles {
				if len(u.Completeness.Evidence[role]) == 0 {
					t.Fatalf("role %s has no evidence", role)
				}
			}
			if len(u.Completeness.Blockers) != 0 {
				t.Fatalf("blockers: %+v", u.Completeness.Blockers)
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("selection: %+v", u.Components)
			}
		})
	}
	for _, path := range []string{"/constant", "/stdio"} {
		if n := len(routes[path]); n != 0 {
			t.Errorf("%s produced %d candidates; constant and data-only calls are negative", path, n)
		}
	}
}
