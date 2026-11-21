package langpy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestCommandBindingsAndOptions(t *testing.T) {
	type tc struct {
		name, file, source string
		want               int    // candidates
		operation          string // expected operation when want > 0
		shell              string // expected effective shell mode
	}
	py := func(name, head, body string, want int, op, shell string) tc {
		return tc{name, "app.py", "from flask import Flask, request\n" + head + "app = Flask(__name__)\n@app.route('/p')\ndef p():\n" + body + "\n    return ''\n", want, op, shell}
	}
	pcases := []tc{
		py("import os", "import os\n", "    os.system('echo ' + request.args.get('x', ''))", 1, "os.system", "enabled"),
		py("os alias", "import os as o\n", "    o.popen('echo ' + request.args.get('x', ''))", 1, "os.popen", "enabled"),
		py("from import", "from subprocess import check_output as co\n", "    co(['ls', request.args.get('x', '')])", 1, "subprocess.check_output", "disabled"),
		py("shell kwarg true", "import subprocess\n", "    subprocess.call('ls ' + request.args.get('x', ''), shell=True)", 1, "subprocess.call", "enabled"),
		py("dynamic shell kwarg", "import subprocess\n", "    subprocess.call('ls ' + request.args.get('x', ''), shell=request.args.get('s'))", 1, "subprocess.call", "unknown"),
		py("kwargs spread", "import subprocess\n", "    subprocess.run(['ls', request.args.get('x', '')], **{'shell': True})", 1, "subprocess.run", "disabled"),
		py("local alias", "import subprocess\nrun = subprocess.run\n", "    run(['ls', request.args.get('x', '')])", 1, "subprocess.run", "disabled"),
		py("reassigned alias", "import subprocess\nrun = subprocess.run\nrun = print\n", "    run(['ls', request.args.get('x', '')])", 0, "", ""),
		py("local variable shadows os", "import os\n", "    os = FakeOS()\n    os.system('echo ' + request.args.get('x', ''))", 0, "", ""),
		py("monkey patch", "import os\nos.system = print\n", "    os.system('echo ' + request.args.get('x', ''))", 0, "", ""),
		py("fake module object", "class os:\n    @staticmethod\n    def system(c):\n        pass\n", "    os.system('echo ' + request.args.get('x', ''))", 0, "", ""),
		py("windows interpreter", "import subprocess\n", "    subprocess.run(['cmd', '/c', request.args.get('x', '')])", 1, "subprocess.run", "unknown"),
	}
	for _, c := range pcases {
		t.Run("python/"+c.name, func(t *testing.T) {
			uses := commandSources(t, map[string]string{c.file: c.source}, "")
			if len(uses) != c.want {
				t.Fatalf("candidates = %d, want %d", len(uses), c.want)
			}
			if c.want == 0 {
				return
			}
			f := uses[0].Command
			if f.Operation != c.operation || f.EffectiveShellMode != c.shell {
				t.Fatalf("facts %+v", f)
			}
			validCommandFacts(t, uses[0])
		})
	}
	// Local module shadowing: a project os.py defeats the standard-library binding.
	t.Run("python/local module shadow", func(t *testing.T) {
		uses := commandSources(t, map[string]string{"os.py": "def system(c):\n    pass\n", "app.py": "import os\nfrom flask import Flask, request\napp = Flask(__name__)\n@app.route('/p')\ndef p():\n    os.system('echo ' + request.args.get('x', ''))\n    return ''\n"}, "")
		if len(uses) != 0 {
			t.Fatalf("shadowed module produced %d candidates", len(uses))
		}
	})
}

func analyzeFixture(t *testing.T, dir string) *analysis.AnalysisReport {
	t.Helper()
	r, err := Analyze(filepath.Join("testdata", dir), "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func commandSources(t *testing.T, files map[string]string, entry string) []analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	writeTree(t, root, files)
	r, err := Analyze(root, entry)
	if err != nil {
		t.Fatal(err)
	}
	return commandUses(r)
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

func commandUses(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "command_execution_candidate" {
			out = append(out, u)
		}
	}
	return out
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
	r := analyzeFixture(t, "command-injection")
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
			for _, role := range u.Completeness.Required {
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
