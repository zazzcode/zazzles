package langpy

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPythonCommandTerminatingGuards(t *testing.T) {
	uses := analyzeCommandRoutes(t, "app.py", `
import os
import sys
import subprocess
from flask import Flask, abort, request
app = Flask(__name__)
ALLOWED = {"uptime", "date"}

def log(value):
    return value

@app.route("/abort")
def guarded_abort():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    os.system("echo " + cmd)
    return "ok"

@app.route("/exit")
def guarded_exit():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        sys.exit(1)
    return str(subprocess.run("echo " + cmd, shell=True))

@app.route("/raise")
def guarded_raise():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        raise ValueError(cmd)
    os.system("echo " + cmd)
    return "ok"

@app.route("/derived")
def guarded_derived():
    cmd = request.args.get("c", "")
    clean = cmd.strip()
    if clean not in ALLOWED:
        abort(403)
    os.system("echo " + cmd)
    return "ok"

@app.route("/unguarded")
def unguarded():
    cmd = request.args.get("c", "")
    os.system("echo " + cmd)
    return "ok"

@app.route("/other-operand")
def other_operand():
    cmd = request.args.get("c", "")
    if request.args.get("other", "") not in ALLOWED:
        abort(403)
    os.system("echo " + cmd)
    return "ok"

@app.route("/bare-call")
def bare_call():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        log(cmd)
    os.system("echo " + cmd)
    return "ok"

@app.route("/presence")
def presence():
    cmd = request.args.get("c", "")
    if not cmd:
        abort(400)
    os.system("echo " + cmd)
    return "ok"

@app.route("/reassigned")
def reassigned():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    cmd = cmd + request.args.get("d", "")
    os.system("echo " + cmd)
    return "ok"
`)
	requireGuards(t, "/abort", uses["/abort"], "terminating_guard: if cmd not in ALLOWED: abort(403)")
	requireGuards(t, "/exit", uses["/exit"], "terminating_guard: if cmd not in ALLOWED: sys.exit(1)")
	requireGuards(t, "/derived", uses["/derived"], "terminating_guard: if clean not in ALLOWED: abort(403)")
	requireGuards(t, "/raise", uses["/raise"], "branch_false_precondition: cmd not in ALLOWED")
	for _, route := range []string{"/abort", "/exit", "/raise", "/derived"} {
		if got := commandProtection(uses[route]); got != "guarded" {
			t.Fatalf("%s protection %s, want guarded", route, got)
		}
	}
	for _, route := range []string{"/unguarded", "/other-operand", "/bare-call", "/presence", "/reassigned"} {
		if got := commandGuardFacts(uses[route]); len(got) != 0 {
			t.Fatalf("%s guards %q, want none", route, got)
		}
		if got := commandProtection(uses[route]); got != "raw" {
			t.Fatalf("%s protection %s, want raw", route, got)
		}
	}
}

func TestPythonCommandUnverifiedAbortIsNotAGuard(t *testing.T) {
	uses := analyzeCommandRoutes(t, "app.py", `
import os
from flask import Flask, request
app = Flask(__name__)
ALLOWED = {"uptime"}

def abort(code):
    return code

@app.route("/local-abort")
def local_abort():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    os.system("echo " + cmd)
    return "ok"
`)
	requireGuards(t, "/local-abort", uses["/local-abort"])
	if got := commandProtection(uses["/local-abort"]); got != "raw" {
		t.Fatalf("protection %s, want raw", got)
	}
}

func TestCommandHelperCallerGuards(t *testing.T) {
	t.Run("python", func(t *testing.T) {
		uses := analyzeCommandRoutes(t, "app.py", `
import os
from flask import Flask, abort, request
app = Flask(__name__)
ALLOWED = {"uptime"}

def run(c):
    os.system("echo " + c)

@app.route("/one")
def one():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    run(cmd)
    return "ok"

@app.route("/two-same")
def two_same():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    run(cmd)
    run(cmd)
    return "ok"

@app.route("/two-mixed")
def two_mixed():
    cmd = request.args.get("c", "")
    if request.args.get("mode") == "a":
        if cmd not in ALLOWED:
            abort(403)
        run(cmd)
    else:
        run(cmd)
    return "ok"
`)
		requireGuards(t, "/one", uses["/one"], "terminating_guard: if cmd not in ALLOWED: abort(403)")
		requireGuards(t, "/two-same", uses["/two-same"], "terminating_guard: if cmd not in ALLOWED: abort(403)")
		for _, g := range commandGuardFacts(uses["/two-mixed"]) {
			if strings.HasPrefix(g, "terminating_guard") {
				t.Fatalf("/two-mixed credited a guard present at one call site only: %q", g)
			}
		}
	})
}

func TestCommandGuardAllowlistDefinitions(t *testing.T) {
	py := analyzeCommandRoutes(t, "app.py", `
import os
from flask import Flask, abort, request
app = Flask(__name__)
ALLOWED = {"uptime", "date"}
DYNAMIC = ["a"]
DYNAMIC.append(os.environ.get("EXTRA"))

@app.route("/abort")
def guarded():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    os.system("echo " + cmd)
    return "ok"

@app.route("/raise")
def raising():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        raise ValueError(cmd)
    os.system("echo " + cmd)
    return "ok"

@app.route("/mutated")
def mutated():
    cmd = request.args.get("c", "")
    if cmd not in DYNAMIC:
        abort(403)
    os.system("echo " + cmd)
    return "ok"
`)
	for _, route := range []string{"/abort", "/raise"} {
		if got := definitionTexts(py[route]); len(got) != 1 || !strings.Contains(got[0], `ALLOWED = {"uptime", "date"}`) {
			t.Fatalf("%s definitions %q", route, got)
		}
	}
	if got := definitionTexts(py["/mutated"]); len(got) != 0 {
		t.Fatalf("/mutated: unexpected definitions %q", got)
	}
}

func TestCommandGuardInvalidatedByEveryWriteForm(t *testing.T) {
	py := analyzeCommandRoutes(t, "app.py", `
import os
import sys
from flask import Flask, abort, request
app = Flask(__name__)
ALLOWED = {"uptime"}
OTHER = ["a"]

@app.route("/derived-root")
def derived_root():
    cmd = request.args.get("c", "")
    clean = cmd.strip()
    if clean not in ALLOWED:
        abort(403)
    cmd = request.args.get("d", "")
    os.system(cmd)
    return "ok"

@app.route("/tuple")
def tuple_write():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    cmd, n = request.args.get("d", ""), 1
    os.system(cmd)
    return "ok"

@app.route("/walrus")
def walrus():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    if (cmd := request.args.get("d", "")):
        os.system(cmd)
    return "ok"

@app.route("/loop")
def loop():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        abort(403)
    for cmd in request.args.getlist("d"):
        pass
    os.system(cmd)
    return "ok"

@app.route("/body-names-another-list")
def body_list():
    cmd = request.args.get("c", "")
    if cmd not in ALLOWED:
        sys.exit(len(OTHER))
    os.system("echo " + cmd)
    return "ok"
`)
	for _, route := range []string{"/derived-root", "/tuple", "/walrus", "/loop"} {
		for _, g := range commandGuardFacts(py[route]) {
			if strings.HasPrefix(g, "terminating_guard") {
				t.Fatalf("%s kept a guard after the operand was rewritten: %q", route, g)
			}
		}
	}
	if got := definitionTexts(py["/body-names-another-list"]); len(got) != 1 || !strings.Contains(got[0], "ALLOWED") {
		t.Fatalf("only the list the condition tests is attached, got %q", got)
	}
}

func analyzeCommandRoutes(t *testing.T, name, source string) map[string]analysis.CandidateUse {
	t.Helper()
	out := map[string]analysis.CandidateUse{}
	for route, uses := range analyzeCommandUses(t, name, source) {
		if len(uses) != 1 {
			t.Fatalf("%s: %d command candidates, want 1", route, len(uses))
		}
		out[route] = uses[0]
	}
	return out
}

// commandGuardFacts lists "kind: condition" for the guard evidence of a command use.
func commandGuardFacts(u analysis.CandidateUse) []string {
	var out []string
	for _, g := range u.Completeness.Evidence["guard"] {
		out = append(out, g.Kind+": "+strings.Join(strings.Fields(g.Text), " "))
	}
	sort.Strings(out)
	return out
}

func commandProtection(u analysis.CandidateUse) string {
	for _, p := range u.Command.Paths {
		if p.Protection != "guarded" {
			return p.Protection
		}
	}
	return "guarded"
}

func definitionTexts(u analysis.CandidateUse) []string {
	var out []string
	for _, e := range u.Context {
		if e.Kind == "allowlist_definition" {
			out = append(out, strings.Join(strings.Fields(e.Text), " "))
		}
	}
	return out
}

func requireGuards(t *testing.T, route string, u analysis.CandidateUse, want ...string) {
	t.Helper()
	got := commandGuardFacts(u)
	if len(got) != len(want) {
		t.Fatalf("%s: guards %q, want %d matching %q", route, got, len(want), want)
	}
	for i, fragment := range want {
		if !strings.HasPrefix(got[i], fragment) && !strings.Contains(got[i], fragment) {
			t.Fatalf("%s: guards %q, want %q", route, got, want)
		}
	}
}

func analyzeCommandUses(t *testing.T, name, source string) map[string][]analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	writeSource(t, root, name, source)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return commandRoutes(r)
}
