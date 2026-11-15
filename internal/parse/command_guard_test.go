package parse

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

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

const jsCommandPrelude = `const express=require('express');const {exec}=require('child_process');const app=express();
const ALLOWED=new Set(['uptime','date']);
`

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

func TestCommandGuardPolarityJS(t *testing.T) {
	uses := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
app.get('/then',(req,res)=>{const cmd=req.query.c;if(isSafe(cmd)){exec(cmd,()=>{});}res.send('x');});
app.get('/else',(req,res)=>{const cmd=req.query.c;if(isSafe(cmd)){res.send('safe');}else{exec(cmd,()=>{});}});
app.get('/elseif',(req,res)=>{const cmd=req.query.c;if(cmd==='a'){res.send('a');}else if(isSafe(cmd)){exec(cmd,()=>{});}else{res.send('n');}});
app.get('/in-condition',(req,res)=>{const cmd=req.query.c;if(exec(cmd,()=>{})){res.send('x');}});
app.get('/terminating',(req,res)=>{const cmd=req.query.c;if(isBad(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
`)
	requireGuards(t, "/then", uses["/then"], "enclosing_guard: (isSafe(cmd))")
	requireGuards(t, "/else", uses["/else"], "branch_false_precondition: (isSafe(cmd))")
	requireGuards(t, "/elseif", uses["/elseif"], "branch_false_precondition: (cmd==='a')", "enclosing_guard: (isSafe(cmd))")
	requireGuards(t, "/in-condition", uses["/in-condition"])
	requireGuards(t, "/terminating", uses["/terminating"], "terminating_guard: if(isBad(cmd))")
	for _, route := range []string{"/then", "/else", "/elseif", "/terminating"} {
		if got := commandProtection(uses[route]); got != "guarded" {
			t.Fatalf("%s protection %s, want guarded", route, got)
		}
	}
	if got := commandProtection(uses["/in-condition"]); got != "raw" {
		t.Fatalf("/in-condition protection %s, want raw", got)
	}
}

func TestCommandGuardDerivedAndReassigned(t *testing.T) {
	uses := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
app.get('/derived',(req,res)=>{const cmd=req.query.c;const clean=cmd.trim();if(!ALLOWED.has(clean)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/reassigned',(req,res)=>{let cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}cmd=cmd+req.query.d;exec(cmd,()=>{});res.send('x');});
app.get('/own-result',(req,res)=>{let cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}cmd=exec(cmd,()=>{});res.send('x');});
app.get('/other-operand',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(req.query.other)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/presence',(req,res)=>{const cmd=req.query.c;if(!cmd){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
`)
	requireGuards(t, "/derived", uses["/derived"], "terminating_guard: if(!ALLOWED.has(clean))")
	requireGuards(t, "/reassigned", uses["/reassigned"])
	requireGuards(t, "/own-result", uses["/own-result"], "terminating_guard: if(!ALLOWED.has(cmd))")
	requireGuards(t, "/other-operand", uses["/other-operand"])
	requireGuards(t, "/presence", uses["/presence"])
	if got := commandProtection(uses["/derived"]); got != "guarded" {
		t.Fatalf("/derived protection %s", got)
	}
	for _, route := range []string{"/reassigned", "/other-operand", "/presence"} {
		if got := commandProtection(uses[route]); got != "raw" {
			t.Fatalf("%s protection %s, want raw", route, got)
		}
	}
}

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
	t.Run("javascript", func(t *testing.T) {
		all := analyzeCommandUses(t, "server.js", jsCommandPrelude+`
function run(c){exec('echo '+c,()=>{});}
app.get('/one',(req,res)=>{const v=req.query.v;if(!ALLOWED.has(v)){return res.sendStatus(400);}run(v);res.send('x');});
app.get('/two-same',(req,res)=>{const v=req.query.v;if(!ALLOWED.has(v)){return res.sendStatus(400);}run(v);run(v);res.send('x');});
app.get('/two-mixed',(req,res)=>{const v=req.query.v;if(req.query.mode==='a'){if(!ALLOWED.has(v)){return res.sendStatus(400);}run(v);}else{run(v);}res.send('x');});
app.get('/none',(req,res)=>{run(req.query.v);res.send('x');});
`)
		for route, want := range map[string][]string{"/one": {"terminating_guard: if(!ALLOWED.has(v))"}, "/two-same": {"terminating_guard: if(!ALLOWED.has(v))"}, "/two-mixed": nil, "/none": nil} {
			if len(all[route]) == 0 {
				t.Fatalf("%s: no command candidates", route)
			}
			for _, u := range all[route] {
				requireGuards(t, route, u, want...)
				wantProtection := "guarded"
				if want == nil {
					wantProtection = "raw"
				}
				if got := commandProtection(u); got != wantProtection {
					t.Fatalf("%s protection %s, want %s", route, got, wantProtection)
				}
			}
		}
	})
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

func TestGuardTerminators(t *testing.T) {
	uses := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
app.get('/exit',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(cmd)){process.exit(1);}exec(cmd,()=>{});res.send('x');});
app.get('/shadowed',(req,res)=>{const process={exit(){}};const cmd=req.query.c;if(!ALLOWED.has(cmd)){process.exit(1);}exec(cmd,()=>{});res.send('x');});
`)
	requireGuards(t, "/exit", uses["/exit"], "terminating_guard: if(!ALLOWED.has(cmd))")
	requireGuards(t, "/shadowed", uses["/shadowed"])

	root := t.TempDir()
	writeSource(t, root, "server.js", `
const express=require('express');const fs=require('fs');const path=require('path');const app=express();
const ROOT=path.resolve(__dirname,'uploads');const ALLOWED=new Set(['a.txt','b.txt']);
app.get('/exit',(req,res)=>{const f=req.query.f;if(!ALLOWED.has(f)){process.exit(1);}res.send(fs.readFileSync(path.join(ROOT,f)));});
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	u, ok := pathUses(report)["/exit"]
	if !ok {
		t.Fatal("missing path candidate")
	}
	if got := guardKinds(u); len(got) != 1 || got[0] != analysis.PathGuardAllowlist {
		t.Fatalf("path guards %v, want [allowlist]", got)
	}
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

func TestCommandGuardAllowlistDefinitions(t *testing.T) {
	js := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
let dynamic = ['a'];
dynamic.push(process.env.EXTRA);
app.get('/constant',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/mutated',(req,res)=>{const cmd=req.query.c;if(!dynamic.includes(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/no-collection',(req,res)=>{const cmd=req.query.c;if(isBad(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
`)
	if got := definitionTexts(js["/constant"]); len(got) != 1 || !strings.Contains(got[0], "new Set(['uptime','date'])") {
		t.Fatalf("/constant definitions %q", got)
	}
	for _, route := range []string{"/mutated", "/no-collection"} {
		if got := definitionTexts(js[route]); len(got) != 0 {
			t.Fatalf("%s: unexpected definitions %q", route, got)
		}
	}
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

func gapKinds(gaps []analysis.Gap) string {
	var out []string
	for _, g := range gaps {
		out = append(out, g.Kind)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func TestCommandGuardResolvesItsControlFlowGaps(t *testing.T) {
	// A modeled if records no control-flow gap. The guard engine still settles the
	// gaps of an if the walk keeps unmodeled (here, one that rebinds the request).
	uses := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
app.get('/guard',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/with-else',(req,res)=>{let cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}else{cmd=cmd.trim();}exec(cmd,()=>{});res.send('x');});
app.get('/unrelated',(req,res)=>{const cmd=req.query.c;if(req.query.d){return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/fallback-guard',(req,res)=>{const cmd=req.query.c;if(!ALLOWED.has(cmd)){req=null;return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
app.get('/fallback-unrelated',(req,res)=>{const cmd=req.query.c;if(res.locals.d){req=null;return res.sendStatus(400);}exec(cmd,()=>{});res.send('x');});
`)
	flowGap := func(kinds string) bool {
		return strings.Contains(kinds, "branch_exit") || strings.Contains(kinds, "unsupported_control_flow")
	}
	for _, route := range []string{"/guard", "/with-else", "/unrelated", "/fallback-guard", "/fallback-unrelated"} {
		u := uses[route]
		resolved, coverage := gapKinds(u.Completeness.Resolved), gapKinds(u.Completeness.Coverage)
		switch route {
		case "/fallback-guard":
			if !strings.Contains(resolved, "branch_exit") || !strings.Contains(resolved, "unsupported_control_flow") || flowGap(coverage) {
				t.Fatalf("%s: resolved [%s] coverage [%s]; the guarded statement's gaps must be resolved", route, resolved, coverage)
			}
		case "/fallback-unrelated":
			if flowGap(resolved) || !flowGap(coverage) {
				t.Fatalf("%s: resolved [%s] coverage [%s]; gaps without a verified guard stay as coverage", route, resolved, coverage)
			}
		default:
			if flowGap(resolved) || flowGap(coverage) || flowGap(gapKinds(u.Gaps)) {
				t.Fatalf("%s: resolved [%s] coverage [%s]; a modeled if records no control-flow gap", route, resolved, coverage)
			}
		}
	}
}

func TestCommandGuardInvalidatedByEveryWriteForm(t *testing.T) {
	js := analyzeCommandRoutes(t, "server.js", jsCommandPrelude+`
app.get('/derived-root',(req,res)=>{let cmd=req.query.c;const clean=cmd.trim();if(!ALLOWED.has(clean)){return res.sendStatus(400);}cmd=req.query.d;exec(cmd,()=>{});res.send('x');});
app.get('/member',(req,res)=>{if(!ALLOWED.has(req.query.c)){return res.sendStatus(400);}req.query.c=req.query.d;exec(req.query.c,()=>{});res.send('x');});
app.get('/destructure',(req,res)=>{let cmd=req.query.c;if(!ALLOWED.has(cmd)){return res.sendStatus(400);}({cmd}=req.query.d);exec(cmd,()=>{});res.send('x');});
app.get('/still-valid',(req,res)=>{const cmd=req.query.c;const clean=cmd.trim();if(!ALLOWED.has(clean)){return res.sendStatus(400);}const other=req.query.d;exec(cmd,()=>{});res.send(other);});
`)
	for _, route := range []string{"/derived-root", "/member", "/destructure"} {
		requireGuards(t, route, js[route])
	}
	requireGuards(t, "/still-valid", js["/still-valid"], "terminating_guard: if(!ALLOWED.has(clean))")

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
