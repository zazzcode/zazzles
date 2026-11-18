package langpy

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func TestPathPythonOperands(t *testing.T) {
	r := analyzeFixture(t, "path-traversal")
	uses := pathUses(r)
	open := "open"
	for route, want := range map[string]pathCase{
		"/v/open":            {operation: open, role: "read", protection: "raw", file: "app.py"},
		"/v/join":            {operation: open, role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/write":           {operation: open, role: "write", protection: "raw"},
		"/v/io-open":         {operation: "io.open", role: "read", protection: "raw"},
		"/v/pathlib-read":    {operation: "pathlib.Path.read_text", role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/pathlib-bytes":   {operation: "pathlib.Path.read_bytes", role: "read", protection: "raw", transforms: []string{"path_object"}},
		"/v/pathlib-write":   {operation: "pathlib.Path.write_text", role: "write", protection: "raw"},
		"/v/normpath-only":   {operation: open, role: "read", protection: "raw", transforms: []string{"normalize"}},
		"/v/try-except":      {operation: open, role: "read", protection: "raw"},
		"/v/blacklist":       {operation: open, role: "read", protection: "guarded", guards: []string{"dotdot_text"}},
		"/v/reassigned":      {operation: open, role: "read", protection: "raw"},
		"/v/sibling-branch":  {operation: open, role: "read", protection: "raw"},
		"/v/helper":          {operation: open, role: "read", protection: "raw", transforms: []string{"join"}},
		"/p/allowlist":       {operation: open, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/allowlist-tuple": {operation: open, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/prefix-boundary": {operation: open, role: "read", protection: "guarded", guards: []string{"prefix_boundary"}},
		"/p/commonpath":      {operation: open, role: "read", protection: "guarded", guards: []string{"commonpath"}},
		"/p/realpath":        {operation: open, role: "read", protection: "guarded", guards: []string{"commonpath"}, transforms: []string{"realpath"}},
		"/u/prefix-bare":     {operation: open, role: "read", protection: "guarded", guards: []string{"prefix_bare"}},
		"/u/missing-helper":  {operation: open, role: "read", protection: "unknown", blocked: true},
		"/u/basename":        {operation: open, role: "read", protection: "raw", transforms: []string{"reduce"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/n/constant", "/n/content-only", "/n/stored", "/n/shadow-def", "/n/shadow-import", "/n/shadow-local"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not be a path candidate", route)
		}
	}
	t.Run("write text is not a path source", func(t *testing.T) {
		for _, route := range []string{"/v/write", "/v/pathlib-write"} {
			u := uses[route]
			for _, p := range u.Path.Paths {
				if src := u.Dependencies[p.Dependency].Source.Text; strings.Contains(src, "text") {
					t.Fatalf("%s: write content became a path flow: %s", route, src)
				}
			}
		}
	})
}

func TestPathGuardPolarityAndBypass(t *testing.T) {
	pyRoot := pythonFixture(t, map[string]string{"app.py": `
import os
from flask import Flask, abort, request
app = Flask(__name__)
ROOT = os.path.abspath("uploads")
ALLOWED = {"a.txt", "b.txt"}

@app.route("/negated-consequence")
def neg_cons():
    full = os.path.abspath(os.path.join(ROOT, request.args.get("f", "")))
    if not full.startswith(ROOT + os.sep):
        return open(full).read()
    return "ok"

@app.route("/inverted-terminating")
def inv_term():
    name = request.args.get("f", "")
    if name in ALLOWED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()

@app.route("/conjunct-bypass")
def conj_bypass():
    name = request.args.get("f", "")
    if not request.args.get("admin") and name not in ALLOWED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()

@app.route("/disjunct-enforced")
def disj_enforced():
    name = request.args.get("f", "")
    if not request.args.get("admin") or name not in ALLOWED:
        abort(403)
    return open(os.path.join(ROOT, name)).read()
`})
	pyReport, err := Analyze(pyRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	pyUses := pathUses(pyReport)
	for _, route := range []string{"/negated-consequence", "/inverted-terminating", "/conjunct-bypass"} {
		u, ok := pyUses[route]
		if !ok {
			t.Fatalf("python missing candidate %s", route)
		}
		for _, k := range guardKinds(u) {
			if analysis.EnforcingPathGuard(k) {
				t.Errorf("python %s wrongly received enforcing guard kind %s", route, k)
			}
		}
	}
	if got := guardKinds(pyUses["/disjunct-enforced"]); len(got) != 1 || got[0] != analysis.PathGuardAllowlist {
		t.Errorf("python /disjunct-enforced guards %v, want [allowlist]", got)
	}
}

func TestPathFalseProtectionControls(t *testing.T) {
	pyRoot := pythonFixture(t, map[string]string{
		"helpers.py": "def pick_dir():\n    return '/tmp/x'\n",
		"app.py": `
import io
import os
from pathlib import Path
from flask import Flask, abort, request, send_from_directory
from helpers import pick_dir
app = Flask(__name__)
ROOT = os.path.abspath("uploads")
SPLAT_MAP = {"a.txt": 1, **os.environ}
MUTATED_SET = {"a.txt"}
MUTATED_SET.add("b.txt")

@app.route("/unresolved-send-dir")
def unresolved_send():
    return send_from_directory(pick_dir(), request.args.get("f", ""))

@app.route("/dict-splat")
def dict_splat():
    name = request.args.get("f", "")
    if name not in SPLAT_MAP:
        abort(403)
    return open(os.path.join(ROOT, name)).read()

@app.route("/mutated-set")
def mutated_set():
    name = request.args.get("f", "")
    if name not in MUTATED_SET:
        abort(403)
    return open(os.path.join(ROOT, name)).read()

@app.route("/pathlib-unlink")
def pathlib_unlink():
    Path(ROOT, request.args.get("f", "")).unlink()
    return "ok"
`,
		"patched.py": `
import io
from flask import Flask, request
app = Flask(__name__)
io.open = lambda p: p
@app.route("/monkey-patched-io")
def patched_io():
    return io.open(request.args.get("f", ""))
`,
	})
	pyReport, err := Analyze(pyRoot, "app.py")
	if err != nil {
		t.Fatal(err)
	}
	pyUses := pathUses(pyReport)
	if got := guardKinds(pyUses["/unresolved-send-dir"]); len(got) != 0 {
		t.Errorf("/unresolved-send-dir wrongly attached guards %v", got)
	}
	if got := guardKinds(pyUses["/dict-splat"]); len(got) != 1 || got[0] != analysis.PathGuardUnclassified {
		t.Errorf("/dict-splat guards %v, want [unclassified]", got)
	}
	if got := guardKinds(pyUses["/mutated-set"]); len(got) != 1 || got[0] != analysis.PathGuardUnclassified {
		t.Errorf("/mutated-set guards %v, want [unclassified]", got)
	}
	if u, ok := pyUses["/pathlib-unlink"]; !ok || u.Path.Operation != "pathlib.Path.unlink" || u.Path.Role != "delete" {
		t.Errorf("/pathlib-unlink missing or wrong role: %+v", u.Path)
	}
	patchedReport, err := Analyze(pyRoot, "patched.py")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pathUses(patchedReport)["/monkey-patched-io"]; ok {
		t.Errorf("monkey-patched io.open must not earn verified contract")
	}
}

func checkPathCase(t *testing.T, route string, u analysis.CandidateUse, want pathCase) {
	t.Helper()
	f := u.Path
	if f == nil {
		t.Fatalf("%s: no path facts", route)
	}
	if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
		t.Fatalf("%s: invalid path facts: %v", route, err)
	}
	if f.Operation != want.operation || f.Role != want.role || f.Platform != "posix" {
		t.Fatalf("%s: operation=%s role=%s platform=%s", route, f.Operation, f.Role, f.Platform)
	}
	if u.APIModel == nil || u.APIModel.ID != f.ContractID || analysispacks.PathContract(f.ContractID) == nil {
		t.Fatalf("%s: contract %+v", route, u.APIModel)
	}
	if len(f.Paths) == 0 {
		t.Fatalf("%s: no path flows", route)
	}
	for _, p := range f.Paths {
		if p.Operand != analysis.PathSlotFile || u.Dependencies[p.Dependency].SinkSlot != analysis.PathSlotFile {
			t.Fatalf("%s: a non-path operand became a path flow: %+v", route, p)
		}
	}
	p := f.Paths[0]
	if p.Protection != want.protection {
		t.Fatalf("%s: protection %s (%s), want %s; blockers %+v", route, p.Protection, p.Reason, want.protection, u.Completeness.Blockers)
	}
	if got := guardKinds(u); strings.Join(got, ",") != strings.Join(want.guards, ",") {
		t.Fatalf("%s: guard kinds %v, want %v", route, got, want.guards)
	}
	for _, tr := range want.transforms {
		found := false
		for _, have := range p.Transforms {
			found = found || have == tr
		}
		if !found {
			t.Fatalf("%s: transform %s missing in %v", route, tr, p.Transforms)
		}
	}
	if p.DecodedAfterGuard != want.decoded {
		t.Fatalf("%s: decoded_after_guard=%v", route, p.DecodedAfterGuard)
	}
	if want.root != "" && p.Root != want.root {
		t.Fatalf("%s: root %q, want %q", route, p.Root, want.root)
	}
	if want.file != "" && !strings.HasSuffix(u.Sink.Span.File, want.file) {
		t.Fatalf("%s: sink file %s", route, u.Sink.Span.File)
	}
	if u.Completeness == nil || u.Completeness.ClaimKind != "path_traversal" {
		t.Fatalf("%s: completeness %+v", route, u.Completeness)
	}
	for _, role := range u.Completeness.Required {
		if len(u.Completeness.Evidence[role]) == 0 {
			t.Fatalf("%s: role %s has no evidence", route, role)
		}
	}
	if want.blocked != (p.Protection == "unknown") {
		t.Fatalf("%s: blocked=%v protection=%s", route, want.blocked, p.Protection)
	}
	if !want.blocked && len(u.Completeness.Blockers) != 0 {
		t.Fatalf("%s: unexpected blockers: %+v", route, u.Completeness.Blockers)
	}
	if u.Components == nil || u.Components.Failure != "" || len(u.Components.Components) == 0 {
		t.Fatalf("%s: component selection %+v", route, u.Components)
	}
	for _, d := range u.Dependencies {
		if d.Source.SHA256 == "" || d.Source.Span.File == "" {
			t.Fatalf("%s: dependency lacks snapshot reference: %+v", route, d.Source)
		}
	}
}

func guardKinds(u analysis.CandidateUse) []string {
	var kinds []string
	for _, g := range u.Path.Guards {
		kinds = append(kinds, g.Kind)
	}
	return kinds
}

type pathCase struct {
	operation  string
	role       string
	protection string // protection of the single request path flow
	guards     []string
	transforms []string
	decoded    bool
	blocked    bool // a blocker touches the flow
	root       string
	file       string // sink file suffix
}

func pathUses(r *analysis.AnalysisReport) map[string]analysis.CandidateUse {
	routes := map[string]string{}
	for _, e := range r.Entries {
		routes[e.ID] = e.HTTPRoute().PathPattern
	}
	out := map[string]analysis.CandidateUse{}
	for _, u := range r.Uses {
		if u.Kind == "path_traversal_candidate" {
			out[routes[u.EntryID]] = u
		}
	}
	return out
}
