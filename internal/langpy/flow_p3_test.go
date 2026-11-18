package langpy

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func p3PathRoutes(t *testing.T, src string) map[string]analysis.CandidateUse {
	t.Helper()
	r, err := Analyze(pythonFixture(t, map[string]string{"app.py": src}), "")
	if err != nil {
		t.Fatal(err)
	}
	return pathUses(r)
}

// TestP3PythonDecodeCalls: a percent-decoder keeps the request provenance and
// raw protection of its argument, so a complete raw path is no longer blocked by
// an unmodeled urllib call; a protection earned before the decoder is never
// carried across it, and a guard on the undecoded name is not a guard on the
// decoded operand.
func TestP3PythonDecodeCalls(t *testing.T) {
	uses := p3PathRoutes(t, `
import os
import urllib.parse
from urllib.parse import unquote
from flask import Flask, request
app = Flask(__name__)
ALLOWED = {"a.txt"}

def pick(req):
    if req.method == "GET" and not req.args.get("f"):
        header = req.headers.get("X-F")
        return urllib.parse.unquote(header.split("=", 1)[1])
    if req.method == "GET":
        return req.args.get("f", "")
    if req.data:
        return req.form.get("f", "")

@app.route("/decode")
def decode():
    return open(unquote(request.args.get("f", ""))).read()

@app.route("/qualified")
def qualified():
    return open(urllib.parse.unquote_plus(request.args.get("f", ""))).read()

@app.route("/multi")
def multi():
    return open(pick(request)).read()

@app.route("/basename-then-decode")
def basename_then_decode():
    name = os.path.basename(request.args.get("f", ""))
    return open(unquote(name)).read()

@app.route("/guard-then-decode")
def guard_then_decode():
    name = request.args.get("f", "")
    if name not in ALLOWED:
        return "no"
    return open(unquote(name)).read()
`)
	for _, route := range []string{"/decode", "/qualified", "/multi"} {
		u, ok := uses[route]
		if !ok {
			t.Fatalf("missing %s", route)
		}
		if len(blockers(u)) != 0 {
			t.Errorf("%s: blockers %+v", route, blockers(u))
		}
		for _, p := range u.Path.Paths {
			if p.Protection != "raw" {
				t.Errorf("%s: protection %s, want raw", route, p.Protection)
			}
		}
	}
	for _, route := range []string{"/basename-then-decode", "/guard-then-decode"} {
		u, ok := uses[route]
		if !ok {
			t.Fatalf("missing %s", route)
		}
		for _, p := range u.Path.Paths {
			switch p.Protection {
			case "raw":
			case "guarded":
				// A mention of the pre-decoded text, with adequacy undecided and the
				// decoding step named; never an established protection.
				if !strings.Contains(p.Reason, "decoding step") {
					t.Errorf("%s: guarded without decode caveat: %s", route, p.Reason)
				}
			default:
				t.Errorf("%s: protection %s", route, p.Protection)
			}
		}
	}
}

// TestP3PythonAsyncMultiReturnHelper: an async helper whose every return is bound
// to request input (one through a version-gated decode branch, one implicit None)
// is summarized: no unresolved blockers and a raw path. A helper with a constant
// return or a raising branch is never reported as protected.
func TestP3PythonAsyncMultiReturnHelper(t *testing.T) {
	uses := p3PathRoutes(t, `
import os
import urllib.parse
from flask import Flask, request
app = Flask(__name__)

async def bound(req):
    if req.method == "GET" and not req.args.get("f"):
        header = req.headers.get("Q")
        return urllib.parse.unquote(header.split("=", 1)[1])
    if req.method == "GET":
        return req.args.get("f", "")
    if req.data:
        return req.form.get("f", "")

async def constant(req):
    if req.method == "GET":
        return req.args.get("f", "")
    return "safe.txt"

async def raising(req):
    if req.method == "GET":
        return req.args.get("f", "")
    raise ValueError("no")

@app.route("/bound")
async def r_bound():
    p = await bound(request)
    return open(p).read()

@app.route("/constant")
async def r_constant():
    p = await constant(request)
    return open(p).read()

@app.route("/raising")
async def r_raising():
    p = await raising(request)
    return open(p).read()
`)
	u := uses["/bound"]
	if len(blockers(u)) != 0 {
		t.Errorf("/bound: blockers %+v", blockers(u))
	}
	if len(u.Path.Paths) == 0 {
		t.Fatalf("/bound: no paths")
	}
	for _, route := range []string{"/bound", "/constant", "/raising"} {
		for _, p := range uses[route].Path.Paths {
			if p.Protection == "guarded" || p.Protection == "protected" {
				t.Errorf("%s: unexpected protection %s", route, p.Protection)
			}
		}
		t.Logf("%s: blockers=%d paths=%+v", route, len(blockers(uses[route])), uses[route].Path.Paths)
	}
}

// TestP3DecodeKeepsRawXSS: a percent-decoder over a raw request source keeps
// the reflected XSS operand raw (the VulnPy wsgi/app.py pattern), never "unknown".
func TestP3DecodeKeepsRawXSS(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.py", `from flask import Flask, request
from urllib.parse import unquote
app = Flask(__name__)

@app.route("/xss")
def xss():
    user_input = unquote(request.args.get("q", ""))
    return "<p>XSS: {}</p>".format(user_input)
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := xssUses(r)
	if len(uses) == 0 {
		t.Fatal("no reflected XSS candidate")
	}
	for _, u := range uses {
		if u.XSS != nil && u.XSS.Protection != "raw" {
			t.Errorf("decoded raw source must stay raw: %s", u.XSS.Protection)
		}
	}
}
