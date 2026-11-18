package parse

import (
	"strconv"
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func gapDetails(r *analysis.AnalysisReport, kind string) []string {
	var out []string
	for _, u := range r.Uses {
		for _, g := range u.Gaps {
			if g.Kind == kind {
				out = append(out, g.Detail)
			}
		}
	}
	return out
}

func anyContains(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}

// TestCallIndexTypedReceivers checks that only typed, binding-stable receivers
// with a listed independent result lose unknown_call_result (spec §8a AC1, D-8).
func TestCallIndexTypedReceivers(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express = require('express')
const os = require('os')
let moved = require('os')
moved = {}
const app = express()
app.get('/a', (req, res) => {
  const host = os.hostname()
  const stamp = new Date().toISOString()
  const text = JSON.stringify({ a: 1 })
  const other = moved.hostname()
  const unknown = mystery.thing()
  const missing = os.readFile()
  res.send(req.query.q + host + stamp + text + other + unknown + missing)
})
app.listen(3000)
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	gaps := gapDetails(r, "unknown_call_result")
	for _, typed := range []string{"os.hostname", "new Date().toISOString", "JSON.stringify"} {
		if anyContains(gaps, typed) {
			t.Errorf("%s kept unknown_call_result: %v", typed, gaps)
		}
	}
	for _, untyped := range []string{"moved.hostname", "mystery.thing", "os.readFile"} {
		if !anyContains(gaps, untyped) {
			t.Errorf("%s lost unknown_call_result: %v", untyped, gaps)
		}
	}
}

// TestCallIndexResolutionKinds checks kinds and reasons on one module.
func TestCallIndexResolutionKinds(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "helper.js", "export function local() { return 1 }\n")
	writeSource(t, root, "server.js", `import { local } from './helper.js'
import os from 'os'
function same() { return 2 }
let w = JSON
w = {}
same(); local(); os.hostname(); JSON.stringify(1); mystery.x(); w.parse(); (() => 1)()
function f(JSON) { JSON.stringify(1) }
`)
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"server.js": true, "helper.js": true}}
	defer set.close()
	m, err := set.load("server.js")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	walkKinds(m.tree.RootNode(), map[string]bool{"call_expression": true}, func(n *sitter.Node) {
		r := set.callResolution(m, n)
		got[n.ChildByFieldName("function").Utf8Text(m.src)+"@"+strconv.Itoa(int(n.StartByte()))] = r.Kind.String() + ":" + r.Receiver + ":" + r.Reason
	})
	want := map[string]string{
		"same":           "direct::",
		"local":          "imported::",
		"os.hostname":    "package_member:module:os:",
		"JSON.stringify": "builtin_method:builtin:JSON:",
		"mystery.x":      "unresolved::unknown_receiver",
		"w.parse":        "unresolved::dynamic_write",
		"(() => 1)":      "unresolved::dynamic_callee",
	}
	for name, kind := range want {
		found := false
		for key, value := range got {
			if strings.HasPrefix(key, name+"@") && value == kind {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: want %s, got %v", name, kind, got)
		}
	}
	shadowedOK := false
	for key, value := range got {
		if strings.HasPrefix(key, "JSON.stringify@") && value == "unresolved::shadowed" {
			shadowedOK = true
		}
	}
	if !shadowedOK {
		t.Errorf("parameter-shadowed JSON resolved as builtin: %v", got)
	}
}

// TestPythonContainerWrite checks that a module-stable local list stores the
// appended value, and that an aliased list keeps today's unresolved behavior.
func TestPythonContainerWrite(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.py", `from flask import Flask, request
app = Flask(__name__)


@app.route('/a')
def a():
    out = []
    out.append(request.args.get('q'))
    return "".join(out)


@app.route('/b')
def b():
    alias = []
    other = alias
    alias.append(request.args.get('q'))
    return "".join(other)
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	stored, aliased := false, false
	for _, u := range r.Uses {
		if u.Sink.Span.StartLine == 9 && len(u.Dependencies) > 0 {
			stored = true
		}
		if u.Sink.Span.StartLine == 17 && len(u.Dependencies) > 0 {
			aliased = true
		}
	}
	if !stored {
		t.Errorf("appended request value did not reach the returned join: %+v", r.Uses)
	}
	if aliased {
		t.Errorf("aliased list was typed: the alias carried the appended value")
	}
}
