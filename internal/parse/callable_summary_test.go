package parse

import (
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// summaryOf loads files into a fresh module set and returns the summary of the
// named function (a declaration or a const-bound function, at any depth) in the
// first file.
func summaryOf(t *testing.T, files map[string]string, first, name string) *callableSummary {
	t.Helper()
	root := t.TempDir()
	allowed := map[string]bool{}
	for path, text := range files {
		writeSource(t, root, path, text)
		allowed[path] = true
	}
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: allowed}
	t.Cleanup(set.close)
	// A whole-repository scan loads every selected file before any flow runs.
	for path := range files {
		if _, err := set.load(path); err != nil {
			t.Fatal(err)
		}
	}
	m := set.modules[first]
	var fn *sitter.Node
	walkKinds(m.tree.RootNode(), map[string]bool{"function_declaration": true, "variable_declarator": true}, func(n *sitter.Node) {
		id := n.ChildByFieldName("name")
		if fn != nil || id == nil || id.Utf8Text(m.src) != name {
			return
		}
		if n.Kind() == "function_declaration" {
			fn = n
		} else if v := n.ChildByFieldName("value"); v != nil && isFunction(v) {
			fn = v
		}
	})
	if fn == nil {
		t.Fatalf("no function %s", name)
	}
	return set.callableSummary(m, fn)
}

func summaryReasons(c *callableSummary) string {
	var kinds []string
	for _, r := range c.reasons {
		kinds = append(kinds, r.Kind)
	}
	return strings.Join(kinds, ",")
}

// TestCallableSummaries covers each reason, parameter indexing, in-repository
// chains and recursion (spec §8b AC1).
func TestCallableSummaries(t *testing.T) {
	for _, tt := range []struct {
		name    string
		files   map[string]string
		fn      string
		reason  string // first reason; "" means closed
		reads   uint64
		returns uint64
	}{
		{name: "identity", files: map[string]string{"lib.js": "function f(a) { return a }"}, fn: "f", reads: 1, returns: 1},
		{name: "constant and unread parameter", files: map[string]string{"lib.js": "const C = 3\nfunction f(a, b) { return C + a }"}, fn: "f", reads: 1, returns: 1},
		{name: "json import", files: map[string]string{"lib.ts": "import pkg from './package.json'\nexport const f = (m?: string) => { if (m) { return pkg.dependencies[m] } return pkg.version }"}, fn: "f", reads: 1, returns: 1},
		{name: "1D table calls", files: map[string]string{"lib.js": "const os = require('os')\nfunction f() { return os.hostname() + Math.max(1, 2) + JSON.stringify({ a: 1 }) + new Date().toISOString() }"}, fn: "f"},
		{name: "same-module chain", files: map[string]string{"lib.js": "function g(x) { return x }\nfunction f(a, b) { return g(b) + a.length * 0 }"}, fn: "f", reads: 3, returns: 3},
		{name: "chain drops a non-returned argument", files: map[string]string{"lib.js": "function g(x, y) { return y }\nfunction f(a, b) { return g(a, b) }"}, fn: "f", reads: 3, returns: 2},
		{name: "imported chain", files: map[string]string{"lib.js": "import { g } from './helper'\nexport function f(a) { return g(a) }", "helper.js": "export function g(x) { return [x] }"}, fn: "f", reads: 1, returns: 1},
		{name: "fresh local object", files: map[string]string{"lib.js": "function f(a) { const o = {}; o.k = a; return o }"}, fn: "f", reads: 1, returns: 1},
		{name: "closed recursion", files: map[string]string{"lib.js": "function f(n) { return n ? f(n - 1) : 0 }"}, fn: "f", reads: 1, returns: 1},
		{name: "closed mutual recursion", files: map[string]string{"lib.js": "function a(x) { return b(x) }\nfunction b(y) { return y && a(y) }"}, fn: "a", reads: 1, returns: 1},
		{name: "closure over request", files: map[string]string{"lib.js": "function outer(req) { function f() { return req.body } return f }"}, fn: "f", reason: "free_variable"},
		{name: "global", files: map[string]string{"lib.js": "function f() { return process.env.X }"}, fn: "f", reason: "free_variable"},
		{name: "mutated module array", files: map[string]string{"lib.js": "const list = []\nfunction add(x) { list.push(x) }\nfunction f() { return list[0] }"}, fn: "f", reason: "mutable_module_binding"},
		{name: "reassigned module let", files: map[string]string{"lib.js": "let v = 1\nfunction set() { v = 2 }\nfunction f() { return v }"}, fn: "f", reason: "mutable_module_binding"},
		{name: "escaping module object", files: map[string]string{"lib.js": "const cfg = {}\nregister(cfg)\nfunction f() { return cfg.x }"}, fn: "f", reason: "mutable_module_binding"},
		{name: "imported value", files: map[string]string{"lib.js": "import { cfg } from './conf'\nfunction f() { return cfg.x }", "conf.js": "export const cfg = {}"}, fn: "f", reason: "imported_value"},
		{name: "arguments", files: map[string]string{"lib.js": "function f() { return arguments[0] }"}, fn: "f", reason: "this_or_arguments"},
		{name: "this", files: map[string]string{"lib.js": "function f() { return this.x }"}, fn: "f", reason: "this_or_arguments"},
		{name: "eval", files: map[string]string{"lib.js": "function f(s) { return eval(s) }"}, fn: "f", reason: "dynamic_code"},
		{name: "dynamic import", files: map[string]string{"lib.js": "async function f(s) { return import(s) }"}, fn: "f", reason: "dynamic_code"},
		{name: "method on a parameter", files: map[string]string{"lib.js": "function f(a) { return a.trim() }"}, fn: "f", reason: "unmodeled_call"},
		{name: "sink", files: map[string]string{"lib.js": "const db = require('db')\nfunction f() { db.query('SELECT 1') }"}, fn: "f", reason: "unmodeled_call"},
		{name: "log sink", files: map[string]string{"lib.js": "const logger = require('./logger')\nfunction f(k) { logger.info(k) }", "logger.js": "module.exports = console"}, fn: "f", reason: "unmodeled_call"},
		{name: "constructor", files: map[string]string{"lib.js": "function f() { return new Map() }"}, fn: "f", reason: "unmodeled_constructor"},
		{name: "parameter write", files: map[string]string{"lib.js": "function f(a) { a.solved = true }"}, fn: "f", reason: "heap_write"},
		{name: "module write", files: map[string]string{"lib.js": "let g\nfunction f() { g = 1 }"}, fn: "f", reason: "heap_write"},
		{name: "callee not closed", files: map[string]string{"lib.js": "function g() { return process.env.X }\nfunction f() { return g() }"}, fn: "f", reason: "callee_not_closed"},
		{name: "destructured parameter", files: map[string]string{"lib.js": "function f({ a }) { return a }"}, fn: "f", reason: "unsupported_parameters"},
		{name: "recursion reaching a global", files: map[string]string{"lib.js": "function f(n) { return n ? f(n - 1) : process.x }"}, fn: "f", reason: "free_variable"},
		{name: "table call receiver is walked", files: map[string]string{"lib.js": "const cp = require('child_process')\nfunction f(cmd) { return new Date(cp.execSync(cmd)).toISOString() }"}, fn: "f", reason: "unmodeled_call"},
		{name: "table call receiver reads a parameter", files: map[string]string{"lib.js": "function f(t) { return new Date(t).getTime() }"}, fn: "f", reads: 1, returns: 1},
		{name: "name bound only in a nested scope", files: map[string]string{"lib.js": "let last\nfunction set(v) { last = v }\nfunction f() { const g = (last) => 0; return last }"}, fn: "f", reason: "free_variable"},
		{name: "nested callable shadows a module constant", files: map[string]string{"lib.js": "const cfg = { dir: '/safe' }\nfunction handler(req) { const cfg = req.body; function pick() { return cfg.dir } return pick() }"}, fn: "pick", reason: "free_variable"},
		{name: "member escapes as an argument", files: map[string]string{"lib.js": "const state = { items: [] }\nfill(state.items)\nfunction f() { return state.items[0] }"}, fn: "f", reason: "mutable_module_binding"},
		{name: "function object written", files: map[string]string{"lib.js": "function store() {}\nfunction set(x) { store.last = x }\nfunction f() { return store.last }"}, fn: "f", reason: "mutable_module_binding"},
		{name: "deep write through a fresh local", files: map[string]string{"lib.js": "function f(p) { const o = { p }; o.p.x = 1 }"}, fn: "f", reason: "heap_write"},
		{name: "cycle member reaching a global", files: map[string]string{"lib.js": "function a(x) { return b(x) }\nfunction b(y) { return y ? a(y) : process.x }"}, fn: "a", reason: "callee_not_closed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := summaryOf(t, tt.files, firstFile(tt.files), tt.fn)
			if got := c.firstReason(); got != tt.reason {
				t.Fatalf("first reason %q (all %s), want %q", got, summaryReasons(c), tt.reason)
			}
			if tt.reason == "" && (c.reads != tt.reads || c.returns != tt.returns) {
				t.Fatalf("reads %b returns %b, want %b %b", c.reads, c.returns, tt.reads, tt.returns)
			}
		})
	}
}

func firstFile(files map[string]string) string {
	if _, ok := files["lib.js"]; ok {
		return "lib.js"
	}
	return "lib.ts"
}

func TestCallableSummaryFixpointCap(t *testing.T) {
	saved := summaryMaxRounds
	summaryMaxRounds = 1
	defer func() { summaryMaxRounds = saved }()
	c := summaryOf(t, map[string]string{"lib.js": "function f(a) { return a }"}, "lib.js", "f")
	if c.firstReason() != "summary_fixpoint_limit" || c.returns != c.reads {
		t.Fatalf("reasons %s returns %b reads %b", summaryReasons(c), c.returns, c.reads)
	}
}

// TestClosedSummaryAtRefusals checks closed/inert and full witness applications.
// Supported parameter-dependent return/sink recipes close refusals; ambient
// helpers retain their explicit gaps.
func TestClosedSummaryAtRefusals(t *testing.T) {
	root := t.TempDir()
	ticks := strings.Repeat("  tick(0)\n", 30)
	writeSource(t, root, "server.js", `const express = require('express')
const fs = require('fs')
const app = express()
function tick(n) { return n }
function env() { return process.env.X }
function d3(v) { return fs.readFileSync(v) }
function d2(v) { return d3(v) }
function d1(v) { return d2(v) }
function d0(v) { return d1(v) }
app.get('/budget', (req, res) => {
`+ticks+`  env()
  tick(req.query.n)
  fs.readFileSync(req.query.name)
})
app.get('/depth', (req, res) => { d0(req.query.name) })
app.listen(3000)
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var limits []string
	for _, u := range r.Uses {
		for _, g := range u.Gaps {
			if strings.HasSuffix(g.Kind, "helper_limit") || g.Kind == "helper_call_limit" {
				limits = append(limits, g.Kind+":"+strings.TrimPrefix(g.Detail, "helper call expansion reached its depth or count limit: "))
			}
		}
	}
	joined := strings.Join(limits, " ")
	t.Logf("limit gaps: %s", joined)
	count := func(want string) int { return strings.Count(" "+joined+" ", " "+want+" ") }
	if n := count("path_unrelated_helper_limit:tick"); n != 0 {
		t.Errorf("closed tick(0) refusals kept %d gaps: %s", n, joined)
	}
	if count("helper_call_limit:tick") != 0 {
		t.Errorf("supported dependent tick return kept its refusal: %s", joined)
	}
	if count("path_unrelated_helper_limit:env") == 0 {
		t.Errorf("env() is not closed and must keep its refusal: %s", joined)
	}
	if count("helper_call_limit:d3") != 0 {
		t.Errorf("supported dependent filesystem witness kept its refusal: %s", joined)
	}
	found := false
	for _, u := range r.Uses {
		if u.Kind != "path_traversal_candidate" || u.Sink.Text != "fs.readFileSync(v)" {
			continue
		}
		found = true
		if u.Path == nil {
			t.Fatal("native filesystem facts missing")
		}
		if err := u.Path.Validate(len(u.Dependencies), len(u.Context)); err != nil {
			t.Fatal(err)
		}
		if len(u.Dependencies) == 0 || u.Dependencies[0].Source.Text != "req.query.name" {
			t.Fatalf("caller origin lost: %+v", u.Dependencies)
		}
		bindings := 0
		for _, e := range u.Dependencies[0].Transfers {
			if e.Kind == "parameter_binding" {
				bindings++
			}
		}
		if bindings != 4 {
			t.Fatalf("want all four concrete helper bindings, got %d", bindings)
		}
	}
	if !found {
		t.Fatal("newly reachable filesystem sink witness missing")
	}
}

// TestCallableSummaryLoadsNothing checks that building a summary never loads a
// module: an in-repository callee in a module that is not loaded blocks the
// summary instead, so the scan's file list cannot change.
func TestCallableSummaryLoadsNothing(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "lib.js", "import { g } from './other'\nimport * as ns from './other'\nexport function f(a) { return g(a) }\nexport function h() { return ns.g(1) }")
	writeSource(t, root, "other.js", "export function g(x) { return x }")
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"lib.js": true, "other.js": true}}
	defer set.close()
	m, err := set.load("lib.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"f", "h"} {
		fn := topDeclaration(m, name)
		if fn == nil {
			t.Fatalf("no %s", name)
		}
		c := set.callableSummary(m, fn)
		if c.firstReason() != "callee_not_loaded" {
			t.Errorf("%s: reasons %s", name, summaryReasons(c))
		}
	}
	if set.modules["other.js"] != nil || set.summaryNoLoad {
		t.Fatalf("summary build loaded other.js or left loading disabled")
	}
	if len(m.calls) != 0 {
		t.Fatalf("summary build filled the call index cache: %d entries", len(m.calls))
	}
}
