package langjs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPollutionWalkStartProbes(t *testing.T) {
	root := filepath.Join("testdata", "pollution", "start-probes")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int{
		"p0-parameter-start": 1, "p1-module-store": 1, "p2-local-object": 1,
		"p3-object-property": 1, "p4-reduce-from-store": 1, "p5-handler-inline": 1,
		"p6-class-field": 0, "p7-null-prototype-store": 1,
	}
	if len(entries) != len(want) {
		t.Fatalf("probe count = %d, want %d", len(entries), len(want))
	}
	for _, entry := range entries {
		t.Run(entry.Name(), func(t *testing.T) {
			count, ok := want[entry.Name()]
			if !ok {
				t.Fatalf("unexpected probe %s", entry.Name())
			}
			report, err := Analyze(filepath.Join(root, entry.Name()), "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != count {
				t.Fatalf("pollution records = %d, want %d", len(uses), count)
			}
			if entry.Name() == "p7-null-prototype-store" {
				p := uses[0].Pollution
				if p.Guard != "null_prototype_root" || len(p.Paths) != 1 || p.Paths[0].Protection != "unknown" {
					t.Errorf("null root = %+v, want Review", p)
				}
			}
		})
	}
}

func TestPollutionWalkStartFixtures(t *testing.T) {
	for _, tt := range []struct{ fixture, declaration string }{
		{"module", "store = {}"}, {"local", "result = {}"}, {"property", "holder = { settings:"},
		{"reduce", "store = {}"}, {"foreach", "store = {}"}, {"while", "store = {}"}, {"inline", "store = {}"},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", "pollution", "start-"+tt.fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			routes := map[string]string{}
			for _, e := range report.Entries {
				routes[e.ID] = e.HTTPRoute().PathPattern
			}
			want := map[string]string{"/vulnerable": "raw", "/guarded": "guarded", "/partial": "raw"}
			for _, u := range usesOf(report, analysis.PollutionKind, "server.js") {
				route := routes[u.EntryID]
				protection, ok := want[route]
				if !ok {
					t.Errorf("unexpected record %s: %+v", route, u.Sink)
					continue
				}
				delete(want, route)
				p := u.Pollution
				if p.Operation != analysis.PollutionWalk || p.KeyOperand != "path" || len(p.Paths) != 1 || p.Paths[0].Protection != protection {
					t.Errorf("%s: facts = %+v, want path walk with %s protection", route, p, protection)
				}
				if u.Completeness == nil || len(u.Completeness.Blockers) != 0 {
					t.Errorf("%s: unexpected completeness %+v", route, u.Completeness)
				}
				if !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool {
					return e.Kind == "sink_binding" && strings.HasPrefix(e.Text, tt.declaration)
				}) {
					t.Errorf("%s: missing start declaration %q", route, tt.declaration)
				}
				if tt.fixture == "inline" && !strings.HasPrefix(u.Sink.Text, "cursor[") {
					t.Errorf("%s: inline sink = %q, want final assignment", route, u.Sink.Text)
				}
				if incomplete := slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool {
					return g.Kind == "key_guard_incomplete" && strings.Contains(g.Detail, "constructor")
				}); incomplete != (route == "/partial") {
					t.Errorf("%s: incomplete deny-list gap = %t", route, incomplete)
				}
			}
			if len(want) != 0 {
				t.Errorf("missing routes: %v", want)
			}
		})
	}
}

func TestPollutionWalkStartIdentity(t *testing.T) {
	const indexedWalk = `const parts = path.split('.');
    let cursor = START;
    BEFORE
    for (let i = 0; i < parts.length - 1; i++) { cursor = cursor[parts[i]]; STEP }
    AFTER
    cursor[parts[parts.length - 1]] = value;`
	for _, tt := range []struct {
		name, setup, parameters, prefix, start, before, step, after, call, guard string
		count                                                                    int
	}{
		{name: "missing declaration", start: "unknown"},
		{name: "computed member", setup: "const holder = { state: {} }; const name = getName();", start: "holder[name]"},
		{name: "fixed bracket member", setup: "const holder = { state: {} };", start: "holder['state']", count: 1},
		{name: "property replaced", setup: "const holder = { state: {} }; function reset() { holder.state = {}; }", start: "holder.state"},
		{name: "property possibly replaced", setup: "const holder = { state: {} }; function reset() { holder[getName()] = {}; }", start: "holder.state"},
		{name: "descendant write retains start", setup: "const holder = { state: {} }; holder.state.other = {};", start: "holder.state", count: 1},
		{name: "module binding reassigned", setup: "let store = {}; function reset() { store = {}; }", start: "store"},
		{name: "module binding destructured", setup: "let store = {}; function reset() { ({ store } = other); }", start: "store"},
		{name: "binding declared later in module", start: "store", call: "write(req.body.path, req.body.value)", after: "", count: 1},
		{name: "same name in another scope", setup: "function unrelated() { let store = {}; store = undefined; }", prefix: "const store = {};", start: "store", count: 1},
		{name: "ordinary call initializer", setup: "const store = initialize();", start: "store", count: 1},
		{name: "imported binding", setup: "import { store } from './state.js';", start: "store", count: 1},
		{name: "parameter reassigned", parameters: "target, path, value", prefix: "target = undefined;", start: "target", call: "write({}, req.body.path, req.body.value)"},
		{name: "parameter property", parameters: "target, path, value", start: "target.state", call: "write({state: {}}, req.body.path, req.body.value)", count: 1},
		{name: "cursor reassigned before loop", setup: "const store = {};", start: "store", before: "cursor = {};"},
		{name: "cursor reassigned inside loop", setup: "const store = {};", start: "store", step: "cursor = {};"},
		{name: "cursor reassigned after loop", setup: "const store = {};", start: "store", after: "cursor = {};"},
		{name: "null property", setup: "const holder = { state: Object.create(null) };", start: "holder.state", guard: "null_prototype_root", count: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			const handler = `app.post('/update', (req, res) => { CALL; res.end(); });`
			if tt.parameters == "" {
				tt.parameters = "path, value"
			}
			if tt.call == "" {
				tt.call = "write(req.body.path, req.body.value)"
			}
			walk := strings.NewReplacer("START", tt.start, "BEFORE", tt.before, "STEP", tt.step, "AFTER", tt.after).Replace(indexedWalk)
			trailing := ""
			if tt.name == "binding declared later in module" {
				trailing = "const store = {};"
			}
			writeSource(t, root, "state.js", "export const store = {};")
			writeSource(t, root, "server.js", "const express = require('express');\nconst app = express();\napp.use(express.json());\n"+
				tt.setup+"\nfunction write("+tt.parameters+") {\n"+tt.prefix+"\n"+walk+"\n}\n"+trailing+
				"\n"+strings.Replace(handler, "CALL", tt.call, 1))
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != tt.count {
				t.Fatalf("pollution records = %d, want %d", len(uses), tt.count)
			}
			for _, u := range uses {
				if u.Pollution.Guard != tt.guard {
					t.Errorf("guard = %q, want %q", u.Pollution.Guard, tt.guard)
				}
			}
		})
	}
}

func TestPollutionWalkStartMultipleRoots(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
const first = Object.create(null);
const second = {};
function write(path, value) {
  const parts = path.split('.');
  let a = first;
  for (let i = 0; i < parts.length - 1; i++) a = a[parts[i]];
  a[parts[parts.length - 1]] = value;
  let b = first;
  for (let i = 0; i < parts.length - 1; i++) b = b[parts[i]];
  b[parts[parts.length - 1]] = value;
  let c = second;
  for (let i = 0; i < parts.length - 1; i++) c = c[parts[i]];
  c[parts[parts.length - 1]] = value;
}
app.post('/update', (req, res) => { write(req.body.path, req.body.value); res.end(); });
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := usesOf(report, analysis.PollutionKind, "server.js")
	if len(uses) != 2 {
		t.Fatalf("pollution records = %d, want 2", len(uses))
	}
	if a, b := uses[0], uses[1]; a.ID == b.ID || a.Pollution.Guard != "null_prototype_root" || a.Pollution.Paths[0].Protection != "unknown" ||
		len(a.Completeness.Evidence["prototype_write"]) != 2 || b.Pollution.Paths[0].Protection != "raw" {
		t.Errorf("unexpected distinct roots: %+v and %+v", a.Pollution, b.Pollution)
	}
}

func TestPollutionInlineWalkGuards(t *testing.T) {
	for _, tt := range []struct {
		name, input, before, step, guard string
		count                            int
	}{
		{name: "if guard in step", input: "req.body.path", step: "if (check(part)) cursor = cursor[part];", guard: "unknown", count: 1},
		{name: "short circuit in step", input: "req.body.path", step: "check(part) && (cursor = cursor[part]);", guard: "unknown", count: 1},
		{name: "conditional guard in step", input: "req.body.path", step: "check(part) ? (cursor = cursor[part]) : undefined;", guard: "unknown", count: 1},
		{name: "unchecked literal input", input: "'settings.theme'", step: "cursor = cursor[part];"},
		{name: "overwritten request container", input: "req.body.path", before: "req.body = { path: 'settings.theme' };", step: "cursor = cursor[part];"},
		{name: "scalar URL parameter split", input: "req.params.path", step: "cursor = cursor[part];", count: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
const store = {};
app.post('/update/:path', (req, res) => {
  `+tt.before+`
  const parts = `+tt.input+`.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    `+tt.step+`
  }
  cursor[parts[parts.length - 1]] = req.body.value;
  res.end();
});
`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != tt.count {
				t.Fatalf("pollution records = %d, want %d", len(uses), tt.count)
			}
			for _, u := range uses {
				if u.Pollution.Guard != tt.guard {
					t.Errorf("guard = %q, want %q", u.Pollution.Guard, tt.guard)
				}
			}
		})
	}
}
