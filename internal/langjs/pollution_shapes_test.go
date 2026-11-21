package langjs

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// TestPollutionShapeProbes pins the eight probe applications of the write-shapes
// contract. Each row started at the count the stage 1 analyzer produced and was
// inverted when its recogniser landed.
func TestPollutionShapeProbes(t *testing.T) {
	for _, tt := range []struct {
		probe, operation, operand string
		want                      int
	}{
		{"p0-control-known-shape", analysis.PollutionMerge, "source", 1},
		{"p1-getOwnPropertyNames", analysis.PollutionMerge, "source", 1},
		{"p2-alias-recursion", analysis.PollutionMerge, "source", 1},
		{"p3-reflect-ownkeys", analysis.PollutionMerge, "source", 1},
		{"p4-array-path", analysis.PollutionWalk, "path", 1},
		{"p5-regex-split", analysis.PollutionWalk, "path", 1},
		{"p6-unflatten", analysis.PollutionWalk, "source_keys", 1},
		{"p7-reduce-walk", analysis.PollutionWalk, "path", 1},
	} {
		t.Run(tt.probe, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", "pollution", "probes", tt.probe), "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != tt.want {
				t.Fatalf("pollution candidates = %d, want %d", len(uses), tt.want)
			}
			for _, u := range uses {
				p := u.Pollution
				if p.Operation != tt.operation || p.KeyOperand != tt.operand || len(p.Paths) != 1 || p.Paths[0].Protection != "raw" || len(u.Completeness.Blockers) > 0 {
					t.Errorf("unexpected facts %+v blockers %+v", p, u.Completeness.Blockers)
				}
			}
		})
	}
}

// TestPollutionShapes checks each added write shape as one small application:
// a vulnerable function, the same function behind a complete key guard, its
// bypass sibling that skips only __proto__, and controls that have no record.
func TestPollutionShapes(t *testing.T) {
	for _, tt := range []struct {
		shape, operation, operand, guard string
		branch                           string
	}{
		{"shapes-own-property-names", analysis.PollutionMerge, "source", "deny_list", "(options.deep)"},
		{"shapes-alias-recursion", analysis.PollutionMerge, "source", "deny_list", ""},
		{"shapes-reflect-own-keys", analysis.PollutionMerge, "source", "deny_list", ""},
		{"shapes-array-path", analysis.PollutionWalk, "path", "deny_list", ""},
		{"shapes-regex-split", analysis.PollutionWalk, "path", "deny_list", ""},
		{"shapes-unflatten", analysis.PollutionWalk, "source_keys", "deny_list", ""},
		{"shapes-reduce-walk", analysis.PollutionWalk, "path", "deny_list", ""},
	} {
		t.Run(tt.shape, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", "pollution", tt.shape), "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			want := map[string]struct{ guard, protection string }{
				"vulnerable": {"", "raw"}, "guarded": {tt.guard, "guarded"}, "partial": {tt.guard, "raw"},
			}
			for _, u := range uses {
				name, _, _ := strings.Cut(u.Sink.Text, "(")
				w, ok := want[name]
				if !ok {
					t.Errorf("control or duplicate has a record: %s %+v", u.Sink.Text, u.Pollution)
					continue
				}
				delete(want, name)
				p := u.Pollution
				if p.Operation != tt.operation || p.KeyOperand != tt.operand || p.Guard != w.guard ||
					len(p.Paths) != 1 || p.Paths[0].Protection != w.protection || len(u.Completeness.Blockers) > 0 {
					t.Errorf("%s facts %+v blockers %+v", name, p, u.Completeness.Blockers)
				}
				incomplete := slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool {
					return g.Kind == "key_guard_incomplete" && strings.Contains(g.Detail, "constructor")
				})
				if incomplete != (name == "partial") {
					t.Errorf("%s incomplete listing = %v: %+v", name, incomplete, u.Gaps)
				}
				if name == "partial" && !slices.Equal(p.Blocked, []string{"__proto__"}) {
					t.Errorf("partial blocked = %v", p.Blocked)
				}
				if tt.branch != "" && !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool {
					return e.Kind == branchTruePrecondition && e.Text == tt.branch
				}) {
					t.Errorf("%s lacks the %s branch evidence", name, tt.branch)
				}
				if _, err := analysispacks.Select(u); err != nil {
					t.Errorf("%s selection: %v", name, err)
				}
			}
			for name := range want {
				t.Errorf("%s has no record", name)
			}
		})
	}
}

// TestPollutionShapeVariants covers the accepted spellings of each added shape
// and the nearest forms that must stay without a record.
func TestPollutionShapeVariants(t *testing.T) {
	merge := func(loop, body string) string {
		return "function write(target, source) {\n" + loop + " {\n" + body + "\n}\n}"
	}
	direct := "if (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];"
	for _, tt := range []struct {
		name, helper, call        string
		operation, operand, guard string
		protection                string
	}{
		{name: "property names with forEach", helper: "function write(target, source) {\nObject.getOwnPropertyNames(source).forEach((key) => {\n" + direct + "\n});\n}",
			call: "write({}, req.body)", operation: analysis.PollutionMerge, operand: "source", protection: "raw"},
		{name: "descriptor value read inline", helper: merge("for (const key of Reflect.ownKeys(source))", "const child = Object.getOwnPropertyDescriptor(source, key).value;\nif (child && typeof child === 'object') write(target[key], child); else target[key] = child;"),
			call: "write({}, req.body)", operation: analysis.PollutionMerge, operand: "source", protection: "raw"},
		{name: "alias declared from a chained assignment", helper: merge("for (const key in source)", "const slot = target[key] = target[key] || {};\nif (typeof source[key] === 'object') write(slot, source[key]); else target[key] = source[key];"),
			call: "write({}, req.body)", operation: analysis.PollutionMerge, operand: "source", protection: "raw"},
		{name: "alias conditionally replaced", helper: merge("for (const key in source)", "let slot = target[key];\nif (!slot) slot = {};\nif (typeof source[key] === 'object') write(slot, source[key]); else target[key] = source[key];"),
			call: "write({}, req.body)"},
		{name: "source value replaced before the recursion", helper: merge("for (const key in source)", "let child = source[key];\nchild = {};\nif (typeof child === 'object') write(target[key], child); else target[key] = child;"),
			call: "write({}, req.body)"},
		{name: "alias of another key", helper: merge("for (const key in source)", "const slot = target.settings;\nif (typeof source[key] === 'object') write(slot, source[key]); else target[key] = source[key];"),
			call: "write({}, req.body)"},
		{name: "module-level class named like the built-in", helper: "class Reflect { static ownKeys() { return ['fixed']; } }\nfunction write(target, source) {\nReflect.ownKeys(source).forEach((key) => {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n});\n}",
			call: "write({}, req.body)"},
		{name: "module-level function named like the built-in", helper: "function Reflect() {}\nReflect.keysOf = () => ['fixed'];\nfunction write(target, source) {\nReflect.ownKeys(source).forEach((key) => {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n});\n}",
			call: "write({}, req.body)"},
		{name: "array path with for-of", helper: "function write(target, path, value) {\nlet cursor = target;\nfor (const part of path.slice(0, -1)) cursor = cursor[part];\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "path parameter split in place", helper: "function write(target, path, value) {\nif (typeof path === 'string') path = path.split('.');\nlet cursor = target;\nfor (let i = 0; i < path.length - 1; i++) cursor = cursor[path[i]];\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "path parameter replaced by a constant", helper: "function write(target, path, value) {\npath = ['settings', 'theme'];\nlet cursor = target;\nfor (let i = 0; i < path.length - 1; i++) cursor = cursor[path[i]];\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "array path compared without a type test", helper: "function write(target, path, value) {\nlet cursor = target;\nfor (const part of path.slice(0, -1)) {\nif (part === '__proto__' || part === 'constructor' || part === 'prototype') return;\ncursor = cursor[part];\n}\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "unknown", protection: "unknown"},
		{name: "array path with a type test in the same condition", helper: "function write(target, path, value) {\nlet cursor = target;\nfor (const part of path.slice(0, -1)) {\nif (typeof part !== 'string' || part === '__proto__' || part === 'constructor' || part === 'prototype') return;\ncursor = cursor[part];\n}\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "deny_list", protection: "guarded"},
		{name: "array path whose type test does not exit", helper: "function write(target, path, value) {\nlet cursor = target;\nfor (const part of path.slice(0, -1)) {\nif (typeof part === 'string') console.log(part);\nif (part === '__proto__' || part === 'constructor' || part === 'prototype') return;\ncursor = cursor[part];\n}\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "unknown", protection: "unknown"},
		{name: "array path with a deny-list on the whole array", helper: "function write(target, path, value) {\nif (path.includes('__proto__') || path.includes('constructor') || path.includes('prototype')) return;\nlet cursor = target;\nfor (let i = 0; i < path.length - 1; i++) cursor = cursor[path[i]];\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "reduce over an array path compared without a type test", helper: "function write(target, path, value) {\nconst holder = path.slice(0, -1).reduce((cursor, part) => {\nif (part === '__proto__' || part === 'constructor' || part === 'prototype') return cursor;\nreturn cursor[part];\n}, target);\nholder[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "unknown", protection: "unknown"},
		{name: "array path with an own-property guard", helper: "function write(target, path, value) {\nlet cursor = target;\nfor (const part of path.slice(0, -1)) {\nif (!Object.hasOwn(cursor, part)) return;\ncursor = cursor[part];\n}\ncursor[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "own_property", protection: "guarded"},
		{name: "empty string separator", helper: "function write(target, path, value) {\nconst parts = path.split('');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "unflatten with forEach into a parameter", helper: "function write(target, source) {\nObject.keys(source).forEach((flat) => {\nconst parts = flat.split('.');\nlet cursor = target;\nfor (const part of parts.slice(0, -1)) cursor = cursor[part];\ncursor[parts[parts.length - 1]] = source[flat];\n});\n}",
			call: "write({}, req.body)", operation: analysis.PollutionWalk, operand: "source_keys", protection: "raw"},
		{name: "unflatten into a null-prototype root", helper: "function write(source) {\nconst out = Object.create(null);\nfor (const flat in source) {\nconst parts = flat.split('.');\nlet cursor = out;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = source[flat];\n}\nreturn out;\n}",
			call: "write(req.body)", operation: analysis.PollutionWalk, operand: "source_keys", guard: "null_prototype_root", protection: "unknown"},
		{name: "unflatten with a reduce walk", helper: "function write(source) {\nconst out = {};\nfor (const flat of Object.keys(source)) {\nconst parts = flat.split('.');\nconst last = parts.pop();\nconst holder = parts.reduce((cursor, part) => cursor[part], out);\nholder[last] = source[flat];\n}\nreturn out;\n}",
			call: "write(req.body)", operation: analysis.PollutionWalk, operand: "source_keys", protection: "raw"},
		{name: "path walk into a local object", helper: "function write(path, value) {\nconst out = {};\nconst parts = path.split('.');\nlet cursor = out;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\nreturn out;\n}",
			call: "write(req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "reduce result indexed in place", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nparts.slice(0, -1).reduce((cursor, part) => cursor[part], target)[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "reduce that creates each slot", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nconst last = parts.pop();\nconst holder = parts.reduce((cursor, part) => (cursor[part] = cursor[part] || {}), target);\nholder[last] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "reduce over an array path", helper: "function write(target, path, value) {\nconst holder = path.slice(0, -1).reduce((cursor, part) => cursor[part], target);\nholder[path[path.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "reduce that does not follow its accumulator", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nconst last = parts.pop();\nconst holder = parts.reduce((cursor, part) => target[part], target);\nholder[last] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "reduce result reassigned", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nconst last = parts.pop();\nlet holder = parts.reduce((cursor, part) => cursor[part], target);\nholder = {};\nholder[last] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "reduce over constant parts", helper: "function write(target, value) {\nconst parts = ['settings', 'theme'];\nconst holder = parts.reduce((cursor, part) => cursor[part], target);\nholder.color = value;\n}",
			call: "write({}, req.body.value)"},
		{name: "whole-path test before the path is decoded", helper: "function write(target, path, value) {\nif (path.includes('__proto__') || path.includes('constructor') || path.includes('prototype')) return;\npath = decodeURIComponent(path);\nconst parts = path.split('.');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "whole-path test that does not exit", helper: "function write(target, path, value) {\nif (path.includes('__proto__') || path.includes('constructor') || path.includes('prototype')) console.warn('unsafe');\nconst parts = path.split('.');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "whole-path equality is not a key guard", helper: "function write(target, path, value) {\nif (path === '__proto__' || path === 'constructor' || path === 'prototype') return;\nconst parts = path.split('.');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", protection: "raw"},
		{name: "deny-list on the parts array", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nif (parts.includes('__proto__') || parts.includes('constructor') || parts.includes('prototype')) throw new Error('unsafe');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)", operation: analysis.PollutionWalk, operand: "path", guard: "deny_list", protection: "guarded"},
		{name: "whole-key deny-list in an unflatten", helper: "function write(source) {\nconst out = {};\nfor (const flat in source) {\nif (flat.includes('__proto__') || flat.includes('constructor') || flat.includes('prototype')) continue;\nconst parts = flat.split('.');\nlet cursor = out;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = source[flat];\n}\nreturn out;\n}",
			call: "write(req.body)", operation: analysis.PollutionWalk, operand: "source_keys", guard: "deny_list", protection: "guarded"},
		{name: "while loop that does not consume the parts", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nlet cursor = target;\nlet i = 0;\nwhile (i < 3) {\ncursor = cursor[parts.shift()];\ni++;\n}\ncursor[parts[0]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "first part written after an index loop", helper: "function write(target, path, value) {\nconst parts = path.split('.');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[0]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "key reduce that returns the looked-up slot", helper: "function write(target, source) {\nreturn Object.keys(source).reduce((acc, key) => {\nif (typeof source[key] === 'object') write(acc[key], source[key]); else acc[key] = source[key];\nreturn acc[key];\n}, target);\n}",
			call: "write({}, req.body)"},
		{name: "key reduce with an own-property test on the accumulator", helper: "function write(target, source) {\nreturn Object.keys(source).reduce((acc, key) => {\nif (!Object.hasOwn(acc, key)) return acc;\nif (typeof source[key] === 'object') write(acc[key], source[key]); else acc[key] = source[key];\nreturn acc;\n}, target);\n}",
			call: "write({}, req.body)", operation: analysis.PollutionMerge, operand: "source", guard: "own_property", protection: "guarded"},
		{name: "first match only is not the list of parts", helper: "function write(target, path, value) {\nconst parts = path.match(/[^.]+/);\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "collected parts that are not the matches", helper: "function write(target, path, value) {\nconst pattern = /[^.]+/g;\nconst parts = [];\nlet match;\nwhile ((match = pattern.exec(path)) !== null) parts.push('settings');\nlet cursor = target;\nfor (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];\ncursor[parts[parts.length - 1]] = value;\n}",
			call: "write({}, req.body.path, req.body.value)"},
		{name: "nested write after the slot is created when absent", helper: "const store = {};",
			call: "if (!store[req.body.a]) store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write behind two helpers with an absent-slot branch", helper: "const store = {};\nfunction inner(key, phase, verdict) {\nif (!store[key]) {\nstore[key] = { done: false };\n}\nif (!store[key][phase]) {\nstore[key][phase] = verdict;\n}\n}\nfunction outer(key, verdict) { inner(key, 'find it', verdict); }",
			call: "outer(req.body.key, false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after an undefined test creates the slot", helper: "const store = {};",
			call: "if (store[req.body.a] === undefined) { store[req.body.a] = {}; } store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after an in test creates the slot", helper: "const store = {};",
			call: "if (!(req.body.a in store)) store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after a typeof test creates the slot", helper: "const store = {};",
			call: "if (typeof store[req.body.a] === 'undefined') store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after the slot defaults to itself", helper: "const store = {};",
			call: "store[req.body.a] = store[req.body.a] || {}; store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after a logical assignment default", helper: "const store = {};",
			call: "store[req.body.a] ??= {}; store[req.body.a][req.body.b] = req.body.v", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "nested write after the slot is always replaced", helper: "const store = {};",
			call: "store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v"},
		{name: "nested write after an own-property test creates the slot", helper: "const store = {};",
			call: "if (!Object.hasOwn(store, req.body.a)) store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v"},
		{name: "nested write after an unrelated branch replaces the slot", helper: "const store = {};",
			call: "if (req.body.reset) store[req.body.a] = {}; store[req.body.a][req.body.b] = req.body.v"},
		{name: "nested write after an absent test with an else branch", helper: "const store = {};",
			call: "if (!store[req.body.a]) store[req.body.a] = {}; else store[req.body.a] = { kept: true }; store[req.body.a][req.body.b] = req.body.v"},
		{name: "gated write: the key must pass a lookup call first", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nconst known = new Map();\nfunction find(key) { return known.has(key) ? known.get(key) : null; }",
			call: "const key = req.body.key; const row = find(key); if (row == null) { res.status(404).end(); return; } storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "gated write: the lookup and its exit sit inside a try block", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nconst known = new Map();\nfunction find(key) { return known.has(key) ? known.get(key) : null; }",
			call: "const key = req.body.key; let row; try { row = find(key); if (row == null) { res.status(404).end(); return; } } catch (error) { res.status(500).end(); return; } storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "ungated write: a try block whose exit does not depend on the key", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nfunction load() { return 1; }",
			call: "const key = req.body.key; let config; try { config = load(); if (config == null) { res.status(500).end(); return; } } catch (error) { res.status(500).end(); return; } storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "gated write: the sink is in the else arm of a test on a looked-up value", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nconst cache = {};\nfunction readFixes(key) { return cache[key]; }",
			call: "const key = req.body.key; const fixData = readFixes(key); if (fixData.fixes.length === 0) { res.status(404).end(); } else { storeVerdict(key, 'fix it', false); }", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "gated write: an allow-list call on the key", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nconst allowed = ['a', 'b'];",
			call: "if (!allowed.includes(req.body.key)) { res.status(400).end(); return; } storeVerdict(req.body.key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "gated write: an unknown validator inside the helper", helper: "const solves = {};\nfunction valid(key) { return registry.accepts(key) && check(key); }\nfunction storeVerdict(key, phase, verdict) {\nif (!valid(key)) return;\nsolves[key] = solves[key] || {};\nsolves[key][phase] = verdict;\n}",
			call: "storeVerdict(req.body.key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "ungated write: a one-line type validator blocks no name", helper: "const solves = {};\nfunction valid(key) { return typeof key === 'string'; }\nfunction storeVerdict(key, phase, verdict) {\nif (!valid(key)) return;\nsolves[key] = solves[key] || {};\nsolves[key][phase] = verdict;\n}",
			call: "storeVerdict(req.body.key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "gated write: a short-circuit on a lookup of the key", helper: "const solves = {};\nconst known = new Map();\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "const key = req.body.key; known.has(key) && storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "gated write: a conditional expression on a lookup of the key", helper: "const solves = {};\nconst known = new Map();\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "const key = req.body.key; known.has(key) ? storeVerdict(key, 'find it', false) : null", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "gated write: a short-circuit in front of a direct nested write", helper: "const solves = {};\nconst known = new Map();\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "known.has(req.body.a) && (solves[req.body.a][req.body.b] = req.body.v)", operation: analysis.PollutionNested, operand: "computed_keys", guard: "unknown", protection: "unknown"},
		{name: "ungated write: a short-circuit on an unrelated flag", helper: "const solves = {};\nconst known = new Map();\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "const key = req.body.key; req.body.enabled && storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "ungated write: an existence test on a plain object lets an inherited key through", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "const key = req.body.key; if (!solves[key]) { res.status(404).end(); return; } storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "ungated write: a presence test on the key itself", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\n",
			call: "const key = req.body.key; if (!key) { res.status(400).end(); return; } storeVerdict(key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "ungated write: a lookup call on another request field", helper: "const solves = {};\nfunction storeVerdict(key, phase, verdict) {\nif (!solves[key]) {\nsolves[key] = { done: false };\n}\nif (!solves[key][phase]) {\nsolves[key][phase] = verdict;\n}\n}\nconst users = new Map();\nfunction findUser(id) { return users.get(id); }",
			call: "const user = findUser(req.body.auth); if (!user) { res.status(403).end(); return; } storeVerdict(req.body.key, 'find it', false)", operation: analysis.PollutionNested, operand: "computed_keys", protection: "raw"},
		{name: "gated merge: a validator call on the source object", helper: "function check(value) { return value && !('__proto__' in value); }\nfunction write(target, source) {\nfor (const key in source) {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n}\n}",
			call: "if (!check(req.body.settings)) { res.status(400).end(); return; } write({}, req.body.settings)", operation: analysis.PollutionMerge, operand: "source", guard: "unknown", protection: "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", "const express = require('express');\nconst app = express();\napp.use(express.json());\n"+tt.helper+
				"\napp.post('/write', (req, res) => { "+tt.call+"; res.end(); });\n")
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if tt.operation == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected record: %+v", uses[0].Pollution)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("pollution candidates = %d, want 1", len(uses))
			}
			p := uses[0].Pollution
			if p.Operation != tt.operation || p.KeyOperand != tt.operand || p.Guard != tt.guard || len(p.Paths) != 1 || p.Paths[0].Protection != tt.protection {
				t.Fatalf("unexpected facts: %+v", p)
			}
			if blockers := uses[0].Completeness.Blockers; tt.protection != "unknown" && len(blockers) > 0 {
				t.Fatalf("unexpected blockers: %+v", blockers)
			}
		})
	}
}

// TestPollutionShapeExploration records the outcome of the four time-boxed
// exploration items. Each began as a fixture without a record (path deny-lists
// began unread, every walk raw) and was kept once one bounded recogniser read it.
// A function absent from its table is a control and has no record.
func TestPollutionShapeExploration(t *testing.T) {
	type outcome struct{ operation, operand, guard, protection string }
	raw := func(operation, operand string) outcome { return outcome{operation, operand, "", "raw"} }
	guarded := func(operation, operand string) outcome { return outcome{operation, operand, "deny_list", "guarded"} }
	partial := func(operation, operand string) outcome { return outcome{operation, operand, "deny_list", "raw"} }
	walk, merge := analysis.PollutionWalk, analysis.PollutionMerge
	for _, tt := range []struct {
		fixture string
		want    map[string]outcome
	}{
		{"explore-while-shift", map[string]outcome{
			"vulnerable": raw(walk, "path"), "guarded": guarded(walk, "path"), "partial": partial(walk, "path"), "lastFirst": raw(walk, "path"),
		}},
		{"explore-path-deny-list", map[string]outcome{
			"vulnerable": raw(walk, "path"), "guarded": guarded(walk, "path"), "partial": partial(walk, "path"),
			"indexed": guarded(walk, "path"), "enclosed": guarded(walk, "path"),
		}},
		{"explore-keys-reduce-map", map[string]outcome{
			"vulnerable": raw(merge, "source"), "guarded": guarded(merge, "source"), "partial": partial(merge, "source"), "mapped": raw(merge, "source"),
		}},
		{"explore-bracket-keys", map[string]outcome{
			"vulnerable": raw(walk, "source_keys"), "matched": raw(walk, "source_keys"),
			"guarded": guarded(walk, "source_keys"), "partial": partial(walk, "source_keys"),
		}},
	} {
		t.Run(tt.fixture, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", "pollution", tt.fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			seen := map[string]bool{}
			for _, u := range usesOf(report, analysis.PollutionKind, "server.js") {
				name, _, _ := strings.Cut(u.Sink.Text, "(")
				w, ok := tt.want[name]
				p := u.Pollution
				if !ok || seen[name] {
					t.Errorf("unexpected record for %s: %+v", name, p)
					continue
				}
				seen[name] = true
				if p.Operation != w.operation || p.KeyOperand != w.operand || p.Guard != w.guard || len(p.Paths) != 1 ||
					p.Paths[0].Protection != w.protection || len(u.Completeness.Blockers) > 0 {
					t.Errorf("%s facts %+v blockers %+v, want %+v", name, p, u.Completeness.Blockers, w)
				}
				incomplete := slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool {
					return g.Kind == "key_guard_incomplete" && strings.Contains(g.Detail, "constructor")
				})
				if incomplete != (name == "partial") {
					t.Errorf("%s incomplete listing = %v", name, incomplete)
				}
				if _, err := analysispacks.Select(u); err != nil {
					t.Errorf("%s selection: %v", name, err)
				}
			}
			for name := range tt.want {
				if !seen[name] {
					t.Errorf("%s has no record", name)
				}
			}
		})
	}
}

// TestPollutionLibrarySourceInRepository pins where a vulnerable function may
// live. A library's source kept in the scanned repository is read when a route
// reaches it through a resolved import. A repository with no application entry
// has no record; the guide lists that as a limit.
func TestPollutionLibrarySourceInRepository(t *testing.T) {
	merge := `function merge(target, source) {
  for (const key in source) {
    if (source[key] && typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
  return target;
}
`
	commonJS := "const express = require('express');\n%s\nconst app = express();\napp.use(express.json());\napp.post('/settings', (req, res) => { %s; res.end(); });\n"
	esm := "import express from 'express';\n%s\nconst app = express();\napp.use(express.json());\napp.post('/settings', (req, res) => { %s; res.end(); });\n"
	for _, tt := range []struct {
		name, library, server, binding, call string
		want                                 int
	}{
		{"CommonJS function export", merge + "module.exports = merge;", commonJS, "const merge = require('./lib/tiny');", "merge({}, req.body)", 1},
		{"CommonJS object export", merge + "module.exports = { merge };", commonJS, "const { merge } = require('./lib/tiny');", "merge({}, req.body)", 1},
		{"CommonJS named export", merge + "exports.merge = merge;", commonJS, "const { merge } = require('./lib/tiny');", "merge({}, req.body)", 1},
		{"ESM named export", "export " + merge, esm, "import { merge } from './lib/tiny.js';", "merge({}, req.body)", 1},
		{"ESM namespace import", "export " + merge, esm, "import * as tiny from './lib/tiny.js';", "tiny.merge({}, req.body)", 1},
		{"ESM default function export", "export default " + merge, esm, "import merge from './lib/tiny.js';", "merge({}, req.body)", 1},
		{"ESM default export of a declared function", merge + "export default merge;", esm, "import merge from './lib/tiny.js';", "merge({}, req.body)", 1},
		{"ESM default object export", merge + "export default { merge };", esm, "import tiny from './lib/tiny.js';", "tiny.merge({}, req.body)", 1},
		{"limit: library with no application entry", merge + "module.exports = merge;", "", "", "", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "lib/tiny.js", tt.library)
			if tt.server != "" {
				writeSource(t, root, "server.js", fmt.Sprintf(tt.server, tt.binding, tt.call))
			}
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "")
			if len(uses) != tt.want {
				t.Fatalf("pollution candidates = %d, want %d", len(uses), tt.want)
			}
			for _, u := range uses {
				writes := u.Completeness.Evidence["prototype_write"]
				if u.Sink.Span.File != "server.js" || len(writes) != 1 || writes[0].Span.File != "lib/tiny.js" || u.Pollution.Paths[0].Protection != "raw" {
					t.Errorf("unexpected record: sink %s writes %+v paths %+v", u.Sink.Span.File, writes, u.Pollution.Paths)
				}
			}
		})
	}
}

// TestPollutionTypeScriptShapes repeats shapes in TypeScript, where callback
// parameters are wrapped nodes and casts surround the enumerator and the last
// path part.
func TestPollutionTypeScriptShapes(t *testing.T) {
	for _, tt := range []struct{ name, helper, call, operation, operand string }{
		{"typed forEach callback", "function write(target: Record<string, any>, source: Record<string, any>) {\nObject.keys(source).forEach((key: string) => {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n});\nreturn target;\n}",
			"write({}, req.body.settings)", analysis.PollutionMerge, "source"},
		{"untyped callback in a TypeScript file", "function write(target: Record<string, any>, source: Record<string, any>) {\nObject.keys(source).forEach((key) => {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n});\n}",
			"write({}, req.body.settings)", analysis.PollutionMerge, "source"},
		{"cast around the key enumerator", "function write(target: Record<string, any>, source: Record<string, any>) {\n(Reflect.ownKeys(source) as string[]).forEach((key) => {\nif (source[key] && typeof source[key] === 'object') write(target[key], source[key]); else target[key] = source[key];\n});\n}",
			"write({}, req.body.settings)", analysis.PollutionMerge, "source"},
		{"typed entries callback", "function write(target: Record<string, any>, source: Record<string, any>) {\nObject.entries(source).forEach(([key, child]: [string, any]) => {\nif (child && typeof child === 'object') write(target[key], child); else target[key] = child;\n});\n}",
			"write({}, req.body.settings)", analysis.PollutionMerge, "source"},
		{"typed reduce over the keys", "function write(target: Record<string, any>, source: Record<string, any>) {\nreturn Object.keys(source).reduce((acc: Record<string, any>, key: string) => {\nif (source[key] && typeof source[key] === 'object') write(acc[key], source[key]); else acc[key] = source[key];\nreturn acc;\n}, target);\n}",
			"write({}, req.body.settings)", analysis.PollutionMerge, "source"},
		{"cast on the last array part", "function write(target: Record<string, any>, path: unknown[], value: unknown) {\nlet cursor = target;\nfor (let i = 0; i < path.length - 1; i++) {\nconst part = path[i];\nif (typeof part !== 'string') return;\ncursor = cursor[part];\n}\ncursor[path[path.length - 1] as string] = value;\n}",
			"write({}, req.body.path, req.body.value)", analysis.PollutionWalk, "path"},
		{"cast on the popped last part", "function write(target: Record<string, any>, path: string, value: unknown) {\nconst parts = path.split('.');\nconst last = parts.pop() as string;\nconst holder = parts.reduce((cursor: Record<string, any>, part: string) => cursor[part], target);\nholder[last] = value;\n}",
			"write({}, req.body.path, req.body.value)", analysis.PollutionWalk, "path"},
		{"non-null assertion on the shifted part", "function write(target: Record<string, any>, path: string, value: unknown) {\nconst parts = path.split('.');\nlet cursor = target;\nwhile (parts.length > 1) {\nconst part = parts.shift()!;\ncursor = cursor[part];\n}\ncursor[parts[0]] = value;\n}",
			"write({}, req.body.path, req.body.value)", analysis.PollutionWalk, "path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", "import express from 'express';\nconst app = express();\napp.use(express.json());\n"+tt.helper+
				"\napp.post('/write', (req, res) => { "+tt.call+"; res.end(); });\n")
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.ts")
			if len(uses) != 1 {
				t.Fatalf("pollution candidates = %d, want 1", len(uses))
			}
			if p := uses[0].Pollution; p.Operation != tt.operation || p.KeyOperand != tt.operand {
				t.Fatalf("unexpected facts: %+v", p)
			}
		})
	}
}

// TestPollutionLibraryShapes holds forms found by scanning real advisory
// libraries: a forEach walk, a walk that recurses on the next object, and key
// tests written as one-line helpers. Each fixture is written for this test in
// the shape of the library code, not copied from it.
func TestPollutionLibraryShapes(t *testing.T) {
	walk := "function setKey(obj, keys, value) {\nvar o = obj;\nkeys.slice(0, -1).forEach(function (key) {\n%s\nif (o[key] === undefined) o[key] = {};\no = o[key];\n});\nvar last = keys[keys.length - 1];\no[last] = value;\n}"
	recursive := "function setIn(object, path, value, index) {\nif (index === path.length) return value;\nvar key = path[index];\n%s\nobject[key] = setIn(object[key], path, value, index + 1);\nreturn object;\n}"
	sliced := "function setPath(obj, path, value) {\nvar current = path[0];\n%s\nif (path.length === 1) { obj[current] = value; return obj; }\nif (obj[current] === undefined) obj[current] = {};\nreturn setPath(obj[current], path.slice(1), value);\n}"
	merge := "function hasOwn(obj, key) { return Object.prototype.hasOwnProperty.call(obj, key); }\nfunction isValidKey(key) { return key !== '__proto__' && key !== 'constructor' && key !== 'prototype'; }\nfunction merge(target, obj) {\nfor (var key in obj) {\nif (%s) continue;\nvar oldVal = obj[key];\nvar newVal = target[key];\nif (newVal && typeof newVal === 'object' && oldVal && typeof oldVal === 'object') target[key] = merge(newVal, oldVal);\nelse target[key] = oldVal;\n}\nreturn target;\n}"
	for _, tt := range []struct{ name, helper, call, operation, guard, protection string }{
		{"forEach walk over the parts", fmt.Sprintf(walk, ""), "setKey({}, req.body.keys, req.body.value)", analysis.PollutionWalk, "", "raw"},
		{"forEach walk with a type test and a deny-list", fmt.Sprintf(walk, "if (typeof key !== 'string' || key === '__proto__' || key === 'constructor' || key === 'prototype') return;"),
			"setKey({}, req.body.keys, req.body.value)", analysis.PollutionWalk, "deny_list", "guarded"},
		{"forEach walk that only reads", "function getKey(obj, keys) {\nvar o = obj;\nkeys.forEach(function (key) { o = o[key]; });\nreturn o;\n}", "res.json(getKey({}, req.body.keys))", "", "", ""},
		{"walk that recurses with the next index", fmt.Sprintf(recursive, ""), "setIn({}, req.body.path, req.body.value, 0)", analysis.PollutionWalk, "", "raw"},
		{"recursive walk behind an assertion on the key", fmt.Sprintf(recursive, "assert.ok(!['__proto__', 'constructor', 'prototype'].includes(key), 'unsafe key');"),
			"setIn({}, req.body.path, req.body.value, 0)", analysis.PollutionWalk, "unknown", "unknown"},
		{"walk that recurses with the rest of the path", fmt.Sprintf(sliced, ""), "setPath({}, req.body.path, req.body.value)", analysis.PollutionWalk, "", "raw"},
		{"recursive walk with a type test and a deny-list", fmt.Sprintf(sliced, "if (typeof current !== 'string' || current === '__proto__' || current === 'constructor' || current === 'prototype') return obj;"),
			"setPath({}, req.body.path, req.body.value)", analysis.PollutionWalk, "deny_list", "guarded"},
		{"recursion that does not write", "function getIn(object, path, index) {\nif (index === path.length) return object;\nreturn getIn(object[path[index]], path, index + 1);\n}", "res.json(getIn({}, req.body.path, 0))", "", "", ""},
		{"own-property helper on the source and a __proto__ test", fmt.Sprintf(merge, "key === '__proto__' || !hasOwn(obj, key)"), "merge({}, req.body.settings)", analysis.PollutionMerge, "deny_list", "raw"},
		{"deny-list written as a helper", fmt.Sprintf(merge, "!isValidKey(key) || !hasOwn(obj, key)"), "merge({}, req.body.settings)", analysis.PollutionMerge, "deny_list", "guarded"},
		{"own-property method on the source", fmt.Sprintf(merge, "!obj.hasOwnProperty(key)"), "merge({}, req.body.settings)", analysis.PollutionMerge, "", "raw"},
		{"own-property helper on the target", fmt.Sprintf(merge, "!hasOwn(target, key)"), "merge({}, req.body.settings)", analysis.PollutionMerge, "own_property", "guarded"},
		{"helper that is not a plain test of the key", "function allowed(key) { return lookup(key); }\n" + fmt.Sprintf(merge, "!allowed(key)"), "merge({}, req.body.settings)", analysis.PollutionMerge, "unknown", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", "const express = require('express');\nconst assert = require('assert');\nconst app = express();\napp.use(express.json());\n"+tt.helper+
				"\napp.post('/write', (req, res) => { "+tt.call+"; res.end(); });\n")
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if tt.operation == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected record: %+v", uses[0].Pollution)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("pollution candidates = %d, want 1", len(uses))
			}
			if p := uses[0].Pollution; p.Operation != tt.operation || p.Guard != tt.guard || len(p.Paths) != 1 || p.Paths[0].Protection != tt.protection {
				t.Fatalf("unexpected facts: %+v", p)
			}
		})
	}
}
