package langjs

import (
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

func TestPollutionLodashWrite(t *testing.T) {
	for _, tt := range []struct {
		name, packageName, operation, resolved, wantVersion, guard string
		want                                                       int
		blocked                                                    []string
	}{
		{name: "AC1 affected lock", packageName: "lodash", operation: "lodash.merge({}, req.body.settings)", resolved: "4.17.4", wantVersion: "4.17.4", want: 1},
		{name: "4.17.5 still affected", packageName: "lodash", operation: "lodash.merge({}, req.body.settings)", resolved: "4.17.5", wantVersion: "4.17.5", want: 1, blocked: []string{"__proto__"}},
		{name: "merge fixed", packageName: "lodash", operation: "lodash.merge({}, req.body.settings)", resolved: "4.17.11"},
		{name: "latest defaultsDeep legacy fix", packageName: "lodash", operation: "lodash.defaultsDeep({}, req.body.settings)", resolved: "4.17.11", wantVersion: "4.17.11", want: 1, blocked: []string{"__proto__"}},
		{name: "defaultsDeep fixed", packageName: "lodash", operation: "lodash.defaultsDeep({}, req.body.settings)", resolved: "4.17.12"},
		{name: "AC1 patched lock", packageName: "lodash", operation: "lodash.merge({}, req.body.settings)", resolved: "4.17.21"},
		{name: "AC1 unresolved range", packageName: "lodash", operation: "lodash.merge({}, req.body.settings)", want: 1},
		{name: "source after trusted object", packageName: "lodash", operation: "lodash.merge({}, {}, req.body.settings, {})", resolved: "4.17.4", wantVersion: "4.17.4", want: 1},
		{name: "target does not carry merge keys", packageName: "lodash", operation: "lodash.merge(req.body.settings, {})", resolved: "4.17.4"},
		{name: "null prototype root", packageName: "lodash", operation: "lodash.merge(Object.create(null), req.body.settings)", resolved: "4.17.4", wantVersion: "4.17.4", guard: "null_prototype_root", want: 1},
		{name: "set affected", packageName: "lodash", operation: "lodash.set({}, req.body.path, true)", resolved: "4.17.18", wantVersion: "4.17.18", want: 1},
		{name: "monolith set fixed", packageName: "lodash", operation: "lodash.set({}, req.body.path, true)", resolved: "4.17.19"},
		{name: "set value only", packageName: "lodash", operation: "lodash.set({}, 'settings.color', req.body.value)", resolved: "4.17.18"},
		{name: "zip first argument", packageName: "lodash", operation: "lodash.zipObjectDeep(req.body.paths, [])", resolved: "4.17.18", wantVersion: "4.17.18", want: 1},
		{name: "standalone setter", packageName: "lodash.set", operation: "lodash({}, req.body.path, true)", resolved: "4.3.2", wantVersion: "4.3.2", want: 1},
		{name: "standalone deep zip affected", packageName: "lodash.zipobjectdeep", operation: "lodash(req.body.paths, [])", resolved: "4.2.0", wantVersion: "4.2.0", want: 1},
		{name: "standalone deep zip patched", packageName: "lodash.zipobjectdeep", operation: "lodash(req.body.paths, [])", resolved: "4.18.0"},
		{name: "standalone merge affected", packageName: "lodash.merge", operation: "lodash({}, req.body.settings)", resolved: "4.6.1", wantVersion: "4.6.1", want: 1},
		{name: "standalone merge patched", packageName: "lodash.merge", operation: "lodash({}, req.body.settings)", resolved: "4.6.2"},
		{name: "standalone defaults affected", packageName: "lodash.defaultsdeep", operation: "lodash({}, req.body.settings)", resolved: "4.6.0", wantVersion: "4.6.0", want: 1},
		{name: "standalone defaults patched", packageName: "lodash.defaultsdeep", operation: "lodash({}, req.body.settings)", resolved: "4.6.1"},
		{name: "local alias", packageName: "lodash", operation: "const write = lodash.merge; write({}, req.body.settings)", resolved: "4.17.4", wantVersion: "4.17.4", want: 1},
		{name: "mutated method", packageName: "lodash", operation: "lodash['merge'] = () => {}; lodash.merge({}, req.body.settings)", resolved: "4.17.4"},
		{name: "shadowed module", packageName: "lodash", operation: "const lodash = {merge(){}}; lodash.merge({}, req.body.settings)", resolved: "4.17.4"},
		{name: "parsed scalar", packageName: "lodash", operation: "const settings = JSON.parse(req.params.data); lodash.merge({}, settings)", resolved: "4.17.4", wantVersion: "4.17.4", want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := pollutionFixture(t, tt.packageName, tt.resolved, "const lodash = require('"+tt.packageName+"');", tt.operation)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != tt.want {
				t.Fatalf("pollution candidates = %d, want %d", len(uses), tt.want)
			}
			if len(uses) == 0 {
				return
			}
			u := uses[0]
			if f := u.Pollution; f.Version != tt.wantVersion || f.Guard != tt.guard || !slices.Equal(f.Blocked, tt.blocked) {
				t.Fatalf("unexpected write facts: %+v", f)
			}
			if tt.wantVersion == "" {
				if !pollutionHasGap(u.Completeness.Blockers, "version_unresolved") {
					t.Fatalf("expected version blocker: %+v", u.Completeness)
				}
			} else if tt.guard == "" {
				if len(u.Completeness.Blockers) != 0 || len(u.Pollution.Paths) != 1 || u.Pollution.Paths[0].Protection != "raw" {
					t.Fatalf("expected complete raw path: %+v / %+v", u.Pollution.Paths, u.Completeness.Blockers)
				}
				if len(u.Completeness.Evidence["dependency_version"]) != 1 {
					t.Fatal("missing lockfile version witness")
				}
			}
		})
	}
}

func TestPollutionSourceWrites(t *testing.T) {
	report, err := Analyze("testdata/pollution/source-writes", "")
	if err != nil {
		t.Fatal(err)
	}
	uses := usesOf(report, analysis.PollutionKind, "server.js")
	for _, tt := range []struct {
		prefix, operation, guard, protection string
	}{
		{"merge(", analysis.PollutionMerge, "", "raw"},
		{"partial(", analysis.PollutionMerge, "deny_list", "raw"},
		{"guarded(", analysis.PollutionMerge, "deny_list", "guarded"},
		{"own(", analysis.PollutionMerge, "own_property", "guarded"},
		{"walk(", analysis.PollutionWalk, "", "raw"},
		{"store[", analysis.PollutionNested, "", "raw"},
		{"Object.create", analysis.PollutionNested, "null_prototype", "guarded"},
	} {
		matches := 0
		for _, u := range uses {
			if !strings.HasPrefix(u.Sink.Text, tt.prefix) {
				continue
			}
			matches++
			p := u.Pollution
			if p.Operation != tt.operation || p.Guard != tt.guard || len(p.Paths) != 1 || p.Paths[0].Protection != tt.protection || len(u.Completeness.Blockers) > 0 {
				t.Errorf("%s facts %+v blockers %+v", tt.prefix, p, u.Completeness.Blockers)
			}
			if tt.prefix == "partial(" && !pollutionHasGap(u.Gaps, "key_guard_incomplete") {
				t.Errorf("%s missing incomplete listing: %+v", tt.prefix, u.Gaps)
			}
			if _, err := analysispacks.Select(u); err != nil {
				t.Errorf("%s selection: %v", tt.prefix, err)
			}
		}
		if matches != 1 {
			t.Errorf("%s found %d candidates, expected one", tt.prefix, matches)
		}
	}
	if len(uses) != 7 {
		t.Fatalf("got %d pollution candidates, want 7", len(uses))
	}
}

func TestPollutionLodashDeletionControls(t *testing.T) {
	for _, tt := range []struct{ pkg, version string }{
		{"lodash", "4.17.22"}, {"lodash", "4.17.23"}, {"lodash", "4.18.0"}, {"lodash", "4.18.1"},
		{"lodash-es", "4.17.23"}, {"lodash-amd", "4.17.23"},
		{"lodash.unset", "4.17.21"}, {"lodash.unset", "4.18.0"},
		{"lodash.omit", "4.5.0"}, {"lodash.omit", "4.18.0"},
	} {
		t.Run(tt.pkg+"@"+tt.version, func(t *testing.T) {
			body := "library.unset({}, req.body.path); library.omit({}, req.body.path); library.pullAt([], req.body.path)"
			if tt.pkg == "lodash.unset" || tt.pkg == "lodash.omit" {
				body = "library({}, req.body.path)"
			}
			root := pollutionFixture(t, tt.pkg, tt.version, "const library = require('"+tt.pkg+"');", body)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			if uses := usesOf(report, analysis.PollutionKind, ""); len(uses) != 0 {
				t.Fatalf("deletion API has a prototype assignment record: %+v", uses)
			}
		})
	}
}

func pollutionFixture(t *testing.T, pkg, version, binding, body string) string {
	t.Helper()
	root := t.TempDir()
	writeSource(t, root, "package.json", `{"dependencies":{"express":"^4.0.0","`+pkg+`":"^4.0.0"}}`)
	if version != "" {
		writeSource(t, root, "package-lock.json", `{"lockfileVersion":3,"packages":{"node_modules/`+pkg+`":{"version":"`+version+`"}}}`)
	}
	writeSource(t, root, "server.js", `const express = require('express'); const app = express(); app.use(express.json());
`+binding+`
app.post('/settings/:data', (req, res) => { `+body+`; res.end(); });`)
	return root
}

func pollutionHasGap(gaps []analysis.Gap, kind string) bool {
	return slices.ContainsFunc(gaps, func(g analysis.Gap) bool { return g.Kind == kind })
}

func TestPollutionHelperGuardCoverage(t *testing.T) {
	for _, tt := range []struct {
		name, secondSource, secondGuard string
		args                            string
		want                            map[string]string
	}{
		{"independent guard coverage", "source", "if (key === '__proto__') continue;", "{}, req.body.settings", map[string]string{"req.body.settings": "raw"}},
		{"both loops guarded", "source", "if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;", "{}, req.body.settings", map[string]string{"req.body.settings": "guarded"}},
		{"each source argument is traced", "extra", "", "{}, req.body.settings, req.body.overrides", map[string]string{"req.body.settings": "guarded", "req.body.overrides": "raw"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express = require('express');
const app = express();
function merge(target, source, extra) {
  for (const key of Object.keys(source)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof source[key] === 'object') merge(target[key], source[key]);
    else target[key] = source[key];
  }
  for (const key of Object.keys(`+tt.secondSource+`)) {
    `+tt.secondGuard+`
    if (typeof `+tt.secondSource+`[key] === 'object') merge(target[key], `+tt.secondSource+`[key], `+tt.secondSource+`[key]);
    else target[key] = `+tt.secondSource+`[key];
  }
}
app.post('/settings', (req, res) => { merge(`+tt.args+`); res.end(); });
`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != len(tt.want) {
				t.Fatalf("got %d candidates, want %d", len(uses), len(tt.want))
			}
			seen := map[string]bool{}
			for _, u := range uses {
				if seen[u.ID] {
					t.Fatalf("duplicate ID %s", u.ID)
				}
				seen[u.ID] = true
				p := u.Pollution.Paths
				d := u.Dependencies[0]
				if len(p) != 1 || p[0].Protection != tt.want[d.Source.Text] {
					t.Fatalf("unexpected paths for %s: %+v", d.Source.Text, p)
				}
				if tt.secondSource == "source" && len(u.Completeness.Evidence["prototype_write"]) != 2 {
					t.Fatalf("expected evidence from both write sites: %+v", u.Completeness.Evidence["prototype_write"])
				}
			}
		})
	}
}

func TestPollutionLocalModuleWrites(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `
import express from 'express';
import { mergeSettings as update, setPath, setOwnedPath, readPath } from './settings.js';
const app = express();
app.use(express.json());
app.post('/merge', (req, res) => { update({}, req.body.settings); res.end(); });
app.post('/set', (req, res) => { setPath({}, req.body.path, req.body.value); res.end(); });
app.post('/owned', (req, res) => { setOwnedPath({}, req.body.path, req.body.value); res.end(); });
app.post('/read', (req, res) => { res.json(readPath({}, req.body.path)); });
`)
	writeSource(t, root, "settings.js", `
export function mergeSettings(target, source) {
  Object.keys(source).forEach((key) => {
    if (source[key] && typeof source[key] === 'object') mergeChild(target[key], source[key]);
    else target[key] = source[key];
  });
}
function mergeChild(target, source) {
  return mergeSettings(target, source);
}

export function setPath(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  for (const segment of parts.slice(0, -1)) cursor = cursor[segment];
  cursor[parts[parts.length - 1]] = value;
}
export function setOwnedPath(target, path, value) {
  const parts = path.split('.');
  let cursor = target;
  for (const segment of parts.slice(0, -1)) {
    if (!Object.hasOwn(cursor, segment)) return;
    cursor = cursor[segment];
  }
  cursor[parts[parts.length - 1]] = value;
}
export function readPath(target, path) {
  const parts = path.split('.');
  let cursor = target;
  for (const segment of parts) cursor = cursor[segment];
  return cursor;
}
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := usesOf(report, analysis.PollutionKind, "")
	cases := map[string]struct{ operation, operand, path, protection string }{
		"update":       {analysis.PollutionMerge, "source", "req.body.settings", "raw"},
		"setPath":      {analysis.PollutionWalk, "path", "req.body.path", "raw"},
		"setOwnedPath": {analysis.PollutionWalk, "path", "req.body.path", "guarded"},
	}
	if len(uses) != len(cases) {
		for _, u := range uses {
			t.Logf("%s: %+v", u.Sink.Text, u.Pollution)
		}
		t.Fatalf("got %d pollution candidates, want %d", len(uses), len(cases))
	}
	for _, u := range uses {
		name, _, _ := strings.Cut(u.Sink.Text, "(")
		want, ok := cases[name]
		if !ok {
			t.Fatalf("unexpected or duplicate candidate %s", u.Sink.Text)
		}
		delete(cases, name)
		p := u.Pollution
		if u.Sink.Span.File != "server.js" || p.ContractID != "" || p.Operation != want.operation ||
			p.KeyOperand != want.operand || len(p.Paths) != 1 || p.Paths[0].Protection != want.protection ||
			u.Dependencies[0].Source.Text != want.path || len(u.Completeness.Blockers) > 0 {
			t.Errorf("unexpected facts for %s: %+v; blockers: %+v", name, p, u.Completeness.Blockers)
		}
		writes := u.Completeness.Evidence["prototype_write"]
		if len(writes) != 1 || writes[0].Span.File != "settings.js" {
			t.Errorf("expected a source write in the imported module for %s: %+v", name, writes)
		}
	}
}
