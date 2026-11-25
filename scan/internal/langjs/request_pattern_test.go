package langjs

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// requestPatternUse returns the single path candidate of a one-route project.
func requestPatternUse(t *testing.T, files map[string]string) analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var found []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Kind == "path_traversal_candidate" {
			found = append(found, u)
		}
	}
	if len(found) != 1 {
		t.Fatalf("path candidates: got %d, want 1", len(found))
	}
	return found[0]
}

// dependencyShape is what a plain and a destructured handler must agree on:
// the request origin of each dependency, the kinds of its transfer steps and
// the blockers of the claim.
func dependencyShape(u analysis.CandidateUse) string {
	var parts []string
	for i, d := range u.Dependencies {
		origin := "no-facts"
		if u.InputFacts != nil && i < len(u.InputFacts.Values) {
			origin = u.InputFacts.Values[i].Origin + "/" + u.InputFacts.Values[i].InitialType
		}
		kinds := []string{}
		for _, e := range d.Transfers {
			kinds = append(kinds, e.Kind)
		}
		parts = append(parts, d.Source.Kind+" "+origin+" ["+strings.Join(kinds, ",")+"]")
	}
	blockers := []string{}
	if u.Completeness != nil {
		for _, g := range u.Completeness.Blockers {
			blockers = append(blockers, g.Kind)
		}
	}
	sort.Strings(blockers)
	return strings.Join(parts, "; ") + " | blockers " + strings.Join(blockers, ",")
}

const patternHead = `import express from 'express';
import path from 'path';
import fs from 'fs';
const app = express();
`

// TestDestructuredRequestParameter covers hardening 3 D-1: an object pattern as
// the request parameter records what the plain parameter records. The first
// project registers handlers directly; the transfer project returns them from
// factories of another module, with different names.
func TestDestructuredRequestParameter(t *testing.T) {
	direct := func(route, handler string) map[string]string {
		return map[string]string{"server.ts": patternHead + "app.get('" + route + "', " + handler + ")"}
	}
	factory := func(route, handler string) map[string]string {
		return map[string]string{
			"lib/reports.ts": "import { type Request, type Response } from 'express';\nimport path from 'path';\nimport fs from 'fs';\nexport function showReport () {\n  return " + handler + "\n}",
			"main.ts":        "import express from 'express';\nimport { showReport } from './lib/reports';\nconst api = express();\napi.use('" + route + "', showReport())",
		}
	}
	for _, tt := range []struct {
		name          string
		build         func(route, handler string) map[string]string
		route         string
		plain         string
		pattern       string
		field         string
		sourceMention string
	}{
		{"shorthand container", direct, "/docs/:name",
			`(req, res) => { res.sendFile(path.resolve('docs/', req.params.name)) }`,
			`({ params }, res) => { res.sendFile(path.resolve('docs/', params.name)) }`, "name", "params.name"},
		{"renamed container", direct, "/docs",
			`(req, res) => { res.send(fs.readFileSync(path.join('docs', req.body.sheet))) }`,
			`({ body: b }, res) => { res.send(fs.readFileSync(path.join('docs', b.sheet))) }`, "sheet", "b.sheet"},
		{"nested pattern", direct, "/docs",
			`(req, res) => { res.sendFile(path.resolve('docs/', req.query.leaf)) }`,
			`({ query: { leaf } }, res) => { res.sendFile(path.resolve('docs/', leaf)) }`, "leaf", "leaf"},
		{"nested pattern with a renamed field", direct, "/docs/:leaf",
			`(req, res) => { res.sendFile(path.resolve('docs/', req.params.leaf)) }`,
			`({ params: { leaf: wanted } }, res) => { res.sendFile(path.resolve('docs/', wanted)) }`, "leaf", "leaf: wanted"},
		{"transfer: factory in another module", factory, "/reports/:sheet",
			`(request, reply) => { reply.sendFile(path.resolve('reports/', request.params.sheet)) }`,
			`({ params, query }, reply) => { reply.sendFile(path.resolve('reports/', params.sheet)) }`, "sheet", "params.sheet"},
		{"transfer: factory with a renamed container", factory, "/reports",
			`(request, reply) => { reply.send(fs.readFileSync(path.join('reports', request.query.sheet))) }`,
			`({ query: q }, reply) => { reply.send(fs.readFileSync(path.join('reports', q.sheet))) }`, "sheet", "q.sheet"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			plain := requestPatternUse(t, tt.build(tt.route, tt.plain))
			got := requestPatternUse(t, tt.build(tt.route, tt.pattern))
			if want := dependencyShape(plain); dependencyShape(got) != want {
				t.Fatalf("destructured handler records\n  %s\nplain handler records\n  %s", dependencyShape(got), want)
			}
			if len(got.Dependencies) != 1 {
				t.Fatalf("dependencies: %+v", got.Dependencies)
			}
			d := got.Dependencies[0]
			if d.Source.Text != tt.sourceMention {
				t.Fatalf("source %q, want %q", d.Source.Text, tt.sourceMention)
			}
			// A nested binding has no member read; its pattern text names the field.
			if !strings.Contains(tt.sourceMention, ".") && !analysis.MatchesFields(d, []string{tt.field}) {
				t.Fatalf("source %q does not name field %q", d.Source.Text, tt.field)
			}
		})
	}
	for _, tt := range []struct{ name, handler string }{
		{"rest element", `({ params, ...others }, res) => { res.sendFile(path.resolve('docs/', params.name)) }`},
		{"computed key", `({ ['params']: p }, res) => { res.sendFile(path.resolve('docs/', p.name)) }`},
		{"default value", `({ params = {} }, res) => { res.sendFile(path.resolve('docs/', params.name)) }`},
		{"nested default value", `({ params: { name = 'index' } }, res) => { res.sendFile(path.resolve('docs/', name)) }`},
		{"two levels of nesting", `({ body: { doc: { name } } }, res) => { res.sendFile(path.resolve('docs/', name)) }`},
	} {
		t.Run("keeps the blocker: "+tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", patternHead+"app.get('/docs/:name', "+tt.handler+")")
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			// The route flow reads what it can and records the rest as a partial
			// projection; the claim keeps the blocker from the chain resolver.
			for _, u := range report.Uses {
				if u.Kind == "path_traversal_candidate" && (u.Completeness == nil || !gapKind(u.Completeness.Blockers, "request_projection_unresolved")) {
					t.Fatalf("path candidate is not blocked: %+v", u.Completeness)
				}
			}
			unresolved := false
			for _, e := range report.Entries {
				unresolved = unresolved || gapKind(e.Gaps, "request_projection_unresolved") || gapKind(e.Gaps, "request_projection_partial")
			}
			if !unresolved {
				t.Fatal("entry carries no request projection gap")
			}
		})
	}
}

// TestNamespaceImportHelper covers hardening 3 D-2: a call of a function
// exported by a scanned module through a namespace import is a known callee.
func TestNamespaceImportHelper(t *testing.T) {
	server := func(module, call string) string {
		return patternHead + "import * as tools from '" + module + "';\napp.get('/docs/:name', (req, res) => { const leaf = " + call + "; res.sendFile(path.resolve('docs/', leaf)) })"
	}
	gapsOf := func(u analysis.CandidateUse) []string {
		var out []string
		for _, g := range u.Gaps {
			if g.Kind == "unknown_value" || g.Kind == "unknown_transfer" || g.Kind == "unknown_call_result" {
				out = append(out, g.Kind+": "+g.Detail)
			}
		}
		return out
	}
	dependsOnName := func(u analysis.CandidateUse) bool {
		for _, d := range u.Dependencies {
			if d.Source.Kind == "input_source" && d.Source.Text == "req.params.name" {
				return true
			}
		}
		return false
	}
	t.Run("returning helper of a scanned module", func(t *testing.T) {
		u := requestPatternUse(t, map[string]string{
			"server.ts":    server("./lib/tools", "tools.tidy(req.params.name)"),
			"lib/tools.ts": "export const tidy = (text: string) => { return text }",
		})
		if !dependsOnName(u) {
			t.Fatalf("dependency lost: %+v", u.Dependencies)
		}
		for _, g := range gapsOf(u) {
			if strings.Contains(g, "tools") {
				t.Fatalf("known callee recorded a gap: %s", g)
			}
		}
	})
	t.Run("branching helper keeps the transfer gap and no receiver gap", func(t *testing.T) {
		u := requestPatternUse(t, map[string]string{
			"server.ts":    server("./lib/tools", "tools.cut(req.params.name)"),
			"lib/tools.ts": "export const cut = (text: string) => {\n  const mark = '%7e'\n  if (text.includes(mark)) {\n    return text.substring(0, text.indexOf(mark))\n  }\n  return text\n}",
		})
		if !dependsOnName(u) {
			t.Fatalf("dependency lost: %+v", u.Dependencies)
		}
		transfer := false
		for _, g := range gapsOf(u) {
			if strings.HasPrefix(g, "unknown_value") && strings.Contains(g, "tools") {
				t.Fatalf("namespace binding of a scanned module recorded as an unknown value: %s", g)
			}
			transfer = transfer || strings.HasPrefix(g, "unknown_transfer") && strings.Contains(g, "tools.cut")
		}
		if !transfer {
			t.Fatalf("the helper flow could not follow the branch, so its transfer gap must stay: %v", gapsOf(u))
		}
	})
	t.Run("transfer: required namespace object of a scanned module", func(t *testing.T) {
		u := requestPatternUse(t, map[string]string{
			"main.ts":      "import express from 'express';\nimport path from 'path';\nimport * as wash from './util/wash';\nconst api = express();\napi.get('/sheets/:name', (req, res) => { const leaf = wash.trimmed(req.params.name); res.sendFile(path.resolve('sheets/', leaf)) })",
			"util/wash.ts": "export function trimmed (value: string) {\n  const end = ';'\n  if (value.endsWith(end)) {\n    return value.slice(0, -1)\n  }\n  return value\n}",
		})
		if !dependsOnName(u) {
			t.Fatalf("dependency lost: %+v", u.Dependencies)
		}
		for _, g := range gapsOf(u) {
			if strings.HasPrefix(g, "unknown_value") && strings.Contains(g, "wash") {
				t.Fatalf("namespace binding of a scanned module recorded as an unknown value: %s", g)
			}
		}
	})
	t.Run("unscanned module keeps the gap", func(t *testing.T) {
		u := requestPatternUse(t, map[string]string{
			"server.ts": server("some-text-library", "tools.cut(req.params.name)"),
		})
		value := false
		for _, g := range gapsOf(u) {
			value = value || strings.HasPrefix(g, "unknown_value") && strings.Contains(g, "tools")
		}
		if !value || u.Completeness == nil || !gapKind(u.Completeness.Blockers, "unknown_value") {
			t.Fatalf("a call into an unscanned module must keep its unknown value blocker: %v", gapsOf(u))
		}
	})
	t.Run("member that is not an exported function keeps the gap", func(t *testing.T) {
		u := requestPatternUse(t, map[string]string{
			"server.ts":    server("./lib/tools", "tools.missing(req.params.name)"),
			"lib/tools.ts": "export const tidy = (text: string) => { return text }",
		})
		value := false
		for _, g := range gapsOf(u) {
			value = value || strings.HasPrefix(g, "unknown_value") && strings.Contains(g, "tools")
		}
		if !value {
			t.Fatalf("an unresolved member must keep its gap: %v", gapsOf(u))
		}
	})
}
