package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

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

func guardKinds(u analysis.CandidateUse) []string {
	var kinds []string
	for _, g := range u.Path.Guards {
		kinds = append(kinds, g.Kind)
	}
	return kinds
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

func TestPathJSOperands(t *testing.T) {
	r := analyzeFixture(t, "typescript/path-traversal")
	uses := pathUses(r)
	read, resolve := "fs.readFile", "fs.readFileSync"
	for route, want := range map[string]pathCase{
		"/v/join-read":          {operation: read, role: "read", protection: "raw", transforms: []string{"join"}, root: "__dirname"},
		"/v/resolve-sync":       {operation: resolve, role: "read", protection: "raw", transforms: []string{"resolve"}, root: "ROOT"},
		"/v/write":              {operation: "fs.writeFile", role: "write", protection: "raw", transforms: []string{"join"}},
		"/v/promises":           {operation: "fs/promises.readFile", role: "read", protection: "raw", transforms: []string{"join"}},
		"/v/normalize-only":     {operation: resolve, role: "read", protection: "raw", transforms: []string{"normalize"}},
		"/v/direct":             {operation: read, role: "read", protection: "raw"},
		"/v/try-catch":          {operation: resolve, role: "read", protection: "raw"},
		"/v/blacklist":          {operation: resolve, role: "read", protection: "guarded", guards: []string{"dotdot_text"}, transforms: []string{"decode"}, decoded: true},
		"/v/reassigned":         {operation: resolve, role: "read", protection: "raw"},
		"/v/sibling-branch":     {operation: resolve, role: "read", protection: "raw"},
		"/v/helper":             {operation: resolve, role: "read", protection: "raw", transforms: []string{"join"}},
		"/p/allowlist":          {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/allowlist-array":    {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}},
		"/p/prefix-boundary":    {operation: resolve, role: "read", protection: "guarded", guards: []string{"prefix_boundary"}, transforms: []string{"resolve"}},
		"/p/relative":           {operation: resolve, role: "read", protection: "guarded", guards: []string{"relative"}},
		"/p/realpath":           {operation: resolve, role: "read", protection: "guarded", guards: []string{"relative"}, transforms: []string{"realpath"}},
		"/u/prefix-bare":        {operation: resolve, role: "read", protection: "guarded", guards: []string{"prefix_bare"}},
		"/u/missing-helper":     {operation: resolve, role: "read", protection: "unknown", blocked: true},
		"/u/basename":           {operation: resolve, role: "read", protection: "raw", transforms: []string{"reduce"}},
		"/p/helper-guard":       {operation: resolve, role: "read", protection: "guarded", guards: []string{"allowlist"}, transforms: []string{"join"}},
		"/u/helper-two-callers": {operation: resolve, role: "read", protection: "unknown", blocked: true, guards: []string{"allowlist"}},
		"/v/url":                {operation: resolve, role: "read", protection: "raw", transforms: []string{"join"}},
		"/static":               {operation: read, role: "read", protection: "guarded", guards: []string{"prefix_bare"}, transforms: []string{"resolve"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/n/constant", "/n/content-only", "/n/shadowed-param", "/n/fake-object", "/n/send-constant"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not be a path candidate", route)
		}
	}
	t.Run("write content is not a path source", func(t *testing.T) {
		u := uses["/v/write"]
		var content *analysis.PathOperand
		for i := range u.Path.Operands {
			if u.Path.Operands[i].Slot == analysis.PathSlotContent {
				content = &u.Path.Operands[i]
			}
		}
		if content == nil || len(content.Dependencies) != 1 || u.Dependencies[content.Dependencies[0]].Source.Text != "req.body.data" {
			t.Fatalf("content operand: %+v", content)
		}
		if len(u.Path.Paths) != 1 || u.Dependencies[u.Path.Paths[0].Dependency].Source.Text != "req.body.name" {
			t.Fatalf("path flows: %+v", u.Path.Paths)
		}
	})
	t.Run("witness dependency keeps its source and transfers", func(t *testing.T) {
		u := uses["/v/join-read"]
		dep := u.Dependencies[u.Path.Paths[0].Dependency]
		if dep.Source.Text != "req.query.filename" || dep.SinkSlot != analysis.PathSlotFile || len(dep.Transfers) == 0 {
			t.Fatalf("dependency: %+v", dep)
		}
		if !strings.Contains(u.Sink.Text, "fs.readFile(filePath") {
			t.Fatalf("sink: %s", u.Sink.Text)
		}
	})
}

func TestPathCommonJSBindings(t *testing.T) {
	r := analyzeFixture(t, "javascript/path-traversal")
	uses := pathUses(r)
	for route, want := range map[string]pathCase{
		"/cjs/read":          {operation: "fs.readFile", role: "read", protection: "raw", transforms: []string{"join"}, file: "server.js"},
		"/cjs/destructured":  {operation: "fs.readFileSync", role: "read", protection: "raw", transforms: []string{"join"}},
		"/cjs/aliased-write": {operation: "fs.writeFile", role: "write", protection: "raw", transforms: []string{"join"}},
		"/cjs/promises":      {operation: "fs/promises.readFile", role: "read", protection: "raw", transforms: []string{"join"}},
		"/cjs/guarded":       {operation: "fs.readFileSync", role: "read", protection: "guarded", guards: []string{"prefix_boundary"}},
	} {
		t.Run(route, func(t *testing.T) {
			u, ok := uses[route]
			if !ok {
				t.Fatalf("no path candidate for %s", route)
			}
			checkPathCase(t, route, u, want)
		})
	}
	for _, route := range []string{"/cjs/local-module", "/cjs/reassigned"} {
		if _, ok := uses[route]; ok {
			t.Fatalf("%s must not carry the verified fs contract", route)
		}
	}
}

// TestPathGraphQLAndGRPCEntries checks that the same path claim attaches to the
// shared GraphQL resolver and unary gRPC handler contexts, with the request field
// as the source and the guard attributed to its own resolver only.
func TestPathGraphQLAndGRPCEntries(t *testing.T) {
	for _, tt := range []struct {
		dir        string
		operations map[string]string // sink function suffix -> expected flow protection ("" = no candidate)
		kind       string
	}{
		{"javascript/path-traversal/graphql", map[string]string{"report": "raw", "listed": "guarded", "fixed": ""}, "graphql"},
		{"javascript/path-traversal/grpc", map[string]string{"fetch": "raw", "fixed": ""}, "grpc"},
	} {
		t.Run(tt.dir, func(t *testing.T) {
			r := analyzeFixture(t, tt.dir)
			byEntry := map[string]analysis.EntryPoint{}
			for _, e := range r.Entries {
				byEntry[e.ID] = e
			}
			got := map[string]analysis.CandidateUse{}
			for _, u := range r.Uses {
				if u.Kind != "path_traversal_candidate" {
					continue
				}
				e := byEntry[u.EntryID]
				if e.Kind != tt.kind {
					t.Fatalf("entry kind %s, want %s", e.Kind, tt.kind)
				}
				name := ""
				if tt.kind == "grpc" {
					name = strings.ToLower(e.GRPC.Method)
				} else {
					name = e.GraphQL.Field
				}
				got[name] = u
			}
			for name, want := range tt.operations {
				u, ok := got[name]
				if want == "" {
					if ok {
						t.Fatalf("%s must not be a candidate", name)
					}
					continue
				}
				if !ok {
					t.Fatalf("no candidate for %s (have %v)", name, len(got))
				}
				if err := u.Path.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Fatal(err)
				}
				if p := u.Path.Paths[0]; p.Protection != want {
					t.Fatalf("%s: protection %s (%s), want %s; blockers %+v", name, p.Protection, p.Reason, want, u.Completeness.Blockers)
				}
				if u.Components == nil || u.Components.Failure != "" {
					t.Fatalf("%s: component selection %+v", name, u.Components)
				}
			}
		})
	}
}

// TestPathArchiveExtraction checks the Zip Slip shape: a request-supplied archive's
// stored entry names reach the destination, and whether the extractor validates them
// is a dependency fact, never a name or a guess.
func TestPathArchiveExtraction(t *testing.T) {
	for _, tt := range []struct {
		dir, assessment, declared string
		guard                     []string
	}{
		{"vulnerable", "vulnerable_version", "0.4.7", nil},
		{"fixed", "fixed_version", "0.5.5", []string{"library_entry_check"}},
		{"ranged", "unknown_version", "^0.4.7", nil},
	} {
		t.Run(tt.dir, func(t *testing.T) {
			uses := pathUses(analyzeFixture(t, "javascript/path-traversal-zip/"+tt.dir))
			u, ok := uses["/import"]
			if !ok {
				t.Fatalf("no archive candidate (have %d)", len(uses))
			}
			if _, bundled := uses["/bundled"]; bundled {
				t.Fatal("a constant archive path is not a request-derived archive")
			}
			f := u.Path
			if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
				t.Fatal(err)
			}
			if f.Operation != "adm-zip.extractAllTo" || f.Role != "write" || f.Extractor == nil || f.Extractor.Assessment != tt.assessment || f.Extractor.Declared != tt.declared {
				t.Fatalf("facts: %+v extractor %+v", f, f.Extractor)
			}
			if len(f.Paths) != 1 || f.Paths[0].Operand != analysis.PathSlotArchive || u.Dependencies[f.Paths[0].Dependency].SinkSlot != analysis.PathSlotArchive || !strings.Contains(u.Dependencies[0].Source.Text, "req.files") {
				t.Fatalf("flows: %+v deps %+v", f.Paths, u.Dependencies)
			}
			if got := guardKinds(u); strings.Join(got, ",") != strings.Join(tt.guard, ",") {
				t.Fatalf("guards %v, want %v", got, tt.guard)
			}
			if u.Completeness == nil || len(u.Completeness.Blockers) != 0 || u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("completeness %+v components %+v", u.Completeness, u.Components)
			}
		})
	}
}

func TestPathExpandedChainAndLayout(t *testing.T) {
	r := analyzeFixture(t, "typescript/path-traversal-expanded")
	uses := pathUses(r)
	for _, route := range []string{"/v/middle", "/v/archive-middle", "/v/layout", "/v/layout-spread", "/v/exported-archive-middle", "/panel", "/v/irrelevant-helper-budget"} {
		u, ok := uses[route]
		if !ok {
			t.Errorf("no general path candidate for %s", route)
			continue
		}
		if err := u.Path.Validate(len(u.Dependencies), len(u.Context)); err != nil {
			t.Error(err)
		}
		if len(u.Path.Paths) == 0 {
			t.Errorf("missing request path at %s", route)
		}
		if len(u.Completeness.Blockers) > 0 {
			t.Errorf("%s blockers: %+v", route, u.Completeness.Blockers)
		}
	}
	for route, want := range map[string]string{"/p/layout-allowlist-alias": analysis.PathGuardAllowlist, "/v/layout-gated-blacklist": analysis.PathGuardSubstring} {
		u, ok := uses[route]
		if !ok {
			t.Errorf("missing %s", route)
			continue
		}
		if got := guardKinds(u); len(got) != 1 || got[0] != want {
			t.Errorf("%s guards %v, want %s", route, got, want)
		}
	}
	if u, ok := uses["/u/archive-filter"]; !ok || len(u.Completeness.Blockers) == 0 {
		t.Error("custom file filter must remain an unresolved predecessor")
	}
	for _, route := range []string{"/n/layout-overridden", "/n/layout-constant"} {
		if _, ok := uses[route]; ok {
			t.Errorf("constant/overridden layout should not be a candidate: %s", route)
		}
	}
}

func TestPathGuardPolarityAndBypass(t *testing.T) {
	tsRoot := t.TempDir()
	writeSource(t, tsRoot, "server.ts", `
import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
const app = express();
const ROOT = path.resolve(__dirname, 'uploads');
const ALLOWED = new Set(['a.txt', 'b.txt']);
app.get('/else-branch', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (ALLOWED.has(f)) { return res.send('cached'); } else { res.send(fs.readFileSync(path.join(ROOT, f))); }
});
app.get('/negated-consequence', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  if (!full.startsWith(ROOT + path.sep)) { res.send(fs.readFileSync(full)); }
});
app.get('/inverted-terminating', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (ALLOWED.has(f)) return res.status(403).end();
  res.send(fs.readFileSync(path.join(ROOT, f)));
});
app.get('/conjunct-bypass', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (!req.query.admin && !ALLOWED.has(f)) return res.status(403).end();
  res.send(fs.readFileSync(path.join(ROOT, f)));
});
app.get('/disjunct-enforced', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (!req.query.admin || !ALLOWED.has(f)) return res.status(403).end();
  res.send(fs.readFileSync(path.join(ROOT, f)));
});
app.get('/enclosing-positive', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  if (full.startsWith(ROOT + path.sep)) { res.send(fs.readFileSync(full)); }
});
`)
	tsReport, err := Analyze(tsRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	tsUses := pathUses(tsReport)
	for _, route := range []string{"/else-branch", "/negated-consequence", "/inverted-terminating", "/conjunct-bypass"} {
		u, ok := tsUses[route]
		if !ok {
			t.Fatalf("missing candidate %s", route)
		}
		for _, k := range guardKinds(u) {
			if analysis.EnforcingPathGuard(k) {
				t.Errorf("%s wrongly received enforcing guard kind %s", route, k)
			}
		}
	}
	for route, want := range map[string]string{"/disjunct-enforced": analysis.PathGuardAllowlist, "/enclosing-positive": analysis.PathGuardPrefixBoundary} {
		u, ok := tsUses[route]
		if !ok {
			t.Fatalf("missing candidate %s", route)
		}
		if got := guardKinds(u); len(got) != 1 || got[0] != want {
			t.Errorf("%s guard kinds %v, want [%s]", route, got, want)
		}
	}
}

func TestPathFalseProtectionControls(t *testing.T) {
	tsRoot := t.TempDir()
	writeSource(t, tsRoot, "ext.ts", `export const EXTERNAL = ['a.txt'];`)
	writeSource(t, tsRoot, "server.ts", `
import express, { Request, Response } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { EXTERNAL } from './ext';
const app = express();
const ROOT = path.resolve(__dirname, 'uploads');
const MUTATED = ['a.txt'];
MUTATED.push(process.env.EXTRA || 'x');
const ALLOWED = new Set(['a.txt']);

function openDecoded(p: string) {
  return fs.readFileSync(path.join(ROOT, decodeURIComponent(p)));
}

function readShared(file: string) {
  return fs.readFileSync(path.join(ROOT, file));
}

app.get('/external-includes', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (!EXTERNAL.includes(f)) return res.status(403).end();
  res.send(fs.readFileSync(path.join(ROOT, f)));
});
app.get('/mutated-allowlist', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (!MUTATED.includes(f)) return res.status(403).end();
  res.send(fs.readFileSync(path.join(ROOT, f)));
});
app.get('/realpath-after-guard', (req: Request, res: Response) => {
  const full = path.resolve(ROOT, req.query.f as string);
  if (!full.startsWith(ROOT + path.sep)) return res.status(403).end();
  const resolved = fs.realpathSync(full);
  res.send(fs.readFileSync(resolved));
});
app.get('/decode-in-helper', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (f.includes('..')) return res.status(400).end();
  res.send(openDecoded(f));
});
app.get('/mixed-helper-callers', (req: Request, res: Response) => {
  const f = req.query.f as string;
  if (req.query.strict) {
    if (!ALLOWED.has(f)) return res.status(403).end();
    return res.send(readShared(f));
  }
  if (f.includes('..')) return res.status(400).end();
  res.send(readShared(f));
});
`)
	tsReport, err := Analyze(tsRoot, "")
	if err != nil {
		t.Fatal(err)
	}
	tsUses := pathUses(tsReport)
	if got := guardKinds(tsUses["/external-includes"]); len(got) != 1 || got[0] != analysis.PathGuardUnclassified {
		t.Errorf("/external-includes guards %v, want [unclassified]", got)
	}
	if got := guardKinds(tsUses["/mutated-allowlist"]); len(got) != 1 || got[0] != analysis.PathGuardUnclassified {
		t.Errorf("/mutated-allowlist guards %v, want [unclassified]", got)
	}
	if u := tsUses["/realpath-after-guard"]; u.Path.Paths[0].RealpathBeforeGuard {
		t.Errorf("/realpath-after-guard set RealpathBeforeGuard=true when realpath ran after guard")
	}
	if u := tsUses["/decode-in-helper"]; !u.Path.Paths[0].DecodedAfterGuard {
		t.Errorf("/decode-in-helper missed DecodedAfterGuard across helper declared above handler")
	}
	if u := tsUses["/mixed-helper-callers"]; u.Path.Paths[0].Protection != "unknown" {
		t.Errorf("/mixed-helper-callers protection=%s, want unknown", u.Path.Paths[0].Protection)
	}
}

func TestPathBindingsAndURLHelpers(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `
const express = require('express');
const { readFile } = require('fs').promises;
const fs = require('fs');
const path = require('path');
const app = express();
const ROOT = path.join(__dirname, 'pub');

function serveReqPath(req, res) {
  res.send(fs.readFileSync(path.join(ROOT, req.path)));
}

app.get('/promises-destructured', async (req, res) => {
  res.send(await readFile(path.join(ROOT, req.query.f)));
});
app.use('/nested-url', (req, res) => serveReqPath(req, res));
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := pathUses(r)
	if u, ok := uses["/promises-destructured"]; !ok || u.Path.Operation != "fs/promises.readFile" {
		t.Errorf("/promises-destructured missing or wrong op: %+v", u.Path)
	}
	if u, ok := uses["/nested-url"]; !ok || u.Path.Operation != "fs.readFileSync" {
		t.Errorf("/nested-url helper req.path missing: %+v", u.Path)
	}
}
