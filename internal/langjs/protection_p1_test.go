package langjs

import (
	"strings"
	"testing"

	sitter "github.com/tree-sitter/go-tree-sitter"
	js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

func p1SSRF(t *testing.T, route string) analysis.CandidateUse {
	t.Helper()
	const head = "const express = require('express');\nconst app = express();\n"
	uses := outboundUses(t, map[string]string{"server.js": head + "app.post('/x', async (req, res, next) => {\n" + route + "\n});\n"})
	var out []analysis.CandidateUse
	for _, u := range uses {
		if u.Kind == "ssrf_candidate" {
			out = append(out, u)
		}
	}
	if len(out) != 1 {
		t.Fatalf("ssrf uses=%d for %s", len(out), route)
	}
	return out[0]
}

func p1HasFact(u analysis.CandidateUse, prefix string) bool {
	if u.Completeness == nil {
		return false
	}
	for _, f := range u.Completeness.ModelFacts {
		if strings.HasPrefix(f, prefix) {
			return true
		}
	}
	return false
}

func p1GuardCount(u analysis.CandidateUse) int {
	n := 0
	for _, e := range u.Context {
		if e.Kind == "terminating_guard" || e.Kind == "enclosing_guard" {
			n++
		}
	}
	return n
}

// TestP1NonEnforcingURLCheck covers S1: a regex check whose only effect is a
// flag (or that runs after the call) is never a guard, a supported transfer or
// a host constraint; an enforcing early exit stays a guard.
func TestP1NonEnforcingURLCheck(t *testing.T) {
	safe := p1SSRF(t, "const url = req.body.imageUrl;\nif (!/^https:\\/\\/img\\.example\\//.test(url)) return res.status(400).end();\nawait fetch(url);\nres.end();")
	if p1GuardCount(safe) == 0 {
		t.Errorf("enforcing early-exit regex test must remain a guard: %+v", safe.Context)
	}
	for _, tt := range []struct{ name, route string }{
		{"flag only (Juice)", "const url = req.body.imageUrl;\nif (url.match(/(.)*solve\\/x(.)*/) !== null) req.app.locals.abused = true;\nawait fetch(url);\nres.end();"},
		{"test flag not read", "const url = req.body.imageUrl;\nconst ok = /^https:\\/\\/img\\.example\\//.test(url);\nawait fetch(url);\nres.end();"},
		{"flag read in unrelated branch", "const url = req.body.imageUrl;\nconst ok = /^https:\\/\\/img\\.example\\//.test(url);\nif (ok) { req.app.locals.n = 1 }\nawait fetch(url);\nres.end();"},
		{"check after fetch", "const url = req.body.imageUrl;\nawait fetch(url);\nif (!/^https:\\/\\/img\\.example\\//.test(url)) return res.status(400).end();\nres.end();"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := p1SSRF(t, tt.route)
			if p1GuardCount(u) != 0 {
				t.Errorf("non-enforcing check became a guard: %+v", u.Context)
			}
			if p1HasFact(u, "supported_transfer") || p1HasFact(u, "url_scheme_only_test") {
				t.Errorf("non-enforcing check offered as constraint: %v", u.Completeness.ModelFacts)
			}
			if u.Outbound == nil || len(u.Outbound.Paths) != 1 || u.Outbound.Paths[0].Protection != "raw" {
				t.Errorf("destination must stay raw: %+v", u.Outbound)
			}
		})
	}
}

// TestP1NonEnforcingClassifier pins the classifier boundary: only a check whose
// effect is positively a flag/variable (or that follows the call) is
// non-enforcing; anything that can exit, gate or rewrite the operand is not.
func TestP1NonEnforcingClassifier(t *testing.T) {
	jsParser, err := parse.OpenParser(js.Language())
	if err != nil {
		t.Fatal(err)
	}
	defer jsParser.Close()
	for _, tt := range []struct {
		name, body string
		want       bool
	}{
		{"flag member assignment", `function h(){ const url = q; if (url.match(/a/) !== null) req.app.locals.x = true; fetch(url); }`, true},
		{"flag variable not read", `function h(){ const url = q; const ok = /a/.test(url); fetch(url); }`, true},
		{"flag read by unrelated branch", `function h(){ const url = q; const ok = /a/.test(url); if (ok) { n = 1 } fetch(url); }`, true},
		{"after the call", `function h(){ const url = q; fetch(url); if (!/a/.test(url)) return; }`, true},
		{"early return", `function h(){ const url = q; if (!/a/.test(url)) return; fetch(url); }`, false},
		{"early throw", `function h(){ const url = q; if (!/a/.test(url)) throw new Error('x'); fetch(url); }`, false},
		{"branch may exit through a call", `function h(){ const url = q; if (/a/.test(url)) next(e); fetch(url); }`, false},
		{"flag gates the call", `function h(){ const url = q; const ok = /a/.test(url); if (ok) { fetch(url); } }`, false},
		{"flag in call branch condition with else exit", `function h(){ const url = q; if (/a/.test(url)) { f = 1 } else { return } fetch(url); }`, false},
		{"flag used by operand", `function h(){ const url = q; const m = url.match(/a/); fetch(m[1]); }`, false},
		{"branch rewrites operand", `function h(){ let url = q; if (/a/.test(url)) url = 'https://x/'; fetch(url); }`, false},
		{"branch rewrites operand member", `function h(){ if (/a/.test(o.u)) o.u = 'x'; fetch(o.u); }`, false},
		{"condition has side effect call", `function h(){ const url = q; if (clean(url) && /a/.test(url)) f = 1; fetch(url); }`, false},
		{"test in expression statement", `function h(){ const url = q; /a/.test(url) || res.end(); fetch(url); }`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			src := []byte(tt.body)
			tree := jsParser.Parse(src, nil)
			defer tree.Close()
			m := &sourceModule{src: src, tree: tree, imports: map[string]importBinding{}}
			root := tree.RootNode()
			sink := findCall(root, src, "call_expression", "fetch(")
			var check *sitter.Node
			walkCalls(root, func(c *sitter.Node) {
				if fn := c.ChildByFieldName("function"); check == nil && fn != nil && fn.Kind() == "member_expression" {
					if p := fn.ChildByFieldName("property"); p != nil && urlCheckCallMethods[p.Utf8Text(src)] {
						check = c
					}
				}
			})
			if sink == nil || check == nil {
				t.Fatal("missing sink or check")
			}
			if got := nonEnforcingCheck(m, root, sink, check); got != tt.want {
				t.Fatalf("nonEnforcing=%v want %v", got, tt.want)
			}
		})
	}
}

const p1ZodHead = `import { z } from 'zod';
import database from '../../lib/database.cjs';
import http from '../../lib/http.cjs';
const { getDatabase } = database;
const { endpoint } = http;
const Note = z.object({ body: z.string().min(1).max(1000) });
`

// p1ZodUses analyzes a lab-shaped Pages Router handler body (the code inside
// the endpoint callback) and returns the SQL candidates it produces.
func p1ZodUses(t *testing.T, body string) []analysis.CandidateUse {
	t.Helper()
	root := nextRepo(t, map[string]string{
		"package.json": `{"dependencies":{"next":"13.4.19","react":"18.2.0","@electric-sql/pglite":"0.5.16","zod":"4.6.7"}}`,
		"lib/database.cjs": `const { PGlite } = require('@electric-sql/pglite');
function getDatabase() { return PGlite.create(); }
module.exports = { getDatabase };`,
		"lib/http.cjs": `function endpoint(methods, run) {
  return async function handler(req, res) {
    if (!methods.includes(req.method)) return res.status(405).end();
    return await run(req, res);
  };
}
module.exports = { endpoint };`,
		"pages/api/n.js": p1ZodHead + "export default endpoint(['GET', 'POST'], async (req, res) => {\n  const db = await getDatabase();\n" + body + "\n});\n",
	})
	return usesOf(analyzeNext(t, root), "sql_query_candidate", "pages/api/n.js")
}

func p1HasEvidence(u analysis.CandidateUse, kind string) bool {
	return u.Completeness != nil && len(u.Completeness.Evidence[kind]) > 0
}

// TestP1ZodSafeParseFieldSource covers S2: a field read once from
// `parsed.data.<key>` of a safeParse over the request keeps its input source.
func TestP1ZodSafeParseFieldSource(t *testing.T) {
	const insert = "await db.query('INSERT INTO notes (body) VALUES ($1)', [parsed.data.body]);"
	uses := p1ZodUses(t, `  const parsed = Note.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).end();
  `+insert+`
  return res.status(201).end();`)
	if len(uses) != 1 {
		t.Fatalf("uses=%d", len(uses))
	}
	if !p1HasEvidence(uses[0], "input_source") {
		t.Errorf("zod field read lost input_source evidence: %v", uses[0].Completeness.Required)
	}

	for _, tt := range []struct{ name, body string }{
		{"safeParse on a non-request object", `  const parsed = Note.safeParse({ body: 'fixed' });
  ` + insert},
		{"result reassigned", `  let parsed = Note.safeParse(req.body ?? {});
  parsed = Note.safeParse({ body: 'fixed' });
  ` + insert},
		{"field read twice", `  const parsed = Note.safeParse(req.body ?? {});
  log(parsed.data.body);
  ` + insert},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for _, u := range p1ZodUses(t, tt.body+"\n  return res.end();") {
				if tt.name != "field read twice" && p1HasEvidence(u, "input_source") {
					t.Errorf("input_source attached without a request value")
				}
			}
		})
	}

	// Unchecked success: the candidate stays request-derived and unguarded.
	u := p1ZodUses(t, `  const parsed = Note.safeParse(req.body ?? {});
  await db.query("SELECT * FROM notes WHERE body = '" + parsed.data.body + "'");
  return res.end();`)
	if len(u) != 1 || len(u[0].Dependencies) == 0 {
		t.Fatalf("unchecked success must stay a request-derived candidate: %+v", u)
	}
	for _, e := range u[0].Context {
		if e.Kind == "terminating_guard" || e.Kind == "branch_false_precondition" {
			t.Errorf("unchecked success became a guard: %+v", e)
		}
	}
}

func p1CatchAllProtection(t *testing.T, body string) string {
	t.Helper()
	return p1CatchAllPath(t, body).Protection
}

func p1CatchAllPath(t *testing.T, body string) analysis.PathFlow {
	t.Helper()
	root := nextRepo(t, map[string]string{
		"app/api/uploads/[...path]/route.ts": `import { NextRequest, NextResponse } from "next/server";
import { readFile } from "fs/promises";
import { join } from "path";
export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
` + body + `
}`,
	})
	uses := usesOf(analyzeNext(t, root), "path_traversal_candidate", "")
	if len(uses) != 1 || uses[0].Path == nil || len(uses[0].Path.Paths) == 0 {
		t.Fatalf("path uses: %d", len(uses))
	}
	// Report the weakest flow: a sibling is only safe when no flow is guarded.
	out := uses[0].Path.Paths[0]
	for _, p := range uses[0].Path.Paths {
		if p.Protection != "guarded" {
			out = p
		}
	}
	return out
}

// TestP1CatchAllJoinGuard covers S3a: a `..` reject written on the joined
// catch-all string guards the final operand built from that same string, and
// only that string.
func TestP1CatchAllJoinGuard(t *testing.T) {
	const reject = `  if (filename.includes("..") || filename.includes("\0")) {
    return NextResponse.json({ error: "Invalid path" }, { status: 400 });
  }
`
	const read = `  const buf = await readFile(join(process.cwd(), "uploads", filename));
  return new NextResponse(buf);`
	if got := p1CatchAllProtection(t, `  const filename = path.join("/");
`+reject+read); got != "guarded" {
		t.Errorf("genuine control: protection=%s, want guarded", got)
	}
	// A decode after the check is flagged so the judge sees the control
	// inspected the pre-decoded text.
	if p := p1CatchAllPath(t, `  const raw = path.join("/");
  if (raw.includes("..")) { return NextResponse.json({}, { status: 400 }); }
  const filename = decodeURIComponent(raw);
`+read); p.Protection == "guarded" && !p.DecodedAfterGuard {
		t.Errorf("decode after the check must set DecodedAfterGuard: %+v", p)
	}
	for _, tt := range []struct{ name, body string }{
		{"check after the read", `  const filename = path.join("/");
  const buf = await readFile(join(process.cwd(), "uploads", filename));
` + reject + `  return new NextResponse(buf);`},
		{"check on a different variable", `  const filename = path.join("/");
  const other = path.join("/");
  if (other.includes("..")) { return NextResponse.json({}, { status: 400 }); }
` + read},
		{"single-pass replace", `  const filename = path.join("/").replace("..", "");
` + read},
		{"reassigned after the check", `  let filename = path.join("/");
  if (filename.includes("..")) { return NextResponse.json({}, { status: 400 }); }
  filename = filename + decodeURIComponent(path[0]);
` + read},
		{"join with a non-literal separator", `  const sep = new URL("http://x/").search;
  const filename = path.join(sep);
` + reject + read},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := p1CatchAllProtection(t, tt.body); got == "guarded" || got == "protected" {
				t.Errorf("vulnerable sibling protection=%s", got)
			}
		})
	}
}

func p1OutboundOrigin(t *testing.T, config, helper string) string {
	t.Helper()
	root := nextRepo(t, map[string]string{
		"lib/config.ts": config,
		"lib/gh.ts":     helper,
		"app/api/x/route.ts": `import { NextResponse } from "next/server";
import { load } from "@/lib/gh";
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const data = await load(searchParams.get("q") ?? "");
  return NextResponse.json({ data });
}`,
	})
	r := analyzeNext(t, root)
	var got []string
	for _, u := range r.Uses {
		if u.Outbound != nil && u.Sink.Span.File == "lib/gh.ts" {
			got = append(got, u.Outbound.DestinationOrigin)
		}
	}
	if len(got) != 1 {
		t.Fatalf("outbound uses in lib/gh.ts = %v", got)
	}
	return got[0]
}

// TestP1ModuleConstDestinationOrigin covers S4: a destination built only from
// module-level string `const`s (including imported ones) is constant; nothing
// that an environment, a request, a reassignment or a shadowing binding can
// change is.
func TestP1ModuleConstDestinationOrigin(t *testing.T) {
	const cfg = `export const SLUG = "org/repo";
export const HOST = "https://api.example.com";
export const FROM_ENV = process.env.API_SLUG;
export let MUTABLE = "org/repo";
export const FROM_ENV_OR = process.env.HOST || "https://api.example.com";
`
	const imports = `import { SLUG, HOST, FROM_ENV, MUTABLE, FROM_ENV_OR } from "@/lib/config";
`
	call := func(decls, use string) string {
		return imports + decls + "\nexport async function load(q: string) {\n  const res = await fetch(" + use + ");\n  return res.json();\n}"
	}
	if got := p1OutboundOrigin(t, cfg, call("const URL1 = `${HOST}/repos/${SLUG}/contributors?per_page=100`;", "URL1")); got != "constant" {
		t.Errorf("imported literal const chain: %s, want constant", got)
	}
	if got := p1OutboundOrigin(t, cfg, call("const BASE = `${HOST}/v1`;\nconst URL2 = `${BASE}/items`;", "URL2")); got != "constant" {
		t.Errorf("module const chain: %s, want constant", got)
	}
	for _, tt := range []struct{ name, decls, use string }{
		{"process.env value", "const URL3 = `https://api.example.com/${FROM_ENV}`;", "URL3"},
		{"env with literal fallback", "const URL3 = `${FROM_ENV_OR}/x`;", "URL3"},
		{"imported let", "const URL3 = `https://api.example.com/${MUTABLE}`;", "URL3"},
		{"request value in host position", "", "`https://${q}.example.com/x`"},
		{"request value in path", "", "`${HOST}/${q}`"},
		{"local let", "let URL3 = `${HOST}/x`;", "URL3"},
		{"reassigned module const holder", "let URL3 = `${HOST}/x`;\nfunction setIt(v: string) { URL3 = v; }", "URL3"},
		{"locally shadowed const", "", "SLUG"},
		{"shadowed by parameter", "const URL3 = `${HOST}/x`;", "((URL3: string) => URL3)(q)"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			helper := call(tt.decls, tt.use)
			if tt.name == "locally shadowed const" {
				helper = imports + "export async function load(SLUG: string) {\n  const res = await fetch(SLUG);\n  return res.json();\n}"
			}
			if got := p1OutboundOrigin(t, cfg, helper); got == "constant" {
				t.Errorf("origin folded to constant for a non-constant destination")
			}
		})
	}
}
