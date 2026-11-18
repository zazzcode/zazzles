package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// nextRepo writes a small Next.js App Router repository: a manifest that
// declares next (and the given extra dependencies), a tsconfig with the `@/`
// alias and the supplied files.
func nextRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	if _, ok := files["package.json"]; !ok {
		writeSource(t, root, "package.json", `{"dependencies":{"next":"15.2.2","react":"19.2.0","better-sqlite3":"11.0.0","pino":"9.0.0","zod":"3.23.8","@prisma/client":"6.0.0"}}`)
	}
	if _, ok := files["tsconfig.json"]; !ok {
		writeSource(t, root, "tsconfig.json", `{
  // comments and trailing commas are accepted
  "compilerOptions": { "paths": { "@/*": ["./*"], }, },
  "exclude": ["node_modules", "docs"],
}`)
	}
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	return root
}

func analyzeNext(t *testing.T, root string) *analysis.AnalysisReport {
	t.Helper()
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	// Every record must be sendable: input facts use the wire vocabulary.
	for _, u := range r.Uses {
		if err := u.InputFacts.Validate(u.Dependencies); err != nil {
			t.Fatalf("%s %s: invalid input facts: %v", u.Kind, u.Sink.Text, err)
		}
		if _, err := analysispacks.Select(u); err != nil {
			t.Fatalf("%s %s: judge component selection rejects the record: %v", u.Kind, u.Sink.Text, err)
		}
		if u.InputFacts != nil && u.EntryFacts != nil && (u.EntryFacts.Kind != u.InputFacts.Acquisition || u.EntryFacts.Location.Span != u.InputFacts.Binding.Span) {
			t.Fatalf("%s: input facts acquisition/binding must match the entry", u.Kind)
		}
	}
	return r
}

func entryNamed(r *analysis.AnalysisReport, name string) *analysis.EntryPoint {
	for i := range r.Entries {
		if r.Entries[i].Name == name {
			return &r.Entries[i]
		}
	}
	return nil
}

func usesOf(r *analysis.AnalysisReport, kind, file string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind && (file == "" || u.Sink.Span.File == file) {
			out = append(out, u)
		}
	}
	return out
}

func origins(u analysis.CandidateUse) []string {
	var out []string
	if u.InputFacts == nil {
		return out
	}
	for _, v := range u.InputFacts.Values {
		out = append(out, v.Origin)
	}
	return out
}

func hasNextGap(gaps []analysis.Gap, kind string) bool {
	for _, g := range gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}

func blockers(u analysis.CandidateUse) []analysis.Gap {
	if u.Completeness == nil {
		return nil
	}
	return u.Completeness.Blockers
}

func TestNextSegmentConversion(t *testing.T) {
	cases := []struct {
		segments []string
		pattern  string
		routable bool
	}{
		{[]string{"api", "orders", "[id]"}, "/api/orders/:id", true},
		{[]string{"api", "files", "[...path]"}, "/api/files/:path*", true},
		{[]string{"api", "vcs", "[[...path]]"}, "/api/vcs/:path*?", true},
		{[]string{"(shop)", "api", "cart"}, "/api/cart", true},
		{[]string{".well-known", "jwks.json"}, "/.well-known/jwks.json", true},
		{[]string{"api", "_internal", "x"}, "", false},
		{[]string{"@modal", "x"}, "", false},
		{[]string{"(.)photo"}, "", false},
	}
	for _, c := range cases {
		pattern, converted, routable := nextRoutePattern(c.segments)
		if routable != c.routable || (routable && pattern != c.pattern) {
			t.Errorf("%v: pattern %q routable %v", c.segments, pattern, routable)
		}
		_ = converted
	}
	if s := convertNextSegment("[...slug]"); s.paramType != "string[]" {
		t.Fatalf("catch-all type %q", s.paramType)
	}
	if s := convertNextSegment("[[...slug]]"); s.paramType != "string[] | undefined" {
		t.Fatalf("optional catch-all type %q", s.paramType)
	}
}

func TestNextRouteHandlersAndWrappers(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/auth.ts": `
import { NextResponse } from "next/server";
export function withAuth(handler) {
  return async (request, context) => {
    const user = request.cookies.get("token")?.value;
    if (!user) { return NextResponse.json({ error: "no" }, { status: 401 }); }
    return handler(request, context, user);
  };
}
export function swaps(handler) {
  return async (request, context) => handler(new Request("http://x"), context);
}`,
		"lib/db.ts": `import Database from "better-sqlite3";
export const unused = 1;`,
		"app/api/a/route.ts": `
import { NextResponse } from "next/server";
export async function GET(request) { return NextResponse.json({}); }
const handler = async (request) => NextResponse.json({});
export { handler as POST, handler as PUT };`,
		"app/api/b/[id]/route.ts": `
import { withAuth, swaps } from "@/lib/auth";
import Database from "better-sqlite3";
export const POST = withAuth(async (request, context, user) => {
  const { id } = await context.params;
  const db = new Database("x.db");
  db.exec("DELETE FROM t WHERE id = '" + id + "' AND owner = '" + user + "'");
  return new Response("ok");
});
export const PATCH = swaps(async (request, context) => new Response("x"));`,
		"app/api/_private/route.ts": `export async function GET() { return new Response("x"); }`,
		"app/api/c/route.ts":        `export async function GET() { return new Response("x"); }`,
		"app/api/c/page.tsx":        `export default function Page() { return null; }`,
		"docs/app/api/route.ts":     `export async function GET() { return new Response("x"); }`,
	})
	r := analyzeNext(t, root)
	for _, name := range []string{"GET /api/a", "POST /api/a", "PUT /api/a", "POST /api/b/:id", "PATCH /api/b/:id"} {
		if entryNamed(r, name) == nil {
			t.Errorf("missing entry %s", name)
		}
	}
	if e := entryNamed(r, "PATCH /api/b/:id"); e == nil || !hasNextGap(e.Gaps, "unresolved_wrapper") {
		t.Errorf("a wrapper that swaps the request must stay unresolved: %+v", e)
	}
	for _, e := range r.Entries {
		if strings.Contains(e.Location.Span.File, "_private") || strings.HasPrefix(e.Location.Span.File, "docs/") || e.Name == "GET /api/c" {
			t.Errorf("unexpected entry %s at %s", e.Name, e.Location.Span.File)
		}
	}
	if !hasNextGap(r.Gaps, "next_route_conflict") || !hasNextGap(r.Gaps, "next_scope_excluded") {
		t.Errorf("route conflict and tsconfig exclusion must be reported: %+v", r.Gaps)
	}
	sql := usesOf(r, "sql_query_candidate", "app/api/b/[id]/route.ts")
	if len(sql) != 1 || sql[0].APIModel == nil || sql[0].APIModel.ID != "better-sqlite3-v1" {
		t.Fatalf("better-sqlite3 exec through a verified wrapper: %+v", sql)
	}
	if o := origins(sql[0]); len(o) != 1 || o[0] != "http.path" {
		t.Fatalf("path origin from awaited context.params; the wrapper's user is not a request origin: %v", o)
	}
	if b := blockers(sql[0]); len(b) != 0 {
		t.Fatalf("complete evidence expected: %+v", b)
	}
	facts := strings.Join(sql[0].Completeness.ModelFacts, "\n")
	if !strings.Contains(facts, "scope_nextjs: route_handler") || !strings.Contains(facts, "sql_multi_statement") {
		t.Fatalf("facts %s", facts)
	}
	authorization := false
	for _, e := range sql[0].Context {
		authorization = authorization || e.Kind == "authorization_context"
	}
	if !authorization {
		t.Fatal("the wrapper's early return must be authorization context")
	}
}

func TestNextWebRequestOrigins(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
const g = globalThis as any;
export const prisma = g.prisma ?? new PrismaClient();`,
		"app/api/q/route.ts": `
import { NextRequest } from "next/server";
import { prisma } from "@/lib/prisma";
export async function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get("q");
  const ua = request.headers.get("User-Agent");
  return prisma.$queryRawUnsafe("SELECT * FROM p WHERE n = '" + q + "' OR ua = '" + ua + "'");
}
export async function POST(request: NextRequest) {
  const { name } = await request.json();
  await prisma.$queryRawUnsafe("SELECT * FROM p WHERE n = $1", name);
  await prisma.$queryRaw` + "`SELECT * FROM p WHERE n = ${name}`" + `;
  const headers = new Map();
  return prisma.$executeRawUnsafe("DELETE FROM p WHERE n = '" + headers.get("x") + "'");
}`,
	})
	r := analyzeNext(t, root)
	sql := usesOf(r, "sql_query_candidate", "app/api/q/route.ts")
	if len(sql) != 1 {
		t.Fatalf("only the interpolated GET query is SQL text: %d uses %+v", len(sql), sql)
	}
	got := strings.Join(origins(sql[0]), ",")
	if got != "http.query,http.headers" {
		t.Fatalf("origins %s", got)
	}
	if sql[0].APIModel == nil || sql[0].APIModel.ID != "prisma-raw-v1" {
		t.Fatalf("prisma contract %+v", sql[0].APIModel)
	}
	for _, v := range sql[0].InputFacts.Values {
		if v.Origin == "http.query" && v.InitialType != "string" {
			t.Fatalf("searchParams.get initial type %q", v.InitialType)
		}
	}
	if e := entryNamed(r, "POST /api/q"); e == nil || hasNextGap(e.Gaps, "async_response_unresolved") {
		t.Fatalf("await request.json() is a modeled transfer: %+v", e)
	}
}

func TestNextTSConfigPaths(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"tsconfig.json":      `{"extends": "./tsconfig.base.json"}`,
		"tsconfig.base.json": `{"compilerOptions": {"baseUrl": ".", "paths": {"@/*": ["src/*"], "~lib/*": ["lib/*"]}}}`,
		"src/util.ts":        `export function runIt(x) { return x; }`,
		"lib/util.ts":        `export function wrong(x) { return x; }`,
		"app/a.ts":           `import { runIt } from "@/util"; import { wrong } from "@/missing";`,
	})
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	set := &moduleSet{root: root, parsers: ps, modules: map[string]*sourceModule{}, allowed: map[string]bool{"src/util.ts": true, "lib/util.ts": true, "app/a.ts": true}}
	defer set.close()
	m, err := set.load("app/a.ts")
	if err != nil {
		t.Fatal(err)
	}
	if target, fn := set.resolve(m, "runIt"); target == nil || fn == nil || target.file != "src/util.ts" {
		t.Fatalf("@/util through extends + baseUrl paths: %v", target)
	}
	if target, _ := set.resolve(m, "wrong"); target != nil {
		t.Fatalf("a mismatched alias must resolve to nothing, got %s", target.file)
	}
}

func TestNextValidationLoggingAndSSRF(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/logger.ts": `import pino from "pino";
export const logger = pino({ redact: ["password"] });`,
		"lib/validation.ts": `
import { z } from "zod";
export async function parseBody(request, schema) {
  const text = await request.text();
  const raw = JSON.parse(text);
  const result = schema.safeParse(raw);
  if (!result.success) { return { success: false, response: null }; }
  return { success: true, data: result.data };
}
export { z };`,
		"lib/schemas.ts": `import { z } from "zod";
export const bodySchema = z.object({ url: z.string(), password: z.string() });`,
		"app/api/s/route.ts": `
import { NextResponse } from "next/server";
import { parseBody } from "@/lib/validation";
import { bodySchema } from "@/lib/schemas";
import { logger } from "@/lib/logger";
export async function POST(request: Request) {
  const parsed = await parseBody(request, bodySchema);
  if (!parsed.success) return parsed.response;
  const { url, password } = parsed.data;
  logger.warn({ password }, ` + "`login password=${password}`" + `);
  const res = await fetch(url);
  const base = process.env.API_BASE;
  await fetch(` + "`${base}/items/${url}`" + `);
  return NextResponse.json({ body: await res.text() });
}`,
		"app/c/Client.tsx": `"use client";
export function Client() {
  const go = async (u: string) => { await fetch(u); };
  return null;
}`,
	})
	r := analyzeNext(t, root)
	ssrf := usesOf(r, "ssrf_candidate", "")
	if len(ssrf) != 1 || ssrf[0].Sink.Span.File != "app/api/s/route.ts" {
		t.Fatalf("one server SSRF; a fixed-origin path and client fetch are not SSRF: %+v", ssrf)
	}
	if b := blockers(ssrf[0]); len(b) != 0 {
		t.Fatalf("SSRF through a verified zod helper must be complete: %+v", b)
	}
	if o := origins(ssrf[0]); len(o) != 1 || o[0] != "http.body" {
		t.Fatalf("body origin through parseBody: %v", o)
	}
	internal := false
	for _, u := range usesOf(r, "outbound_http_candidate", "app/api/s/route.ts") {
		internal = internal || hasNextGap(u.Gaps, "request_path_in_internal_url")
	}
	if !internal {
		t.Fatal("fixed origin with a request path must be a request_path_in_internal_url observation")
	}
	schema := false
	for _, e := range ssrf[0].Context {
		schema = schema || (e.Kind == "validation_schema" && strings.Contains(e.Text, "bodySchema"))
	}
	if !schema {
		t.Fatal("the zod schema definition must be supplied as validation evidence")
	}
	if logs := usesOf(r, "log_sink_candidate", "app/api/s/route.ts"); len(logs) != 1 {
		t.Fatalf("pino warn logs the password: %+v", logs)
	}
}

func TestNextClientComponents(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/api.ts": `
async function apiRequest(endpoint, options = {}) {
  const res = await fetch(endpoint, options);
  return res.json();
}
export const api = {
  get: (endpoint, options) => apiRequest(endpoint, { ...options, method: "GET" }),
};`,
		"app/api/reviews/route.ts": `
import { NextResponse } from "next/server";
export async function GET(request) { return NextResponse.json([]); }
export async function POST(request) { return new Response("x"); }`,
		"app/login/Form.tsx": `"use client";
import { useState, useEffect, useRef } from "react";
import { useSearchParams } from "next/navigation";
import { api } from "@/lib/api";
export default function Form() {
  const params = useSearchParams();
  const next = params.get("next");
  const q = params.get("q");
  const [items, setItems] = useState([]);
  const refs = useRef<Record<string, HTMLDivElement | null>>({});
  useEffect(() => {
    api.get("/api/reviews").then(() => {});
  }, []);
  useEffect(() => {
    const load = async () => { const data = await api.get("/api/reviews"); setItems(data); };
    load();
  }, []);
  useEffect(() => {
    items.forEach((item) => { const el = refs.current[item.id]; if (el) { el.innerHTML = item.body; } });
  }, [items]);
  const submit = () => {
    window.location.href = next;
    window.location.href = "/" + encodeURIComponent(q);
  };
  return <div><h1>{q}</h1><input value={q} /></div>;
}`,
	})
	r := analyzeNext(t, root)
	var urlSinks, htmlSinks []analysis.CandidateUse
	for _, u := range usesOf(r, "xss_candidate", "app/login/Form.tsx") {
		switch u.XSS.OutputContext {
		case "url":
			urlSinks = append(urlSinks, u)
		case "html_text":
			htmlSinks = append(htmlSinks, u)
		}
	}
	if len(urlSinks) == 0 || !strings.Contains(urlSinks[0].Sink.Text, "location.href = next") {
		t.Fatalf("location.href from useSearchParams must be a url sink: %+v", urlSinks)
	}
	for _, u := range htmlSinks {
		if !strings.Contains(u.Sink.Text, "innerHTML") {
			t.Errorf("React-encoded JSX text or attributes produced a record: %s", u.Sink.Text)
		}
	}
	if len(htmlSinks) != 1 || htmlSinks[0].XSS.ResponsePath != "/api/reviews" {
		t.Fatalf("ref innerHTML from fetched state must link to /api/reviews: %+v", htmlSinks)
	}
	foundRedirect := false
	for _, p := range r.Practice {
		foundRedirect = foundRedirect || p.Check == "NX-BP-10"
	}
	if !foundRedirect {
		t.Fatal("open redirect practice observation missing")
	}
}

func TestNextPagesMiddlewareAndActions(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"middleware.ts": `
import { NextResponse } from "next/server";
export function middleware(request) {
  if (!request.cookies.get("t")) return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}
export const config = { matcher: ["/admin/:path*"] };`,
		"app/admin/settings/page.tsx": `
export default function Page() { return <p>ok</p>; }`,
		"app/api/admin/route.ts": `export async function GET() { return new Response("x"); }`,
		"app/view/[id]/page.tsx": `
import { redirect } from "next/navigation";
import fs from "fs";
export default async function View({ params, searchParams }) {
  const { id } = await params;
  const sp = await searchParams;
  if (id === "bad") { redirect("/"); }
  const text = fs.readFileSync("/data/" + id, "utf8");
  return <div><h1>{sp.q}</h1><div dangerouslySetInnerHTML={{ __html: sp.html }} /></div>;
}`,
		"app/actions.ts": `"use server";
import Database from "better-sqlite3";
export async function rename(id: number, name: string) {
  const db = new Database("x.db");
  db.exec("UPDATE t SET name = '" + name + "' WHERE id = " + id);
}`,
	})
	r := analyzeNext(t, root)
	staged := map[string]bool{}
	ents := map[string]string{}
	for _, e := range r.Entries {
		ents[e.ID] = e.Name
	}
	for _, c := range r.InvocationContexts {
		for _, ctl := range c.Controls {
			if ctl.Evidence.Kind == "middleware_handler" {
				staged[ents[c.EntryID]] = true
			}
		}
	}
	if !staged["GET /admin/settings"] || staged["GET /api/admin"] || staged["GET /view/:id"] {
		t.Fatalf("middleware stage must follow the matcher only: %v", staged)
	}
	if paths := usesOf(r, "path_traversal_candidate", "app/view/[id]/page.tsx"); len(paths) != 1 || origins(paths[0])[0] != "http.path" {
		t.Fatalf("page params reach a path sink: %+v", paths)
	}
	xss := usesOf(r, "xss_candidate", "app/view/[id]/page.tsx")
	if len(xss) != 1 || !strings.Contains(xss[0].Sink.Text, "dangerouslySetInnerHTML") {
		t.Fatalf("only the raw-HTML sink records in a Server Component, never JSX text: %+v", xss)
	}
	action := usesOf(r, "sql_query_candidate", "app/actions.ts")
	if len(action) != 1 {
		t.Fatalf("server action arguments are request data: %+v", action)
	}
	for _, o := range origins(action[0]) {
		if o != "http.body" {
			t.Fatalf("TypeScript-typed action arguments are still http.body: %v", origins(action[0]))
		}
	}
	found := false
	for _, e := range r.Entries {
		found = found || (e.HTTP != nil && e.HTTP.Surface == "server_action" && hasNextGap(e.Gaps, "next_action_path_dynamic"))
	}
	if !found {
		t.Fatal("server action entry with dynamic path gap missing")
	}
}

func TestNextNavigationExitIsVerified(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"app/p/page.tsx": `
import fs from "fs";
function redirect(x) { return x; }
export default async function P({ searchParams }) {
  const sp = await searchParams;
  if (sp.f) { redirect("/"); }
  return <pre>{fs.readFileSync(sp.f)}</pre>;
}`,
	})
	r := analyzeNext(t, root)
	if len(usesOf(r, "path_traversal_candidate", "app/p/page.tsx")) != 1 {
		t.Fatal("a local function named redirect is not an exit; the sink stays reachable")
	}
}

func TestNextClientCallsAreNotRoutes(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"app/c/Cart.tsx": `"use client";
import axios from "axios";
import { api } from "@/lib/api";
export function Cart() { api.post("/api/cart/add", { id: 1 }); axios.post("/api/x", { a: 1 }); return null; }`,
		"app/api/cart/add/route.ts": `export async function POST(request) { return new Response("x"); }`,
		"next.config.mjs":           `export default { rewrites: async () => [{ source: "/.git/:path*", destination: "/api/cart/:path*" }] };`,
	})
	inv, err := routeInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Routes) != 1 || inv.Routes[0].Framework != "nextjs" || inv.Routes[0].PathPattern != "/api/cart/add" {
		t.Fatalf("client calls must not be routes: %+v", inv.Routes)
	}
	r := analyzeNext(t, root)
	rewrite := false
	for _, p := range r.Practice {
		rewrite = rewrite || p.Check == "NX-BP-08"
	}
	versions := false
	for _, p := range r.Practice {
		versions = versions || p.Check == "NX-BP-03"
	}
	if !rewrite || !versions {
		t.Fatalf("rewrite and version practice observations: %+v", r.Practice)
	}
}

func TestParseRecoveryKeepsSpans(t *testing.T) {
	ps, err := newParsers()
	if err != nil {
		t.Fatal(err)
	}
	defer ps.close()
	for _, c := range []struct{ file, src string }{
		{"a.tsx", `export default function A() { return <h3>Supply Chain & Insecure Design</h3>; }`},
		{"b.tsx", `export default function B() { return <a href="https://x.test/?q=1&type=code">x</a>; }`},
		{"c.ts", "export const f = async () => { const r = await prisma.$queryRaw<{ a: string; b: number }[]>`SELECT 1`; return r; };"},
	} {
		tree, steps := parseRecovered(ps.forPath(c.file), []byte(c.src))
		if tree.RootNode().HasError() || len(steps) == 0 {
			t.Errorf("%s: not recovered (steps %v)", c.file, steps)
		}
		if int(tree.RootNode().EndByte()) != len(c.src) {
			t.Errorf("%s: span length changed", c.file)
		}
	}
}

func TestNextUploadFilenameSanitizer(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"app/api/up/route.ts": `
import { writeFile } from "fs/promises";
import { join } from "path";
export async function POST(request: Request) {
  const form = await request.formData();
  const file = form.get("f") as File;
  const safe = file.name.replace(/[^a-zA-Z0-9.-]/g, "_");
  await writeFile(join("/up", safe), Buffer.from(await file.arrayBuffer()));
  const keep = file.name.replace(/[^a-zA-Z0-9./-]/g, "_");
  await writeFile(join("/up", keep), "x");
}`,
	})
	r := analyzeNext(t, root)
	uses := usesOf(r, "path_traversal_candidate", "app/api/up/route.ts")
	if len(uses) != 2 {
		t.Fatalf("two upload writes: %d", len(uses))
	}
	for _, u := range uses {
		sanitized := false
		for _, g := range u.Path.Guards {
			sanitized = sanitized || g.Kind == analysis.PathGuardComponentSanitizer
		}
		want := !strings.Contains(u.Sink.Text, "keep")
		if sanitized != want {
			t.Errorf("%s: component sanitizer %v, want %v (a class that keeps / is not one)", u.Sink.Text, sanitized, want)
		}
	}
}

func TestNextStoredAndFetchedXSSLinks(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/prisma.ts": `import { PrismaClient } from "@prisma/client";
export const prisma = new PrismaClient();`,
		"lib/api.ts": `
async function apiRequest(endpoint, options = {}) { const r = await fetch(endpoint, options); return r.json(); }
export const api = {
  get: (endpoint, options) => apiRequest(endpoint, { ...options, method: "GET" }),
  post: (endpoint, body, options) => apiRequest(endpoint, { ...options, method: "POST", body }),
};`,
		"app/api/notes/route.ts": `
import { NextResponse } from "next/server";
import { prisma } from "@/lib/prisma";
export async function POST(request: Request) {
  const { body } = await request.json();
  await prisma.note.create({ data: { body } });
  return NextResponse.json({ ok: true });
}
export async function GET(request: Request) {
  const notes = await prisma.note.findMany();
  return NextResponse.json(notes);
}`,
		"app/api/preview/route.ts": `
import { NextResponse } from "next/server";
export async function POST(request: Request) {
  const { url } = await request.json();
  const res = await fetch(url);
  const html = await res.text();
  return NextResponse.json({ data: { html } });
}`,
		"app/n/Notes.tsx": `"use client";
import { useState, useEffect } from "react";
import { api } from "@/lib/api";
export default function Notes() {
  const [notes, setNotes] = useState([]);
  const [preview, setPreview] = useState(null);
  useEffect(() => { const load = async () => { const d = await api.get("/api/notes"); setNotes(d); }; load(); }, []);
  const show = async () => { const r = await api.post("/api/preview", { url: "x" }); setPreview(r.data); };
  return <div>{notes.map((n) => <p key={n.id} dangerouslySetInnerHTML={{ __html: n.body }} />)}
    <div dangerouslySetInnerHTML={{ __html: preview.html }} /></div>;
}`,
	})
	r := analyzeNext(t, root)
	xss := usesOf(r, "xss_candidate", "app/n/Notes.tsx")
	if len(xss) != 2 {
		t.Fatalf("two client raw-HTML sinks: %+v", xss)
	}
	for _, u := range xss {
		if !u.XSS.OriginResolved || len(blockers(u)) != 0 {
			t.Errorf("%s: link must be complete (resolved %v, blockers %+v)", u.Sink.Text, u.XSS.OriginResolved, blockers(u))
		}
		facts := strings.Join(u.Completeness.ModelFacts, "\n")
		if strings.Contains(u.Sink.Text, "preview") != strings.Contains(facts, "xss_via_fetched_content") {
			t.Errorf("%s: fetched-content fact %q", u.Sink.Text, facts)
		}
	}
}

func TestNextPagesRouterAPI(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"lib/logger.ts": `import pino from "pino";
export const logger = pino();`,
		"pages/api/users/[id].ts": `
import type { NextApiRequest, NextApiResponse } from "next";
import Database from "better-sqlite3";
import { logger } from "../../../lib/logger";
export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const db = new Database("app.db");
  if (req.method === "POST") {
    logger.info({ password: req.body.password }, "update");
    return res.status(200).json({ ok: true });
  }
  const rows = db.prepare("SELECT * FROM users WHERE id = '" + req.query.id + "'").all();
  res.status(200).json(rows);
}`,
		"pages/api/index.ts": `
import fs from "fs";
export default async function handler(req, res) {
  res.send(fs.readFileSync("/data/" + req.cookies.file));
}`,
		"pages/about.tsx": `export default function About() { return <p>about</p>; }`,
	})
	r := analyzeNext(t, root)
	for _, name := range []string{"ALL /api/users/:id", "ALL /api"} {
		e := entryNamed(r, name)
		if e == nil || e.HTTP.Framework != "nextjs-pages" || e.HTTP.Router != "pages" || e.HTTP.Surface != "api_route" {
			t.Fatalf("Pages Router entry %s: %+v", name, e)
		}
	}
	for _, e := range r.Entries {
		if strings.Contains(e.Location.Span.File, "about") {
			t.Errorf("a Pages Router page is not an API entry: %s", e.Name)
		}
	}
	sql := usesOf(r, "sql_query_candidate", "pages/api/users/[id].ts")
	if len(sql) != 1 || sql[0].APIModel == nil || sql[0].APIModel.ID != "better-sqlite3-v1" {
		t.Fatalf("req.query.id reaches better-sqlite3 prepare: %+v", sql)
	}
	if o := origins(sql[0]); len(o) != 1 || o[0] != "http.query" {
		t.Fatalf("Express-shaped req.query origin: %v", o)
	}
	if b := blockers(sql[0]); len(b) != 0 {
		t.Fatalf("complete evidence expected: %+v", b)
	}
	if logs := usesOf(r, "log_sink_candidate", "pages/api/users/[id].ts"); len(logs) != 1 || origins(logs[0])[0] != "http.body" {
		t.Fatalf("req.body.password logged through pino: %+v", logs)
	}
	paths := usesOf(r, "path_traversal_candidate", "pages/api/index.ts")
	if len(paths) != 1 || origins(paths[0])[0] != "http.cookies" {
		t.Fatalf("req.cookies reaches readFileSync: %+v", paths)
	}
	inv, err := routeInventory(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inv.Routes) != 2 {
		t.Fatalf("--routes lists both API routes: %+v", inv.Routes)
	}
}

// TestNextPagesServerSidePropsAndPGlite covers the Pages Router page entry
// (getServerSideProps props reaching the component's raw HTML), a CommonJS
// multi-argument handler factory, the PGlite contract and client provenance,
// a direct zod parse, PGlite raw-SQL stored links and script-context JSON.
func TestNextPagesServerSidePropsAndPGlite(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"package.json": `{"dependencies":{"next":"13.4.19","react":"18.2.0","@electric-sql/pglite":"0.5.16","zod":"4.6.7"}}`,
		"lib/database.cjs": `const { PGlite } = require('@electric-sql/pglite');
async function seed(db) { await db.query('INSERT INTO users (name) VALUES ($1)', ['admin']); }
async function createDatabase() { const db = await PGlite.create(); await seed(db); return db; }
function getDatabase() {
  if (!globalThis.__db) { globalThis.__db = createDatabase().catch((e) => { delete globalThis.__db; throw e; }); }
  return globalThis.__db;
}
module.exports = { getDatabase };`,
		"lib/http.cjs": `function endpoint(methods, run, { discloseErrors = false } = {}) {
  return async function handler(req, res) {
    if (!methods.includes(req.method)) return res.status(405).end();
    try { return await run(req, res); } catch (error) { return res.status(500).json({ error: 'failed' }); }
  };
}
module.exports = { endpoint };`,
		"pages/api/notes.js": `import { z } from 'zod';
import database from '../../lib/database.cjs';
import http from '../../lib/http.cjs';
const { getDatabase } = database;
const { endpoint } = http;
const Note = z.object({ body: z.string().min(1) });
export default endpoint(['GET', 'POST'], async (req, res) => {
  const db = await getDatabase();
  if (req.method === 'GET') {
    const { rows } = await db.query('SELECT id, body FROM notes ORDER BY id');
    return res.status(200).json({ notes: rows });
  }
  const parsed = Note.safeParse(req.body ?? {});
  if (!parsed.success) return res.status(400).json({ error: 'bad' });
  await db.query('INSERT INTO notes (body) VALUES ($1)', [parsed.data.body]);
  return res.status(201).json({ ok: true });
});`,
		"pages/api/search.js": `import database from '../../lib/database.cjs';
import http from '../../lib/http.cjs';
export default http.endpoint(['GET'], async (req, res) => {
  const db = await database.getDatabase();
  const results = await db.exec("SELECT * FROM notes WHERE body LIKE '%" + req.query.q + "%'");
  return res.status(200).json({ results });
});`,
		"pages/notes.js": `import database from '../lib/database.cjs';
export default function Notes({ notes }) {
  return <ul>{notes.map((note) => <li key={note.id} dangerouslySetInnerHTML={{ __html: note.body }} />)}</ul>;
}
export async function getServerSideProps() {
  const db = await database.getDatabase();
  const { rows } = await db.query('SELECT id, body FROM notes ORDER BY id');
  return { props: { notes: JSON.parse(JSON.stringify(rows)) } };
}`,
		"pages/echo.js": `import { useState } from 'react';
function embed(value) { return JSON.stringify(value).replace(/</g, '\\u003c'); }
export default function Echo({ payload, data }) {
  const [draft] = useState(payload);
  return <div>
    <p>{draft}</p>
    <div dangerouslySetInnerHTML={{ __html: payload }} />
    <script dangerouslySetInnerHTML={{ __html: "window.a = " + JSON.stringify({ data }) }} />
    <script dangerouslySetInnerHTML={{ __html: "window.b = " + embed({ data }) }} />
  </div>;
}
export function getServerSideProps({ query }) {
  const payload = typeof query.payload === 'string' ? query.payload : 'hi';
  return { props: { payload, data: query.data ?? '' } };
}`,
	})
	r := analyzeNext(t, root)
	if e := entryNamed(r, "GET /echo"); e == nil || e.HTTP.Router != "pages" || e.HTTP.Surface != "page" {
		t.Fatalf("getServerSideProps page entry: %+v", e)
	}
	if entryNamed(r, "GET /notes") == nil {
		t.Fatal("no GET /notes page entry")
	}
	sql := usesOf(r, "sql_query_candidate", "")
	contracts := map[string]int{}
	for _, u := range sql {
		if u.Sink.Span.File == "lib/database.cjs" {
			t.Errorf("seed query reached from a request: %s:%d", u.Sink.Span.File, u.Sink.Span.StartLine)
		}
		if u.APIModel != nil {
			contracts[u.Sink.Span.File+":"+u.APIModel.ID]++
		}
		if len(blockers(u)) > 0 {
			t.Errorf("%s:%d blockers %+v", u.Sink.Span.File, u.Sink.Span.StartLine, blockers(u))
		}
	}
	if contracts["pages/api/search.js:pglite-v1"] == 0 || contracts["pages/api/notes.js:pglite-v1"] == 0 {
		t.Errorf("pglite-v1 contracts: %v", contracts)
	}
	byLine := map[int]analysis.CandidateUse{}
	for _, u := range usesOf(r, "xss_candidate", "pages/echo.js") {
		byLine[u.Sink.Span.StartLine] = u
	}
	if len(byLine) != 3 {
		t.Fatalf("echo XSS records (React text must not record) = %d", len(byLine))
	}
	for line, want := range map[int]string{7: "raw", 8: "raw", 9: "sanitized"} {
		if u, ok := byLine[line]; !ok || u.XSS == nil || u.XSS.Protection != want {
			t.Errorf("echo.js:%d protection %+v, want %s", line, u.XSS, want)
		}
	}
	stored := usesOf(r, "xss_candidate", "pages/notes.js")
	if len(stored) != 1 || !stored[0].XSS.OriginResolved || len(stored[0].Dependencies) == 0 || stored[0].Dependencies[0].Source.Span.File != "pages/api/notes.js" {
		t.Fatalf("stored notes link: %+v", stored)
	}
}
