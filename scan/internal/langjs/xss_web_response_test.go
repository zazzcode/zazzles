package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// TestWebResponseHTMLSink covers a Fetch Response or NextResponse whose init
// sets an HTML Content-Type (phase 5, OOPS-XSS-R01). Only an explicit HTML type
// makes the body HTML; the Fetch default for a string body is text/plain, so
// non-HTML and omitted types stay silent. An init or header value that is not a
// closed literal stays an unresolved candidate.
func TestWebResponseHTMLSink(t *testing.T) {
	route := func(imports, body string) string {
		return imports + `
export async function GET(request: Request) {
  const q = new URL(request.url).searchParams.get('q') ?? '';
` + body + `
}`
	}
	next := `import { NextResponse } from 'next/server';`
	html := "`<h1>${q}</h1>`"
	tests := []struct {
		name, file, src string
		want            string // "raw", "unknown" or "" for no xss_candidate
	}{
		{"next response html", "app/api/a/route.ts", route(next, `  return new NextResponse(`+html+`, { headers: { "Content-Type": "text/html; charset=utf-8" } });`), "raw"},
		{"fetch response html", "app/api/b/route.ts", route("", `  return new Response(`+html+`, { status: 200, headers: { 'content-type': 'text/html' } });`), "raw"},
		{"helper renders listing", "app/api/vcs/[[...path]]/route.ts", next + `
function renderListing(directory: string) {
  return ` + "`<html><head><title>Index of ${directory}</title></head></html>`" + `;
}
export async function GET(request: Request, { params }: { params: Promise<{ path?: string[] }> }) {
  const { path = [] } = await params;
  const directory = path.join('/');
  return new NextResponse(renderListing(directory), { headers: { "Content-Type": "text/html" } });
}`, "raw"},
		{"json type", "app/api/c/route.ts", route(next, `  return new NextResponse(`+html+`, { headers: { "Content-Type": "application/json" } });`), ""},
		{"plain type", "app/api/d/route.ts", route("", `  return new Response(`+html+`, { headers: { "Content-Type": "text/plain; charset=utf-8" } });`), ""},
		{"headers object non-html", "app/api/e/route.ts", route("", `  return new Response(`+html+`, { headers: new Headers({ "Content-Type": "text/csv" }) });`), ""},
		{"no init defaults to text plain", "app/api/f/route.ts", route("", `  return new Response(`+html+`);`), ""},
		{"init without content type", "app/api/g/route.ts", route("", `  return new Response(`+html+`, { status: 404 });`), ""},
		{"headers variable", "app/api/h/route.ts", route(next, `  const headers = { "Content-Type": request.headers.get('accept') ?? 'text/html' };
  return new NextResponse(`+html+`, { headers });`), "unknown"},
		{"spread after type", "app/api/i/route.ts", route("", `  const extra = Object.fromEntries(new URL(request.url).searchParams);
  return new Response(`+html+`, { headers: { "Content-Type": "text/plain", ...extra } });`), "unknown"},
		{"non literal type", "app/api/j/route.ts", route("", `  const type = new URL(request.url).searchParams.get('t') ?? 'text/html';
  return new Response(`+html+`, { headers: { "Content-Type": type } });`), "unknown"},
		{"xhtml type", "app/api/m/route.ts", route("", `  return new Response(`+html+`, { headers: { "Content-Type": "application/xhtml+xml" } });`), "raw"},
		{"comment before body", "app/api/n/route.ts", route("", `  return new Response(/* body */ `+html+`, { headers: { "Content-Type": "text/html" } });`), "raw"},
		{"init spread after headers", "app/api/o/route.ts", route("", `  const init = { headers: { "Content-Type": "text/html" } };
  return new Response(`+html+`, { headers: { "Content-Type": "text/plain" }, ...init });`), "unknown"},
		{"init spread before headers", "app/api/p/route.ts", route("", `  const init = { status: 200 };
  return new Response(`+html+`, { ...init, headers: { "Content-Type": "text/plain" } });`), ""},
		{"shorthand header without type", "app/api/q/route.ts", route("", `  const etag = '"v1"';
  return new Response(`+html+`, { headers: { etag } });`), ""},
		{"shadowed next response", "app/api/r/route.ts", route(next, `  const NextResponse = function (b: string, i: any) { return { b, i }; };
  return new NextResponse(`+html+`, { headers: { "Content-Type": "text/html" } });`), ""},
		{"next response not from next server", "app/api/k/route.ts", route(`import { NextResponse } from './response';`, `  return new NextResponse(`+html+`, { headers: { "Content-Type": "text/html" } });`), ""},
		{"locally bound response", "app/api/l/route.ts", route(`class Response { constructor(public body: string, public init: any) {} }`, `  return new Response(`+html+`, { headers: { "Content-Type": "text/html" } });`), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeNext(t, nextRepo(t, map[string]string{tt.file: tt.src}))
			uses := usesOf(r, "xss_candidate", tt.file)
			if tt.want == "" {
				if len(uses) != 0 {
					t.Fatalf("want no xss_candidate, got %d (%+v)", len(uses), uses[0].XSS)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("want one xss_candidate, got %d", len(uses))
			}
			u := uses[0]
			if u.XSS == nil || u.XSS.Protection != tt.want || u.Sink.Kind != "html_response" {
				t.Fatalf("protection/sink = %+v %s, want %s html_response", u.XSS, u.Sink.Kind, tt.want)
			}
			if len(u.Dependencies) == 0 || u.Dependencies[0].Source.Kind != "input_source" {
				t.Fatalf("missing request source: %+v", u.Dependencies)
			}
			if _, err := analysispacks.Select(u); err != nil {
				t.Fatalf("judge selection rejects the record: %v", err)
			}
			b := blockers(u)
			if tt.want == "raw" && len(b) != 0 {
				t.Fatalf("raw HTML response has blockers %+v", b)
			}
			if tt.want == "unknown" && (len(b) == 0 || b[0].Kind != "render_protection_unresolved") {
				t.Fatalf("unresolved content type must block a decisive claim, got %+v", b)
			}
		})
	}
}

// TestDestructuringDefaultProjection binds `{ name = fallback }` to the
// projected property, keeping the request source (phase 5, the OOPS-XSS-R01
// `{ path = [] } = await params` hop). An aliased default stays an explicit gap.
func TestDestructuringDefaultProjection(t *testing.T) {
	tests := []struct {
		name, body string
		source     bool
	}{
		{"express shorthand default", "const { name = 'guest' } = req.query; res.send(`<h1>${name}</h1>`);", true},
		{"fallback keeps its own source", "const { name = req.query.alt } = {}; res.send(`<h1>${name}</h1>`);", true},
		{"constant object default", "const { name = 'guest' } = { other: 1 }; res.send(`<h1>${name}</h1>`);", false},
		{"aliased default stays a gap", "const { name: n = 'guest' } = req.query; res.send(`<h1>${n}</h1>`);", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file, src := conditionalHandler("js", "", tt.body)
			r := conditionalReport(t, file, src)
			uses := usesOfKind(r, "xss_candidate")
			if !tt.source {
				if len(uses) != 0 {
					t.Fatalf("want no xss_candidate, got %+v", uses[0].Dependencies)
				}
				if tt.name == "aliased default stays a gap" && !anyGap(r, "unsupported_binding") {
					t.Fatal("aliased default must keep its unsupported_binding gap")
				}
				return
			}
			if len(uses) != 1 || len(uses[0].Dependencies) == 0 || uses[0].Dependencies[0].Source.Kind != "input_source" || uses[0].XSS.Protection != "raw" {
				t.Fatalf("want one raw xss_candidate from the request, got %+v", uses)
			}
		})
	}
	nextFile := "app/api/vcs/[[...path]]/route.ts"
	r := analyzeNext(t, nextRepo(t, map[string]string{nextFile: `import { NextResponse } from 'next/server';
export async function GET(request: Request, { params }: { params: Promise<{ path?: string[] }> }) {
  const { path = [] } = await params;
  return NextResponse.json({ found: path.join('/') });
}`}))
	if uses := usesOf(r, "xss_data_candidate", nextFile); len(uses) == 0 && len(usesOf(r, "input_validation_candidate", nextFile)) == 0 {
		t.Fatal("awaited params default lost its route-parameter source")
	}
}

func anyGap(r *analysis.AnalysisReport, kind string) bool {
	for _, u := range r.Uses {
		for _, g := range u.Gaps {
			if g.Kind == kind {
				return true
			}
		}
	}
	for _, g := range r.Gaps {
		if g.Kind == kind {
			return true
		}
	}
	return false
}
