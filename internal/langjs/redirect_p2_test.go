package langjs

import (
	"strings"
	"testing"
)

func p2Redirects(t *testing.T, files map[string]string) map[string]int {
	t.Helper()
	r := analyzeNext(t, nextRepo(t, files))
	out := map[string]int{}
	for _, u := range usesOf(r, "open_redirect_candidate", "") {
		out[u.Sink.Span.File]++
	}
	return out
}

// S5: a destination whose origin is fixed by construction is excluded; every
// sibling with a raw, mutable or ambiguous operand stays a candidate.
func TestP2RedirectFixedOrigin(t *testing.T) {
	files := map[string]string{
		// genuine safe controls
		"app/api/vcs/[[...path]]/route.ts": `import { NextResponse } from 'next/server';
const PUBLIC_ROOT = "/.git/";
export async function GET(request: Request, { params }: { params: Promise<{ path?: string[] }> }) {
  const directory = (await params).path?.join('/') ?? '';
  return NextResponse.redirect(new URL(` + "`${PUBLIC_ROOT}${directory}`" + `, request.url), 301);
}`,
		"app/checkout/CheckoutClient.tsx": `"use client";
import { useRouter } from 'next/navigation';
export default function C({ order }: any) {
  const router = useRouter();
  async function pay() {
    const res = await fetch('/api/pay', { method: 'POST' });
    const order = await res.json();
    const url = order.flag ? ` + "`/order?id=${order.id}&flag=${order.flag}`" + ` : ` + "`/order?id=${order.id}`" + `;
    router.push(url);
  }
  return <button onClick={pay}>pay</button>;
}`,
		// siblings: all must remain candidates
		"app/api/raw-branch/route.ts": `import { NextResponse } from 'next/server';
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  const url = to ? to : '/home';
  return NextResponse.redirect(new URL(url, request.url));
}`,
		"app/api/double-slash/route.ts": `import { NextResponse } from 'next/server';
const ROOT = "//";
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/backslash/route.ts": `import { NextResponse } from 'next/server';
const ROOT = "/\\evil/";
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/let-root/route.ts": `import { NextResponse } from 'next/server';
let ROOT = "/.git/";
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/reassigned-root/route.ts": `import { NextResponse } from 'next/server';
let ROOT = "/.git/";
export function setRoot(v: string) { ROOT = v; }
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/env-root/route.ts": `import { NextResponse } from 'next/server';
const ROOT = process.env.ROOT_PATH;
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/raw-first/route.ts": `import { NextResponse } from 'next/server';
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(to, request.url));
}`,
		"app/api/empty-prefix/route.ts": `import { NextResponse } from 'next/server';
const ROOT = "";
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  return NextResponse.redirect(new URL(` + "`${ROOT}${to}`" + `, request.url));
}`,
		"app/api/ternary-one-raw/route.ts": `import { NextResponse } from 'next/server';
export async function GET(request: Request) {
  const to = new URL(request.url).searchParams.get('to') ?? '';
  const url = to ? ` + "`${to}`" + ` : ` + "`/home`" + `;
  return NextResponse.redirect(new URL(url, request.url));
}`,
	}
	got := p2Redirects(t, files)
	for _, safe := range []string{"app/api/vcs/[[...path]]/route.ts", "app/checkout/CheckoutClient.tsx"} {
		if got[safe] != 0 {
			t.Errorf("%s: fixed-origin destination must not be a candidate", safe)
		}
	}
	for file := range files {
		if strings.Contains(file, "vcs") || strings.Contains(file, "checkout") {
			continue
		}
		if got[file] == 0 {
			t.Errorf("%s: vulnerable sibling lost its candidate", file)
		}
	}
}

func p2Facts(t *testing.T, body string) ([]string, []string) {
	t.Helper()
	root := t.TempDir()
	writeSource(t, root, "package.json", `{"dependencies":{"express":"4.19.0"}}`)
	writeSource(t, root, "server.js", `const express=require('express');const app=express();app.get('/x',(req,res)=>{`+body+`;res.end()});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := usesOf(r, "open_redirect_candidate", "")
	if len(uses) != 1 || uses[0].Completeness == nil {
		t.Fatalf("want one redirect candidate for %q, got %d", body, len(uses))
	}
	prot := []string{}
	for _, p := range uses[0].CodePaths() {
		prot = append(prot, p.Protection)
	}
	return uses[0].Completeness.ModelFacts, prot
}

// S6: destination-normalization facts per validator predicate. A safe control
// records no bypass form; each sibling records the form its predicate permits,
// or is not guarded at all (reassignment, decoding or another operand).
func TestP2RedirectPredicateFacts(t *testing.T) {
	safe := "!(typeof to==='string' && to.startsWith('/') && !to.startsWith('//') && !to.includes('\\\\'))"
	for _, tt := range []struct {
		name, body string
		bypass     string // expected bypass forms; "" means none
		unguarded  bool   // the path must not be guarded
	}{
		{name: "relative control", body: `const to=req.query.to; if(` + safe + `) return; res.redirect(to)`},
		{name: "regex excluding slash and backslash", body: `const to=req.query.to; if(!/^\/[^/\\\\]/.test(to)) return; res.redirect(to)`},
		{name: "regex lookahead excluding both", body: `const to=req.query.to; if(!/^\/(?![\/\\\\])/.test(to)) return; res.redirect(to)`},
		{name: "parsed origin control", body: `const to=req.query.to; if(new URL(to,'https://site.example').origin!=='https://site.example') return; res.redirect(to)`},
		{name: "parsed url control", body: `const to=req.query.to; const u=new URL(to,'https://site.example'); if(u.origin!=='https://site.example') return; res.redirect(u.href)`},
		{name: "parsed host control", body: `const to=req.query.to; const u=new URL(to,'https://site.example'); if(u.host!=='site.example') return; res.redirect(to)`},
		{name: "lab regex permits backslash", body: `const to=req.query.to; if(!/^\/[^/]/.test(to)) return; res.redirect(to)`, bypass: "slash_backslash"},
		{name: "leading slash only", body: `const to=req.query.to; if(!to.startsWith('/')) return; res.redirect(to)`, bypass: "protocol_relative,slash_backslash"},
		{name: "no double-slash test", body: `const to=req.query.to; if(!(to.startsWith('/') && !to.includes('\\\\'))) return; res.redirect(to)`, bypass: "protocol_relative,slash_backslash"},
		{name: "no backslash test", body: `const to=req.query.to; if(!(to.startsWith('/') && !to.startsWith('//'))) return; res.redirect(to)`, bypass: "slash_backslash"},
		{name: "no leading slash", body: `const to=req.query.to; if(!(!to.startsWith('//') && !to.includes('\\\\'))) return; res.redirect(to)`, bypass: "absolute_url,backslash_prefix,slash_backslash"},
		{name: "origin prefix without slash", body: `const to=req.query.to; if(!to.startsWith('https://site.example')) return; res.redirect(to)`, bypass: "origin_prefix"},
		{name: "parsed origin against request value", body: `const to=req.query.to; if(new URL(to,'https://site.example').origin!==req.headers.origin) return; res.redirect(to)`, bypass: "parsed_origin_unfixed"},
		{name: "decode after check", body: `const to=req.query.to; if(` + safe + `) return; res.redirect(decodeURIComponent(to))`, unguarded: true},
		{name: "decode assignment after check", body: `let to=req.query.to; if(` + safe + `) return; to=decodeURIComponent(to); res.redirect(to)`, unguarded: true},
		{name: "reassigned after check", body: `let to=req.query.to; if(` + safe + `) return; to=req.query.other; res.redirect(to)`, unguarded: true},
		{name: "check one variable redirect another", body: `const a=req.query.a, b=req.query.b; if(!(a.startsWith('/') && !a.startsWith('//') && !a.includes('\\\\'))) return; res.redirect(b)`, unguarded: true},
		{name: "parsed check one variable redirect another", body: `const a=req.query.a, b=req.query.b; if(new URL(a,'https://site.example').origin!=='https://site.example') return; res.redirect(b)`, unguarded: true},
		{name: "parsed check then reassigned", body: `let to=req.query.to; if(new URL(to,'https://site.example').origin!=='https://site.example') return; to=req.query.o; res.redirect(to)`, unguarded: true},
		{name: "parsed check then decoded", body: `const to=req.query.to; if(new URL(to,'https://site.example').origin!=='https://site.example') return; res.redirect(decodeURIComponent(to))`, unguarded: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			facts, prot := p2Facts(t, tt.body)
			got := ""
			for _, f := range facts {
				if strings.HasPrefix(f, "redirect_predicate_bypass: ") {
					got = strings.TrimPrefix(f, "redirect_predicate_bypass: ")
				}
			}
			if got != tt.bypass {
				t.Errorf("bypass forms %q, want %q (facts %q)", got, tt.bypass, facts)
			}
			guarded := len(prot) > 0
			for _, p := range prot {
				guarded = guarded && p == "guarded"
			}
			if tt.unguarded && guarded {
				t.Errorf("vulnerable sibling is guarded (facts %q)", facts)
			}
			if !tt.unguarded && !guarded {
				t.Errorf("control is not guarded: %v", prot)
			}
		})
	}
}
