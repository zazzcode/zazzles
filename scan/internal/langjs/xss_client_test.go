package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestBrowserSourceSinkControls(t *testing.T) {
	tests := []struct{ name, source, protection, context string }{
		{"DOM HTML", "const el=document.getElementById('result');el.innerHTML=location.search", "raw", "html_text"},
		{"DOM text", "const el=document.querySelector('#result');el.textContent=location.hash", "encoded", "html_text"},
		{"URL parameters", "const p=new URLSearchParams(location.search);document.body.innerHTML=p.get('q')", "raw", "html_text"},
		{"document write", "document.write(location.hash)", "raw", "html_text"},
		{"HTML fragment", "const r=document.createRange();r.createContextualFragment(location.hash)", "raw", "html_text"},
		{"adjacent HTML", "document.body.insertAdjacentHTML('beforeend',location.hash)", "raw", "html_text"},
		{"URL sink", "const link=document.querySelector('a');link.href=location.hash", "raw", "url"},
		{"string timer", "setTimeout(location.hash,1)", "raw", "script"},
		{"function constructor", "new Function(location.hash)", "raw", "script"},
		{"message event", "const el=document.querySelector('#x');window.addEventListener('message',(message)=>{el.innerHTML=message.data})", "raw", "html_text"},
		{"sanitized HTML", "import DOMPurify from 'dompurify';document.body.innerHTML=DOMPurify.sanitize(location.hash)", "sanitized", "html_text"},
		{"fake document", "const document={write:x=>x};document.write(location.hash)", "", ""},
		{"shadowed location", "function run(location){document.body.innerHTML=location.hash}", "", ""},
		{"fake DOM object", "const el={innerHTML:''};el.innerHTML=location.hash", "", ""},
		{"fixed script creation", "const script=document.createElement('script');script.src='https://example.test/app.js';document.body.appendChild(script)", "", ""},
		{"imported jQuery", "import $ from 'jquery';const el=$('#result');el.html(location.hash)", "raw", "html_text"},
		{"helper-contained DOM sink", "function render(value){document.body.innerHTML=value};render(location.hash)", "raw", "html_text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "browser.js", tt.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if tt.protection == "" {
				if len(uses) > 0 {
					t.Fatalf("unexpected XSS: %+v", uses)
				}
				return
			}
			if len(uses) != 1 || uses[0].EntryKind != "browser" || uses[0].EntryID == "" || uses[0].XSS.Protection != tt.protection || uses[0].XSS.OutputContext != tt.context {
				t.Fatalf("want client %s/%s: %+v", tt.protection, tt.context, uses)
			}
			if len(testBrowserEntries(r)) != 1 {
				t.Fatal("browser source has no dedicated entry")
			}
		})
	}
}

func TestReactAndVueRenderingControls(t *testing.T) {
	for _, tt := range []struct{ name, file, source, protection string }{
		{"React raw HTML", "browser.jsx", "import React from 'react';const value=location.hash;const View=()=> <div dangerouslySetInnerHTML={{__html:value}} />", "raw"},
		{"React escaped text", "browser.jsx", "import React from 'react';const value=location.hash;const View=()=> <p>{value}</p>", "encoded"},
		{"Vue raw HTML", "view.vue", `<script setup>const value=location.hash</script><template><div v-html="value"></div></template>`, "raw"},
		{"Vue escaped text", "view.vue", `<script setup>const value=location.hash</script><template><div>{{value}}</div></template>`, "encoded"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, tt.file, tt.source)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection || len(testBrowserEntries(r)) != 1 {
				t.Fatalf("want %s; got %+v", tt.protection, uses)
			}
		})
	}
}

func TestAngularTrustAndTemplateBindings(t *testing.T) {
	for _, tt := range []struct{ name, expression, template, protection string }{
		{"trust bypass", "this.sanitizer.bypassSecurityTrustHtml(q)", `<div [innerHTML]="value"></div>`, "raw"},
		{"default sanitization", "q", `<div [innerHTML]="value"></div>`, "sanitized"},
		{"missing renderer", "this.sanitizer.bypassSecurityTrustHtml(q)", `<div>constant</div>`, "unknown"},
		// A plain sibling path keeps default sanitization but never hides the bypassed path, in either order.
		{"bypass beside plain path", "(q.length>1?this.sanitizer.bypassSecurityTrustHtml(q):q)", `<div [innerHTML]="value"></div>`, "raw"},
		{"plain path before bypass", "(q.length>1?q:this.sanitizer.bypassSecurityTrustHtml(q))", `<div [innerHTML]="value"></div>`, "raw"},
		{"bypass for another context", "this.sanitizer.bypassSecurityTrustUrl(q)", `<div [innerHTML]="value"></div>`, "unknown"},
		{"URL bypass in URL binding", "this.sanitizer.bypassSecurityTrustUrl(q)", `<a [href]="value">x</a>`, "raw"},
		{"unknown wrapper is not default protection", "this.wrap(q)", `<div [innerHTML]="value"></div>`, "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "component.ts", "import {Component,inject} from '@angular/core';import {ActivatedRoute} from '@angular/router';import {DomSanitizer} from '@angular/platform-browser';@Component({templateUrl:'./page.html'}) export class Page {private route=inject(ActivatedRoute);private sanitizer=inject(DomSanitizer);run(){const q=this.route.snapshot.queryParams.q;this.value="+tt.expression+"}}")
			writeSource(t, root, "page.html", tt.template)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want %s; got %+v", tt.protection, uses)
			}
			if tt.protection != "unknown" && uses[0].Sink.Span.File != "page.html" {
				t.Fatal("template witness missing")
			}
		})
	}
}

func TestSameSinkClientRecordsMerge(t *testing.T) {
	dep := func(text string, at uint) analysis.Dependency {
		return analysis.Dependency{Source: analysis.Evidence{Kind: "browser_source", Text: text, Span: analysis.Span{File: "c.ts", StartByte: int(at)}}, Transfers: []analysis.Evidence{}}
	}
	use := func(kind, protection string, resolved bool, d analysis.Dependency) analysis.CandidateUse {
		return analysis.CandidateUse{ID: "xss:client:c.ts:1", EntryID: "client:c.ts", EntryKind: "browser", Kind: "xss_candidate", Sink: analysis.Evidence{Span: analysis.Span{File: "c.html", StartByte: 9}},
			Dependencies: []analysis.Dependency{d}, XSS: &analysis.XSSFacts{Type: kind, Protection: protection, OriginResolved: resolved, ResponsePath: map[bool]string{false: "/api/x"}[resolved]}}
	}
	tests := []struct {
		name       string
		uses       []analysis.CandidateUse
		protection string
		typ        string
		paths      string
	}{
		{"weak cross-tier first does not hide later raw DOM", []analysis.CandidateUse{use("cross_tier", "unknown", false, dep("api", 1)), use("dom", "raw", true, dep("location.hash", 2))}, "raw", "dom", "raw,unknown"},
		// The unresolved cross-tier claim is kept (Review), not replaced by the protected sibling.
		{"unresolved cross-tier raw path is not covered by a protected sibling", []analysis.CandidateUse{use("dom", "encoded", true, dep("location.hash", 2)), use("cross_tier", "raw", false, dep("api", 1))}, "raw", "cross_tier", "raw,encoded"},
		{"protected record does not cover an unknown sibling", []analysis.CandidateUse{use("dom", "encoded", true, dep("a", 1)), use("dom", "unknown", true, dep("b", 2))}, "unknown", "dom", "unknown,encoded"},
		{"identical records stay one protected record", []analysis.CandidateUse{use("dom", "encoded", true, dep("a", 1)), use("dom", "encoded", true, dep("a", 1))}, "encoded", "dom", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &analysis.AnalysisReport{}
			addClientUses(r, &clientContext{entry: analysis.EntryPoint{ID: "client:c.ts", Kind: "browser", Browser: &analysis.BrowserEntryMetadata{Category: "script"}}}, tt.uses)
			if len(r.Uses) != 1 || r.Uses[0].XSS.Protection != tt.protection || r.Uses[0].XSS.Type != tt.typ {
				t.Fatalf("want one %s %s record: %+v", tt.typ, tt.protection, r.Uses)
			}
			var got []string
			for _, p := range r.Uses[0].XSS.Paths {
				got = append(got, p.Protection)
			}
			if strings.Join(got, ",") != tt.paths || len(r.Uses[0].Dependencies) != len(strings.Split(tt.paths, ",")) && tt.paths != "" {
				t.Fatalf("paths %v, want %s", got, tt.paths)
			}
			if tt.typ == "dom" && tt.uses[0].XSS.Type == "cross_tier" {
				found := false
				for _, g := range r.Uses[0].Gaps {
					found = found || g.Kind == "cross_tier_sibling_unresolved"
				}
				if !found {
					t.Fatal("unlinked API sibling lost its gap")
				}
			}
		})
	}
}

func TestDOMAugmentedSink(t *testing.T) {
	for _, tt := range []struct{ source, protection string }{
		{"const el=document.getElementById('r');el.innerHTML+=location.hash", "raw"},
		{"import DOMPurify from 'dompurify';const el=document.getElementById('r');el.innerHTML+=DOMPurify.sanitize(location.hash)", "sanitized"},
	} {
		root := t.TempDir()
		writeSource(t, root, "browser.js", tt.source)
		r, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		if uses := xssUses(r); len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
			t.Fatalf("%s: want %s, got %+v", tt.source, tt.protection, uses)
		}
	}
}
