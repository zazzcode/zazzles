package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func xssUses(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var uses []analysis.CandidateUse
	for _, use := range r.Uses {
		if use.Kind == "xss_candidate" {
			uses = append(uses, use)
		}
	}
	return uses
}

func TestXSSResponseContexts(t *testing.T) {
	tests := []struct{ name, imports, body, protection, context string }{
		{"HTML response", "", "res.send(`<h1>${req.query.q}</h1>`)", "raw", "html_text"},
		{"quoted attribute", "", "res.send(`<input value=\"${req.query.q}\">`)", "raw", "html_attribute"},
		{"JSON negative", "", "res.json({html:req.query.q})", "", ""},
		{"plain text negative", "", "res.type('text/plain').send(`${req.query.q}`)", "", ""},
		{"unknown content type", "", "res.end(req.query.q)", "unknown", "unknown"},
		{"explicit HTML write", "", "res.setHeader('Content-Type','text/html');res.write(req.query.q)", "raw", "html_text"},
		{"unknown sanitizer", "", "res.send(`<p>${clean(req.query.q)}</p>`)", "unknown", "html_text"},
		{"verified encoder", "import * as entities from 'entities';", "res.send(`<p>${entities.encode(req.query.q)}</p>`)", "sanitized", "html_text"},
		{"encoding in script insufficient", "import * as entities from 'entities';", "res.send(`<script>${entities.encode(req.query.q)}</script>`)", "unknown", "script"},
		{"encoding in URL insufficient", "import * as entities from 'entities';", "res.send(`<a href=\"${entities.encode(req.query.q)}\">link</a>`)", "unknown", "url"},
		{"fake encoder", "const entities={encode:x=>x};", "res.send(`<p>${entities.encode(req.query.q)}</p>`)", "unknown", "html_text"},
		{"literal response", "", "res.send('<p>constant</p>')", "", ""},
		{"fake response", "", "const other={send:x=>x};other.send(`<p>${req.query.q}</p>`)", "", ""},
		{"response reassigned", "", "res=other;res.send(`<p>${req.query.q}</p>`)", "", ""},
		{"mixed branch sanitizer", "import sanitize from 'sanitize-html';", "res.send(`<p>${req.query.safe ? sanitize(req.query.q) : req.query.q}</p>`)", "raw", "html_text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.ts", "import express from 'express';"+tt.imports+"const app=express();app.get('/x',(req,res)=>{"+tt.body+"})")
			r, err := Analyze(root, "app.ts")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if tt.protection == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected XSS use: %+v", uses)
				}
				return
			}
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection || uses[0].XSS.OutputContext != tt.context {
				t.Fatalf("want %s/%s: %+v", tt.protection, tt.context, uses)
			}
		})
	}
}

func TestXSSRawAndEscapedTemplates(t *testing.T) {
	tests := []struct{ name, extension, template, protection, context string }{
		{"raw EJS attribute", "ejs", `<input value="<%- value %>">`, "raw", "html_attribute"},
		{"escaped EJS text", "ejs", `<p><%= value %></p>`, "encoded", "html_text"},
		{"escaped EJS attribute", "ejs", `<input value="<%= value %>">`, "encoded", "html_attribute"},
		{"escaped EJS script", "ejs", `<script>let x='<%= value %>'</script>`, "unknown", "script"},
		{"raw Handlebars", "hbs", `<p>{{{value}}}</p>`, "raw", "html_text"},
		{"escaped Handlebars", "hbs", `<p>{{value}}</p>`, "encoded", "html_text"},
		{"raw Pug", "pug", `p !{value}`, "raw", "html_text"},
		{"escaped Pug", "pug", `p #{value}`, "encoded", "html_text"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const app=express();app.set('view engine','"+tt.extension+"');const routes=require('./routes');app.get('/x',routes.show)")
			writeSource(t, root, "routes/index.js", "exports.show=function(request,response){return response.render('page',{value:request.query.q})}")
			writeSource(t, root, "views/page."+tt.extension, tt.template)
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection || uses[0].XSS.OutputContext != tt.context {
				t.Fatalf("want %s/%s: %+v", tt.protection, tt.context, uses)
			}
			if uses[0].Sink.Span.File != "views/page."+tt.extension || uses[0].Sink.SHA256 == "" {
				t.Fatal("template sink provenance missing")
			}
		})
	}
}

func TestWholeRequestRenderOptionsRemainReview(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "app.js", "const express=require('express');const app=express();app.set('view engine','hbs');app.post('/profile',(req,res)=>{const profile=req.body;res.render('profile',profile)})")
	writeSource(t, root, "views/profile.hbs", `<p>{{firstname}}</p>`)
	r, err := Analyze(root, "app.js")
	if err != nil {
		t.Fatal(err)
	}
	uses := xssUses(r)
	if len(uses) != 1 || uses[0].XSS.Protection != "unknown" || !gapKind(uses[0].Gaps, "render_options_unresolved") {
		t.Fatalf("whole-object options were declared protected: %+v", uses)
	}
}

func TestBranchingHelpersAndAugmentedAssignment(t *testing.T) {
	tests := []struct{ name, helper, body, protection string }{
		// A literal-token test without HTML-significant characters cannot guard markup: the unchanged path is raw.
		{"content-neutral token branch", "function fmt(t){var tok=' in ';var r=t.toString().indexOf(tok);if(r>0){t=t.slice(0,r)}return t}", "res.send('<p>'+fmt(req.query.q))", "raw"},
		{"unknown predicate may guard", "function clean(x){if(bad(x)){x=''}return x}", "res.send('<p>'+clean(req.query.q))", "unknown"},
		{"HTML-significant literal may guard", "function clean(x){if(x.indexOf('<')>=0){x=''}return x}", "res.send('<p>'+clean(req.query.q))", "unknown"},
		{"returning branch may guard", "function clean(x){if(x.length>9){return ''}return x}", "res.send('<p>'+clean(req.query.q))", "unknown"},
		{"reassigned token is not a constant", "function fmt(t){var tok=' in ';tok=pick();if(t.indexOf(tok)>0){t=t.slice(1)}return t}", "res.send('<p>'+fmt(req.query.q))", "unknown"},
		{"string building keeps request data", "", "let h='<p>';h+=req.query.q;res.send(h)", "raw"},
		{"encoded string building", "", "let h='<p>';h+=escapeHtml(req.query.q);res.send(h)", "sanitized"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const escapeHtml=require('escape-html');const app=express();"+tt.helper+";app.get('/x',(req,res)=>{"+tt.body+"})")
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want protection=%s; got %+v", tt.protection, uses)
			}
		})
	}
}

func TestSanitizerBindingGates(t *testing.T) {
	tests := []struct{ name, imports, body, template, protection string }{
		{"server DOMPurify without a window", "const DOMPurify=require('dompurify');", "res.send('<p>'+DOMPurify.sanitize(req.query.q))", "", "unknown"},
		{"isomorphic DOMPurify", "const DOMPurify=require('isomorphic-dompurify');", "res.send('<p>'+DOMPurify.sanitize(req.query.q))", "", "sanitized"},
		{"sanitize-html with custom options", "const sanitizeHtml=require('sanitize-html');", "res.send('<p>'+sanitizeHtml(req.query.q,{allowedTags:false}))", "", "unknown"},
		{"Handlebars SafeString in escaped output", "const Handlebars=require('handlebars');", "res.render('page',{name:new Handlebars.SafeString(req.query.q)})", "<p>{{name}}</p>", "raw"},
		{"hbs SafeString in escaped output", "const hbs=require('hbs');", "res.render('page',{name:new hbs.handlebars.SafeString(req.query.q)})", "<p>{{name}}</p>", "raw"},
		{"plain value in escaped output", "const Handlebars=require('handlebars');", "res.render('page',{name:req.query.q})", "<p>{{name}}</p>", "encoded"},
		{"look-alike SafeString", "const Handlebars={SafeString:function(v){this.v=v}};", "res.render('page',{name:new Handlebars.SafeString(req.query.q)})", "<p>{{name}}</p>", "encoded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			engine := ""
			if tt.template != "" {
				engine = "app.set('view engine','hbs');"
				writeSource(t, root, "views/page.hbs", tt.template)
			}
			writeSource(t, root, "app.js", "const express=require('express');"+tt.imports+"const app=express();"+engine+"app.get('/x',(req,res)=>{"+tt.body+"})")
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want protection=%s; got %+v", tt.protection, uses)
			}
		})
	}
}
