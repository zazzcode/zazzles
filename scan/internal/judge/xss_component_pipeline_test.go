package judge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"github.com/zazzcode/zazzles/scan/internal/report"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type xssCase struct {
	name                       string
	files                      map[string]string
	protection, output, status string
}

func parsedXSS(t *testing.T, files map[string]string) (*analysis.AnalysisReport, analysis.CandidateUse) {
	t.Helper()
	root := t.TempDir()
	for file, source := range files {
		name := filepath.Join(root, file)
		if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := pipeline.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var uses []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "xss_candidate" {
			uses = append(uses, u)
		}
	}
	if len(uses) != 1 {
		t.Fatalf("want one rendering claim, got %d: %+v", len(uses), uses)
	}
	return r, uses[0]
}

func xssAnswer(u analysis.CandidateUse, provider, mode string) []byte {
	values := map[string]string{"output_context": u.XSS.OutputContext, "encoding_adequacy": "not_present", "sanitizer_effectiveness": "absent", "xss_all_paths_protected": "no", "xss_exposure": "vulnerable"}
	if mode == "protected" {
		values["encoding_adequacy"] = "adequate"
		values["xss_all_paths_protected"] = "yes"
		values["xss_exposure"] = "protected"
	}
	if mode == "unknown" {
		values["encoding_adequacy"] = "unknown"
		values["xss_all_paths_protected"] = "unknown"
		values["xss_exposure"] = "unknown"
	}
	if mode == "not_applicable" {
		values["xss_exposure"] = "not_applicable"
	}
	if provider == "jev" {
		answers := map[string]any{}
		for k, v := range values {
			answers[k] = map[string]string{"type": "choice", "choice": v}
		}
		b, _ := json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
		return b
	}
	answers := []answer{}
	for _, q := range questionsFor(u) {
		answers = append(answers, answer{"choice", q.name, values[q.name]})
	}
	b, _ := json.Marshal(map[string]any{"model": "fixture-model", "answers": answers})
	return b
}

func xssPipeline(t *testing.T, cases []xssCase) {
	t.Helper()
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			r, u := parsedXSS(t, tt.files)
			if u.XSS.Protection != tt.protection || u.XSS.OutputContext != tt.output {
				t.Fatalf("source facts: %+v", u.XSS)
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("selection: %+v", u.Components)
			}
			before, _ := json.Marshal(u)
			m, err := analysispacks.ForUse(u)
			if err != nil {
				t.Fatal(err)
			}
			material, _ := json.Marshal(m)
			t.Logf("components=%d material=%d", len(u.Components.Components), len(material))
			for _, provider := range []string{"openai", "jev"} {
				t.Run(provider, func(t *testing.T) {
					c, _ := New(provider, "fixture-model", "offline-key")
					preview, err := c.Preview(u)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("body=%d", preview.RequestBytes)
					if preview.QuestionVersion != analysispacks.XSSProtocol || preview.RequestDigest == "" {
						t.Fatal("missing selected provenance")
					}
					var body map[string]any
					json.Unmarshal(preview.Request, &body)
					// The five XSS questions, plus any resolution questions (resolve_*).
					family := 0
					switch qs := body["questions"].(type) {
					case []any:
						for _, q := range qs {
							if name, _ := q.(map[string]any)["name"].(string); !strings.HasPrefix(name, resolvePrefix) {
								family++
							}
						}
						if family != 5 {
							t.Fatal("wrong questions")
						}
					case map[string]any:
						for name := range qs {
							if !strings.HasPrefix(name, resolvePrefix) {
								family++
							}
						}
						if family != 5 {
							t.Fatal("wrong questions")
						}
					default:
						t.Fatal("missing questions")
					}
					mode := "raw"
					if tt.protection == "encoded" || tt.protection == "sanitized" {
						mode = "protected"
					}
					if tt.protection == "unknown" {
						mode = "protected"
					} // optimistic answer must still fail closed
					calls := 0
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
						calls++
						b, _ := io.ReadAll(req.Body)
						if !sameRequest(b, preview.Request) {
							t.Error("wire payload changed")
						}
						w.Write(xssAnswer(u, provider, mode))
					}))
					defer server.Close()
					c.endpoint = server.URL
					c.http = server.Client()
					a, tr := c.AssessTrace(context.Background(), u)
					if calls != 1 || a.Status != "completed" || a.FindingStatus != tt.status {
						t.Fatalf("assessment: %+v calls=%d", a, calls)
					}
					if replay := c.Replay(u, tr); !reflect.DeepEqual(a, replay) {
						t.Fatalf("exact replay differs: %+v %+v", a, replay)
					}
					after, _ := json.Marshal(u)
					if !bytes.Equal(before, after) {
						t.Fatal("judgment changed source facts")
					}
					for i := range r.Uses {
						if r.Uses[i].ID == u.ID {
							r.Uses[i].Assessment = a
						}
					}
					assertXSSExports(t, r, u, tt.status)
				})
			}
		})
	}
}

func assertXSSExports(t *testing.T, r *analysis.AnalysisReport, u analysis.CandidateUse, status string) {
	t.Helper()
	report.Enrich(r)
	found := false
	for _, f := range r.Findings {
		if f.UseID == u.ID {
			found = true
			if f.Status != status && !(status == "needs_evidence" && f.Status == "needs_review") {
				t.Fatalf("finding status %s, want %s", f.Status, status)
			}
		}
	}
	if !found {
		t.Fatal("claim disappeared")
	}
	var html bytes.Buffer
	if err := report.HTML(&html, r); err != nil {
		t.Fatal(err)
	}
	sarif, _ := json.Marshal(report.SARIF(r))
	data, _ := json.Marshal(r)
	if !strings.Contains(html.String(), u.Sink.Span.File+":"+fmt.Sprint(u.Sink.Span.StartLine)) || !strings.Contains(string(sarif), u.Sink.Span.File) || !strings.Contains(string(data), u.Sink.SHA256) {
		t.Fatal("source provenance lost in exports")
	}
	if !strings.Contains(string(sarif), "CWE-79") {
		t.Fatal("XSS family lost")
	}
	var decoded analysis.AnalysisReport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Findings) != len(r.Findings) || len(decoded.Entries) != len(r.Entries) || len(decoded.Uses) != len(r.Uses) {
		t.Fatal("JSON counts drift")
	}
	if u.EntryKind == "browser" && !strings.Contains(html.String(), "Browser") {
		t.Fatal("browser grouping lost")
	}
}

func TestXSSServerComponentParity(t *testing.T) {
	var cases []xssCase
	for _, v := range []struct{ name, expr, protect, output, status string }{
		{"raw", "req.query.q", "raw", "html_text", "confirmed_vulnerability"},
		{"encoder", "escapeHtml(req.query.q)", "sanitized", "html_text", "protected_for_claim"},
		{"unknown helper", "opaque(req.query.q)", "unknown", "html_text", "needs_evidence"},
	} {
		cases = append(cases, xssCase{v.name, map[string]string{"app.js": `const express=require('express');const escapeHtml=require('escape-html');const app=express();app.get('/x',(req,res)=>{res.send('<p>'+` + v.expr + `+'</p>')})`}, v.protect, v.output, v.status})
	}
	for _, v := range []struct{ ext, raw, escaped string }{{"ejs", "<%- value %>", "<%= value %>"}, {"hbs", "{{{value}}}", "{{value}}"}, {"pug", "p !{value}", "p #{value}"}} {
		for _, escaped := range []bool{false, true} {
			template, protect, status := v.raw, "raw", "confirmed_vulnerability"
			if escaped {
				template, protect, status = v.escaped, "encoded", "protected_for_claim"
			}
			cases = append(cases, xssCase{fmt.Sprint(v.ext, escaped), map[string]string{"app.js": `const express=require('express');const app=express();app.set('view engine','` + v.ext + `');app.get('/x',(req,res)=>res.render('page',{value:req.query.q}))`, "views/page." + v.ext: template}, protect, "html_text", status})
		}
	}
	cases = append(cases, xssCase{"Jinja", map[string]string{"a.py": "from flask import Flask,request,render_template\napp=Flask(__name__)\n@app.get('/')\ndef index():\n    return render_template('page.html',value=request.args.get('q'))\n", "templates/page.html": "<p>{{ value }}</p>"}, "encoded", "html_text", "protected_for_claim"})
	xssPipeline(t, cases)
}

func TestXSSStoredComponentParity(t *testing.T) {
	var cases []xssCase
	for _, v := range []struct{ name, write, template, protection, status string }{
		{"raw", "req.body.text", "<%- note.body %>", "raw", "confirmed_vulnerability"},
		{"escaped", "req.body.text", "<%= note.body %>", "encoded", "protected_for_claim"},
		{"unknown", "opaque(req.body.text)", "<%- note.body %>", "unknown", "needs_evidence"},
	} {
		cases = append(cases, xssCase{v.name, map[string]string{"app.js": `const express=require('express');const mongoose=require('mongoose');const Note=mongoose.model('Note');const app=express();app.set('view engine','ejs');app.post('/write',(req,res)=>{new Note({body:` + v.write + `}).save()});app.get('/read',(req,res)=>{Note.find({}).exec(function(err,notes){res.render('page',{notes})})})`, "views/page.ejs": "<% notes.forEach(function(note){ %>" + v.template + "<% }); %>"}, v.protection, "html_text", v.status})
	}
	cases = append(cases, xssCase{"Sequelize", map[string]string{"app.ts": `import express from 'express';import {Model} from 'sequelize';class Note extends Model {} const app=express();app.set('view engine','ejs');app.post('/write',(req,res)=>{Note.create({body:req.body.text})});app.get('/read',(req,res)=>{Note.findAll().then(notes=>res.render('page',{notes}))})`, "views/page.ejs": `<% notes.forEach(function(note){ %><%- note.body %><% }); %>`}, "raw", "html_text", "confirmed_vulnerability"})
	xssPipeline(t, cases)
}

func TestXSSBrowserComponentParity(t *testing.T) {
	cases := []xssCase{
		{"DOM", map[string]string{"client.js": `document.body.innerHTML=location.hash`}, "raw", "html_text", "confirmed_vulnerability"},
		{"text", map[string]string{"client.js": `document.body.textContent=location.hash`}, "encoded", "html_text", "protected_for_claim"},
		{"DOMPurify", map[string]string{"client.js": `import DOMPurify from 'dompurify';document.body.innerHTML=DOMPurify.sanitize(location.hash)`}, "sanitized", "html_text", "protected_for_claim"},
		{"jQuery", map[string]string{"client.js": `import $ from 'jquery';$('#out').html(location.hash)`}, "raw", "html_text", "confirmed_vulnerability"},
		{"React", map[string]string{"client.jsx": `import React from 'react';const value=location.hash;const View=()=> <div dangerouslySetInnerHTML={{__html:value}} />`}, "raw", "html_text", "confirmed_vulnerability"},
		{"Vue", map[string]string{"view.vue": `<script setup>const value=location.hash</script><template><div v-html="value"></div></template>`}, "raw", "html_text", "confirmed_vulnerability"},
		{"event", map[string]string{"client.js": `window.addEventListener('message',(message)=>{document.body.innerHTML=message.data})`}, "raw", "html_text", "confirmed_vulnerability"},
		{"inline", map[string]string{"a.py": "from flask import Flask,render_template\napp=Flask(__name__)\n@app.get('/')\ndef index():\n    return render_template('page.html')\n", "templates/page.html": `<script>document.body.innerHTML=location.hash</script>`}, "raw", "html_text", "confirmed_vulnerability"},
	}
	for _, bypass := range []bool{false, true} {
		expr, protection, status := "q", "sanitized", "protected_for_claim"
		if bypass {
			expr, protection, status = "this.sanitizer.bypassSecurityTrustHtml(q)", "raw", "confirmed_vulnerability"
		}
		cases = append(cases, xssCase{fmt.Sprint("Angular", bypass), map[string]string{"component.ts": `import {Component,inject} from '@angular/core';import {ActivatedRoute} from '@angular/router';import {DomSanitizer} from '@angular/platform-browser';@Component({templateUrl:'./page.html'}) export class Page {private route=inject(ActivatedRoute);private sanitizer=inject(DomSanitizer);run(){const q=this.route.snapshot.queryParams.q;this.value=` + expr + `}}`, "page.html": `<div [innerHTML]="value"></div>`}, protection, "html_text", status})
	}
	xssPipeline(t, cases)
}
