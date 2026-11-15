package parse

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func outboundUses(t *testing.T, files map[string]string) []analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		writeSource(t, root, name, src)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "outbound_http_candidate" || u.Kind == "ssrf_candidate" {
			out = append(out, u)
		}
	}
	return out
}

func TestOutboundDestinationOrigin(t *testing.T) {
	const head = "const express = require('express');\nconst app = express();\n"
	for _, tt := range []struct {
		name, route, want, kind string
	}{
		{"constant string", `fetch('https://api.invalid/x', {method:'POST', body: req.body.v});`, analysis.DestinationConstant, "outbound_http_candidate"},
		{"constant template", "fetch(`https://api.invalid/x`, {body: req.body.v});", analysis.DestinationConstant, "outbound_http_candidate"},
		{"environment", `fetch(process.env.HOOK, {body: req.body.v});`, analysis.DestinationEnvironment, "outbound_http_candidate"},
		{"environment through a local", `const hook = process.env.HOOK; fetch(hook, {body: req.body.v});`, analysis.DestinationEnvironment, "outbound_http_candidate"},
		{"computed destination", `fetch(pick(), {body: req.body.v});`, analysis.DestinationUnestablished, "outbound_http_candidate"},
		{"request destination", `fetch(req.query.url);`, analysis.DestinationRequest, "ssrf_candidate"},
		{"request in template", "fetch(`https://${req.query.host}/x`);", analysis.DestinationRequest, "ssrf_candidate"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := outboundUses(t, map[string]string{"server.js": head + "app.post('/x', (req, res) => { " + tt.route + " res.send('ok') });\n"})
			if len(uses) != 1 {
				t.Fatalf("outbound uses=%d", len(uses))
			}
			u := uses[0]
			if u.Kind != tt.kind || u.Outbound == nil || u.Outbound.DestinationOrigin != tt.want {
				t.Fatalf("kind=%s outbound=%+v, want %s %s", u.Kind, u.Outbound, tt.kind, tt.want)
			}
		})
	}
	t.Run("environment through a parameter default", func(t *testing.T) {
		uses := outboundUses(t, map[string]string{"server.js": head + "async function notify(body, hook = process.env.HOOK) { return fetch(hook, {method: 'POST', body}) }\napp.post('/x', (req, res) => { notify(req.body.v); res.send('ok') });\n"})
		if len(uses) != 1 || uses[0].Outbound == nil || uses[0].Outbound.DestinationOrigin != analysis.DestinationEnvironment {
			t.Fatalf("uses=%+v", uses)
		}
	})
	t.Run("python second-order destination", func(t *testing.T) {
		uses := outboundUses(t, map[string]string{"app.py": "from flask import Flask, request\nimport requests\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    r = requests.get('https://api.invalid/next')\n    requests.get(r.text)\n    requests.post('https://api.invalid/fixed', data=request.args.get('v'))\n    return 'ok'\n"})
		if len(uses) != 1 || uses[0].Kind != "outbound_http_candidate" || uses[0].Outbound.DestinationOrigin != analysis.DestinationExternalData {
			t.Fatalf("uses=%+v", uses)
		}
	})
}

func TestSSRFCandidates(t *testing.T) {
	for _, tt := range []struct {
		name     string
		files    map[string]string
		contract string // empty: stays an observation
	}{
		{"global fetch", map[string]string{"server.js": "const express=require('express');const app=express();app.get('/x',(req,res)=>{fetch(req.query.url);res.send('ok')});"}, "fetch-url-v1"},
		{"axios default import", map[string]string{"server.ts": "import express from 'express';import axios from 'axios';const app=express();app.get('/x',async (req,res)=>{await axios.get(req.query.url as string);res.send('ok')});"}, "axios-url-v1"},
		{"axios namespace default", map[string]string{"server.ts": "import express from 'express';import * as axios from 'axios';const app=express();app.get('/x',async (req,res)=>{await axios.default.get(req.query.url as string);res.send('ok')});"}, "axios-url-v1"},
		{"axios require post", map[string]string{"server.js": "const express=require('express');const axios=require('axios');const app=express();app.post('/x',(req,res)=>{axios.post(req.body.target,{a:1});res.send('ok')});"}, "axios-url-v1"},
		{"python requests", map[string]string{"app.py": "from flask import Flask, request\nimport requests\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    requests.get(request.args.get('url'))\n    return 'ok'\n"}, "python-http-url-v1"},
		{"shadowed fetch", map[string]string{"server.js": "const express=require('express');const app=express();app.get('/x',(req,res)=>{const fetch=v=>v;fetch(req.query.url);res.send('ok')});"}, ""},
		{"local axios object", map[string]string{"server.js": "const express=require('express');const axios={get:x=>x};const app=express();app.get('/x',(req,res)=>{axios.get(req.query.url);res.send('ok')});"}, ""},
		{"axios config object", map[string]string{"server.js": "const express=require('express');const axios=require('axios');const app=express();app.get('/x',(req,res)=>{axios({url:req.query.url});res.send('ok')});"}, ""},
		{"fixed destination", map[string]string{"server.js": "const express=require('express');const app=express();app.post('/x',(req,res)=>{fetch('https://api.invalid/x',{method:'POST',body:req.body.v});res.send('ok')});"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := outboundUses(t, tt.files)
			if len(uses) != 1 {
				t.Fatalf("outbound uses=%d", len(uses))
			}
			u := uses[0]
			if tt.contract == "" {
				if u.Kind != "outbound_http_candidate" {
					t.Fatalf("became %s", u.Kind)
				}
				return
			}
			if u.Kind != "ssrf_candidate" || u.APIModel == nil || u.APIModel.ID != tt.contract || u.Outbound.ContractID != tt.contract {
				t.Fatalf("kind=%s api=%+v outbound=%+v", u.Kind, u.APIModel, u.Outbound)
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("component selection: %+v", u.Components)
			}
			if len(u.Dependencies) == 0 || len(u.Outbound.Paths) != len(u.Dependencies) {
				t.Fatalf("paths=%+v deps=%d", u.Outbound.Paths, len(u.Dependencies))
			}
			for _, d := range u.Dependencies {
				if d.SinkSlot != analysis.OutboundSlotDestination {
					t.Fatalf("dependency slot %q", d.SinkSlot)
				}
			}
			if u.Completeness == nil || u.Completeness.ClaimKind != "ssrf" || len(u.Completeness.Evidence["sink_binding"]) == 0 || len(u.Completeness.Evidence["destination_operand"]) == 0 {
				t.Fatalf("completeness: %+v", u.Completeness)
			}
		})
	}
}

// A guard that rejects a destination before the call is attached to that path;
// a guard on another value is not.
func TestSSRFGuards(t *testing.T) {
	src := "const express=require('express');const app=express();const HOSTS=new Set(['api.invalid']);\n" +
		"app.get('/a',(req,res)=>{const url=req.query.url;if(!HOSTS.has(new URL(url).hostname)){return res.sendStatus(400)}fetch(url);res.send('ok')});\n" +
		"app.get('/b',(req,res)=>{const url=req.query.url;if(!HOSTS.has(req.query.other)){return res.sendStatus(400)}fetch(url);res.send('ok')});\n"
	uses := outboundUses(t, map[string]string{"server.js": src})
	for _, u := range uses {
		if u.Kind != "ssrf_candidate" {
			t.Fatalf("not a claim: %s", u.Sink.Text)
		}
	}
	if len(uses) != 2 {
		t.Fatalf("uses=%d", len(uses))
	}
	protections := []string{}
	for _, u := range uses {
		protections = append(protections, u.Outbound.Paths[0].Protection)
	}
	if !(protections[0] == "guarded" && protections[1] == "raw") && !(protections[0] == "raw" && protections[1] == "guarded") {
		t.Fatalf("path protections %v", protections)
	}
}
