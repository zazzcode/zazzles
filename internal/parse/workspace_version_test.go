package parse

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func usesUnder(r *analysis.AnalysisReport, kind, dir string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == kind && strings.HasPrefix(u.Sink.Span.File, dir+"/") {
			out = append(out, u)
		}
	}
	return out
}

const sanitizerRoute = "const express=require('express');const sanitizeHtml=require('sanitize-html');const app=express();\napp.get('/a',(req,res)=>{res.send(`<p>${sanitizeHtml(req.query.q)}</p>`)})\n"

func TestWorkspaceVersionConsumers(t *testing.T) {
	t.Run("sanitizer advisory follows the workspace", func(t *testing.T) {
		r := analyzeFiles(t, map[string]string{
			"package.json":              `{"private":true,"workspaces":["packages/*"],"dependencies":{"sanitize-html":"1.4.3"}}`,
			"packages/api/package.json": `{"dependencies":{"sanitize-html":"1.4.2"}}`,
			"packages/api/app.js":       sanitizerRoute,
			"packages/web/app.js":       sanitizerRoute,
		})
		for dir, want := range map[string]string{"packages/api": "ineffective", "packages/web": "sanitized"} {
			uses := usesUnder(r, "xss_candidate", dir)
			if len(uses) != 1 || uses[0].XSS.Protection != want {
				t.Fatalf("%s: want %s got %v", dir, want, summarize(uses))
			}
		}
	})
	t.Run("workspace lock resolves a range-only manifest", func(t *testing.T) {
		r := analyzeFiles(t, map[string]string{
			"package.json":              `{"private":true,"workspaces":["packages/*"]}`,
			"packages/api/package.json": `{"dependencies":{"sanitize-html":"^1.4.0"}}`,
			"packages/api/app.js":       sanitizerRoute,
			"package-lock.json": `{"lockfileVersion":3,"packages":{"":{},"packages/api":{"dependencies":{"sanitize-html":"^1.4.0"}},
				"node_modules/sanitize-html":{"version":"2.0.0"},"packages/api/node_modules/sanitize-html":{"version":"1.4.2"}}}`,
		})
		uses := usesUnder(r, "xss_candidate", "packages/api")
		if len(uses) != 1 || uses[0].XSS.Protection != "ineffective" {
			t.Fatalf("nested lock entry must win over the hoisted one: %v", summarize(uses))
		}
	})
	t.Run("adm-zip assessment per workspace with evidence from the establishing manifest", func(t *testing.T) {
		app := "const express=require('express');const AdmZip=require('adm-zip');const app=express();\napp.post('/import',(req,res)=>{const zip=new AdmZip(req.files.archive.data);zip.extractAllTo('/tmp/out',true);res.send('ok')});\n"
		r := analyzeFiles(t, map[string]string{
			"packages/api/package.json": `{"dependencies":{"adm-zip":"0.4.7"}}`,
			"packages/api/app.js":       app,
			"packages/web/package.json": `{"dependencies":{"adm-zip":"0.5.5"}}`,
			"packages/web/app.js":       app,
		})
		for dir, want := range map[string]string{"packages/api": "vulnerable_version", "packages/web": "fixed_version"} {
			uses := usesUnder(r, "path_traversal_candidate", dir)
			if len(uses) != 1 || uses[0].Path.Extractor == nil || uses[0].Path.Extractor.Assessment != want {
				t.Fatalf("%s: want %s got %+v", dir, want, uses)
			}
			e := uses[0].Context[uses[0].Path.Extractor.Context]
			if e.Kind != "dependency_declaration" || e.Span.File != dir+"/package.json" {
				t.Fatalf("%s: declaration evidence %+v", dir, e)
			}
		}
	})
	t.Run("mongoose contract follows the workspace pin", func(t *testing.T) {
		route := `const express=require('express');const mongoose=require('mongoose');const User=mongoose.model('User',new mongoose.Schema({password:String}));const app=express();app.use(express.json());app.post('/lookup',(req,res)=>{User.find({password:req.body.password},(error,users)=>res.json(users))});`
		r := analyzeFiles(t, map[string]string{
			"packages/api/package.json": `{"dependencies":{"mongoose":"4.2.4"}}`,
			"packages/api/server.js":    route,
			"packages/web/package.json": `{"dependencies":{"mongoose":"4.2.5"}}`,
			"packages/web/server.js":    route,
		})
		for dir, want := range map[string]bool{"packages/api": true, "packages/web": false} {
			uses := usesUnder(r, "nosql_query_candidate", dir)
			if len(uses) != 1 {
				t.Fatalf("%s: %d candidates", dir, len(uses))
			}
			got := uses[0].APIModel != nil && uses[0].APIModel.ID == "mongoose-model-query-v2"
			if got != want {
				t.Fatalf("%s: pinned contract=%v want %v", dir, got, want)
			}
			if want {
				for _, e := range uses[0].Completeness.Evidence["model_dependency_version"] {
					if e.Span.File != dir+"/package.json" {
						t.Fatalf("version evidence anchored to %s", e.Span.File)
					}
				}
			}
		}
	})
}
