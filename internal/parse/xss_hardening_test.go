package parse

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func summarize(uses []analysis.CandidateUse) []string {
	var out []string
	for _, u := range uses {
		out = append(out, u.XSS.Type+"/"+u.XSS.OutputContext+"/"+u.XSS.Protection)
	}
	sort.Strings(out)
	return out
}

func analyzeFiles(t *testing.T, files map[string]string) *analysis.AnalysisReport {
	t.Helper()
	root := t.TempDir()
	for name, text := range files {
		writeSource(t, root, name, text)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const expressPrelude = "const express=require('express');const app=express();function layout(t,b){return `<html><title>${t}</title><body>${b}</body></html>`}\n"

func TestServerHTMLThroughWrappers(t *testing.T) {
	for _, tt := range []struct {
		name, handler string
		want          []string
	}{
		{"wrapper keeps HTML text", "app.get('/a',(req,res)=>{const n=req.query.n||'x';res.send(layout('T',`<h1>${n}</h1>`))})", []string{"reflected/html_text/raw"}},
		{"contexts split into separate claims", "app.get('/a',(req,res)=>{const q=req.query.q;res.send(layout('T',`<input value=\"${q}\"><p>${req.query.r}</p>`))})", []string{"reflected/html_attribute/raw", "reflected/html_text/raw"}},
		{"encoder through wrapper", "const he=require('he');app.get('/a',(req,res)=>{res.send(layout('T',`<h1>${he.encode(req.query.n)}</h1>`))})", []string{"reflected/html_text/sanitized"}},
		{"response written in callback", "const http=require('http');app.post('/a',(req,res)=>{const u=req.body.u;http.get(u,(r)=>{r.on('end',()=>{res.send(layout('T',`<h1>${u}</h1>`))})})})", []string{"reflected/html_text/raw"}},
		{"callback without a response stays unvisited", "const http=require('http');app.post('/a',(req,res)=>{http.get(req.body.u,(r)=>{r.resume()});res.json({})})", nil},
		{"object argument is JSON", "app.get('/a',(req,res)=>{res.send({value:req.query.q})})", nil},
		{"literal page has no claim", "app.get('/a',(req,res)=>{res.send(layout('T','<h1>x</h1>'))})", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeFiles(t, map[string]string{"app.js": expressPrelude + tt.handler})
			if got := summarize(xssUses(r)); strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("want %v got %v", tt.want, got)
			}
		})
	}
}

func TestContextSplitUsesDistinctIdentities(t *testing.T) {
	r := analyzeFiles(t, map[string]string{"app.js": expressPrelude + "app.get('/a',(req,res)=>{res.send(`<input value=\"${req.query.q}\"><p>${req.query.r}</p>`)})"})
	uses := xssUses(r)
	if len(uses) != 2 || uses[0].ID == uses[1].ID {
		t.Fatalf("two distinct records required: %+v", uses)
	}
	for _, u := range uses {
		facts := 0
		for _, fact := range u.Completeness.ModelFacts {
			if strings.HasPrefix(fact, "claim_output=") {
				facts++
			}
		}
		if facts != 1 {
			t.Fatalf("one innermost output line per claim: %v", u.Completeness.ModelFacts)
		}
		found := false
		want := "req.query.r"
		if u.XSS.OutputContext == "html_attribute" {
			want = "req.query.q"
		}
		for _, fact := range u.Completeness.ModelFacts {
			found = found || (strings.HasPrefix(fact, "claim_output=") && strings.Contains(fact, want))
		}
		if !found {
			t.Fatalf("%s claim does not name its output: %v", u.XSS.OutputContext, u.Completeness.ModelFacts)
		}
	}
}

const sqlJSPrelude = "const express=require('express');const initSqlJs=require('sql.js');const app=express();let db;async function init(){const SQL=await initSqlJs();db=new SQL.Database()}\n" +
	"function queryAll(sql){const stmt=db.prepare(sql);const rows=[];while(stmt.step()){rows.push(stmt.getAsObject())}return rows}\n"

func TestSQLBackedStoredXSS(t *testing.T) {
	read := "app.get('/n',(_req,res)=>{const notes=queryAll('SELECT id, body FROM notes');const html=notes.map(n=>`<p>${n.body}</p>`).join('');res.send(`<div>${html}</div>`)});\n"
	for _, tt := range []struct {
		name, write, read string
		protection        string
		resolved          bool
	}{
		{"bound insert", "app.post('/n',(req,res)=>{const {body}=req.body;db.run('INSERT INTO notes (user_id, body) VALUES (2, ?)',[body]);res.redirect('/n')});", read, "raw", true},
		{"bound update", "app.post('/n',(req,res)=>{db.run('UPDATE notes SET body = ? WHERE id = 1',[req.body.b]);res.redirect('/n')});", read, "raw", true},
		{"different table is no origin", "app.post('/n',(req,res)=>{db.run('INSERT INTO other (body) VALUES (?)',[req.body.b]);res.redirect('/n')});", read, "raw", false},
		{"different column is no origin", "app.post('/n',(req,res)=>{db.run('INSERT INTO notes (title) VALUES (?)',[req.body.b]);res.redirect('/n')});", read, "raw", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeFiles(t, map[string]string{"app.js": sqlJSPrelude + tt.write + tt.read})
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Type != "stored" || uses[0].XSS.OriginResolved != tt.resolved || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("got %+v", uses)
			}
		})
	}
	t.Run("an unverified receiver is not storage", func(t *testing.T) {
		source := strings.ReplaceAll(sqlJSPrelude, "require('sql.js')", "require('./fake')")
		r := analyzeFiles(t, map[string]string{"app.js": source + "app.post('/n',(req,res)=>{db.run('INSERT INTO notes (body) VALUES (?)',[req.body.b]);res.redirect('/n')});" + read, "fake.js": "module.exports=()=>({})"})
		for _, u := range xssUses(r) {
			if u.XSS.Type == "stored" {
				t.Fatalf("fake database became storage: %+v", u.XSS)
			}
		}
	})
}

func TestSQLJSInjectionCandidates(t *testing.T) {
	helper := "function queryOne(sql){const r=queryAll(sql);return r[0]}\n"
	for _, tt := range []struct {
		name, handler string
		want          int
	}{
		{"built text through two helpers", "app.post('/l',(req,res)=>{const {email}=req.body;const q=`SELECT * FROM users WHERE email = '${email}'`;const u=queryOne(q);res.json(u)});", 1},
		{"destructured fields are the source", "app.post('/l',(req,res)=>{const {email,password}=req.body;res.json(queryAll(`SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`))});", 1},
		{"route parameter in run", "app.delete('/u/:id',(req,res)=>{db.run(`DELETE FROM users WHERE id = ${req.params.id}`);res.json({})});", 1},
		{"try does not guard its query", "app.get('/s',(req,res)=>{try{const r=queryAll(`SELECT * FROM notes WHERE t = '${req.query.q}'`);res.json(r)}catch(err){res.status(500).json({})}});", 1},
		{"bound values are not a claim", "app.post('/n',(req,res)=>{db.run('INSERT INTO notes (body) VALUES (?)',[req.body.b]);res.json({})});", 0},
		{"literal SQL is not a claim", "app.get('/n',(_req,res)=>{res.json(queryAll('SELECT body FROM notes'))});", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeFiles(t, map[string]string{"app.js": sqlJSPrelude + helper + "app.use(express.json());" + tt.handler})
			count := 0
			for _, u := range r.Uses {
				if u.Kind != "sql_query_candidate" {
					continue
				}
				count++
				if u.APIModel == nil || u.APIModel.ID != "sqljs-statement-v1" || len(u.Completeness.Evidence["sink_binding"]) == 0 {
					t.Fatalf("sql.js contract or binding missing: %+v", u)
				}
				if len(u.Completeness.Blockers) != 0 {
					t.Fatalf("unexpected blockers: %+v", u.Completeness.Blockers)
				}
				if len(u.Completeness.Evidence["input_source"]) == 0 {
					t.Fatal("input_source evidence missing")
				}
			}
			if count != tt.want {
				t.Fatalf("want %d SQL candidates, got %d", tt.want, count)
			}
		})
	}
	t.Run("finally stays a control gap", func(t *testing.T) {
		r := analyzeFiles(t, map[string]string{"app.js": sqlJSPrelude + "app.get('/s',(req,res)=>{try{res.json(queryAll(`SELECT * FROM notes WHERE t = '${req.query.q}'`))}finally{res.end()}});"})
		for _, u := range r.Uses {
			if u.Kind == "sql_query_candidate" && len(u.Completeness.Blockers) == 0 {
				t.Fatalf("finally must keep a blocker: %+v", u)
			}
		}
	})
	t.Run("an unverified receiver is not a sink", func(t *testing.T) {
		source := strings.ReplaceAll(sqlJSPrelude, "require('sql.js')", "require('./fake')")
		r := analyzeFiles(t, map[string]string{"app.js": source + "app.delete('/u/:id',(req,res)=>{db.run(`DELETE FROM users WHERE id = ${req.params.id}`);res.json({})});", "fake.js": "module.exports=()=>({})"})
		for _, u := range r.Uses {
			if u.Kind == "sql_query_candidate" {
				t.Fatalf("fake database became a SQL sink: %+v", u)
			}
		}
	})
}

func sequelizeFixture(setter, sanitizerVersion string) map[string]string {
	return map[string]string{
		"package.json": `{"dependencies":{"sanitize-html":"` + sanitizerVersion + `"}}`,
		"lib.ts":       "import sanitizeLib from 'sanitize-html'\nexport const clean = (h: string) => sanitizeLib(h)\nexport const legacy = (i = '') => i.replace(/<(?:\\w+)\\W+?[\\w]/gi, '')\n",
		"note.ts":      "import { Model, DataTypes } from 'sequelize'\nimport * as lib from './lib'\nexport class Note extends Model {}\nexport const init = (sequelize: any) => { Note.init({ body: { type: DataTypes.STRING, set (body: string) { " + setter + "; this.setDataValue('body', body) } } }, { tableName: 'Notes', sequelize }) }\n",
		"app.ts":       "import express from 'express'\nimport { Note } from './note'\nconst app = express()\napp.post('/n', async (req, res) => { await Note.create({ body: req.body.b }); res.redirect('/n') })\napp.get('/n', async (_req, res) => { const n = await Note.findByPk(1); res.send(`<p>${n.body}</p>`) })\n",
	}
}

func TestModelSetterSemantics(t *testing.T) {
	for _, tt := range []struct{ name, setter, version, want string }{
		{"no reassignment stores raw", "", "2.0.0", "raw"},
		{"old sanitize-html is bypassable", "body = lib.clean(body)", "1.4.2", "ineffective"},
		{"fixed sanitize-html protects", "body = lib.clean(body)", "1.4.3", "sanitized"},
		{"version range establishes nothing", "body = lib.clean(body)", "^1.4.2", "sanitized"},
		{"single-pass tag stripping is bypassable", "body = lib.legacy(body)", "2.0.0", "ineffective"},
		{"a raw branch beats a sanitized sibling", "if (body.length > 3) { body = lib.clean(body) }", "2.0.0", "raw"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := xssUses(analyzeFiles(t, sequelizeFixture(tt.setter, tt.version)))
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want || !uses[0].XSS.OriginResolved {
				t.Fatalf("want %s got %+v", tt.want, uses)
			}
		})
	}
}

func TestStoredPathCompactionKeepsEveryClass(t *testing.T) {
	u := &analysis.CandidateUse{}
	var deps []analysis.Dependency
	var protections, entries []string
	for i := 0; i < 12; i++ {
		start := 1
		protection := "unknown"
		if i == 11 {
			start, protection = 2, "raw"
		}
		deps = append(deps, analysis.Dependency{Source: analysis.Evidence{Span: analysis.Span{File: "a", StartByte: start}}})
		protections, entries = append(protections, protection), append(entries, "")
	}
	got, kept, _ := compactStoredPaths(u, deps, protections, entries)
	if len(got) != 2 || kept[1] != "raw" || len(u.Gaps) != 1 || u.Gaps[0].Kind != "stored_paths_compacted" {
		t.Fatalf("got %d paths %v gaps %+v", len(got), kept, u.Gaps)
	}
	few, _, _ := compactStoredPaths(&analysis.CandidateUse{}, deps[:8], protections[:8], entries[:8])
	if len(few) != 8 {
		t.Fatal("a small path set must stay complete")
	}
}

func TestGeneratedIdentifierIsNotAStoredClaim(t *testing.T) {
	app := func(write string) map[string]string {
		return map[string]string{
			"app.js":         "const express=require('express');const mongoose=require('mongoose');const Note=mongoose.model('Note');const app=express();app.set('view engine','ejs');app.post('/w',(req,res)=>{" + write + "});app.get('/r',(req,res)=>{Note.find({}).exec(function(err,notes){res.render('page',{notes})})})",
			"views/page.ejs": `<% notes.forEach(function(note){ %><a href="/edit/<%= note._id %>">x</a><% }); %>`,
		}
	}
	if uses := xssUses(analyzeFiles(t, app("new Note({body:req.body.t}).save()"))); len(uses) != 0 {
		t.Fatalf("generated _id became a claim: %+v", uses)
	}
	if uses := xssUses(analyzeFiles(t, app("new Note({_id:req.body.t}).save()"))); len(uses) != 1 {
		t.Fatalf("a request-written _id must stay a claim: %+v", uses)
	}
}

func TestSanitizerContractsOnNovelInputs(t *testing.T) {
	text, attribute := "<p>${v}</p>", `<a title="${v}">x</a>`
	for _, tt := range []struct{ name, library, version, expression, output, want string }{
		{"advisory version is bypassable", "sanitize-html", "1.4.2", "sanitizeHtml(req.query.q)", text, "ineffective"},
		{"fixed version protects", "sanitize-html", "1.4.3", "sanitizeHtml(req.query.q)", text, "sanitized"},
		{"a range matches no advisory", "sanitize-html", "^1.4.2", "sanitizeHtml(req.query.q)", text, "sanitized"},
		{"custom options are not trusted", "sanitize-html", "1.4.2", "sanitizeHtml(req.query.q,{allowedTags:[]})", text, "unknown"},
		{"default-config advisory inside a later line", "sanitize-html", "2.17.3", "sanitizeHtml(req.query.q)", text, "ineffective"},
		{"its fixed release protects", "sanitize-html", "2.17.4", "sanitizeHtml(req.query.q)", text, "sanitized"},
		{"marked before the fix", "marked", "0.3.4", "marked(req.query.q)", text, "ineffective"},
		{"marked after the fix is not protection", "marked", "0.3.6", "marked(req.query.q)", text, "unknown"},
		{"tag-stripping regex", "x", "1.0.0", "req.query.q.replace(/<[^>]*>/g,'')", text, "ineffective"},
		{"grouped tag-stripping regex", "x", "1.0.0", "req.query.q.replace(/(<([^>]+)>)/gi,'')", text, "ineffective"},
		{"script-tag stripping", "x", "1.0.0", "req.query.q.replace(/<\\/?script>/gi,'')", text, "ineffective"},
		{"non-global stripping", "x", "1.0.0", "req.query.q.replace(/<[^>]*>/,'')", text, "ineffective"},
		{"alternative that strips a tag", "x", "1.0.0", "req.query.q.replace(/javascript:|<script>/gi,'')", text, "ineffective"},
		{"literal tag deleted by replaceAll", "x", "1.0.0", "req.query.q.replaceAll('<script>','')", text, "ineffective"},
		{"every angle bracket deleted", "x", "1.0.0", "req.query.q.replace(/[<>]/g,'')", text, "sanitized"},
		{"one angle bracket deleted", "x", "1.0.0", "req.query.q.replace(/[<>]/,'')", text, "ineffective"},
		{"every < encoded", "x", "1.0.0", "req.query.q.replace(/</g,'&lt;')", text, "sanitized"},
		{"every < deleted by replaceAll", "x", "1.0.0", "req.query.q.replaceAll('<','')", text, "sanitized"},
		{"angle deletion does not protect an attribute", "x", "1.0.0", "req.query.q.replace(/[<>]/g,'')", attribute, "unknown"},
		{"angle and quote deletion protects an attribute", "x", "1.0.0", "req.query.q.replace(/[<>\"']/g,'')", attribute, "sanitized"},
		{"stripping after encoding keeps the encoding", "x", "1.0.0", "he.encode(req.query.q).replace(/<script>/g,'')", text, "sanitized"},
		{"encoding after stripping protects", "x", "1.0.0", "he.encode(req.query.q.replace(/<script>/g,''))", text, "sanitized"},
		{"an unrelated pattern claims nothing", "x", "1.0.0", "req.query.q.replace(/a+b/g,'')", text, "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := analyzeFiles(t, map[string]string{
				"package.json": `{"dependencies":{"` + tt.library + `":"` + tt.version + `"}}`,
				"app.js":       "const express=require('express');const sanitizeHtml=require('sanitize-html');const marked=require('marked');const he=require('he');const app=express();\napp.get('/a',(req,res)=>{const v=" + tt.expression + ";res.send(`" + tt.output + "`)})\n",
			})
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want {
				t.Fatalf("want %s got %v", tt.want, summarize(uses))
			}
		})
	}
}

func TestAdvisoryRangesAreHalfOpen(t *testing.T) {
	for _, tt := range []struct {
		version string
		want    bool
	}{{"2.17.2", false}, {"2.17.3", true}, {"2.17.4", false}, {"0.0.0", true}, {"1.4.3", false}, {"2.17.3-beta.1", false}, {"~2.17.3", false}} {
		v, ok := exactVersion(tt.version)
		hit := false
		for _, a := range sanitizerAdvisories {
			if ok && a.library == "sanitize-html" && !versionLess(v, a.introduced) && versionLess(v, a.fixed) {
				hit = true
			}
		}
		if hit != tt.want {
			t.Fatalf("%s: want %v", tt.version, tt.want)
		}
	}
}

func TestRegexStripKeepsDeletingAllAnglesUnknown(t *testing.T) {
	uses := xssUses(analyzeFiles(t, map[string]string{"app.js": "const express=require('express');const app=express();app.get('/a',(req,res)=>{res.send(`<p>${req.query.q.replace(/</g,'')}</p>`)})"}))
	if len(uses) != 1 || uses[0].XSS.Protection == "ineffective" {
		t.Fatalf("deleting every angle bracket is not tag stripping: %+v", uses)
	}
}

func angularFixture(component, html string) map[string]string {
	return map[string]string{
		"package.json":        `{"dependencies":{"@angular/core":"19.0.0"}}`,
		"server.ts":           "import express from 'express'\nimport * as finale from 'finale-rest'\nimport { Note } from './note'\nconst app = express()\nfinale.resource({ model: Note, endpoints: ['/api/Notes', '/api/Notes/:id'], excludeAttributes: ['secret'] })\n",
		"note.ts":             "import { Model, DataTypes } from 'sequelize'\nexport class Note extends Model {}\nexport const init = (sequelize: any) => { Note.init({ body: DataTypes.STRING, secret: DataTypes.STRING, stars: DataTypes.INTEGER }, { tableName: 'Notes', sequelize }) }\n",
		"note.service.ts":     "import { HttpClient } from '@angular/common/http'\nimport { map } from 'rxjs/operators'\nimport { Injectable, inject } from '@angular/core'\n@Injectable()\nexport class NoteService {\n  private readonly http = inject(HttpClient)\n  private readonly host = '/api/Notes'\n  find () { return this.http.get(this.host + '/').pipe(map((response: any) => response.data)) }\n}\n",
		"view.component.ts":   "import { Component, inject } from '@angular/core'\nimport { DomSanitizer } from '@angular/platform-browser'\nimport { NoteService } from './note.service'\n@Component({ selector: 'app-view', templateUrl: './view.component.html' })\nexport class ViewComponent {\n  private readonly sanitizer = inject(DomSanitizer)\n  private readonly notes = inject(NoteService)\n" + component + "\n}\n",
		"view.component.html": html,
	}
}

func TestAngularCrossTierAliases(t *testing.T) {
	loop := func(field string) string {
		return "  load () { this.notes.find().subscribe({ next: (rows) => { for (const row of rows) { row." + field + " = this.sanitizer.bypassSecurityTrustHtml(row." + field + ") } } }) }"
	}
	for _, tt := range []struct {
		name, component, html string
		protection            string
		resolved              bool
	}{
		{"iteration variable renders a trusted REST column", loop("body"), `<p *ngFor="let row of rows" [innerHTML]="row.body"></p>`, "raw", true},
		{"excluded attribute has no response origin", loop("secret"), `<p *ngFor="let row of rows" [innerHTML]="row.secret"></p>`, "raw", false},
		{"numeric column has no markup origin", loop("stars"), `<p *ngFor="let row of rows" [innerHTML]="row.stars"></p>`, "raw", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var outputs []analysis.CandidateUse
			for _, u := range xssUses(analyzeFiles(t, angularFixture(tt.component, tt.html))) {
				if u.Sink.Kind == "angular_output" {
					outputs = append(outputs, u)
				}
			}
			if len(outputs) != 1 || outputs[0].XSS.Protection != tt.protection || outputs[0].XSS.OriginResolved != tt.resolved {
				t.Fatalf("got %+v", outputs)
			}
		})
	}
	t.Run("a component field of the same name is not an iteration variable", func(t *testing.T) {
		for _, u := range xssUses(analyzeFiles(t, angularFixture(loop("body"), `<p [innerHTML]="row.body"></p>`))) {
			if u.Sink.Kind == "angular_output" {
				t.Fatalf("binding without `let row` was linked: %+v", u)
			}
		}
	})
}

func TestAngularDialogRequiresEveryEdge(t *testing.T) {
	base := func(html string) map[string]string {
		files := angularFixture("  load () { this.notes.find().subscribe({ next: (rows) => { for (const row of rows) { row.body = this.sanitizer.bypassSecurityTrustHtml(row.body) } } }) }", html)
		files["card.component.ts"] = "import { Component, inject } from '@angular/core'\nimport { MatDialog } from '@angular/material/dialog'\nimport { DetailComponent } from './detail.component'\n@Component({ selector: 'app-card', templateUrl: './card.component.html' })\nexport class CardComponent {\n  private readonly dialog = inject(MatDialog)\n  show (note: any) { this.dialog.open(DetailComponent, { data: { note } }) }\n}\n"
		files["card.component.html"] = "<button (click)=\"show(item)\"></button>"
		files["detail.component.ts"] = "import { Component, inject } from '@angular/core'\nimport { MAT_DIALOG_DATA } from '@angular/material/dialog'\n@Component({ selector: 'app-detail', templateUrl: './detail.component.html' })\nexport class DetailComponent {\n  data = inject(MAT_DIALOG_DATA)\n}\n"
		files["detail.component.html"] = `<div [innerHTML]="data.note.body"></div>`
		return files
	}
	find := func(files map[string]string) *analysis.CandidateUse {
		uses := xssUses(analyzeFiles(t, files))
		for i := range uses {
			if strings.HasSuffix(uses[i].Sink.Span.File, "detail.component.html") {
				return &uses[i]
			}
		}
		return nil
	}
	if u := find(base(`<app-card [item]="row"></app-card>`)); u == nil || u.XSS.Protection != "raw" || !u.XSS.OriginResolved {
		t.Fatalf("linked dialog: %+v", u)
	}
	if u := find(base(`<p>no card here</p>`)); u != nil {
		t.Fatalf("selector edge missing, still linked: %+v", u)
	}
}

func TestTokenClaimRequiresSignedModelField(t *testing.T) {
	files := func(claim string) map[string]string {
		return map[string]string{
			"package.json":      `{"dependencies":{"@angular/core":"19.0.0"}}`,
			"note.ts":           "import { Model, DataTypes } from 'sequelize'\nexport class User extends Model {}\nexport const init = (sequelize: any) => { User.init({ ip: DataTypes.STRING }, { tableName: 'Users', sequelize }) }\n",
			"sec.ts":            "import jwt from 'jsonwebtoken'\nexport const authorize = (user = {}) => jwt.sign(user, 'k')\n",
			"wrap.ts":           "export const wrap = (data: any, status: string = 'ok') => { return { status, data } }\n",
			"server.ts":         "import express from 'express'\nimport { User } from './note'\nimport * as sec from './sec'\nimport * as w from './wrap'\nconst app = express()\napp.get('/save', async (req, res) => { const u = await User.findByPk(1); const saved = await u.update({ ip: req.headers['x-ip'] }); const t = sec.authorize(w.wrap(saved)); res.json({ t }) })\n",
			"ip.component.ts":   "import { Component, inject } from '@angular/core'\nimport { DomSanitizer } from '@angular/platform-browser'\nimport { jwtDecode } from 'jwt-decode'\n@Component({ selector: 'app-ip', templateUrl: './ip.component.html' })\nexport class IpComponent {\n  private readonly sanitizer = inject(DomSanitizer)\n  shown: any\n  read () { const payload: any = jwtDecode(localStorage.getItem('token')); this.shown = this.sanitizer.bypassSecurityTrustHtml(`<b>${payload." + claim + "}</b>`) }\n}\n",
			"ip.component.html": `<p [innerHTML]="shown"></p>`,
		}
	}
	for _, tt := range []struct {
		claim    string
		resolved bool
	}{{"data.ip", true}, {"data.other", false}, {"ip", false}} {
		t.Run(tt.claim, func(t *testing.T) {
			uses := xssUses(analyzeFiles(t, files(tt.claim)))
			if len(uses) != 1 || uses[0].XSS.OriginResolved != tt.resolved || uses[0].XSS.Type != "cross_tier" {
				t.Fatalf("got %+v", uses)
			}
		})
	}
}

func TestPythonFrameworkHTMLResponses(t *testing.T) {
	for _, tt := range []struct {
		name, source string
		want         []string
	}{
		{"django default is HTML", "from django.http import HttpResponse\nfrom django.urls import path\ndef view(request):\n    return HttpResponse('<p>' + request.GET['q'] + '</p>')\nurlpatterns = [path('a', view)]\n", []string{"reflected/html_text/raw", "reflected/html_text/raw"}},
		{"django explicit non-HTML", "from django.http import HttpResponse\nfrom django.urls import path\ndef view(request):\n    return HttpResponse(request.GET['q'], content_type='text/plain')\nurlpatterns = [path('a', view)]\n", nil},
		{"aiohttp must state HTML", "from aiohttp import web\nasync def view(request):\n    return web.Response(text=request.rel_url.query.get('q'))\napp = web.Application()\napp.add_routes([web.get('/a', view)])\n", nil},
		{"aiohttp stated HTML", "from aiohttp import web\nasync def view(request):\n    return web.Response(text=request.rel_url.query.get('q'), content_type='text/html')\napp = web.Application()\napp.add_routes([web.get('/a', view)])\n", []string{"reflected/html_text/raw"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := summarize(pythonXSSOnly(analyzeFiles(t, map[string]string{"app.py": tt.source}).Uses))
			if strings.Join(got, ",") != strings.Join(tt.want, ",") {
				t.Fatalf("want %v got %v", tt.want, got)
			}
		})
	}
}

func TestJinjaEnvironmentAutoescape(t *testing.T) {
	source := func(option string) string {
		return "from pathlib import Path\nfrom flask import Flask, request\nfrom jinja2 import Environment, FileSystemLoader\nenv = Environment(loader=FileSystemLoader(Path(__file__).parent / 'templates')" + option + ")\napp = Flask(__name__)\n@app.route('/a')\ndef view():\n    return env.get_template('a.html').render(q=request.args.get('q'))\n"
	}
	for _, tt := range []struct{ name, option, template, want string }{
		{"default environment does not escape", "", "<p>{{ q }}</p>", "raw"},
		{"autoescape escapes", ", autoescape=True", "<p>{{ q }}</p>", "encoded"},
		{"safe filter defeats autoescape", ", autoescape=True", "<p>{{ q | safe }}</p>", "raw"},
		{"computed autoescape is unknown", ", autoescape=select_autoescape()", "<p>{{ q }}</p>", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := pythonXSSOnly(analyzeFiles(t, map[string]string{"app.py": source(tt.option), "templates/a.html": tt.template}).Uses)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.want {
				t.Fatalf("want %s got %+v", tt.want, uses)
			}
		})
	}
}
