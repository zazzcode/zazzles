package langjs

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestAuthorizationWrittenValues covers hardening 3 D-8: an update carries, as
// a fact, whether any written value depends on the request and, for an update
// document, the operators it uses. The fact states no judgment.
func TestAuthorizationWrittenValues(t *testing.T) {
	const sequelize = `import express from 'express'
import { Model, DataTypes } from 'sequelize'
class Ticket extends Model {}
Ticket.init({ state: DataTypes.STRING, votes: DataTypes.INTEGER }, { sequelize })
const app = express()
`
	const collection = `const express = require('express')
const MarsDB = require('marsdb')
const posts = new MarsDB.Collection('posts')
const site = express()
`
	for _, tt := range []struct {
		name, source, file string
		dependent          string // "" when the record must carry no fact
		operators          string
	}{
		{"increment by a constant", collection + `site.post('/posts/like', (request, response) => { posts.update({ _id: request.body.ref }, { $inc: { likes: 1 } }); response.send('ok') })`, "api.js", "no", "$inc"},
		{"set a request value", collection + `site.post('/posts/edit', (request, response) => { posts.update({ _id: request.body.ref }, { $set: { text: request.body.text } }); response.send('ok') })`, "api.js", "yes", "$set"},
		{"two operators, one request value", collection + `site.post('/posts/tag', (request, response) => { posts.update({ _id: request.body.ref }, { $push: { tags: request.body.tag }, $inc: { edits: 1 } }); response.send('ok') })`, "api.js", "yes", "$inc,$push"},
		{"comments between the arguments", collection + `site.post('/posts/edit', (request, response) => { posts.update( // selector
  { _id: request.body.ref }, // document
  { $set: { text: request.body.text } }); response.send('ok') })`, "api.js", "yes", "$set"},
		{"value from a lookup", collection + `site.post('/posts/stamp', (request, response) => { posts.update({ _id: request.body.ref }, { $set: { stamp: clock.now() } }); response.send('ok') })`, "api.js", "unknown", "$set"},
		{"remove carries no fact", collection + `site.post('/posts/drop', (request, response) => { posts.remove({ _id: request.body.ref }); response.send('ok') })`, "api.js", "", ""},
		{"transfer: model update with constants", sequelize + `app.put('/tickets/:id', (req, res) => { Ticket.update({ state: 'closed' }, { where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "no", ""},
		{"transfer: model update with a request value", sequelize + `app.put('/tickets/:id', (req, res) => { Ticket.update({ state: req.body.state }, { where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: instance update through a constant alias", sequelize + `app.put('/tickets/:id', async (req, res) => { const next = req.body.state; const row = await Ticket.findByPk(req.params.id); await row.update({ state: next }); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: increment a named column", sequelize + `app.post('/tickets/:id/vote', (req, res) => { Ticket.increment('votes', { where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "no", ""},
		// The amount of an increment is its `by` option (Sequelize v6, Model.increment).
		{"transfer: increment by a request amount", sequelize + `app.post('/tickets/:id/vote', (req, res) => { Ticket.increment('votes', { by: req.body.weight, where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: decrement by a constant amount", sequelize + `app.post('/tickets/:id/vote', (req, res) => { Ticket.decrement(['votes'], { by: 2, where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "no", ""},
		{"transfer: increment by a looked-up amount", sequelize + `app.post('/tickets/:id/vote', (req, res) => { Ticket.increment('votes', { by: weights.current(), where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "unknown", ""},
		// A save writes whatever the handler put on the instance. "no" needs every
		// change of the instance to be a literal member assignment.
		{"transfer: save after literal assignments only", sequelize + `app.put('/tickets/:id', async (req, res) => { const row = await Ticket.findByPk(req.params.id); row.state = 'closed'; await row.save(); res.send('ok') })`, "server.ts", "no", ""},
		{"transfer: save after the request is copied onto the instance", sequelize + `app.put('/tickets/:id', async (req, res) => { const row = await Ticket.findByPk(req.params.id); row.state = 'closed'; Object.assign(row, req.body); await row.save(); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: save after a setter call with the request", sequelize + `app.put('/tickets/:id', async (req, res) => { const row = await Ticket.findByPk(req.params.id); row.set(req.body); row.state = 'closed'; await row.save(); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: save after a computed member write", sequelize + `app.put('/tickets/:id', async (req, res) => { const row = await Ticket.findByPk(req.params.id); row.state = 'closed'; row[req.body.field] = req.body.value; await row.save(); res.send('ok') })`, "server.ts", "yes", ""},
		{"transfer: save after a call that receives the instance", sequelize + `app.put('/tickets/:id', async (req, res) => { const row = await Ticket.findByPk(req.params.id); row.state = 'closed'; stamp(row); await row.save(); res.send('ok') })`, "server.ts", "unknown", ""},
		{"transfer: destroy carries no fact", sequelize + `app.delete('/tickets/:id', (req, res) => { Ticket.destroy({ where: { id: req.params.id } }); res.send('ok') })`, "server.ts", "", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := claimOfKind(t, map[string]string{tt.file: tt.source}, analysis.AuthorizationKind)
			if err := u.Authorization.Validate(); err != nil {
				t.Fatal(err)
			}
			w := u.Authorization.Written
			if tt.dependent == "" {
				if w != nil {
					t.Fatalf("a %s must carry no written-values fact: %+v", u.Authorization.Operation.Operation, w)
				}
				return
			}
			if w == nil {
				t.Fatal("update carries no written-values fact")
			}
			if w.RequestDependent != tt.dependent || strings.Join(w.Operators, ",") != tt.operators {
				t.Fatalf("written values = %s [%s], want %s [%s]", w.RequestDependent, strings.Join(w.Operators, ","), tt.dependent, tt.operators)
			}
		})
	}
}

// TestDirectoryListingContents covers hardening 3 D-9: a directory-listing
// record joins the names of up to eight entries of the listed directory at the
// scan root, sorted, with the total count; an absent or empty directory is
// stated as such.
func TestDirectoryListingContents(t *testing.T) {
	source := func(receiver, dir string) string {
		return "import express from 'express';\nimport browse from 'serve-index';\nconst " + receiver + " = express();\n" + receiver + ".use('/files', browse('" + dir + "', { icons: true }));"
	}
	for _, tt := range []struct {
		name, receiver, dir string
		entries             []string // created under dir; a trailing slash makes a directory
		create              bool
		want                []string
		not                 string
	}{
		{"two files and a directory", "app", "public", []string{"notes.md", "archive/", "a.txt"}, true, []string{"3 entries", "a.txt, archive/, notes.md"}, "first"},
		{"more than eight entries", "app", "drop", []string{"k.txt", "j.txt", "i.txt", "h.txt", "g.txt", "f.txt", "e.txt", "d.txt", "c.txt", "b.txt", "a.txt"}, true, []string{"11 entries", "a.txt, b.txt, c.txt, d.txt, e.txt, f.txt, g.txt, h.txt"}, "i.txt"},
		{"empty directory", "app", "spool", nil, true, []string{"is empty"}, "entries:"},
		{"transfer: absent directory", "site", "var/reports", nil, false, []string{"is not in the scanned tree"}, "entries:"},
		{"transfer: nested directory", "site", "var/reports", []string{"q1.csv"}, true, []string{"1 entry", "q1.csv"}, "is empty"},
		{"directory outside the scan root is not read", "site", "../elsewhere", nil, false, nil, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", source(tt.receiver, tt.dir))
			if tt.create {
				if err := os.MkdirAll(filepath.Join(root, tt.dir), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range tt.entries {
				p := filepath.Join(root, tt.dir, name)
				if strings.HasSuffix(name, "/") {
					if err := os.MkdirAll(p, 0755); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(p, []byte("x"), 0644); err != nil {
					t.Fatal(err)
				}
			}
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var contents []analysis.Evidence
			found := 0
			for _, u := range report.Uses {
				if u.Kind != analysis.ConfigurationKind || u.Configuration.Check != analysis.CheckDirectoryListing {
					continue
				}
				found++
				for _, e := range u.Configuration.Joined {
					if e.Kind == "directory_contents" {
						contents = append(contents, e)
					}
				}
			}
			if found != 1 {
				t.Fatalf("directory listing records: %d", found)
			}
			if tt.want == nil {
				if len(contents) != 0 {
					t.Fatalf("a directory outside the scan root must not be read: %+v", contents)
				}
				return
			}
			if len(contents) != 1 {
				t.Fatalf("directory_contents facts: %d", len(contents))
			}
			text := contents[0].ModelText
			for _, w := range tt.want {
				if !strings.Contains(text, w) {
					t.Fatalf("fact %q does not state %q", text, w)
				}
			}
			if tt.not != "" && strings.Contains(text, tt.not) {
				t.Fatalf("fact %q must not state %q", text, tt.not)
			}
		})
	}
}

// TestRedirectAnchoredPathPattern covers hardening 3 D-10. A browser resolves
// a redirect target with the WHATWG URL parser, where a backslash is a slash
// for http(s) (https://url.spec.whatwg.org/#relative-slash-state). A pattern
// admits only a same-origin path when it is anchored with ^\/ and the class
// after it excludes both the slash and the backslash.
func TestRedirectAnchoredPathPattern(t *testing.T) {
	for _, tt := range []struct {
		name, pattern string
		bypass        string // forms the predicate permits; "" for a same-origin path test; "-" when no predicate is recognized
	}{
		{"anchored, class excludes slash and backslash", `/^\/[^\/\\]/`, ""},
		{"anchored, class excludes the slash only", `/^\/[^\/]/`, "slash_backslash"},
		{"anchored slash alone", `/^\//`, "protocol_relative,slash_backslash"},
		{"unanchored", `/\/safe/`, "-"},
		{"anchored, any second character", `/^\/./`, "protocol_relative,slash_backslash"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			for i, source := range []string{
				"import express from 'express';\nconst app = express();\napp.get('/go', (req, res) => { const to = req.query.to; if (" + tt.pattern + ".test(to)) { res.redirect(to) } else { res.status(400).end() } })",
				"import express from 'express';\nconst site = express();\nsite.get('/leave', function (request, reply) { const target = request.query.next; if (target.match(" + tt.pattern + ") === null) { return reply.sendStatus(400) }; reply.redirect(target) })",
			} {
				u := claimOfKind(t, map[string]string{"server.ts": source}, "open_redirect_candidate")
				bypass, recognized := "", false
				for _, fact := range u.Completeness.ModelFacts {
					if rest, ok := strings.CutPrefix(fact, "redirect_predicate_bypass: "); ok {
						bypass = rest
					}
					recognized = recognized || strings.HasPrefix(fact, "redirect_normalization: ")
				}
				label := fmt.Sprintf("project %d", i)
				if tt.bypass == "-" {
					if recognized {
						t.Fatalf("%s: an unanchored pattern must not be recognized as a path predicate: %v", label, u.Completeness.ModelFacts)
					}
					continue
				}
				if !recognized {
					t.Fatalf("%s: predicate not recognized: %v", label, u.Completeness.ModelFacts)
				}
				for _, form := range strings.Split(tt.bypass, ",") {
					if form != "" && !strings.Contains(bypass, form) {
						t.Fatalf("%s: bypass forms %q, want %q", label, bypass, tt.bypass)
					}
				}
				if tt.bypass == "" && bypass != "" {
					t.Fatalf("%s: a same-origin path test must record no bypass form, got %q", label, bypass)
				}
			}
		})
	}
}
