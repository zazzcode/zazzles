package langjs

import (
	"sort"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestExpressRejectsAll covers the express-jwt contract that a middleware
// whose secret is a fresh random value accepts no request, and that a mount on
// the same path pattern as the route covers it.
func TestExpressRejectsAll(t *testing.T) {
	const head = `import express from 'express';
import { expressjwt } from 'express-jwt';
import crypto from 'node:crypto';
const app = express();
`
	for _, tt := range []struct {
		name, body, entry, want string
		rejects                 bool
	}{
		{"Math.random secret", `const closed = () => expressjwt({ secret: '' + Math.random() } as any);
app.put('/x/:id', closed(), (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessRequired, true},
		{"crypto random secret", `app.put('/x/:id', expressjwt({ secret: crypto.randomBytes(32).toString('hex'), algorithms: ['HS256'] }), (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessRequired, true},
		{"constant secret", `app.put('/x/:id', expressjwt({ secret: 's', algorithms: ['HS256'] }), (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessRequired, false},
		{"secret held in a shared variable", `const key = crypto.randomBytes(32).toString('hex');
app.put('/x/:id', expressjwt({ secret: key, algorithms: ['HS256'] }), (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessRequired, false},
		{"mount on the same pattern", `app.use('/x/:id', expressjwt({ secret: 's', algorithms: ['HS256'] }));
app.put('/x/:id', (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessRequired, false},
		{"mount on another pattern stays unresolved", `app.use('/x/:name/edit', expressjwt({ secret: 's', algorithms: ['HS256'] }));
app.put('/x/:id', (req, res) => { res.send('ok') })`, "PUT /x/:id", analysis.AccessUnresolved, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", head+tt.body)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			access := entryAccessOf(t, report, tt.entry)
			if access == nil {
				t.Fatal("entry has no access record")
			}
			if access.Authentication != tt.want || access.RejectsAll != tt.rejects {
				t.Fatalf("authentication = %q rejects_all = %v, want %q %v (sources %+v)", access.Authentication, access.RejectsAll, tt.want, tt.rejects, access.Sources)
			}
		})
	}
}

// TestExpressGeneratedReachability: a generated endpoint that no request can
// reach makes no claim, registrations written as a route chain count, and an
// attribute a registered middleware overwrites is not request-chosen.
func TestExpressGeneratedReachability(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "api.ts", `import express from 'express'
import finale from 'finale-rest'
import { expressjwt } from 'express-jwt'
import { Model, DataTypes } from 'sequelize'

class Note extends Model {}
Note.init({ text: DataTypes.STRING, ownerId: DataTypes.INTEGER }, { sequelize })
class Label extends Model {}
Label.init({ text: DataTypes.STRING }, { sequelize })

const closed = () => expressjwt({ secret: '' + Math.random() } as any)
const signedIn = () => expressjwt({ secret: 'k', algorithms: ['HS256'] })
const stamp = () => (req, res, next) => { req.body.ownerId = 7; next() }

const app = express()
app.post('/api/Notes', stamp())
app.route('/api/Notes/:id')
  .get(signedIn())
  .put(closed())
  .delete(signedIn())
app.post('/api/Labels', closed())
app.use('/api/Labels/:id', closed())
finale.initialize({ app, sequelize })
finale.resource({ model: Note, endpoints: ['/api/Notes', '/api/Notes/:id'] })
finale.resource({ model: Label, endpoints: ['/api/Labels', '/api/Labels/:id'] })
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]analysis.EntryPoint{}
	for _, e := range report.Entries {
		names[e.ID] = e
	}
	var got []string
	for _, u := range report.Uses {
		if u.Kind != analysis.MassAssignmentKind && u.Kind != analysis.AuthorizationKind {
			continue
		}
		e := names[u.EntryID]
		got = append(got, u.Kind+" "+e.Name)
		if u.Kind == analysis.MassAssignmentKind {
			for _, f := range u.MassAssignment.MappedFields {
				if f == "ownerId" {
					t.Errorf("%s: an attribute the registered middleware overwrites is listed as request-chosen", e.Name)
				}
			}
		}
		if e.Name == "DELETE /api/Notes/:id" && (e.Access == nil || e.Access.Authentication != analysis.AccessRequired || e.Access.RejectsAll) {
			t.Errorf("DELETE /api/Notes/:id access = %+v, want required from the route chain", e.Access)
		}
	}
	sort.Strings(got)
	want := []string{
		analysis.AuthorizationKind + " DELETE /api/Notes/:id",
		analysis.MassAssignmentKind + " POST /api/Notes",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("records:\n got %v\nwant %v", got, want)
	}
}

// TestExpressGeneratedAnsweredFirst: a generated endpoint makes no claim when a
// handler registered earlier for the same method and path cannot pass the
// request on, because it declares no next parameter.
func TestExpressGeneratedAnsweredFirst(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "api.ts", `import express from 'express'
import finale from 'finale-rest'
import { Model, DataTypes } from 'sequelize'

class Memo extends Model {}
Memo.init({ text: DataTypes.STRING }, { sequelize })

const removeOwn = () => async (req, res) => { res.json({ ok: true }) }
const tag = () => (req, res, next) => { req.body.seen = true; next() }

const app = express()
app.delete('/api/Memos/:id', tag(), removeOwn())
app.put('/api/Memos/:id', tag())
finale.initialize({ app, sequelize })
finale.resource({ model: Memo, endpoints: ['/api/Memos', '/api/Memos/:id'] })
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, e := range report.Entries {
		names[e.ID] = e.Name
	}
	var got []string
	for _, u := range report.Uses {
		if u.Kind == analysis.AuthorizationKind {
			got = append(got, names[u.EntryID])
		}
	}
	sort.Strings(got)
	// The delete is answered by removeOwn; the update passes through tag.
	if want := "PUT /api/Memos/:id"; strings.Join(got, "|") != want {
		t.Fatalf("authorization entries: got %v, want [%s]", got, want)
	}
}

// TestExpressEnvSettingGuard: Express's own environment setting is an
// environment guard, as process.env.NODE_ENV is.
func TestExpressEnvSettingGuard(t *testing.T) {
	for _, tt := range []struct {
		name, cond string
		guarded    bool
	}{
		{"app.get('env')", `app.get('env') == 'development'`, true},
		{"process.env.NODE_ENV", `process.env.NODE_ENV !== 'production'`, true},
		{"another setting", `app.get('view engine') == 'pug'`, false},
		{"unrelated condition", `verbose`, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", `const express = require('express')
const errorHandler = require('errorhandler')
const app = express()
const verbose = true
if (`+tt.cond+`) {
  app.use(errorHandler())
}
app.get('/x', (req, res) => { res.send('ok') })
`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			found, guarded := false, false
			for _, u := range report.Uses {
				if u.Kind != analysis.ExposureKind {
					continue
				}
				found = true
				for _, evs := range u.Completeness.Evidence {
					for _, ev := range evs {
						if ev.Kind == "configuration_precondition" {
							guarded = true
						}
					}
				}
				for _, ev := range u.Context {
					if ev.Kind == "configuration_precondition" {
						guarded = true
					}
				}
			}
			if !found {
				t.Fatal("no exposure candidate recorded")
			}
			if guarded != tt.guarded {
				t.Fatalf("environment guard recorded = %v, want %v", guarded, tt.guarded)
			}
		})
	}
}
