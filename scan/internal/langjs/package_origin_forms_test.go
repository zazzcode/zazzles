package langjs

import "testing"

// The forms below were written for an earlier, list-based binding of the native
// MongoDB driver. They are kept as written: none was designed against the
// package-origin search. want is what that search must give. It records a call
// when one definition path from the mongodb import to its receiver exists, so a
// form where another value may also reach the receiver is recorded, and the
// decision model reads the path. A value that never comes from the package is
// never recorded.

// TestPackageOriginForms covers JavaScript modules.
func TestPackageOriginForms(t *testing.T) {
	const app = "import express from 'express'\n"
	route := func(op string) string {
		return "const app = express()\napp.use(express.json())\napp.post('/r', async (req, res) => {\n  " + op + "\n  res.json({})\n})\napp.listen(3000)\n"
	}
	const esm = "import { MongoClient } from 'mongodb'\n"
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"module collection", map[string]string{"app.js": app + esm + "const client = new MongoClient('x')\nconst users = client.db('d').collection('users')\n" + route("await users.findOne({ name: req.body.name })")}, true},
		{"inline chain", map[string]string{"app.js": app + esm + "const client = new MongoClient('x')\n" + route("await client.db('d').collection('users').deleteMany({ name: req.body.name })")}, true},
		{"connect static", map[string]string{"app.js": app + esm + "const client = await MongoClient.connect('x')\nconst db = client.db()\n" + route("await db.collection('users').updateOne({ a: 1 }, { $set: req.body })")}, true},
		{"aggregate", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.collection('a').aggregate(req.body.stages).toArray()")}, true},
		{"cursor sort", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.collection('a').find({}).sort(req.body.sort).toArray()")}, true},
		{"cursor projection", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.collection('a').find({}).limit(5).project(req.body.p).toArray()")}, true},
		{"namespace import", map[string]string{"app.js": app + "import * as mongo from 'mongodb'\nconst db = new mongo.MongoClient('x').db()\n" + route("await db.collection('a').countDocuments(req.body)")}, true},
		{"default import", map[string]string{"app.js": app + "import mongodb from 'mongodb'\nconst db = new mongodb.MongoClient('x').db()\n" + route("await db.collection('a').countDocuments(req.body)")}, true},
		{"commonjs", map[string]string{"app.js": "const express = require('express')\nconst { MongoClient } = require('mongodb')\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').replaceOne({ k: req.body.k }, {})")}, true},
		{"commonjs namespace", map[string]string{"app.js": "const express = require('express')\nconst mongo = require('mongodb')\nconst db = new mongo.MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, true},
		{"commonjs member", map[string]string{"app.js": "const express = require('express')\nconst MongoClient = require('mongodb').MongoClient\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, true},
		{"commonjs other package", map[string]string{"app.js": "const express = require('express')\nconst mongo = require('mongodb-like')\nconst db = new mongo.MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
		{"own require", map[string]string{"app.js": "import express from 'express'\nfunction require() { return { MongoClient: class { db() { return this } collection() { return { findOne() {} } } } } }\nconst mongo = require('mongodb')\nconst db = new mongo.MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
		{"spread replaces", map[string]string{"db.js": esm + "const extra = {}\nexport function connect() { return { db: new MongoClient('x').db(), ...extra } }\n", "app.js": app + "import { connect } from './db.js'\n" + route("await connect().db.collection('a').findOne(req.body)")}, true},
		{"assigned in another function", map[string]string{"app.js": app + esm + "let db = new MongoClient('x').db()\nfunction swap(other) { db = other }\n" + route("await db.collection('a').findOne(req.body)")}, true},
		{"local variable hides import", map[string]string{"db.js": esm + "export const users = new MongoClient('x').db().collection('u')\n", "app.js": app + "import { users } from './db.js'\n" + route("for (const users of [{ findOne() {} }]) { await users.findOne({ name: req.body.name }) }")}, false},
		{"hidden by array pattern", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("const [users] = [{ findOne() {} }]\n  await users.findOne({ name: req.body.name })")}, false},
		{"hidden by default pattern", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("const { users = { findOne() {} } } = {}\n  await users.findOne({ name: req.body.name })")}, false},
		{"hidden by catch", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("try { go() } catch (users) { users.findOne({ name: req.body.name }) }")}, false},
		{"hidden in a switch", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("switch (req.body.k) { case 1: const users = { findOne() {} }; users.findOne({ name: req.body.name }) }")}, false},
		{"hidden by a for variable", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("for (let users = { findOne() {} }; ; ) { users.findOne({ name: req.body.name }); break }")}, false},
		{"assigned later", map[string]string{"app.js": app + esm + "let db\nasync function init() { const c = await new MongoClient('x').connect(); db = c.db('d') }\ninit()\n" + route("await db.collection('a').distinct('k', req.body)")}, true},
		{"imported collection", map[string]string{"db.js": esm + "const client = new MongoClient('x')\nexport const users = client.db('d').collection('users')\n", "app.js": app + "import { users } from './db.js'\n" + route("await users.findOneAndDelete({ name: req.body.name })")}, true},
		{"imported getter", map[string]string{"db.js": esm + "const client = new MongoClient('x')\nexport async function getDb() {\n  await client.connect()\n  return client.db('d')\n}\n", "app.js": app + "import { getDb } from './db.js'\n" + route("const db = await getDb()\n  await db.collection('a').find(req.body).toArray()")}, true},
		{"global promise helper", map[string]string{"db.cjs": "const { MongoClient } = require('mongodb')\nasync function start() {\n  const client = new MongoClient('x')\n  return { client, db: client.db('d') }\n}\nfunction connection() {\n  if (!globalThis.__c) {\n    globalThis.__c = start().catch((e) => { throw e })\n  }\n  return globalThis.__c\n}\nasync function collection(name) {\n  return (await connection()).db.collection(name)\n}\nmodule.exports = { collection }\n", "app.js": app + "import mongo from './db.cjs'\n" + route("const a = await mongo.collection('a')\n  await a.findOne({ k: req.body.k })")}, true},
		{"destructured result", map[string]string{"db.js": esm + "export async function connect() {\n  const client = await MongoClient.connect('x')\n  return { client, db: client.db('d') }\n}\n", "app.js": app + "import { connect } from './db.js'\n" + route("const { db } = await connect()\n  await db.collection('a').findOne(req.body)")}, true},
		{"instance method", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\nclass Repo {\n  constructor() { this.items = db.collection('items') }\n  find(f) { return this.items.findOne(f) }\n}\nconst repo = new Repo()\n" + route("await repo.find({ k: req.body.k })")}, true},

		{"constant filter", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.collection('a').find({ k: 1 }).toArray()")}, false},
		{"insert", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.collection('a').insertOne({ k: req.body.k })")}, true},
		{"array find", map[string]string{"app.js": app + esm + "const list = []\n" + route("list.find((x) => x === req.body.k)")}, false},
		{"other package", map[string]string{"app.js": app + "import { MongoClient } from 'mongodb-like'\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
		{"local class", map[string]string{"app.js": app + "class MongoClient { db() { return this } collection() { return this } findOne() {} }\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
		{"shadowed", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("const users = { findOne() {} }\n  await users.findOne({ name: req.body.name })")}, false},
		{"parameter", map[string]string{"app.js": app + esm + "const users = new MongoClient('x').db().collection('u')\n" + route("const run = (users) => users.findOne({ name: req.body.name })\n  run({ findOne() {} })")}, false},
		{"reassigned to another", map[string]string{"app.js": app + esm + "let users = new MongoClient('x').db().collection('u')\nusers = { findOne() {} }\n" + route("await users.findOne({ name: req.body.name })")}, true},
		{"mixed returns", map[string]string{"app.js": app + esm + "const c = new MongoClient('x')\nfunction get(x) { if (x) { return { findOne() {} } } return c.db().collection('u') }\n" + route("await get(1).findOne({ name: req.body.name })")}, true},
		{"method on db", map[string]string{"app.js": app + esm + "const db = new MongoClient('x').db()\n" + route("await db.find({ name: req.body.name })")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "package.json", `{"type":"module","dependencies":{"express":"5.1.0","mongodb":"7.0.0"}}`)
			for f, src := range c.files {
				writeSource(t, root, f, src)
			}
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			bound := false
			for _, u := range r.Uses {
				if u.Kind == "nosql_query_candidate" && u.APIModel != nil && u.APIModel.ID == "mongodb-document-query-v1" {
					bound = true
					for _, g := range u.Completeness.Blockers {
						if g.Kind == "sink_binding_unverified" {
							t.Errorf("bound record keeps its binding blocker")
						}
					}
				}
			}
			if bound != c.want {
				kinds := []string{}
				for _, u := range r.Uses {
					kinds = append(kinds, u.Kind)
				}
				t.Errorf("bound %v, want %v; records %v", bound, c.want, kinds)
			}
		})
	}
}

// TestPackageOriginFormsTypeScript covers TypeScript and the import forms that
// only ES modules have.
func TestPackageOriginFormsTypeScript(t *testing.T) {
	const head = "import express, { Request, Response } from 'express'\n"
	route := func(op string) string {
		return "const app = express()\napp.use(express.json())\napp.post('/r', async (req: Request, res: Response) => {\n  " + op + "\n  res.json({})\n})\napp.listen(3000)\n"
	}
	cases := []struct {
		name  string
		files map[string]string
		want  bool
	}{
		{"typed collection", map[string]string{"app.ts": head + "import { MongoClient, Collection, Db } from 'mongodb'\ninterface User { name: string }\nconst client: MongoClient = new MongoClient('x')\nconst db: Db = client.db('d')\nconst users: Collection<User> = db.collection<User>('users')\n" + route("await users.findOne({ name: req.body.name })")}, true},
		{"aliased import", map[string]string{"app.ts": head + "import { MongoClient as Mongo } from 'mongodb'\nconst db = new Mongo('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, true},
		{"inline type import", map[string]string{"app.ts": head + "import { MongoClient, type Filter } from 'mongodb'\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').find(req.body as Filter<any>).toArray()")}, true},
		{"as and non null", map[string]string{"app.ts": head + "import { MongoClient, Db } from 'mongodb'\nlet db: Db | undefined\nasync function init() { db = (await MongoClient.connect('x')).db('d') as Db }\ninit()\n" + route("await db!.collection('a').updateOne({ k: req.body.k }, { $set: { a: 1 } })")}, true},
		{"import equals require", map[string]string{"app.ts": head + "import mongo = require('mongodb')\nconst db = new mongo.MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, true},
		{"dynamic import", map[string]string{"app.ts": head + "const { MongoClient } = await import('mongodb')\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, true},
		{"shared client promise", map[string]string{"mongodb.ts": "import { MongoClient } from 'mongodb'\nlet client: MongoClient\nlet clientPromise: Promise<MongoClient>\nif (process.env.NODE_ENV === 'development') {\n  if (!global._mongoClientPromise) {\n    client = new MongoClient('x')\n    global._mongoClientPromise = client.connect()\n  }\n  clientPromise = global._mongoClientPromise\n} else {\n  client = new MongoClient('x')\n  clientPromise = client.connect()\n}\nexport default clientPromise\n", "app.ts": head + "import clientPromise from './mongodb'\n" + route("const client = await clientPromise\n  await client.db('d').collection('a').findOne({ k: req.body.k })")}, true},
		{"re-exported", map[string]string{"client.ts": "import { MongoClient } from 'mongodb'\nexport const db = new MongoClient('x').db()\n", "index.ts": "export { db } from './client'\n", "app.ts": head + "import { db } from './index'\n" + route("await db.collection('a').deleteOne({ k: req.body.k })")}, true},
		{"default instance", map[string]string{"client.ts": "import { MongoClient } from 'mongodb'\nconst client = new MongoClient('x')\nexport default client\n", "app.ts": head + "import client from './client'\n" + route("await client.db().collection('a').deleteOne({ k: req.body.k })")}, true},
		{"default function", map[string]string{"client.ts": "import { MongoClient } from 'mongodb'\nexport default async function getDb() { return (await MongoClient.connect('x')).db() }\n", "app.ts": head + "import getDb from './client'\n" + route("const db = await getDb()\n  await db.collection('a').deleteOne({ k: req.body.k })")}, true},
		{"then callback value", map[string]string{"app.ts": head + "import { MongoClient } from 'mongodb'\nconst dbp = new MongoClient('x').connect().then((c) => c.db('d'))\n" + route("const db = await dbp\n  await db.collection('a').findOne({ k: req.body.k })")}, true},

		{"type only import", map[string]string{"app.ts": head + "import type { MongoClient } from 'mongodb'\nclass Local { db() { return this } collection() { return { findOne(q: any) {} } } }\nconst c = new Local() as unknown as MongoClient\n" + route("await c.db().collection('a').findOne({ k: req.body.k })")}, false},
		{"annotation only", map[string]string{"app.ts": head + "import { Collection } from 'mongodb'\nfunction run(users: Collection, name: any) { return users.findOne({ name }) }\n" + route("await run({ findOne() {} } as any, req.body.name)")}, false},
		{"dynamic other package", map[string]string{"app.ts": head + "const { MongoClient } = await import('mongodb-like')\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
		{"mongodb types package", map[string]string{"app.ts": head + "import { MongoClient } from '@types/mongodb'\nconst db = new MongoClient('x').db()\n" + route("await db.collection('a').findOne({ k: req.body.k })")}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "package.json", `{"type":"module","dependencies":{"express":"5.1.0","mongodb":"7.0.0"}}`)
			for f, src := range c.files {
				writeSource(t, root, f, src)
			}
			r, err := Analyze(root, "app.ts")
			if err != nil {
				t.Fatal(err)
			}
			bound := false
			for _, u := range r.Uses {
				bound = bound || u.Kind == "nosql_query_candidate" && u.APIModel != nil && u.APIModel.ID == "mongodb-document-query-v1"
			}
			if bound != c.want {
				t.Errorf("bound %v, want %v", bound, c.want)
			}
		})
	}
}
