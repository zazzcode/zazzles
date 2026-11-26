package langjs

import (
	"strings"
	"testing"
)

// TestPackageOriginNextRoutes records database package operations through the
// shapes that hide them from a list of forms: a route helper that passes the
// handler on, a client kept in a global promise, a loop over a cursor, a method
// of the application's own class, a bound method, a command document, a renamed
// destructured property and a request-chosen collection name.
func TestPackageOriginNextRoutes(t *testing.T) {
	const client = `import { MongoClient } from 'mongodb';
export function ready() {
  globalThis.__shared ??= (async () => {
    const client = await new MongoClient('mongodb://x').connect();
    return { uri: 'mongodb://x', client };
  })().catch((error) => { delete globalThis.__shared; throw error; });
  return globalThis.__shared;
}
export const address = async () => (await ready()).uri;
export const database = async () => (await ready()).client.db('d');
export default async function connect() { return (await ready()).client; }
`
	const route = `import http from './http.cjs';
export const post = (run) => http.endpoint(['POST'], run);
export const twice = (run) => http.endpoint(['POST'], (req, res) => { run(req, res); return run(req, res); });
`
	const endpoint = `function endpoint(methods, run) {
  return async function handler(req, res) {
    if (!methods.includes(req.method)) return res.status(405).end();
    return run(req, res);
  };
}
module.exports = { endpoint };
`
	const repository = `export class Repository {
  constructor(db) { this.items = db.collection('items'); }
  async many(criteria) { return this.items.find(criteria).toArray(); }
}
`
	const queries = `import { database } from './client.js';
export async function list(criteria) {
  const rows = [];
  for await (const row of (await database()).collection('items').find(criteria)) rows.push(row.name);
  return rows;
}
`
	head := "import { database, address } from '../../lib/client.js';\nimport connect from '../../lib/client.js';\nimport { post, twice } from '../../lib/route.js';\nimport { Repository } from '../../lib/repository.js';\nimport { list } from '../../lib/queries.js';\n"
	cases := []struct{ name, handler, sink string }{
		{"helper and global promise", "export default post(async (req, res) => res.json(await (await database()).collection('items').findOne({ name: req.body.name })));", "findOne({ name: req.body.name })"},
		{"loop over a cursor", "export default post(async (req, res) => res.json(await list({ name: req.body.name })));", "find(criteria)"},
		{"method of the application's class", "export default post(async (req, res) => res.json(await new Repository(await database()).many({ ...req.body })));", "this.items.find(criteria)"},
		{"bound method", "const bound = (target) => ({ findOne: target.findOne.bind(target) });\nexport default post(async (req, res) => {\n  const { findOne } = bound((await database()).collection('items'));\n  return res.json(await findOne(req.body));\n});", "findOne(req.body)"},
		{"command document", "export default post(async (req, res) => {\n  const db = (await connect()).db('d');\n  return res.json(await db.command({ mapReduce: 'items', map: `function () { emit(this.k, ${req.body.factor}); }`, out: { inline: 1 } }));\n});", "db.command("},
		{"renamed property and collection name", "export default post(async (req, res) => {\n  const { of: name = 'items' } = req.query;\n  const db = await database();\n  return res.json(await db.collection(name).estimatedDocumentCount());\n});", "db.collection(name)"},
		{"count", "export default post(async (req, res) => res.json(await (await database()).collection('items').count({ ...req.body })));", "count({ ...req.body })"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := nextRepo(t, map[string]string{"lib/client.js": client, "lib/route.js": route, "lib/http.cjs": endpoint, "lib/repository.js": repository, "lib/queries.js": queries, "pages/api/r.js": head + c.handler + "\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, u := range r.Uses {
				if u.Kind != "nosql_query_candidate" || u.APIModel == nil || u.APIModel.ID != "mongodb-document-query-v1" || !strings.Contains(u.Sink.Text, c.sink) {
					continue
				}
				found = true
				path := u.Completeness.Evidence["sink_binding"]
				if len(path) < 3 || !strings.Contains(path[0].Text, "'mongodb'") || path[len(path)-1].Span != u.Sink.Span {
					t.Errorf("receiver path does not run from the import to the call: %d steps", len(path))
				}
				if len(u.Completeness.Blockers) != 0 {
					t.Errorf("record is held by %v", u.Completeness.Blockers)
				}
				if len(u.Completeness.Evidence["input_source"]) == 0 {
					t.Error("record has no input source")
				}
			}
			if !found {
				kinds := []string{}
				for _, u := range r.Uses {
					kinds = append(kinds, u.Kind+" "+u.Sink.Text)
				}
				t.Errorf("no database package operation at %q; records %v; entry gaps %v", c.sink, kinds, r.Entries[0].Gaps)
			}
		})
	}
	// A value that never comes from the package, and a helper that does more than
	// pass the handler on, record nothing.
	for _, c := range []struct{ name, handler string }{
		{"address is not a handle", "export default post(async (req, res) => res.json((await address()).split(req.body.sep)));"},
		{"result data is not a handle", "export default post(async (req, res) => {\n  const local = { findOne() {} };\n  return res.json(await local.findOne({ name: req.body.name }));\n});"},
		{"helper calls the handler twice", "export default twice(async (req, res) => res.json(await (await database()).collection('items').findOne({ name: req.body.name })));"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := nextRepo(t, map[string]string{"lib/client.js": client, "lib/route.js": route, "lib/http.cjs": endpoint, "lib/repository.js": repository, "lib/queries.js": queries, "pages/api/r.js": head + c.handler + "\n"})
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			for _, u := range r.Uses {
				if u.Kind == "nosql_query_candidate" {
					t.Errorf("recorded %q", u.Sink.Text)
				}
			}
		})
	}
}

// TestReferencedDefinitions sends the module-level definitions the handler uses
// and the model would otherwise judge without seeing: a constant map and a
// function passed as a callback. A definition already shown is not repeated.
func TestReferencedDefinitions(t *testing.T) {
	const client = "import { MongoClient } from 'mongodb';\nexport const items = new MongoClient('mongodb://x').db('d').collection('items');\n"
	handler := `import { items } from '../../lib/client.js';
const NAMES = { place: 'bin', title: 'name' };
const revive = (key, value) => (key.startsWith('$') ? undefined : value);
const unused = { a: 1 };
export default async function handler(req, res) {
  const filter = JSON.parse(req.body.payload, revive);
  const field = Object.hasOwn(NAMES, req.query.by) ? NAMES[req.query.by] : NAMES.place;
  return res.json(await items.distinct(field, filter));
}
`
	root := nextRepo(t, map[string]string{"lib/client.js": client, "pages/api/r.js": handler})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range r.Uses {
		if u.Kind != "nosql_query_candidate" {
			continue
		}
		found = true
		got := map[string]int{}
		for _, e := range u.Context {
			if e.Kind == "referenced_definition" {
				for _, name := range []string{"const NAMES", "const revive", "const unused", "MongoClient", "export default"} {
					if strings.Contains(e.Text, name) {
						got[name]++
					}
				}
			}
		}
		if got["const NAMES"] != 1 || got["const revive"] != 1 || got["const unused"] != 0 || got["MongoClient"] != 0 || got["export default"] != 0 {
			t.Errorf("referenced definitions: %v", got)
		}
	}
	if !found {
		t.Fatal("no database package operation recorded")
	}
}
