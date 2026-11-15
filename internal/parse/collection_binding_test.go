package parse

import "testing"

// A MarsDB collection reached through an ES named import is bound exactly like
// the namespace form; anything that could rebind the name stays unverified.
func TestCollectionBindingNamedImports(t *testing.T) {
	const marsData = `import * as MarsDB from 'marsdb';export const records=new MarsDB.Collection('records');`
	const route = `api.get('/lookup',(req,res)=>records.find({$where:'this.id == '+req.query.id}));`
	for _, tt := range []struct {
		name    string
		files   map[string]string
		server  string
		binding bool
	}{
		{"named import", map[string]string{"data.ts": marsData}, `import { records } from './data';` + route, true},
		{"aliased import", map[string]string{"data.ts": marsData}, `import { records as rows } from './data';api.get('/lookup',(req,res)=>rows.find({$where:'this.id == '+req.query.id}));`, true},
		{"export clause alias", map[string]string{"data.ts": `import * as MarsDB from 'marsdb';const inner=new MarsDB.Collection('records');export { inner as records };`}, `import { records } from './data';` + route, true},
		{"re-export", map[string]string{"data.ts": marsData, "index.ts": `export { records } from './data';`}, `import { records } from './index';` + route, true},
		{"aliased re-export", map[string]string{"data.ts": marsData, "index.ts": `export { records as items } from './data';`}, `import { items as records } from './index';` + route, true},
		{"shadowed in handler", map[string]string{"data.ts": marsData}, `import { records } from './data';api.get('/lookup',(req,res)=>{const records={find(x){return x}};records.find({$where:'this.id == '+req.query.id})});`, false},
		{"reassigned export", map[string]string{"data.ts": `import * as MarsDB from 'marsdb';export let records=new MarsDB.Collection('records');export function reset(v){records=v}`}, `import { records } from './data';` + route, false},
		{"exported twice", map[string]string{"data.ts": `import * as MarsDB from 'marsdb';const a=new MarsDB.Collection('a');const b=new MarsDB.Collection('b');export { a as records };export { b as records };`}, `import { records } from './data';` + route, false},
		{"other constructor", map[string]string{"data.ts": `import * as Other from 'other-db';export const records=new Other.Collection('records');`}, `import { records } from './data';` + route, false},
		{"package import", map[string]string{"data.ts": marsData}, `import { records } from 'data';` + route, false},
		{"missing export", map[string]string{"data.ts": `import * as MarsDB from 'marsdb';const records=new MarsDB.Collection('records');`}, `import { records } from './data';` + route, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			for name, src := range tt.files {
				writeSource(t, root, name, src)
			}
			writeSource(t, root, "server.ts", `import express from 'express';const api=express();`+tt.server)
			r, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, u := range r.Uses {
				if u.Kind != "nosql_query_candidate" {
					continue
				}
				found = true
				bound := u.Completeness != nil && len(u.Completeness.Evidence["sink_binding"]) > 0
				if bound != tt.binding {
					t.Fatalf("binding=%v want %v: blockers=%+v", bound, tt.binding, u.Completeness.Blockers)
				}
				if tt.binding && (u.APIModel == nil || u.APIModel.ID != "marsdb-collection-v1") {
					t.Fatalf("api model=%+v", u.APIModel)
				}
				if tt.binding {
					// The importing declaration, the marsdb import and the constructor all travel as evidence.
					if n := len(u.Completeness.Evidence["sink_binding"]); n < 3 {
						t.Fatalf("sink_binding evidence=%d, want import + library + constructor", n)
					}
				}
			}
			if tt.binding && !found {
				t.Fatal("no nosql candidate")
			}
		})
	}
}
